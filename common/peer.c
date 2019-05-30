#include "peer.h"
#include "macros.h"


/* =========================
 *  static decls
 * ========================= */

static int push_encrypted_bytes(peer_t *peer, uint8_t * src, ssize_t len);

static inline bool ssl_status_want_io(int status)
{
  return status == SSL_ERROR_WANT_WRITE || status == SSL_ERROR_WANT_READ;
}

static inline bool ssl_status_ok(int status)
{
  return status == SSL_ERROR_NONE;
}

static inline bool ssl_status_fail(int status)
{
  return !ssl_status_ok(status) && !ssl_status_want_io(status);
}

/* =========================
 *  implementation
 * ========================= */

int peer_do_handshake(peer_t *peer)
{
  uint8_t buf[DEFAULT_BUF_SIZE];
  int status;

  int n = SSL_do_handshake(peer->ssl);
  status = SSL_get_error(peer->ssl, n);

  /* Did SSL request to write bytes? */
  if (ssl_status_want_io(status)) {
    do {
      n = BIO_read(peer->wbio, buf, sizeof(buf));
      if (n > 0)
        peer_queue_to_decrypt(peer, buf, n);
      else if (!BIO_should_retry(peer->wbio))
        return -1;
    } while (n > 0);
  }

  return (!ssl_status_fail(status)) ? 0 : -1;
}


/* Process outbound unencrypted data that is waiting to be encrypted.  The
 * waiting data resides in encrypt_buf.  It needs to be passed into the SSL
 * object for encryption, which in turn generates the encrypted bytes that then
 * will be queued for later socket write. */
int peer_encrypt(peer_t *peer)
{
  uint8_t buf[DEFAULT_BUF_SIZE];
  int status;

  if (!SSL_is_init_finished(peer->ssl))
    return 0;

  while (peer_want_encrypt(peer)) {
    int n = SSL_write(peer->ssl, peer->encrypt_buf, peer->encrypt_sz);
    status = SSL_get_error(peer->ssl, n);

    if (n > 0) {
      /* consume the waiting bytes that have been used by SSL */
      if (n < peer->encrypt_sz)
        memmove(peer->encrypt_buf, peer->encrypt_buf+n, peer->encrypt_sz-n);
      peer->encrypt_sz -= n;
      peer->encrypt_buf = realloc(peer->encrypt_buf, peer->encrypt_sz);

      /* take the output of the SSL object and queue it for socket write */
      do {
        n = BIO_read(peer->wbio, buf, sizeof(buf));
        if (n > 0)
          peer_queue_to_decrypt(peer, buf, n);
        else if (!BIO_should_retry(peer->wbio))
          return -1;
      } while (n > 0);
    }

    if (ssl_status_fail(status))
      return -1;

    if (n == 0)
      break;
  }
  return 0;
}

/* Read encrypted bytes from socket. */
int peer_recv(peer_t *peer)
{
  uint8_t buf[DEFAULT_BUF_SIZE];
  ssize_t n = read(peer->socket, buf, sizeof(buf));

  if (n > 0)
    return push_encrypted_bytes(peer, buf, (size_t)n);
  else
    return -1;
}

/* Write encrypted bytes to the socket. */
int peer_send(peer_t *peer)
{
  ssize_t n = write(peer->socket, peer->write_buf, peer->write_sz);
  if (n > 0) {
    if (n < peer->write_sz)
      memmove(peer->write_buf, peer->write_buf+n, peer->write_sz-n);

    peer->write_sz -= n;
    peer->write_buf = realloc(peer->write_buf, peer->write_sz);
    return 0;
  }
  else
    return -1;
}

/* =========================
 *  static
 * ========================= */

/* Process SSL bytes received from the peer. The data needs to be fed into the
   SSL object to be unencrypted.  On success, returns 0, on SSL error -1. */
static int push_encrypted_bytes(peer_t *peer, uint8_t * src, ssize_t len)
{
  uint8_t buf[DEFAULT_BUF_SIZE];
  int status;
  int n;

  while (len > 0) {
    n = BIO_write(peer->rbio, src, len);

    if (n <= 0)
      return -1; /* assume bio write failure is unrecoverable */

    src += n;
    len -= n;

    if (!SSL_is_init_finished(peer->ssl)) {
      if (peer_do_handshake(peer) == -1)
        return -1;
      if (!SSL_is_init_finished(peer->ssl))
        return 0;
    }

    /* The encrypted data is now in the input bio so now we can perform actual
     * read of unencrypted data. */

    do {
      n = SSL_read(peer->ssl, buf, sizeof(buf));
      if (n > 0)
        peer_queue_to_process(peer, buf, n);
    } while (n > 0);

    status = SSL_get_error(peer->ssl, n);

    /* Did SSL request to write bytes? This can happen if peer has requested SSL
     * renegotiation. */
    if (ssl_status_want_io(status))
      do {
        n = BIO_read(peer->wbio, buf, sizeof(buf));
        if (n > 0)
          peer_queue_to_decrypt(peer, buf, n);
        else if (!BIO_should_retry(peer->wbio))
          return -1;
      } while (n > 0);

    if (ssl_status_fail(status))
      return -1;
  }

  return 0;
}
