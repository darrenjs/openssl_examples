#include "peer.h"
#include "macros.h"


/* =========================
 *  static decls
 * ========================= */

/* Obtain the return value of an SSL operation and convert into a simplified
 * error code, which is easier to examine for failure. */
typedef enum { SSLSTATUS_OK, SSLSTATUS_WANT_IO, SSLSTATUS_FAIL} ssl_status_t ;

static ssl_status_t get_sslstatus(SSL* ssl, int n);
static int push_encrypted_bytes(peer_t *peer, uint8_t * src, ssize_t len);

/* =========================
 *  implementation
 * ========================= */

int peer_do_handshake(peer_t *peer)
{
  uint8_t buf[DEFAULT_BUF_SIZE];
  ssl_status_t status;

  int n = SSL_do_handshake(peer->ssl);
  status = get_sslstatus(peer->ssl, n);

  /* Did SSL request to write bytes? */
  if (status == SSLSTATUS_WANT_IO) {
    do {
      n = BIO_read(peer->wbio, buf, sizeof(buf));
      if (n > 0)
        peer_queue_to_decrypt(peer, buf, n);
      else if (!BIO_should_retry(peer->wbio))
        return -1;
    } while (n > 0);
  }

  return (status == SSLSTATUS_OK) ? 0 : -1;
}


/* Process outbound unencrypted data that is waiting to be encrypted.  The
 * waiting data resides in encrypt_buf.  It needs to be passed into the SSL
 * object for encryption, which in turn generates the encrypted bytes that then
 * will be queued for later socket write. */
int peer_encrypt(peer_t *peer)
{
  uint8_t buf[DEFAULT_BUF_SIZE];
  ssl_status_t status;

  if (!SSL_is_init_finished(peer->ssl))
    return 0;

  while (peer_want_encrypt(peer)) {
    int n = SSL_write(peer->ssl, peer->encrypt_buf, peer->encrypt_sz);
    status = get_sslstatus(peer->ssl, n);

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

    if (status == SSLSTATUS_FAIL)
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

void ssl_init(SSL_CTX **ctx, const char * certfile, const char * keyfile)
{
  printf("initialising SSL\n");

  /* SSL library initialisation */
  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();

  /* create the SSL server context */
  *ctx = SSL_CTX_new(SSLv23_method());
  if (!(*ctx))
    die("SSL_CTX_new()");

  /* Load certificate and private key files, and check consistency */
  if (certfile && keyfile) {
    if (SSL_CTX_use_certificate_file(*ctx, certfile,  SSL_FILETYPE_PEM) != 1)
      LOG_KILL("SSL_CTX_use_certificate_file failed");

    if (SSL_CTX_use_PrivateKey_file(*ctx, keyfile, SSL_FILETYPE_PEM) != 1)
      LOG_KILL("SSL_CTX_use_PrivateKey_file failed");

    /* Make sure the key and certificate file match. */
    if (SSL_CTX_check_private_key(*ctx) != 1)
      LOG_KILL("SSL_CTX_check_private_key failed");
    else
      printf("certificate and private key loaded and verified\n");
  }

  /* Recommended to avoid SSLv2 & SSLv3 */
  SSL_CTX_set_options(*ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3);
}

/* =========================
 *  static
 * ========================= */

static ssl_status_t get_sslstatus(SSL* ssl, int n)
{
  switch (SSL_get_error(ssl, n))
  {
    case SSL_ERROR_NONE:
      return SSLSTATUS_OK;
    case SSL_ERROR_WANT_WRITE:
    case SSL_ERROR_WANT_READ:
      return SSLSTATUS_WANT_IO;
    case SSL_ERROR_ZERO_RETURN:
    case SSL_ERROR_SYSCALL:
    default:
      return SSLSTATUS_FAIL;
  }
}

/* Process SSL bytes received from the peer. The data needs to be fed into the
   SSL object to be unencrypted.  On success, returns 0, on SSL error -1. */
static int push_encrypted_bytes(peer_t *peer, uint8_t * src, ssize_t len)
{
  uint8_t buf[DEFAULT_BUF_SIZE];
  ssl_status_t status;
  int n;

  while (len > 0) {
    n = BIO_write(peer->rbio, src, len);

    if (n <= 0)
      return -1; /* assume bio write failure is unrecoverable */

    src += n;
    len -= n;

    if (!SSL_is_init_finished(peer->ssl)) {
      if (peer_do_handshake(peer) == SSLSTATUS_FAIL)
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

    status = get_sslstatus(peer->ssl, n);

    /* Did SSL request to write bytes? This can happen if peer has requested SSL
     * renegotiation. */
    if (status == SSLSTATUS_WANT_IO)
      do {
        n = BIO_read(peer->wbio, buf, sizeof(buf));
        if (n > 0)
          peer_queue_to_decrypt(peer, buf, n);
        else if (!BIO_should_retry(peer->wbio))
          return -1;
      } while (n > 0);

    if (status == SSLSTATUS_FAIL)
      return -1;
  }

  return 0;
}
