#include "peer.h"
#include "macros.h"

#define DEFAULT_BUF_SIZE 64

void print_unencrypted_data(uint8_t *buf, ssize_t len)
{
  printf("%.*s", (int)len, (char *) buf);
}

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

/* Handle request to send unencrypted data to the SSL.  All we do here is just
 * queue the data into the encrypt_buf for later processing by the SSL
 * object. */
void send_unencrypted_bytes(peer_t *peer, const uint8_t *buf, ssize_t len)
{
  peer->encrypt_buf = realloc(peer->encrypt_buf, peer->encrypt_len + len);
  memcpy(peer->encrypt_buf+peer->encrypt_len, buf, len);
  peer->encrypt_len += len;
}

/* Queue encrypted bytes. Should only be used when the SSL object has requested a
 * write operation. */
void queue_encrypted_bytes(peer_t *peer, const uint8_t *buf, ssize_t len)
{
  peer->write_buf = realloc(peer->write_buf, peer->write_len + len);
  memcpy(peer->write_buf+peer->write_len, buf, len);
  peer->write_len += len;
}

ssl_status_t do_ssl_handshake(peer_t *peer)
{
  uint8_t buf[DEFAULT_BUF_SIZE];
  ssl_status_t status;

  int n = SSL_do_handshake(peer->ssl);
  status = get_sslstatus(peer->ssl, n);

  /* Did SSL request to write bytes? */
  if (status == SSLSTATUS_WANT_IO)
    do {
      n = BIO_read(peer->wbio, buf, sizeof(buf));
      if (n > 0)
        queue_encrypted_bytes(peer, buf, n);
      else if (!BIO_should_retry(peer->wbio))
        return SSLSTATUS_FAIL;
    } while (n>0);

  return status;
}

/* Process SSL bytes received from the peer. The data needs to be fed into the
   SSL object to be unencrypted.  On success, returns 0, on SSL error -1. */
int on_read_cb(peer_t *peer, uint8_t * src, ssize_t len)
{
  uint8_t buf[DEFAULT_BUF_SIZE];
  ssl_status_t status;
  int n;

  while (len > 0) {
    n = BIO_write(peer->rbio, src, len);

    if (n<=0)
      return -1; /* assume bio write failure is unrecoverable */

    src += n;
    len -= n;

    if (!SSL_is_init_finished(peer->ssl)) {
      if (do_ssl_handshake(peer) == SSLSTATUS_FAIL)
        return -1;
      if (!SSL_is_init_finished(peer->ssl))
        return 0;
    }

    /* The encrypted data is now in the input bio so now we can perform actual
     * read of unencrypted data. */

    do {
      n = SSL_read(peer->ssl, buf, sizeof(buf));
      if (n > 0)
        peer->io_on_read(buf, n);
    } while (n > 0);

    status = get_sslstatus(peer->ssl, n);

    /* Did SSL request to write bytes? This can happen if peer has requested SSL
     * renegotiation. */
    if (status == SSLSTATUS_WANT_IO)
      do {
        n = BIO_read(peer->wbio, buf, sizeof(buf));
        if (n > 0)
          queue_encrypted_bytes(peer, buf, n);
        else if (!BIO_should_retry(peer->wbio))
          return -1;
      } while (n>0);

    if (status == SSLSTATUS_FAIL)
      return -1;
  }

  return 0;
}

/* Process outbound unencrypted data that is waiting to be encrypted.  The
 * waiting data resides in encrypt_buf.  It needs to be passed into the SSL
 * object for encryption, which in turn generates the encrypted bytes that then
 * will be queued for later socket write. */
int do_encrypt(peer_t *peer)
{
  uint8_t buf[DEFAULT_BUF_SIZE];
  ssl_status_t status;

  if (!SSL_is_init_finished(peer->ssl))
    return 0;

  while (peer->encrypt_len>0) {
    int n = SSL_write(peer->ssl, peer->encrypt_buf, peer->encrypt_len);
    status = get_sslstatus(peer->ssl, n);

    if (n>0) {
      /* consume the waiting bytes that have been used by SSL */
      if (n < peer->encrypt_len)
        memmove(peer->encrypt_buf, peer->encrypt_buf+n, peer->encrypt_len-n);
      peer->encrypt_len -= n;
      peer->encrypt_buf = realloc(peer->encrypt_buf, peer->encrypt_len);

      /* take the output of the SSL object and queue it for socket write */
      do {
        n = BIO_read(peer->wbio, buf, sizeof(buf));
        if (n > 0)
          queue_encrypted_bytes(peer, buf, n);
        else if (!BIO_should_retry(peer->wbio))
          return -1;
      } while (n>0);
    }

    if (status == SSLSTATUS_FAIL)
      return -1;

    if (n==0)
      break;
  }
  return 0;
}

/* Read bytes from stdin and queue for later encryption. */
void do_stdin_read(peer_t *peer)
{
  uint8_t buf[DEFAULT_BUF_SIZE];
  ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
  if (n>0)
    send_unencrypted_bytes(peer, buf, (size_t)n);
}

/* Read encrypted bytes from socket. */
int do_sock_read(peer_t *peer)
{
  uint8_t buf[DEFAULT_BUF_SIZE];
  ssize_t n = read(peer->fd, buf, sizeof(buf));

  if (n>0)
    return on_read_cb(peer, buf, (size_t)n);
  else
    return -1;
}

/* Write encrypted bytes to the socket. */
int do_sock_write(peer_t *peer)
{
  ssize_t n = write(peer->fd, peer->write_buf, peer->write_len);
  if (n>0) {
    if (n < peer->write_len)
      memmove(peer->write_buf, peer->write_buf+n, peer->write_len-n);
    peer->write_len -= n;
    peer->write_buf = realloc(peer->write_buf, peer->write_len);
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
