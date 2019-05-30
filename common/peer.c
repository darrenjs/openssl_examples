/**
 * implementation
 */

#include "peer.h"
#include "macros.h"

/* =========================
 *  global static decls
 * ========================= */

static int peer_encrypt(peer_t *peer, const uint8_t *buf_to_encrypt, ssize_t buf_sz);
static int peer_decrypt(peer_t *peer, uint8_t * src, ssize_t len);

static int peer_queue_to_write(peer_t *peer, const uint8_t *buf, ssize_t len);
static int peer_queue_to_process(peer_t *peer, const uint8_t *buf, ssize_t len);

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


/* =================================================== */

/* =========================
 *  type funcs
 * ========================= */

static int peer_setup(peer_t * peer)
{
  peer->rbio = BIO_new(BIO_s_mem());
  peer->wbio = BIO_new(BIO_s_mem());
  peer->ssl  = SSL_new(peer->ctx);

  if (peer->server)
    SSL_set_accept_state(peer->ssl);
  else
    SSL_set_connect_state(peer->ssl);

  SSL_set_bio(peer->ssl, peer->rbio, peer->wbio);
  return 0;
}


int peer_create(peer_t *peer, SSL_CTX *ctx, bool server)
{
  /* missing stuff */
  memset(peer, 0, sizeof(peer_t));
  peer->socket = -1;
  peer->server = server;
  peer->ctx    = ctx;

  return peer_setup(peer);
}

int peer_delete(peer_t * peer)
{
  if (peer == NULL)
    return -1;

  if (peer->socket != -1)
    close(peer->socket);
  peer->socket = -1;

  if (peer->ssl)
    SSL_free(peer->ssl);
  peer->ssl = NULL;

  if (peer->write_buf)
    free(peer->write_buf);
  if (peer->process_buf)
    free(peer->process_buf);

  peer->write_buf = peer->process_buf = NULL;
  peer->write_sz = peer->process_sz = 0;

  peer->ctx = NULL;
  return 0;
}

int peer_connect(peer_t * const peer, struct sockaddr_in *addr)
{
  peer->socket = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
  if (peer->socket < 0) {
    perror("socket");
    LOG("failed to open socket");
    return -1;
  }

  peer->address = *addr;
  errno = 0;
  while (
      connect(peer->socket, (struct sockaddr *) &(peer->address), sizeof(struct sockaddr)) == -1
      && errno == EINPROGRESS
      );

  if (errno != 0 && errno != EINPROGRESS) {
    perror("connect");
    LOG("failed to connect");
    return -1;
  }

  return 0;
}

int peer_accept(peer_t * peer, int listen_socket)
{
  socklen_t len = sizeof(struct sockaddr);
  peer->socket = accept(listen_socket, (struct sockaddr *) &peer->address, &len);
  if (peer->socket == -1) {
    perror("accept");
    LOG("failed to accept");
    return -1;
  }

  return 0;
}

int peer_close(peer_t *peer)
{
  if (peer == NULL)
    return -1;

  if (peer->socket != -1)
    close(peer->socket);
  peer->socket = -1;

  peer->write_sz = peer->process_sz = 0;

  // SSL object has garbage, needs to be reset to allow for
  // another connection
  if (peer->ssl)
    SSL_free(peer->ssl);

  return peer_setup(peer);
}

/* =================================================== */

/* =========================
 *  queue funcs
 * ========================= */


static int __queue(uint8_t ** dst_buf, ssize_t *dst_sz,
             const uint8_t * src_buf, ssize_t src_sz)
{
  *dst_buf = realloc(*dst_buf, *dst_sz + src_sz);
  memcpy(*dst_buf + *dst_sz, src_buf, src_sz);
  *dst_sz += src_sz;
  return 0;
}

static int peer_queue_to_write(peer_t *peer, const uint8_t *buf, ssize_t len)
{
  return __queue(&peer->write_buf, &peer->write_sz, buf, len);
}

static int peer_queue_to_process(peer_t *peer, const uint8_t *buf, ssize_t len)
{
  return __queue(&peer->process_buf, &peer->process_sz, buf, len);
}

/* =================================================== */

/* =========================
 *  bool funcs
 * ========================= */


bool peer_valid(const peer_t * const peer) { return peer->socket != -1; }
bool peer_want_write(peer_t *peer) { return peer->write_sz > 0; }
bool peer_want_read(peer_t *peer) { return peer->process_sz > 0; }

/* =================================================== */

/* =========================
 *  io funcs
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
        peer_queue_to_write(peer, buf, n);
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
static int peer_encrypt(peer_t *peer, const uint8_t *buf_to_encrypt, ssize_t buf_sz)
{
  uint8_t buf[DEFAULT_BUF_SIZE];
  int status;

  if (!SSL_is_init_finished(peer->ssl))
    return 0;

  int written = 0;
  while (written < buf_sz) {
    int n = SSL_write(peer->ssl, buf_to_encrypt + written, buf_sz - written);
    status = SSL_get_error(peer->ssl, n);

    if (n > 0) {
      written += n;

      /* take the output of the SSL object
       * and queue it for socket write */
      do {
        n = BIO_read(peer->wbio, buf, sizeof(buf));
        if (n > 0)
          peer_queue_to_write(peer, buf, n);
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
    return peer_decrypt(peer, buf, n);
  else
    return -1;
}

/* Read encrypted bytes from socket. */
int peer_prepare_message_to_send(peer_t *peer, const uint8_t * buf, ssize_t sz)
{
  if (sz > 0) {
    return peer_encrypt(peer, buf, sz);
  }
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


/* =================================================== */

/* =========================
 *  getter
 * ========================= */

const char * peer_get_addr(const peer_t * const peer)
{
  static char __address_str[INET_ADDRSTRLEN + 16];
  char        __str_peer_ipv4[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &peer->address.sin_addr, __str_peer_ipv4, INET_ADDRSTRLEN);
  snprintf(__address_str, INET_ADDRSTRLEN + 15,
      "%s:%d", __str_peer_ipv4, ntohs(peer->address.sin_port));

  return __address_str;
}


/* =================================================== */

/* =========================
 *  static implementation
 * ========================= */

static int peer_decrypt(peer_t *peer, uint8_t * src, ssize_t len)
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
          peer_queue_to_write(peer, buf, n);
        else if (!BIO_should_retry(peer->wbio))
          return -1;
      } while (n > 0);

    if (ssl_status_fail(status))
      return -1;
  }

  return 0;
}
