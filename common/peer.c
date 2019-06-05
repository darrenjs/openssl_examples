/**
 * implementation
 */

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <unistd.h>

#include "peer.h"
#include "macros.h"
#include "ssl_util.h"

/* =========================
 *  global static decls
 * ========================= */

static int peer_encrypt(peer_t *peer, const uint8_t *buf_to_encrypt, ssize_t buf_sz);
static int peer_decrypt(peer_t *peer, uint8_t * src, ssize_t len);

static inline bool ssl_status_want_io(int status) { return status == SSL_ERROR_WANT_WRITE || status == SSL_ERROR_WANT_READ; }
static inline bool ssl_status_ok(int status) { return status == SSL_ERROR_NONE; }
static inline bool ssl_status_fail(int status) { return !ssl_status_ok(status) && !ssl_status_want_io(status); }

static ssize_t find_next_power_of_2(ssize_t arg)
{
  int pow = 1;
  while (pow < arg) pow <<= 1;
  return pow;
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
  peer->write_cap = peer->process_cap = 0;

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


static int __queue(uint8_t ** dst_buf, ssize_t *dst_sz, ssize_t * dst_cap,
             const uint8_t * src_buf, ssize_t src_sz)
{
  if (*dst_cap == 0) {
    *dst_cap = (src_sz <= DEFAULT_BUF_SIZE)
      ? DEFAULT_BUF_SIZE : find_next_power_of_2(src_sz);

    *dst_buf = malloc(*dst_cap * sizeof(uint8_t));
    if (*dst_buf == NULL)
      LOG_KILL("failed on malloc");
  }

  else if (*dst_sz + src_sz > *dst_cap) {
    *dst_cap = find_next_power_of_2(*dst_sz + src_sz);
    *dst_buf = realloc(*dst_buf, *dst_cap);
    if (*dst_buf == NULL)
      LOG_KILL("failed on realloc");
  }

  memcpy(*dst_buf + *dst_sz, src_buf, src_sz);
  *dst_sz += src_sz;
  return 0;
}

static int peer_queue_to_write(peer_t *peer, const uint8_t *buf, ssize_t len)
{
  return __queue(&peer->write_buf, &peer->write_sz, &peer->write_cap, buf, len);
}

static int peer_queue_to_process(peer_t *peer, const uint8_t *buf, ssize_t len)
{
  return __queue(&peer->process_buf, &peer->process_sz, &peer->process_cap, buf, len);
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

bool peer_finished_handshake(const peer_t *peer)
{ return SSL_is_init_finished(peer->ssl); }

int peer_do_handshake(peer_t *peer)
{
  uint8_t buf[DEFAULT_BUF_SIZE];
  int status;

  int ret = SSL_do_handshake(peer->ssl);
  status = SSL_get_error(peer->ssl, ret);

  // ssl may want to read stuff
  if (ssl_status_want_io(status)) {
    do {
      ret = BIO_read(peer->wbio, buf, sizeof(buf));
      if (ret > 0)
        peer_queue_to_write(peer, buf, ret);
      else if (!BIO_should_retry(peer->wbio))
        return -1;
    } while (ret > 0);
  }

  return (!ssl_status_fail(status)) ? 0 : -1;
}

int peer_do_nonblock_handshake(peer_t *peer)
{
  fd_set read_fds;
  fd_set write_fds;
  fd_set except_fds;

  peer_do_handshake(peer);
  while (!peer_finished_handshake(peer)) {
    FD_ZERO(&read_fds); FD_SET(peer->socket, &read_fds);
    FD_ZERO(&write_fds);
    if (peer_want_write(peer))
      FD_SET(peer->socket, &write_fds);
    FD_ZERO(&except_fds); FD_SET(peer->socket, &except_fds);

    int activity = select(peer->socket + 1, &read_fds, &write_fds, &except_fds, NULL);
    switch (activity) {
      case -1:
        perror("select");
        LOG("failed to select");
        return -1;

      case 0:
        LOG("select returned 0");
        break;

      default:
        if (FD_ISSET(peer->socket, &read_fds)) {
          if (peer_recv(peer) != 0) {
            LOG("failed to receive from server");
            peer_close(peer);
            return -1;
          }
        }
        if (FD_ISSET(peer->socket, &write_fds)) {
          if (peer_send(peer) != 0) {
            LOG("failed to sent to server");
            peer_close(peer);
            return -1;
          }
        }
        if (FD_ISSET(peer->socket, &except_fds)) {
          LOG("exception on peer socket");
          return -1;
        }
    }
  }

  return 0;
}


/* Read encrypted bytes from socket. */
int peer_recv(peer_t *peer)
{
  uint8_t buf[DEFAULT_BUF_SIZE];
  ssize_t nbytes = read(peer->socket, buf, DEFAULT_BUF_SIZE);

  if (nbytes > 0)
    return peer_decrypt(peer, buf, nbytes);
  else
    return -1;
}

int peer_prepare_message_to_send(peer_t *peer, const uint8_t * buf, ssize_t sz)
{
  if (sz > 0) {
    return peer_encrypt(peer, buf, sz);
  }
  else
    return -1;
}

int peer_send(peer_t *peer)
{
  ssize_t nwritten = write(peer->socket, peer->write_buf, peer->write_sz);
  if (nwritten > 0) {
    if (nwritten < peer->write_sz)
      memmove(peer->write_buf, peer->write_buf + nwritten, peer->write_sz - nwritten);

    peer->write_sz -= nwritten;
    return 0;
  }
  else
    return -1;
}

/* =================================================== */

/* =========================
 *  crypto funcs
 * ========================= */

// get a public key
EVP_PKEY *peer_get_pubkey(const peer_t * const peer)
{
  if (!peer_valid(peer)) return NULL;
  X509 *cert = SSL_get_peer_certificate(peer->ssl);
  if (cert == NULL) {
    fprintf(stderr, "Failed to get the certificate\n");
    return NULL;
  }

  EVP_PKEY *key = X509_get_pubkey(cert);
  X509_free(cert);
  return key;
}

// show the certs
void peer_show_certificate(FILE *stream, const peer_t * const peer)
{
  if (!peer_valid(peer)) {
    fputs("No connection\n", stream);
  }

  show_certificates(stream, peer->ssl);
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

static int peer_encrypt(peer_t *peer, const uint8_t *buf_to_encrypt, ssize_t buf_sz)
{
  uint8_t buf[DEFAULT_BUF_SIZE];
  int status;

  if (!SSL_is_init_finished(peer->ssl))
    return 0;

  int written = 0;
  while (written < buf_sz) {
    int ret = SSL_write(peer->ssl, buf_to_encrypt + written, buf_sz - written);
    status = SSL_get_error(peer->ssl, ret);

    if (ret > 0) {
      written += ret;

      /* take the output of the SSL object
       * and queue it for socket write */
      do {
        ret = BIO_read(peer->wbio, buf, sizeof(buf));
        if (ret > 0)
          peer_queue_to_write(peer, buf, ret);
        else if (!BIO_should_retry(peer->wbio))
          return -1;
      } while (ret > 0);
    }

    if (ssl_status_fail(status))
      return -1;

    if (ret == 0)
      break;
  }
  return 0;
}

static int peer_decrypt(peer_t *peer, uint8_t * src, ssize_t len)
{
  uint8_t buf[DEFAULT_BUF_SIZE];
  int status;
  int ret;

  while (len > 0) {
    ret = BIO_write(peer->rbio, src, len);

    if (ret <= 0)
      return -1; // bio failure is irrecoverable

    src += ret;
    len -= ret;

    if (!SSL_is_init_finished(peer->ssl)) {
      if (peer_do_handshake(peer) == -1)
        return -1;
      if (!SSL_is_init_finished(peer->ssl))
        return 0;
    }

    // read cleartext
    do {
      ret = SSL_read(peer->ssl, buf, sizeof(buf));
      if (ret > 0)
        peer_queue_to_process(peer, buf, ret);
    } while (ret > 0);

    status = SSL_get_error(peer->ssl, ret);

    // may have renegotiation
    if (ssl_status_want_io(status))
      do {
        ret = BIO_read(peer->wbio, buf, sizeof(buf));
        if (ret > 0)
          peer_queue_to_write(peer, buf, ret);
        else if (!BIO_should_retry(peer->wbio))
          return -1;
      } while (ret > 0);

    if (ssl_status_fail(status))
      return -1;
  }

  return 0;
}
