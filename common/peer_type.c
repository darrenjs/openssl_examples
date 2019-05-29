/**
 * implementation
 */

#include "peer_type.h"
#include "macros.h"
#include <string.h>
#include <unistd.h>

int peer_create(peer_t *peer, SSL_CTX *ctx, bool server)
{
  /* missing stuff */
  memset(peer, 0, sizeof(peer_t));

  peer->rbio = BIO_new(BIO_s_mem());
  peer->wbio = BIO_new(BIO_s_mem());
  peer->ssl  = SSL_new(ctx);

  if (server)
    SSL_set_accept_state(peer->ssl);
  else
    SSL_set_connect_state(peer->ssl);

  SSL_set_bio(peer->ssl, peer->rbio, peer->wbio);
  return 0;
}

int peer_delete(peer_t * peer)
{
  if (peer_close(peer) == -1)
    return -1;

  if (peer->ssl)
    SSL_free(peer->ssl);
  peer->ssl = NULL;

  if (peer->write_buf)
    free(peer->write_buf);
  if (peer->encrypt_buf)
    free(peer->encrypt_buf);
  if (peer->process_buf)
    free(peer->process_buf);

  peer->write_buf = peer->encrypt_buf = peer->process_buf = NULL;
  peer->write_sz = peer->encrypt_sz = peer->process_sz = 0;

  return 0;
}

int peer_close(peer_t *peer)
{
  if (peer == NULL)
    return -1;

  if (peer->socket != -1)
    close(peer->socket);

  peer->socket = -1;
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

static int __queue(uint8_t ** dst_buf, ssize_t *dst_sz,
             const uint8_t * src_buf, ssize_t src_sz)
{
  *dst_buf = realloc(*dst_buf, *dst_sz + src_sz);
  memcpy(*dst_buf + *dst_sz, src_buf, src_sz);
  *dst_sz += src_sz;
  return 0;
}

int peer_queue_to_encrypt(peer_t *peer, const uint8_t *buf, ssize_t len)
{
  return __queue(&peer->encrypt_buf, &peer->encrypt_sz, buf, len);
}

int peer_queue_to_decrypt(peer_t *peer, const uint8_t *buf, ssize_t len)
{
  return __queue(&peer->write_buf, &peer->write_sz, buf, len);
}

int peer_queue_to_process(peer_t *peer, const uint8_t *buf, ssize_t len)
{
  return __queue(&peer->process_buf, &peer->process_sz, buf, len);
}


bool peer_valid(const peer_t * const peer) { return peer->socket != -1; }
bool peer_want_write(peer_t *peer) { return peer->write_sz > 0; }
bool peer_want_encrypt(peer_t *peer) { return peer->encrypt_sz > 0; }
bool peer_want_read(peer_t *peer) { return peer->process_sz > 0; }


const char * peer_get_addr(const peer_t * const peer)
{
  static char __address_str[INET_ADDRSTRLEN + 16];
  char        __str_peer_ipv4[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &peer->address.sin_addr, __str_peer_ipv4, INET_ADDRSTRLEN);
  snprintf(__address_str, INET_ADDRSTRLEN + 15,
      "%s:%d", __str_peer_ipv4, ntohs(peer->address.sin_port));

  return __address_str;
}
