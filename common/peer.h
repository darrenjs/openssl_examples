/*
 * peer_type.h
 *
 * definition of the peer type
 */
#pragma once

#include <stdbool.h>

typedef struct peer_t
{
  int socket;
  struct sockaddr_in address;
  SSL *ssl;

  BIO *rbio; // SSL reads from, we write to
  BIO *wbio; // SSL writes to, we read from

  // waiting to be written to socket;
  uint8_t *write_buf;
  ssize_t  write_sz;
  ssize_t write_cap;

  // waiting to be processed
  uint8_t *process_buf;
  ssize_t  process_sz;
  ssize_t process_cap;

  // to allow for reset
  bool server;
  SSL_CTX * ctx;
} peer_t;

// type funcs
int peer_create(peer_t * const, SSL_CTX *, bool server);
int peer_delete(peer_t * const);

// connect funcs
int peer_close(peer_t * const);
int peer_connect(peer_t * const, struct sockaddr_in *addr);
int peer_accept(peer_t * const, int listen_socket);

// bool funcs
bool peer_valid(const peer_t * const);
bool peer_want_write(peer_t *peer);
bool peer_want_read(peer_t *peer);

// io funcs
bool peer_finished_handshake(const peer_t *peer);
int peer_do_handshake(peer_t *peer);
int peer_do_nonblock_handshake(peer_t *peer);
int peer_recv(peer_t *peer);
int peer_send(peer_t *peer);
int peer_prepare_message_to_send(peer_t *peer, const uint8_t * buf, ssize_t sz);

// crypto funcs
EVP_PKEY *peer_get_pubkey(const peer_t * const);
void      peer_show_certificate(FILE *stream, const peer_t * const);
uint64_t  peer_get_id(const peer_t * const);

// getter
const char * peer_get_addr(const peer_t * const); // static mem
