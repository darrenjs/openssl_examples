/*
 * peer_type.h
 *
 * definition of the peer type
 */
#pragma once

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#include <stddef.h>
#include <stdbool.h>

typedef struct peer_t
{
  int fd;
  SSL *ssl;

  BIO *rbio; // SSL reads from, we write to
  BIO *wbio; // SSL writes to, we read from

  // waiting to be written to socket;
  uint8_t *write_buf;
  ssize_t  write_sz;

  // waiting to be encrypted by SSL object
  uint8_t *encrypt_buf;
  ssize_t  encrypt_sz;

  // waiting to be processed
  uint8_t *process_buf;
  ssize_t  process_sz;
} peer_t;

int peer_create(peer_t * const, SSL_CTX *, int fd, bool server);
int peer_delete(peer_t * const);

int peer_queue_to_decrypt(peer_t *peer, const uint8_t *buf, ssize_t len);
int peer_queue_to_encrypt(peer_t *peer, const uint8_t *buf, ssize_t len);
int peer_queue_to_process(peer_t *peer, const uint8_t *buf, ssize_t len);

bool peer_valid(const peer_t * const);
bool peer_want_write(peer_t *peer);
bool peer_want_encrypt(peer_t *peer);
bool peer_want_read(peer_t *peer);
