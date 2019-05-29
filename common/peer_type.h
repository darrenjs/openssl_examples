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

// define func type
typedef int (*buf_operator_t)(uint8_t *, ssize_t);

typedef struct peer_t
{
  int fd;
  SSL *ssl;

  BIO *rbio; // SSL reads from, we write to
  BIO *wbio; // SSL writes to, we read from

  // waiting to be written to socket;
  uint8_t *write_buf;
  ssize_t  write_len;

  // waiting to be encrypted by SSL object
  uint8_t *encrypt_buf;
  ssize_t  encrypt_len;

  buf_operator_t io_on_read;
} peer_t;

int peer_create(peer_t * const, SSL_CTX *, int fd, buf_operator_t, bool server);
int peer_delete(peer_t * const);

bool peer_valid(const peer_t * const);
bool peer_want_write(peer_t *peer);
