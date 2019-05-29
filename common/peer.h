#pragma once
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#include <arpa/inet.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

#include "peer_type.h"

void print_unencrypted_data(uint8_t *buf, ssize_t len);

/* Obtain the return value of an SSL operation and convert into a simplified
 * error code, which is easier to examine for failure. */
typedef enum { SSLSTATUS_OK, SSLSTATUS_WANT_IO, SSLSTATUS_FAIL} ssl_status_t ;

void send_unencrypted_bytes(peer_t *peer, const uint8_t *buf, ssize_t len);

void queue_encrypted_bytes(peer_t *peer, const uint8_t *buf, ssize_t len);

ssl_status_t do_ssl_handshake(peer_t *peer);

int on_read_cb(peer_t *peer, uint8_t * src, ssize_t len);

int do_encrypt(peer_t *peer);

void do_stdin_read(peer_t *peer);

int do_sock_read(peer_t *peer);

int do_sock_write(peer_t *peer);

void ssl_init(SSL_CTX **ctx, const char * certfile, const char * keyfile);
