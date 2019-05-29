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

/* Obtain the return value of an SSL operation and convert into a simplified
 * error code, which is easier to examine for failure. */
typedef enum { SSLSTATUS_OK, SSLSTATUS_WANT_IO, SSLSTATUS_FAIL} ssl_status_t ;

ssl_status_t peer_do_handshake(peer_t *peer);

int peer_encrypt(peer_t *peer);

int peer_recv(peer_t *peer);

int peer_send(peer_t *peer);

void ssl_init(SSL_CTX **ctx, const char * certfile, const char * keyfile);
