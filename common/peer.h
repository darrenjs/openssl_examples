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


int peer_do_handshake(peer_t *peer);

int peer_encrypt(peer_t *peer);

int peer_recv(peer_t *peer);

int peer_send(peer_t *peer);
