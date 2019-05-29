/*
Copyright (c) 2017 Darren Smith

ssl_examples is free software; you can redistribute it and/or modify
it under the terms of the MIT license. See LICENSE for details.
*/

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "peer.h"
#include "config.h"
#include "macros.h"

/* ================================================ */

SSL_CTX *client_ctx;
peer_t server;

/* ================================================ */

int  setup_signals();
void shutdown_properly(int code);
void handle_signal_action(int sig_number);

int  handle_read_from_stdin(peer_t *server);
int  handle_received_message(peer_t *peer);

/* ================================================ */

int main(int argc, char **argv)
{
  int port = (argc > 1) ? atoi(argv[1]) : default_port;

  const char * host = default_host;

  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0)
    die("socket()");

  /* Specify socket address */
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  if (inet_pton(AF_INET, host, &(addr.sin_addr)) <= 0)
    die("inet_pton()");

  if (connect(sockfd, (struct sockaddr*) &addr, sizeof(addr)) < 0)
    die("connect()");

  struct pollfd fdset[2];
  memset(&fdset, 0, sizeof(fdset));

  fdset[0].fd = STDIN_FILENO;
  fdset[0].events = POLLIN;

  ssl_init(&client_ctx, 0, 0);
  peer_create(&server, client_ctx, sockfd, false);

  fdset[1].fd = sockfd;
  fdset[1].events = POLLERR | POLLHUP | POLLNVAL | POLLIN;
#ifdef POLLRDHUP
  fdset[1].events |= POLLRDHUP;
#endif

  /* event loop */

  peer_do_handshake(&server);

  while (1) {
    fdset[1].events &= ~POLLOUT;
    fdset[1].events |= (peer_want_write(&server)) ? POLLOUT : 0;

    int nready = poll(&fdset[0], 2, -1);

    if (nready == 0)
      continue; /* no fd ready */

    int revents = fdset[1].revents;
    if (revents & POLLIN)
      if (peer_recv(&server) == -1)
        break;
    if (revents & POLLOUT)
      if (peer_send(&server) == -1)
        break;
    if (revents & (POLLERR | POLLHUP | POLLNVAL))
      break;
#ifdef POLLRDHUP
    if (revents & POLLRDHUP)
      break;
#endif
    if (fdset[0].revents & POLLIN)
      handle_read_from_stdin(&server);
    if (server.encrypt_len>0)
      peer_encrypt(&server);

    if (server.processing_len > 0)
      handle_received_message(&server);
  }

  close(fdset[1].fd);
  peer_delete(&server);

  return 0;
}

/* ========================== */

int handle_read_from_stdin(peer_t *peer)
{
  uint8_t buf[DEFAULT_BUF_SIZE];
  ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));

  if (n > 0)
    return peer_queue_to_encrypt(peer, buf, (size_t)n);
  else
    return -1;
}

int  handle_received_message(peer_t *peer)
{
  printf("%.*s", (int)peer->processing_len, (char *) peer->processing_buf);
  peer->processing_len = 0;
  return 0;
}
