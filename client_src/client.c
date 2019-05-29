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

#include "network_wrappers.h"
#include "ssl_util.h"
#include "peer.h"
#include "config.h"
#include "macros.h"

/* ================================================ */

SSL_CTX *client_ctx;
peer_t server;

/* ================================================ */

int  setup_signals();
void shutdown_properly(int code, void *arg);
void handle_signal_action(int sig_number);

int  handle_read_from_stdin(peer_t *server);
int  handle_received_message(peer_t *peer);

/* ================================================ */

int main(int argc, char **argv)
{
  if (setup_signals() != 0) {
    LOG_KILL("failed to setup signals");
  }

  if (init_client_ssl_ctx(&client_ctx) == -1) {
    LOG_KILL("failed to setup client SSL ctx");
  }

  if (load_certificates(client_ctx, client_cert_path, client_key_path) == -1){
    LOG_KILL("failed to load client certificates");
  }

  int port = (argc > 1) ? atoi(argv[1]) : default_port;
  const char * host = default_host;

  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0)
    LOG_KILL("socket()");

  /* Specify socket address */
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  if (inet_pton(AF_INET, host, &(addr.sin_addr)) <= 0)
    LOG_KILL("inet_pton()");

  if (connect(sockfd, (struct sockaddr*) &addr, sizeof(addr)) < 0)
    LOG_KILL("connect()");

  struct pollfd fdset[2];
  memset(&fdset, 0, sizeof(fdset));

  fdset[0].fd = STDIN_FILENO;
  fdset[0].events = POLLIN;

  peer_create(&server, client_ctx, sockfd, false);

  fdset[1].fd = sockfd;
  fdset[1].events = POLLERR | POLLHUP | POLLNVAL | POLLIN;

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

    if (fdset[0].revents & POLLIN)
      handle_read_from_stdin(&server);

    if (peer_want_encrypt(&server))
      peer_encrypt(&server);

    if (peer_want_read(&server))
      handle_received_message(&server);
  }

  return 0;
}

/* ========================== */

void handle_signal_action(int sig_number)
{
  if (sig_number == SIGINT) {
    fprintf(stderr, "\n\nSIGINT was catched!\n");
    exit(EXIT_SUCCESS);
  }
  else if (sig_number == SIGPIPE) {
    fprintf(stderr, "\n\nSIGPIPE was catched!\n");
    exit(EXIT_SUCCESS);
  }
}

/* ========================== */

int setup_signals()
{
  struct sigaction sa;
  sa.sa_handler = handle_signal_action;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_NODEFER;
  if (sigaction(SIGINT, &sa, 0) != 0) {
    perror("sigaction()");
    return -1;
  }
  if (sigaction(SIGPIPE, &sa, 0) != 0) {
    perror("sigaction()");
    return -1;
  }

  if (on_exit(shutdown_properly, NULL) != 0) {
    perror("on_exit()");
    return -1;
  }

  return 0;
}

/* ========================== */

void shutdown_properly(int code, void *__)
{
  peer_delete(&server);
  fputs("Shutdown client properly.\n", stderr);
  close_ssl_ctx(client_ctx);
  _exit(code);
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
  printf("%.*s", (int)peer->process_sz, (char *) peer->process_buf);
  peer->process_sz = 0;
  return 0;
}

/* ========================== */

