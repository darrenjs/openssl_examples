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

/* =============================== */

SSL_CTX *server_ctx;
peer_t client;

/* =============================== */

int setup_signals();
void shutdown_properly(int code, void *arg);
void handle_signal_action(int sig_number);

int handle_read_from_stdin(peer_t *client);
int handle_received_message(peer_t *peer);

/* =============================== */

int main(int argc, char **argv)
{
  if (setup_signals() != 0) {
    LOG_KILL("failed to setup signals");
  }

  if (init_server_ssl_ctx(&server_ctx) == -1) {
    LOG_KILL("failed to setup server SSL ctx");
  }

  if (load_certificates(server_ctx, server_cert_path, server_key_path) == -1){
    LOG_KILL("failed to load server certificates");
  }

  char str[INET_ADDRSTRLEN];
  int port = (argc > 1) ? atoi(argv[1]) : default_port;

  int servfd = socket(AF_INET, SOCK_STREAM, 0);
  if (servfd < 0)
    LOG_KILL("socket");

  int enable = 1;
  if (setsockopt(servfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0)
    LOG_KILL("setsockopt(SO_REUSEADDR)");

  /* Specify socket address */
  struct sockaddr_in servaddr;
  memset(&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = htonl(INADDR_ANY); // FIXME
  servaddr.sin_port = htons(port);

  if (bind(servfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
    LOG_KILL("bind()");

  if (listen(servfd, 128) < 0)
    LOG_KILL("listen()");

  int clientfd;
  struct sockaddr_in peeraddr;
  socklen_t peeraddr_len = sizeof(peeraddr);

  struct pollfd fdset[2];
  memset(&fdset, 0, sizeof(fdset));

  fdset[0].fd = STDIN_FILENO;
  fdset[0].events = POLLIN;

  while (1) {
    printf("waiting for next connection on port %d\n", port);

    clientfd = accept(servfd, (struct sockaddr *)&peeraddr, &peeraddr_len);
    if (clientfd < 0)
      LOG_KILL("accept()");


    peer_create_old(&client, server_ctx, clientfd, true);

    inet_ntop(peeraddr.sin_family, &peeraddr.sin_addr, str, INET_ADDRSTRLEN);
    printf("new connection from %s:%d\n", str, ntohs(peeraddr.sin_port));

    fdset[1].fd = clientfd;

    /* event loop */

    fdset[1].events = POLLERR | POLLHUP | POLLNVAL | POLLIN;

    while (1) {
      fdset[1].events &= ~POLLOUT;
      fdset[1].events |= (peer_want_write(&client)? POLLOUT : 0);

      int nready = poll(&fdset[0], 2, -1);

      if (nready == 0)
        continue; /* no fd ready */

      int revents = fdset[1].revents;
      if (revents & POLLIN)
        if (peer_recv(&client) == -1)
          break;
      if (revents & POLLOUT)
        if (peer_send(&client) == -1)
          break;
      if (revents & (POLLERR | POLLHUP | POLLNVAL))
        break;

      if (fdset[0].revents & POLLIN)
        handle_read_from_stdin(&client);
      if (peer_want_encrypt(&client))
        peer_encrypt(&client);

      if (peer_want_read(&client))
        handle_received_message(&client);
    }
    peer_delete(&client);
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
  peer_delete(&client);
  fputs("Shutdown server properly.\n", stderr);
  close_ssl_ctx(server_ctx);
  _exit(code);
}

/* ============================== */

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
