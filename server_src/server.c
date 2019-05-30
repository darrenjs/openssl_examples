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
int listen_sock;

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

  const char * hostname = (argc > 1) ? argv[1] : default_host;
  int listen_port = (argc > 2) ? atoi(argv[2]) : default_port;
  if (net_start_listen_socket(hostname, &listen_port, &listen_sock) != 0) {
    LOG_KILL("failed to setup the listen socket");
  }


  struct pollfd fdset[2];
  memset(&fdset, 0, sizeof(fdset));

  fdset[0].fd = STDIN_FILENO;
  fdset[0].events = POLLIN;

  while (1) {
    peer_create(&client, server_ctx, true);
    printf("waiting for next connection on port %d\n", listen_port);

    fd_set listen_fds;
    FD_ZERO(&listen_fds);
    FD_SET(listen_sock, &listen_fds);

    int ret = 0;
    while (ret == 0) {
      ret = select(listen_sock + 1, &listen_fds, NULL, NULL, NULL);
    }

    if (FD_ISSET(listen_sock, &listen_fds)) {
      if (peer_accept(&client, listen_sock) != 0)
        LOG_KILL("failed to accept");
    }
    else {
      continue;
    }

    printf("new connection from %s\n", peer_get_addr(&client));

    fdset[1].fd = client.socket;
    fdset[1].events = POLLERR | POLLHUP | POLLNVAL | POLLIN;

    /* event loop */
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
