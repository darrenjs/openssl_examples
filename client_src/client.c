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

int build_fd_sets(peer_t *server, fd_set *read_fds, fd_set *write_fds, fd_set *except_fds);

int  handle_read_from_stdin(peer_t *server);
int  handle_received_message(peer_t *peer);

/* ================================================ */

int main(int argc, char **argv)
{
  const char * hostname = (argc > 1) ? argv[1] : default_host;
  int server_port = (argc > 2) ? atoi(argv[2]) : default_port;
  if (setup_signals() != 0) {
    LOG_KILL("failed to setup signals");
  }

  if (init_client_ssl_ctx(&client_ctx) == -1) {
    LOG_KILL("failed to setup client SSL ctx");
  }

  if (load_certificates(client_ctx, client_cert_path, client_key_path) == -1){
    LOG_KILL("failed to load client certificates");
  }

  /* Set nonblock for stdin. */
  int flag = fcntl(STDIN_FILENO, F_GETFL, 0);
  flag |= O_NONBLOCK;
  fcntl(STDIN_FILENO, F_SETFL, flag);

  peer_create(&server, client_ctx, false);

  /* Specify socket address */
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(server_port);
  if (inet_pton(AF_INET, hostname, &(addr.sin_addr)) <= 0)
    LOG_KILL("inet_pton()");

  if (peer_connect(&server, &addr) != 0)
    LOG_KILL("failed to connect to peer");

  peer_do_handshake(&server);


  fprintf(stdout, "Connected to peer at %s\n", peer_get_addr(&server));

  fd_set read_fds;
  fd_set write_fds;
  fd_set except_fds;

  /* event loop */
  while (1) {
    if (peer_valid(&server)) {
      if (peer_want_read(&server)) {
        handle_received_message(&server);
      }
    }
    int high_sock = build_fd_sets(&server, &read_fds, &write_fds, &except_fds);
    int activity  = select(high_sock + 1, &read_fds, &write_fds, &except_fds, NULL);

    switch (activity) {
      case -1:
        perror("select");
        LOG_KILL("failed to select");
        break;

      case 0:
        LOG("select returned 0");
        break;

      default:
        if (FD_ISSET(STDIN_FILENO, &read_fds)) {
          handle_read_from_stdin(&server); // FIXME ret val
        }
        if (FD_ISSET(STDIN_FILENO, &except_fds)) {
          LOG_KILL("exception on stdin");
        }

        if (peer_valid(&server)) {
          if (FD_ISSET(server.socket, &read_fds)) {
            if (peer_recv(&server) != 0) {
              peer_close(&server);
              LOG_KILL("failed to receive from sever");
            }
          }
          if (FD_ISSET(server.socket, &write_fds)) {
            if (peer_send(&server) != 0) {
              peer_close(&server);
              LOG_KILL("failed to send to sever");
            }
          }
          if (FD_ISSET(server.socket, &except_fds)) {
            LOG_KILL("exception on server socket");
          }
        }
    }
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
    return peer_prepare_message_to_send(peer, buf, n);
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

int build_fd_sets(peer_t *server, fd_set *read_fds, fd_set *write_fds, fd_set *except_fds)
{
  FD_ZERO(read_fds);
  FD_SET(STDIN_FILENO, read_fds);
  FD_SET(server->socket, read_fds);

  FD_ZERO(write_fds);
  // there is smth to send, set up write_fd for server socket
  if (peer_want_write(server))
    FD_SET(server->socket, write_fds);

  FD_ZERO(except_fds);
  FD_SET(STDIN_FILENO, except_fds);
  FD_SET(server->socket, except_fds);

  return server->socket;
}
