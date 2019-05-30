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

/* ------------------------------= */

SSL_CTX *server_ctx;
peer_t client;
int listen_sock;

/* ------------------------------= */

int setup_signals();
void shutdown_properly(int code, void *arg);
void handle_signal_action(int sig_number);

int build_fd_sets(fd_set *read_fds,
    fd_set *write_fds,
    fd_set *except_fds,
    int listen_sock
    );

int handle_new_connection();

int handle_read_from_stdin(peer_t *client);
int handle_received_message(peer_t *peer);

/* ------------------------------= */

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

  peer_create(&client, server_ctx, true); // FIXME (strawman)
  fd_set read_fds;
  fd_set write_fds;
  fd_set except_fds;

  fprintf(stderr, "Waiting for incoming connections.\n");
  while (1) {
    if (peer_valid(&client)) {
      if (peer_want_read(&client))
        handle_received_message(&client);
    }

    int high_sock = build_fd_sets(&read_fds, &write_fds, &except_fds, listen_sock);
    int activity  = select(high_sock + 1, &read_fds, &write_fds, &except_fds, NULL);

    switch (activity) {
      case -1:
        perror("select");
        LOG_KILL("failed on select");
        break;

      case 0:
        LOG("select returned 0");
        break;

      default:
        if (FD_ISSET(STDIN_FILENO, &read_fds)) {
          if (handle_read_from_stdin(&client) != 0)
            LOG_KILL("failed on read from stdin");
        }
        if (FD_ISSET(STDIN_FILENO, &except_fds)) {
          LOG_KILL("exception on stdin");
        }

        if (FD_ISSET(listen_sock, &read_fds)) {
          handle_new_connection();
        }
        if (FD_ISSET(listen_sock, &except_fds)) {
          LOG_KILL("exception on listen socket");
        }

        if (peer_valid(&client)) {
          if (FD_ISSET(client.socket, &read_fds)) {
            if (peer_recv(&client) != 0) {
              fprintf(stderr, "peer_recv failed; closing client on %s\n", peer_get_addr(&client));
              peer_close(&client);
              continue;
            }
          }
          if (FD_ISSET(client.socket, &write_fds)) {
            if (peer_send(&client) != 0) {
              fprintf(stderr, "peer_recv failed; closing client on %s\n", peer_get_addr(&client));
              peer_close(&client);
              continue;
            }
          }
          if (FD_ISSET(client.socket, &except_fds)) {
            fprintf(stderr, "Exception on socket; closing client on %s\n", peer_get_addr(&client));
            peer_close(&client);
            continue;
          }
        }
        break;
    }
  }

  return 0;
}

/* ------------------------== */

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

/* ------------------------== */

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

/* ------------------------== */

void shutdown_properly(int code, void *__)
{
  peer_delete(&client);
  fputs("Shutdown server properly.\n", stderr);
  close_ssl_ctx(server_ctx);
  _exit(code);
}

/* ------------------------------ */

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

/* ------------------------------- */

int build_fd_sets(fd_set *read_fds,
    fd_set *write_fds,
    fd_set *except_fds,
    int listen_sock)
{
  int high_sock= listen_sock;

  FD_ZERO(read_fds);
  FD_SET(STDIN_FILENO, read_fds);

  FD_ZERO(write_fds);

  FD_ZERO(except_fds);
  FD_SET(STDIN_FILENO, except_fds);

  if (listen_sock != -1) {
    FD_SET(listen_sock, read_fds);
    FD_SET(listen_sock, except_fds);
  }

  if (peer_valid(&client)) {
    FD_SET(client.socket, read_fds);
    FD_SET(client.socket, except_fds);

    // max
    high_sock = (high_sock > client.socket) ? high_sock : client.socket;

    if (peer_want_write(&client))
      FD_SET(client.socket, write_fds);
  }

  return high_sock;
}


/* ------------------------------------------------------- */

int handle_new_connection()
{
  if (peer_valid(&client)) {
    fputs("There is too much connections, ignoring the new one\n", stderr);
    return -1;
  }

  if (peer_accept(&client, listen_sock) != 0) {
    fputs("Failed to accept connection\n", stderr);
    return -1;
  }

  fprintf(stderr, "Accepted connection on %s\n", peer_get_addr(&client));
  return 0;
}
