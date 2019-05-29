/*
Copyright (c) 2017 Darren Smith

ssl_examples is free software; you can redistribute it and/or modify
it under the terms of the MIT license. See LICENSE for details.
*/

#include "peer.h"
#include "config.h"
#include "macros.h"

SSL_CTX *ctx;
peer_t client;

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

  ssl_init(&ctx, 0, 0);
  peer_create(&client, ctx, sockfd, print_unencrypted_data, false);

  fdset[1].fd = sockfd;
  fdset[1].events = POLLERR | POLLHUP | POLLNVAL | POLLIN;
#ifdef POLLRDHUP
  fdset[1].events |= POLLRDHUP;
#endif

  /* event loop */

  do_ssl_handshake(&client);

  while (1) {
    fdset[1].events &= ~POLLOUT;
    fdset[1].events |= (peer_want_write(&client)) ? POLLOUT : 0;

    int nready = poll(&fdset[0], 2, -1);

    if (nready == 0)
      continue; /* no fd ready */

    int revents = fdset[1].revents;
    if (revents & POLLIN)
      if (do_sock_read(&client) == -1)
        break;
    if (revents & POLLOUT)
      if (do_sock_write(&client) == -1)
        break;
    if (revents & (POLLERR | POLLHUP | POLLNVAL))
      break;
#ifdef POLLRDHUP
    if (revents & POLLRDHUP)
      break;
#endif
    if (fdset[0].revents & POLLIN)
      do_stdin_read(&client);
    if (client.encrypt_len>0)
      do_encrypt(&client);
  }

  close(fdset[1].fd);
  peer_delete(&client);

  return 0;
}

