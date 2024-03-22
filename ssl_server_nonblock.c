/*
Copyright (c) 2017 Darren Smith

ssl_examples is free software; you can redistribute it and/or modify
it under the terms of the MIT license. See LICENSE for details.
*/

#include "common.h"


int main(int argc, char **argv)
{
  char str[INET_ADDRSTRLEN];
  int port = (argc>1)? atoi(argv[1]):55555;

  int servfd = socket(AF_INET, SOCK_STREAM, 0);
  if (servfd < 0)
    die("socket()");

  int enable = 1;
  if (setsockopt(servfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0)
    die("setsockopt(SO_REUSEADDR)");

  /* Specify socket address */
  struct sockaddr_in servaddr;
  memset(&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  servaddr.sin_port = htons(port);

  if (bind(servfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
    die("bind()");

  if (listen(servfd, 128) < 0)
    die("listen()");

  int clientfd;
  struct sockaddr_in peeraddr;
  socklen_t peeraddr_len = sizeof(peeraddr);

  struct pollfd fdset[2];
  memset(&fdset, 0, sizeof(fdset));

  fdset[0].fd = STDIN_FILENO;
  fdset[0].events = POLLIN;

  struct ssl_client *p_client; /* struct per remote client      */
  p_client=&client;            /* use the single global for now */

  ssl_init("server.crt", "server.key"); // see README to create these files

  while (1) {
    printf("waiting for next connection on port %d\n", port);

    clientfd = accept(servfd, (struct sockaddr *)&peeraddr, &peeraddr_len);
    if (clientfd < 0)
      die("accept()");

    ssl_client_init(p_client, clientfd, SSLMODE_SERVER);

    inet_ntop(peeraddr.sin_family, &peeraddr.sin_addr, str, INET_ADDRSTRLEN);
    printf("new connection from %s:%d\n", str, ntohs(peeraddr.sin_port));

    fdset[1].fd = clientfd;

    /* event loop */

    fdset[1].events = POLLERR | POLLHUP | POLLNVAL | POLLIN;
#ifdef POLLRDHUP
    fdset[1].events |= POLLRDHUP;
#endif

    while (1) {
      fdset[1].events &= ~POLLOUT;
      fdset[1].events |= (ssl_client_want_write(p_client)? POLLOUT : 0);

      int nready = poll(&fdset[0], 2, -1);

      if (nready == 0)
        continue; /* no fd ready */

      int revents = fdset[1].revents;
      if (revents & POLLIN)
        if (do_sock_read() == -1)
          break;
      if (revents & POLLOUT)
        if (do_sock_write() == -1)
          break;
      if (revents & (POLLERR | POLLHUP | POLLNVAL))
        break;
#ifdef POLLRDHUP
      if (revents & POLLRDHUP)
        break;
#endif
      if (fdset[0].revents & POLLIN)
        do_stdin_read();
      if (client.encrypt_len>0)
        do_encrypt();
    }

    close(fdset[1].fd);
    ssl_client_cleanup(p_client);
  }

  return 0;
}
