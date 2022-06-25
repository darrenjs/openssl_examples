/*
  Copyright (c) 2017 Darren Smith

  ssl_examples is free software; you can redistribute it and/or modify
  it under the terms of the MIT license. See LICENSE for details.
*/

#include "common.h"

int main(int argc, char **argv)
{
  /* --- CONFIGURE PEER SOCKET --- */

  // port name, optionally take from args
  int port = argc>1? atoi(argv[1]):443;

  // host IP address. Attention! This must be a numeric address, not a server
  // host name, because this example code does not perform address lookup.
  char* host_ip = "2600:9000:225d:600:14:c251:2440:93a1";

  // provide the hostname if this SSL client needs to use SNI to tell the server
  // what certificate to use
  const char * host_name = "api.huobi.pro";

  // socket family, AF_INET (ipv4) or AF_INET6 (ipv6), must match host_ip above
  int ip_family = AF_INET6;

  /* Example for localhost connection
     int port = argc>1? atoi(argv[1]):55555;
     const char* host_ip = "127.0.0.1";
     const char * host_name = NULL;
     int ip_family = AF_INET;
  */


  /* --- CONFIGURAITON ENDS --- */

  int sockfd = socket(ip_family, SOCK_STREAM, 0);

  if (sockfd < 0)
    die("socket()");

  /* Specify socket address */

  if (ip_family == AF_INET6) {
    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = ip_family;
    addr.sin6_port = htons(port);

    if (inet_pton(ip_family, host_ip, &(addr.sin6_addr)) <= 0)
      die("inet_pton()");

    if (connect(sockfd, (struct sockaddr*) &addr, sizeof(addr)) < 0)
      die("connect()");
  }

  if (ip_family == AF_INET) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = ip_family;
    addr.sin_port = htons(port);

    if (inet_pton(ip_family, host_ip, &(addr.sin_addr)) <= 0)
      die("inet_pton()");

    if (connect(sockfd, (struct sockaddr*) &addr, sizeof(addr)) < 0)
      die("connect()");
  }

  printf("socket connected\n");

  struct pollfd fdset[2];
  memset(&fdset, 0, sizeof(fdset));

  fdset[0].fd = STDIN_FILENO;
  fdset[0].events = POLLIN;

  ssl_init(0,0);
  ssl_client_init(&client, sockfd, SSLMODE_CLIENT);

  if (host_name)
    SSL_set_tlsext_host_name(client.ssl, host_name); // TLS SNI

  fdset[1].fd = sockfd;
  fdset[1].events = POLLERR | POLLHUP | POLLNVAL | POLLIN;
#ifdef POLLRDHUP
  fdset[1].events |= POLLRDHUP;
#endif

  /* event loop */

  do_ssl_handshake();

  while (1) {
    fdset[1].events &= ~POLLOUT;
    fdset[1].events |= ssl_client_want_write(&client)? POLLOUT:0;

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
      if (do_encrypt() < 0)
        break;
  }

  close(fdset[1].fd);
  print_ssl_state();
  print_ssl_error();
  ssl_client_cleanup(&client);

  return 0;
}

