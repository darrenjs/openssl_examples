/***
 * network_wrapper.h
 */
#pragma once

#include <sys/types.h>
#include <arpa/inet.h>

void net_get_public_ip(struct sockaddr_in *addr);
int  net_start_listen_socket(const char *server_addr, int *server_port, int *listen_socket);
const char * net_get_my_ipv4_addr();
