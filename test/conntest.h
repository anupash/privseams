#ifndef HIP_TEST_CONNTEST_H
#define HIP_TEST_CONNTEST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/time.h>
#include <time.h>
#include <sys/uio.h>
#include "lib/core/debug.h"
#include "lib/core/ife.h"
#include "lib/core/misc.h"

int create_socket(int proto);
int create_serversocket(int type, in_port_t port);
int main_server(int type, in_port_t port);
int main_server_tcp(int serversock);
int main_server_native(int socktype, char *port_name, char *name);

int hip_connect_func(struct addrinfo *res, int *sock);
int main_client_gai(int socktype, char *peer_name,
                    char *peer_port_name,
                    int hints);
int main_client_native(int socktype, char *peer_name, char *peer_port_name);

#endif /* HIP_TEST_CONNTEST_H */
