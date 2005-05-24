#ifndef CONNTEST_H
#define CONNTEST_H

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
#include "libinet6/debug.h"

int create_socket(int proto);
int create_serversocket(int proto, int port);
int main_server(int proto, int port);
int main_server_native(int socktype, char *port_name);

int hip_connect_func(int proto, struct addrinfo *res);
int main_client_gai(int proto, int socktype, char *peer_name, char *peer_port_name);
int main_client_native(int proto, int socktype, char *peer_name, char *peer_port_name);

#endif /* CONNTEST_H */
