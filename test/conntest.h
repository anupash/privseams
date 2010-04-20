/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 */
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


int main_server(int type, in_port_t port);
int main_client_gai(int socktype, char *peer_name,
                    char *peer_port_name,
                    int hints);

#endif /* HIP_TEST_CONNTEST_H */
