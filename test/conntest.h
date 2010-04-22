/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 */

#ifndef HIP_TEST_CONNTEST_H
#define HIP_TEST_CONNTEST_H

#include <netinet/in.h>

int main_server(int type, in_port_t port);
int main_client_gai(int socktype, char *peer_name,
                    char *peer_port_name,
                    int hints);

#endif /* HIP_TEST_CONNTEST_H */
