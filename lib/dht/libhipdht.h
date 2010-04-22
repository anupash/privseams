/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 *
 */

#ifndef HIP_LIB_DHT_LIBHIPDHT_H
#define HIP_LIB_DHT_LIBHIPDHT_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "config.h"
#include "lib/core/protodefs.h"

/* Resolve the gateway address using opendht.nyuld.net */
//#define OPENDHT_GATEWAY "opendht.nyuld.net"
//#define OPENDHT_GATEWAY "hipdht2.infrahip.net"
#define OPENDHT_GATEWAY "193.167.187.134"
#define OPENDHT_PORT 5851
#define OPENDHT_TTL 120
#define STATE_OPENDHT_IDLE 0
#define STATE_OPENDHT_WAITING_ANSWER 1
#define STATE_OPENDHT_WAITING_CONNECT 2
#define STATE_OPENDHT_START_SEND 3
#define DHT_CONNECT_TIMEOUT 2
#define OPENDHT_SERVERS_FILE HIPL_SYSCONFDIR "/dhtservers"
#define OPENDHT_ERROR_COUNT_MAX 3

int init_dht_gateway_socket_gw(int, struct addrinfo *);

int resolve_dht_gateway_info(char *, struct addrinfo **, in_port_t, int);

int connect_dht_gateway(int, struct addrinfo *, int);

int opendht_put_rm(int, unsigned char *, unsigned char *,
                   unsigned char *, unsigned char *, int, int);

int opendht_put(unsigned char *key, unsigned char *value,
                unsigned char *host, int opendht_port,
                int opendht_ttl, void *put_packet);

int opendht_rm(int, unsigned char *, unsigned char *,
               unsigned char *, unsigned char *, int, int);

int opendht_get(int, unsigned char *, unsigned char *, int);

int opendht_send(int sockfd, void *packet);

int hip_opendht_get_key(int (*value_handler)(unsigned char *packet,
                                             void *answer),
                                             struct addrinfo *gateway,
                        const char *key, void *opaque_answer,
                        int dont_verify_hdrr);
int opendht_handle_key(unsigned char *, char *);

int opendht_handle_value(unsigned char *, char *);


int opendht_read_response(int, unsigned char *);

int (*value_handler)(unsigned char *packet, void *answer);

int handle_hdrr_value(unsigned char *packet, void *hdrr);
int handle_locator_value(unsigned char *packet, void *locator_ipv4);
int handle_hit_value(unsigned char *packet, void *hit);
int handle_locator_all_values(unsigned char *packet, void *locator_complete);
int handle_ip_value(unsigned char *packet, void *ip);
int handle_cert_key(struct in6_addr *lhit,
                    struct in6_addr *rhit,
                    void *final_key);
int verify_hddr_lib(struct hip_common *hipcommonmsg, struct in6_addr *addrkey);

#endif /* HIP_LIB_DHT_LIBHIPDHT_H */
