#ifndef _HIPD_MAINTENANCE
#define _HIPD_MAINTENANCE

#include <stdlib.h>
#include "hidb.h"
#include "hipd.h"
#include "oppdb.h"
#include "fcntl.h"
#include "hip_statistics.h"
#include "nat.h"

#define FORCE_EXIT_COUNTER_START		5

extern int hip_icmp_interval;

int hip_handle_retransmission(hip_ha_t *entry, void *current_time);
int hip_scan_retransmissions();
void register_to_dht();
void publish_hit(char *hostname, char *tmp_hit_str);
int publish_addr(char *tmp_hit_str);
int periodic_maintenance();
int hip_get_firewall_status();
void hip_set_firewall_status();
int hip_get_firewall_status();
int verify_hdrr (struct hip_common *msg,struct in6_addr *addrkey);
void send_packet_to_lookup_from_queue();
void init_dht_sockets (int *socket, int *socket_status);
int hip_icmp_recvmsg(int sockfd);
int hip_icmp_statistics(struct in6_addr * src, struct in6_addr * dst,
			struct timeval *stval, struct timeval *rtval);

/*Communication with firewall daemon*/
int hip_firewall_set_bex_data(int action, hip_ha_t *entry, struct in6_addr *hit_s,
			      struct in6_addr *hit_r);
int hip_firewall_set_esp_relay(int action);
#endif /* _HIPD_MAINTENANCE */

