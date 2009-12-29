#ifndef _HIPD_MAINTENANCE
#define _HIPD_MAINTENANCE

#include <stdlib.h>
#include "hidb.h"
#include "hipd.h"
#include "oppdb.h"
#include "fcntl.h"
#include "libhipcore/hip_statistics.h"
#include "nat.h"
#include "update.h"
#include "update_legacy.h"
#include "hipqueue.h"

extern int hip_icmp_interval;
extern int hip_wait_addr_changes_to_stabilize;
extern int address_change_time_counter;
extern int hip_trigger_update_on_heart_beat_failure;

int hip_agent_filter(struct hip_common *msg,
                     struct in6_addr *src_addr,
                     struct in6_addr *dst_addr,
	                 hip_portpair_t *msg_info);
void register_to_dht();
void opendht_remove_current_hdrr();
int periodic_maintenance();
int hip_get_firewall_status();
void hip_set_firewall_status();
int hip_agent_update_status(int msg_type, void *data, size_t size);
int hip_agent_update(void);
int hip_get_firewall_status();
int verify_hdrr (struct hip_common *msg,struct in6_addr *addrkey);
void init_dht_sockets (int *socket, int *socket_status);
int hip_icmp_recvmsg(int sockfd);
int hip_icmp_statistics(struct in6_addr * src, struct in6_addr * dst,
			struct timeval *stval, struct timeval *rtval);

/*Communication with firewall daemon*/
int hip_firewall_set_savah_status(int status);
int hip_firewall_set_bex_data(int action, hip_ha_t *entry, struct in6_addr *hit_s,
			      struct in6_addr *hit_r);
int hip_firewall_set_esp_relay(int action);
int hip_firewall_set_i2_data(int action,  hip_ha_t *entry, 
                             struct in6_addr *hit_s, 
                             struct in6_addr *hit_r,
                             struct in6_addr *src,
                             struct in6_addr *dst);
#endif /* _HIPD_MAINTENANCE */

