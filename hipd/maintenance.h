#ifndef HIPD_MAINTENANCE_H
#define HIPD_MAINTENANCE_H

#include <stdlib.h>
#include <fcntl.h>
#include "hidb.h"
#include "hipd.h"
#include "oppdb.h"
#include "lib/core/hip_statistics.h"
#include "nat.h"
#include "update.h"
#include "update_legacy.h"
#include "hipqueue.h"
#include "dht.h"

extern int heartbeat_counter;

int periodic_maintenance(void);
void hip_set_firewall_status(void);
int hip_get_firewall_status(void);

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
#endif /* HIPD_MAINTENANCE_H */

