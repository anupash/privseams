#ifndef _HIPD_MAINTENANCE
#define _HIPD_MAINTENANCE

#include <stdlib.h>

#include "hidb.h"
#include "hipd.h"
#include "oppdb.h"

#define FORCE_EXIT_COUNTER_START		5


int hip_handle_retransmission(hip_ha_t *entry, void *current_time);
int hip_scan_retransmissions();
int hip_agent_add_lhit(struct hip_host_id_entry *entry, void *msg);
int hip_agent_add_lhits(void);
int hip_agent_send_rhit(hip_ha_t *entry, void *msg);
int hip_agent_send_remote_hits(void);
int hip_agent_filter(struct hip_common *msg);
void register_to_dht();
int periodic_maintenance();
int hip_get_firewall_status();
void hip_set_firewall_status();

#endif /* _HIPD_MAINTENANCE */

