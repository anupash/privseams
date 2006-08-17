#ifndef _HIPD_MAINTENANCE
#define _HIPD_MAINTENANCE

#include <stdlib.h>

#include "hip.h"
#include "hipd.h"


int hip_handle_retransmission(hip_ha_t *entry, void *current_time);
int hip_scan_retransmissions();
int hip_agent_add_lhit(struct hip_host_id_entry *entry, void *msg);
int hip_agent_add_lhits(void);
int hip_agent_filter(struct hip_common *msg);
void register_to_dht();
int periodic_maintenance();


#endif /* _HIPD_MAINTENANCE */

