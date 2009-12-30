#ifndef HEARTBEAT_H
#define HEARTBEAT_H

#include "state.h"

int hip_handle_update_heartbeat_trigger(hip_ha_t *ha, void *unused);
int hip_send_heartbeat(hip_ha_t *entry, void *opaq);
int hip_icmp_recvmsg(int sockfd);

#endif /* HEARTBEAT_H */
