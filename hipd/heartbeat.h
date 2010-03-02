#ifndef HIP_HIPD_HEARTBEAT_H
#define HIP_HIPD_HEARTBEAT_H

#include "lib/core/state.h"

int hip_send_heartbeat(hip_ha_t *entry, void *opaq);
int hip_icmp_recvmsg(int sockfd);

#endif /* HIP_HIPD_HEARTBEAT_H */
