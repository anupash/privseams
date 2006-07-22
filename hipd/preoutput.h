#ifndef HIP_PREOUTPUT_H
#define HIP_PREOUTPUT_H

#include "beet.h"
#include "misc.h"
//#include "debug.h"
#include "preinput.h"
#include "workqueue.h"
#include "hip.h"
#include "string.h"

extern int hip_raw_sock_v6;
extern int hip_raw_sock_v4;
extern int hip_nat_status;
/* Called by userspace daemon or kernel packet processing to send a
   packet to wire */
int hip_csum_send(struct in6_addr *src_addr, struct in6_addr *peer_addr,
		  uint32_t src_port, uint32_t dst_port,
		  struct hip_common* buf, hip_ha_t *entry, int retransmit);

#endif /* HIP_PREOUTPUT_H */
