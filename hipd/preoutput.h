#ifndef HIP_PREOUTPUT_H
#define HIP_PREOUTPUT_H

#include "beet.h"
#include "misc.h"
//#include "debug.h"
#include "preinput.h"
#include "workqueue.h"
#include "hip.h"

/* Called by userspace daemon or kernel packet processing to send a
   packet to wire */
int hip_csum_send(int hip_raw_sock, struct in6_addr *src_addr, struct in6_addr *peer_addr,
		  struct hip_common* buf);

#endif /* HIP_PREOUTPUT_H */
