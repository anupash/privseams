#ifndef COMMON_HIPD_MSG_H_
#define COMMON_HIPD_MSG_H_

#include "lib/core/protodefs.h"

int hip_get_bex_state_from_IPs(const struct in6_addr *src_ip,
		      	   const struct in6_addr *dst_ip,
			       struct in6_addr *src_hit,
			       struct in6_addr *dst_hit,
			       hip_lsi_t *src_lsi,
			       hip_lsi_t *dst_lsi);

#endif /* COMMON_HIPD_MSG_H_ */
