#ifndef HIP_MISC_H
#define HIP_MISC_H

//#include <linux/time.h>
//#include <linux/in6.h>
//#include <linux/socket.h>
#include <linux/types.h>
//#include <linux/sched.h>
#include <net/ipv6.h>
#include <net/hip.h>

/*#include "debug.h"
#include "builder.h"
#include "hip.h"
*/

int hip_host_id_to_hit(const struct hip_host_id *host_id,
		       struct in6_addr *hit, int hit_type);
int hip_private_host_id_to_hit(const struct hip_host_id *host_id,
			       struct in6_addr *hit, int hit_type);
int hip_timeval_diff(const struct timeval *t1, const struct timeval *t2,
		     struct timeval *result);
void hip_set_sockaddr(struct sockaddr_in6 *sin, struct in6_addr *addr);
int hip_lhi_are_equal(const struct hip_lhi *lhi1,
		      const struct hip_lhi *lhi2);
char* hip_in6_ntop(const struct in6_addr *in6, char *buf);
int hip_in6_ntop2(const struct in6_addr *in6, char *buf);
char* hip_hit_ntop(const hip_hit_t *hit, char *buf);
int hip_is_hit(const hip_hit_t *hit);
int hip_host_id_contains_private_key(struct hip_host_id *host_id);
u8 *hip_host_id_extract_public_key(u8 *buffer, struct hip_host_id *data);
int hip_hit_is_bigger(const struct in6_addr *hit1,
		      const struct in6_addr *hit2);
 
#endif /* HIP_MISC_H */
