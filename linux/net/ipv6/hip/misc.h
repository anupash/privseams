#ifndef HIP_MISC_H
#define HIP_MISC_H

#include <linux/time.h>
#include <linux/in6.h>
#include <linux/socket.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <net/ipv6.h>
#include <net/hip.h>

#include "debug.h"
#include "builder.h"

int hip_timeval_diff(const struct timeval *t1, const struct timeval *t2,
		     struct timeval *result);
void hip_set_sockaddr(struct sockaddr_in6 *sin, struct in6_addr *addr);
int hip_lhi_are_equal(const struct hip_lhi *lhi1,
		      const struct hip_lhi *lhi2);
char* hip_in6_ntop(const struct in6_addr *in6, char *buf);

#endif /* HIP_MISC_H */
