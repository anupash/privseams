#ifndef HIP_COOKIE_H
#define HIP_COOKIE_H

#ifdef __KERNEL__
#  include <linux/types.h>
#  include <linux/random.h>
#  include <asm/scatterlist.h>
#  include <net/ipv6.h>
#endif /* __KERNEL__ */

#include <net/hip.h>
#include "debug.h"
#include "hip.h"
#include "builder.h"

struct hip_r1entry {
	struct hip_common *r1;
	uint32_t generation;
	uint64_t Ci;
	uint8_t Ck;
	uint8_t Copaque[3];
};

#define HIP_PUZZLE_MAX_LIFETIME 60 /* in seconds */
#define HIP_R1TABLESIZE 3 /* precreate only this many R1s */
#define HIP_DEFAULT_COOKIE_K 10ULL

struct hip_common *hip_get_r1(struct in6_addr *ip_i, struct in6_addr *ip_r);
int hip_init_r1(void);
void hip_uninit_r1(void);
int hip_precreate_r1(const struct in6_addr *src_hit);
int hip_verify_cookie(struct in6_addr *ip_i, struct in6_addr *ip_r, 
		      struct hip_common *hdr,
		      struct hip_solution *cookie);
uint64_t hip_solve_puzzle(void *puzzle, struct hip_common *hdr, int mode);
int hip_verify_generation(struct in6_addr *ip_i, struct in6_addr *ip_r,
			  uint64_t birthday);


#endif /* HIP_COOKIE_H */
