#ifndef HIP_COOKIE_H
#define HIP_COOKIE_H

#include "debug.h"
#include "builder.h"
#include "output.h"
#include "list.h"
#include "hipd.h"

struct hip_r1entry {
	struct hip_common *r1;
	uint32_t generation;
	uint64_t Ci;
	uint8_t Ck;
	uint8_t Copaque[3];
};

#define HIP_R1TABLESIZE         3 /* precreate only this many R1s */
struct hip_common * hip_get_r1(struct in6_addr *ip_i, struct in6_addr *ip_r, struct in6_addr *src_hit, struct in6_addr *peer_hit);
struct hip_r1entry * hip_init_r1(void);
void hip_uninit_r1(struct hip_r1entry *);
int hip_recreate_all_precreated_r1_packets();
int hip_precreate_r1(struct hip_r1entry *r1table, 
		     struct in6_addr *hit, 
		     int (*sign)(struct hip_host_id *p, struct hip_common *m),
		     void *privkey,		     
		     struct hip_host_id *pubkey);
int hip_verify_cookie(in6_addr_t *ip_i, in6_addr_t *ip_r,  hip_common_t *hdr,
		      struct hip_solution *cookie);
int hip_set_cookie_difficulty(hip_hit_t *not_used, int k);
int hip_get_cookie_difficulty(hip_hit_t *not_used);
int hip_inc_cookie_difficulty(hip_hit_t *not_used);
int hip_dec_cookie_difficulty(hip_hit_t *not_used);
#endif /* HIP_COOKIE_H */
