#ifndef HIP_COOKIE_H
#define HIP_COOKIE_H

#include "db.h"
#include "debug.h"
#include "hip.h"
#include "linux/spinlock.h"
#include "workqueue.h"

#ifndef MODULE
# define MODULE
#endif

struct hip_r1entry {
	struct hip_common *r1;
	uint64_t Ci;
	uint64_t Ck;
	int used;
};

#define HIP_COOKIE_LT 7
#define HIP_COOKIE_LIFETIME (1<<HIP_COOKIE_LT)
#define HIP_COOKIE_LTMASK (~(HIP_COOKIE_LIFETIME-1))
#define HIP_R1TABLESIZE 10
#define HIP_DEFAULT_COOKIE_K 10ULL

struct hip_common *hip_get_r1(struct in6_addr *ip_i, struct in6_addr *ip_r);
int hip_init_r1(void);
void hip_uninit_r1(void);
int hip_precreate_r1(struct in6_addr *src_hit);
int hip_verify_cookie(struct in6_addr *ip_i, struct in6_addr *ip_r, 
		      struct hip_common *hdr,
		      struct hip_birthday_cookie *cookie);
int hip_solve_puzzle(struct hip_birthday_cookie *puzzle, 
		     struct hip_common *hdr,uint64_t *param, int mode);


#endif /* HIP_COOKIE_H */
