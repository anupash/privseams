#ifndef HIP_RVS_H
#define HIP_RVS_H

#include "hadb.h"

#include <linux/spinlock.h>
#include <linux/types.h>
#include <asm/atomic.h>
#include <net/ipv6.h>

#define HIP_RVA_MAX_IPS 2

typedef enum { HIP_RVASTATE_INVALID=0, HIP_RVASTATE_VALID=1 } hip_rvastate_t;

struct hip_rendezvous_association
{
	uint8_t               type;
	struct list_head      next_hit;

	atomic_t              refcnt;
	spinlock_t            rva_lock;

	hip_rvastate_t        rvastate
	uint32_t              lifetime;
	struct in6_addr       hit;
	struct in6_addr       ip_addrs[HIP_RVA_MAX_IPS];
/* ip_addrs field is allocated as a one chunk. So it must be freed as a one
   chunk too. This means that when altering the addresses we must copy
   over the pointers present */

	struct hip_crypto_key hmac_our;
	struct hip_crypto_key hmac_peer;
}

typedef struct hip_rendezvous_association HIP_RVA;

/************* primitives *************/

//void hip_init_rvadb();
//void hip_uninit_rvadb();

HIP_RVA *hip_rva_allocate(int gfpmask);
HIP_RVA *hip_ha_to_rva(hip_ha_t *ha, int gfpmask);

//void hip_rva_remove(HIP_RVA *rva);
//int hip_rva_insert(HIP_RVA *rva);

HIP_RVA *hip_rva_find(struct in6_addr *hit);

int hip_rva_insert_ip(HIP_RVA *rva, struct in6_addr *ip, int gfpmask);
int hip_rva_insert_ip_n(HIP_RVA *rva, struct in6_addr *ip, int n, int gfpmask);
struct in6_addr *hip_rva_get_ip(HIP_RVA *rva);
struct in6_addr *hip_rva_get_ip_n(HIP_RVA *rva, int n);



/************* macros *****************/

#define hip_hold_rva(rva) do { \
	atomic_inc(&rva->refcnt); \
} while(0) 

#define hip_put_rva(rva) do { \
	if (atomic_dec_and_test(&rva->refcnt)) { \
		hip_rva_delete(rva); \
	} \
} while(0) 

#define HIP_LOCK_RVA(rva) spin_lock(&rva->rva_lock)
#define HIP_UNLOCK_RVA(rva) spin_unlock(&rva->rva_lock)

/************ constructs *************/


#endif
