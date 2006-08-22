#ifndef HIP_RVS_H
#define HIP_RVS_H

#include "hadb.h"
#include "hashtable.h"
#include "misc.h"
#include "builder.h"
#include "output.h"

/* CONSTANTS */
/* Maximum number of HIT->IP mappings for a single HIT. */
#define HIP_RVA_MAX_IPS 2
/* Maximum number of clients (HITs) the RVS can have.*/
#define HIP_RVA_SIZE    7

/* TYPE DEFINITIONS */
/* TODO: Add HIP_RVASTATE_REGISTERING? */
typedef enum { HIP_RVASTATE_INVALID=0, HIP_RVASTATE_VALID=1 } hip_rvastate_t;
typedef struct hip_rendezvous_association
{
	struct list_head      list_hit;
	atomic_t              refcnt;
	spinlock_t            lock;
	hip_rvastate_t        rvastate;
	uint32_t              lifetime;
	struct in6_addr       hit;
	struct in6_addr       ip_addrs[HIP_RVA_MAX_IPS];
	struct hip_crypto_key hmac_our;
	struct hip_crypto_key hmac_peer;
}HIP_RVA;

/* FUNCTION PROTOTYPES */
void hip_init_rvadb(void);
void hip_rva_delete(HIP_RVA *rva);
void hip_rva_get_ip(HIP_RVA *rva, struct in6_addr *dst, unsigned int index);
void hip_rva_put_ip(HIP_RVA *rva, struct in6_addr *ip, unsigned int index);
void hip_rva_remove(HIP_RVA *rva);
void hip_uninit_rvadb(void);
int hip_rva_put_rva(HIP_RVA *rva);
int hip_rvs_set_request_flag(hip_hit_t *, hip_hit_t *);
HIP_RVA *hip_rva_ha2rva(hip_ha_t *ha, int gfpmask);
HIP_RVA *hip_rva_allocate(int gfpmask);
HIP_RVA *hip_rva_get(struct in6_addr *hit);
HIP_RVA *hip_rva_get_valid(struct in6_addr *hit);

/* MACRO DEFINITIONS */
#define hip_hold_rva(rva) do { \
	atomic_inc(&rva->refcnt); \
        HIP_DEBUG("RVA: %p, refcnt increased to: %d\n",rva, atomic_read(&rva->refcnt)); \
} while(0) 

#define hip_put_rva(rva) do { \
	if (atomic_dec_and_test(&rva->refcnt)) { \
                HIP_DEBUG("RVA: %p, refcnt reached zero. Deleting...\n",rva); \
		hip_rva_delete(rva); \
	} else { \
                HIP_DEBUG("RVA: %p, refcnt decremented to: %d\n", rva, atomic_read(&rva->refcnt)); \
        } \
} while(0) 

#endif /* HIP_RVS_H */
