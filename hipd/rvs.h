#ifndef HIP_RVS_H
#define HIP_RVS_H


#include "hadb.h"
#include "hashtable.h"
#include "misc.h"
#include "builder.h"
#include "output.h"

#define HIP_RVA_MAX_IPS 2
#define HIP_RVA_SIZE 7  /* small hash table = less wasted memory :) */

typedef enum { HIP_RVASTATE_INVALID=0, HIP_RVASTATE_VALID=1 } hip_rvastate_t;

struct hip_rendezvous_association
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
};

typedef struct hip_rendezvous_association HIP_RVA;

/************* primitives *************/

void hip_init_rvadb(void);
void hip_uninit_rvadb(void);

HIP_RVA *hip_rva_allocate(int gfpmask);
HIP_RVA *hip_ha_to_rva(hip_ha_t *ha, int gfpmask);

void hip_rva_remove(HIP_RVA *rva);
int hip_rva_insert(HIP_RVA *rva);
void hip_rva_delete(HIP_RVA *rva);

HIP_RVA *hip_rva_find(struct in6_addr *hit);
HIP_RVA *hip_rva_find_valid(struct in6_addr *hit);

void hip_rva_insert_ip(HIP_RVA *rva, struct in6_addr *ip);
void hip_rva_insert_ip_n(HIP_RVA *rva, struct in6_addr *ip, unsigned int n);
struct in6_addr *hip_rva_get_ip(HIP_RVA *rva, int gfpmask);
struct in6_addr *hip_rva_get_ip_n(HIP_RVA *rva, int gfpmask, unsigned int n);
void hip_rva_fetch_ip(HIP_RVA *rva, struct in6_addr *dst);
void hip_rva_fetch_ip_n(HIP_RVA *rva, struct in6_addr *dst, unsigned int n);


/************* macros *****************/

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

/************ constructs *************/

int hip_select_rva_types(struct hip_rva_request *rreq, int *type_list, int llen);
int hip_rvs_set_request_flag(hip_hit_t *, hip_hit_t *);

#endif
