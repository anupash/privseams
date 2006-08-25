/** @file
 * A header file for rvs.c.
 * 
 * @author  (version 1.0) Kristian Slavov
 * @author  (version 1.1) Lauri Silvennoinen
 * @version 1.1
 * @date    25.08.2006
 * @draft   <a href="http://tools.ietf.org/wg/hip/draft-ietf-hip-rvs/draft-ietf-hip-rvs-05.txt">
 *          draft-ietf-hip-rvs-05</a>
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl.txt">GNU/GPL</a>
 * @note    Version 1.0 was document scarcely and the comments regarding
 *          version 1.0 that have been added afterwards may be inaccurate
 *          or even misleading.
 */
#ifndef HIP_RVS_H
#define HIP_RVS_H

#include "hadb.h"
#include "hashtable.h"
#include "misc.h"
#include "builder.h"
#include "output.h"

/* CONSTANTS */
/** Maximum number of HIT->IP mappings for a single HIT. */
#define HIP_RVA_MAX_IPS 2
/** Maximum number of clients (HITs) the RVS can have.*/
#define HIP_RVA_SIZE    7

/* TYPE DEFINITIONS */
/** @todo Add HIP_RVASTATE_REGISTERING? */
/** The state of a rendezvous association. */
typedef enum { HIP_RVASTATE_INVALID=0, HIP_RVASTATE_VALID=1 } hip_rvastate_t;
/** A rendezvous association used by the rendezvous server to store the
    HIT->IP address mappings of its clients. Used as an element of the
    rendezvous hashtable. */
typedef struct hip_rendezvous_association
{
	/** A linked list head.
	    @todo Version 1.0 author might explain what is the function
	    of this.*/
	struct list_head      list_hit;
	/** Reference count of this rendezvous association. */
	atomic_t              refcnt;
	/** Spinlock. */
	spinlock_t            lock;
	/** The state of this rendezvous association. */
	hip_rvastate_t        rvastate;
	/** The lifetime of this rendezvous association. */
	uint32_t              lifetime;
	/** Client hit. */
	struct in6_addr       hit;
	/** An array of client IP addresses.
	    @todo Indicate what is the preferred IP addresses. */
	struct in6_addr       ip_addrs[HIP_RVA_MAX_IPS];
	/** Our HMAC. */
	struct hip_crypto_key hmac_our;
	/** Client HMAC. */
	struct hip_crypto_key hmac_peer;
}HIP_RVA;

/* FUNCTION PROTOTYPES */
void hip_rvs_init_rvadb(void);
void hip_rvs_free_rva(HIP_RVA *rva);
void hip_rvs_get_ip(HIP_RVA *rva, struct in6_addr *dst, unsigned int index);
void hip_rvs_put_ip(HIP_RVA *rva, struct in6_addr *ip, unsigned int index);
void hip_rvs_remove(HIP_RVA *rva);
void hip_rvs_uninit_rvadb(void);
int hip_rvs_put_rva(HIP_RVA *rva);
int hip_rvs_set_request_flag(hip_hit_t *, hip_hit_t *);
HIP_RVA *hip_rvs_ha2rva(hip_ha_t *ha, int gfpmask);
HIP_RVA *hip_rvs_allocate(int gfpmask);
HIP_RVA *hip_rvs_get(struct in6_addr *hit);
HIP_RVA *hip_rvs_get_valid(struct in6_addr *hit);

/* MACRO DEFINITIONS */
/**
 * Holds (increases the reference count) a rva.
 */
#define hip_hold_rva(rva) do { \
	atomic_inc(&rva->refcnt); \
        HIP_DEBUG("RVA: %p, refcnt increased to: %d\n",rva, atomic_read(&rva->refcnt)); \
} while(0) 

/**
 * Puts (decreases the reference count) a rva.
 */
#define hip_put_rva(rva) do { \
	if (atomic_dec_and_test(&rva->refcnt)) { \
                HIP_DEBUG("RVA: %p, refcnt reached zero. Deleting...\n",rva); \
		hip_rvs_free_rva(rva); \
	} else { \
                HIP_DEBUG("RVA: %p, refcnt decremented to: %d\n", rva, atomic_read(&rva->refcnt)); \
        } \
} while(0) 

#endif /* HIP_RVS_H */
