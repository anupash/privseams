/** @file
 * A header file for rvs.c.
 * 
 * @author  (version 1.0) Kristian Slavov
 * @author  (version 1.1) Lauri Silvennoinen
 * @version 1.1
 * @date    25.08.2006
 * @note    Related draft:
 *          <a href="http://tools.ietf.org/wg/hip/draft-ietf-hip-rvs/draft-ietf-hip-rvs-05.txt">
 *          draft-ietf-hip-rvs-05</a>
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl.txt">GNU/GPL</a>.
 * @note    Version 1.0 was document scarcely and the comments regarding
 *          version 1.0 that have been added afterwards may be inaccurate.
 */
#ifndef HIP_RVS_H
#define HIP_RVS_H

#include "hadb.h"
#include "hashtable.h"
#include "misc.h"
#include "builder.h"
#include "output.h"
#include "state.h"

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
	/** Client UDP port received in I2 packet of registration. */
	in_port_t             client_udp_port;
	/** Our HMAC. */
	struct hip_crypto_key hmac_our;
	/** Client HMAC. */
	struct hip_crypto_key hmac_peer;
        /** A function pointer to the function to be used for relaying the I1
	    packet. */
	int    (*send_pkt)    (struct in6_addr *, struct in6_addr *, in_port_t,
			       in_port_t, struct hip_common*, hip_ha_t *, int);
}HIP_RVA;

/* FUNCTION PROTOTYPES */
void hip_rvs_init_rvadb(void);
void hip_rvs_free_rva(HIP_RVA*);
void hip_rvs_get_ip(HIP_RVA*, struct in6_addr*, unsigned int);
void hip_rvs_put_ip(HIP_RVA*, struct in6_addr*, unsigned int);
void hip_rvs_remove(HIP_RVA*);
void hip_rvs_uninit_rvadb(void);
int hip_rvs_put_rva(HIP_RVA*);
int hip_rvs_set_request_flag(hip_hit_t*, hip_hit_t*);
int hip_rvs_relay_i1(struct hip_common*, struct in6_addr*,struct in6_addr*,
		     HIP_RVA*, struct hip_stateless_info*);
//HIP_RVA *hip_rvs_ha2rva(hip_ha_t*);
HIP_RVA *hip_rvs_ha2rva(hip_ha_t *ha, int (*send_pkt)
			(struct in6_addr *,struct in6_addr *,
			 in_port_t, in_port_t,
			 struct hip_common*, hip_ha_t *,
			 int));
HIP_RVA *hip_rvs_allocate(int);
HIP_RVA *hip_rvs_get(struct in6_addr*);
HIP_RVA *hip_rvs_get_valid(struct in6_addr*);

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
