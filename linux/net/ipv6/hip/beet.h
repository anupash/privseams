/**
 * BEET API for the kernel and the userspace. XFRM API is for
 * management of IPsec SAs and BEET API is for management of
 * HIT<->SPI,IP mappings. 
 */
#ifndef HIP_BEET_H
#define HIP_BEET_H

#ifdef __KERNEL__
#  include <linux/in6.h>  /* struct in6_addr */
#  include <linux/list.h> /* struct list */
#endif /* __KERNEL__ */
#include <net/hip.h>
#include "hashtable.h"
#include "debug.h"
#include "hadb.h"
#include "workqueue.h"

#define HIP_BEETDB_SIZE 53

/* BEET database entry struct and access functions to retrieve them. */
struct hip_xfrm_state {
	struct list_head     next;
	spinlock_t           lock;
	atomic_t             refcnt;
        uint32_t             spi;                 /* SPI out */
        //int                  dir;                 /* Direction */
        hip_hit_t            hit_our;             /* The HIT we use with
                                                   * this host */
        hip_hit_t            hit_peer;            /* Peer's HIT */ 
	hip_hit_t            hash_key;            /* key for the hash table */
	struct in6_addr      preferred_peer_addr; /* preferred dst
						   * address to use when
						   * sending data to
						   * peer */
	int                  state;               /* state */
};

typedef struct hip_xfrm_state hip_xfrm_t;

void hip_beetdb_hold_entry(void *entry);

#ifdef __KERNEL__

/* Initialize */
void hip_init_beetdb(void);

/* Uninitialize */
void hip_uninit_beetdb(void);

/* For inbound packet processing (SPI->(HITd,HITs) mapping) */
struct hip_xfrm_state *hip_xfrm_find_by_spi(uint32_t spi);

/* For outbound packet processing (HITd->(SPI, IP) mapping */
//struct hip_xfrm_state *hip_xfrm_find_by_hit(const struct in6_addr *dst_hit);
struct hip_xfrm_state *hip_xfrm_find_by_hits(const struct in6_addr *src_hit, 
					     const struct in6_addr *dst_hit);
struct hip_xfrm_state *hip_xfrm_try_to_find_by_peer_hit(
	const struct in6_addr *hit);

void hip_beetdb_delete_state(hip_xfrm_t *x);

uint32_t hip_get_default_spi_out(struct in6_addr *hit, int *state_ok);

int hip_xfrm_hit_is_our(const hip_hit_t *hit);

#define hip_put_xfrm(ha) hip_db_put_ha(ha, hip_beetdb_delete_state)

#endif /* __KERNEL__ */

/*
 * These are wrappers to netlink calls (from the userspace daemon to
 * the kernel XFRM management) or to the BEET patch (from the kernel
 * daemon to the kernel XFRM management). The functions are used to
 * manage the replica of HADB within the kernel.
 */
int hip_xfrm_dst_init(struct in6_addr * dst_hit, struct in6_addr * dst_addr);
int hip_xfrm_update(hip_hit_t *hit, hip_hit_t *hit2, struct in6_addr *addr, 
		    uint32_t spi, int state, int dir);
int hip_xfrm_delete(hip_hit_t * hit, uint32_t spi, int dir);
int hip_for_each_xfrm(int (*func)(hip_xfrm_t *entry, void *opaq), void *opaque);

#endif /* HIP_BEET_H */

