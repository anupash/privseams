#ifndef HIP_XFRMAPI_H
#define HIP_XFRMAPI_H

#include <net/hip.h>
#ifdef __KERNEL__
#include <linux/xfrm.h>
#include <net/xfrm.h>
#endif
#include "debug.h"
#include "hadb.h"

#ifdef __KERNEL__
/* For now, only the kernel module inserts the security policy */

/* Setup IPsec security policy (module/hipd load) */
int hip_setup_sp(int dir);
/* Unsetup IPsec security policy (module/hipd unload) */
int hip_delete_sp(int dir);
#endif

/* Allocates SPI for fixed time */
uint32_t hip_acquire_spi(hip_hit_t *srchit, hip_hit_t *dsthit);

/* Setups the SA (with a given SPI if so said) */
int hip_setup_sa(struct in6_addr *srchit, struct in6_addr *dsthit,
                 uint32_t *spi, int alg, void *enckey, void *authkey,
                 int already_acquired, int direction);

/* Changes the state to a VALID state, transport layer is woken up. */
void hip_finalize_sa(struct in6_addr *hit, u32 spi);

int hip_delete_sa(u32 spi, struct in6_addr *dst);

#ifdef __KERNEL__
/* BEET database entry struct and access functions to retrieve them. */
struct hip_xfrm_state {
        struct               spi;
	hip_hit_t            hit_our;             /* The HIT we use with
						   * this host */
	hip_hit_t            hit_peer;            /* Peer's HIT */    
	struct in6_addr      preferred_peer_addr; /* preferred dst
						   * address to use when
						   * sending data to
						   * peer */
	int                  state;               /* state */
};

/* For inbound packet processing (SPI->(HITd,HITs) mapping) */
struct hip_xfrm_state *hip_xfrm_find_by_spi(uint32_t spi);

/* For outbound packet processing (HITd->(SPI, IP) mapping */
struct hip_xfrm_state *hip_xfrm_find_by_hit(struct in6_addr *dst_hit);

#endif /* __KERNEL__ */

int hip_xfrm_init(struct in6_addr * dst_hit, struct in6_addr * dst_addr);
int hip_xfrm_update(uint32 spi, struct in6_addr * dst_addr, int state, int dir);
int hip_xfrm_delete(uint32 spi, struct in6_addr * hit, int dir);

#endif /* HIP_XFRMAPI_H */

