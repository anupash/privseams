#ifndef HIP_XFRM_H
#define HIP_XFRM_H

#ifdef __KERNEL__
#  include <linux/xfrm.h>
#  include <net/xfrm.h>
#else
#  include "netlink.h"
#endif
#include <net/hip.h>
#include "hadb.h"
#include "debug.h"

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
int hip_add_sa(struct in6_addr *srchit, struct in6_addr *dsthit,
	       uint32_t *spi, int alg, struct hip_crypto_key *enckey, struct hip_crypto_key *authkey,
	       int already_acquired, int direction);

/* Changes the state to a VALID state, transport layer is woken up. */
int hip_finalize_sa(struct in6_addr *hit, u32 spi);

int hip_delete_sa(u32 spi, struct in6_addr *dst);

#endif /* HIP_XFRM_H */

