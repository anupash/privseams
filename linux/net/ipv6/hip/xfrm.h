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

#endif /* HIP_XFRMAPI_H */

