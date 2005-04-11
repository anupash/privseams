#ifndef HIP_SECURITY_H
#define HIP_SECURITY_H

#ifdef __KERNEL__
#  include <linux/types.h>
#  include <net/ipv6.h>
#  include <linux/in6.h>
#  include <linux/xfrm.h>
#  include <net/xfrm.h>
#endif

#include "hadb.h"
#include "crypto.h"
#include "debug.h"

int hip_insert_dh(u8 *buffer, int bufsize, int group_id);
void hip_regen_dh_keys(u32 bitmask);
uint16_t hip_get_dh_size(uint8_t hip_dh_group_type);
void hip_dh_uninit(void);
int hip_calculate_shared_secret(struct hip_diffie_hellman *dhf, u8* buffer,
				int bufsize);

#endif /* HIP_SECURITY_H */
