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
#include "crypto/dh.h"
#include "hip.h"
#include "debug.h"

int hip_delete_esp(hip_ha_t *entry);
uint32_t hip_acquire_spi(hip_hit_t *srchit, hip_hit_t *dsthit);
int hip_setup_sa(struct in6_addr *srchit, struct in6_addr *dsthit,
		 uint32_t *spi, int alg,
		 void *enckey, void *authkey, int already_acquired, int direction);

int hip_insert_dh(u8 *buffer, int bufsize, int group_id);
//int hip_generate_shared_secret(int group_id, u8* peerkey, size_t peer_len, u8 *out, size_t outlen);
void hip_regen_dh_keys(u32 bitmask);
uint16_t hip_get_dh_size(uint8_t hip_dh_group_type);
void hip_dh_uninit(void);
int hip_calculate_shared_secret(struct hip_diffie_hellman *dhf, u8* buffer,
				int bufsize);
int hip_delete_sa(u32 spi, struct in6_addr *dst);
int hip_delete_sp(int dir);
int hip_setup_sp(int dir);
void hip_finalize_sa(struct in6_addr *hit, u32 spi);

#endif /* HIP_SECURITY_H */
