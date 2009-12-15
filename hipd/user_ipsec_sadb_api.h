/**
 * API used by the hipd to set up and maintain userspace IPsec state
 *
 * Description:
 *
 * Authors:
 *   - Rene Hummen <rene.hummen@rwth-aachen.de> 2008
 *
 * Licence: GNU/GPL
 *
 */

#ifndef USER_IPSEC_SADB_API_H_
#define USER_IPSEC_SADB_API_H_

#include "misc.h"
/* used for mapping HIPL ESP ecnryption INDEX to SADB encryption INDEX */
//#include <linux/pfkeyv2.h>  /* ESP transform defines */

uint32_t hip_userspace_ipsec_add_sa(struct in6_addr *saddr, struct in6_addr *daddr,
			      struct in6_addr *src_hit, struct in6_addr *dst_hit,
			      uint32_t spi, int ealg,
			      struct hip_crypto_key *enckey,
			      struct hip_crypto_key *authkey,
			      int already_acquired,
			      int direction, int update,
			      hip_ha_t *entry);
void hip_userspace_ipsec_delete_sa(uint32_t spi, struct in6_addr *not_used,
		struct in6_addr *dst_addr, int direction, hip_ha_t *entry);
int hip_userspace_ipsec_flush_all_sa();
int hip_userspace_ipsec_setup_hit_sp_pair(const hip_hit_t *src_hit,
					  const hip_hit_t *dst_hit,
					  const struct in6_addr *src_addr,
					  const struct in6_addr *dst_addr,
					  u8 proto,
					  int use_full_prefix,
					  int update);
void hip_userspace_ipsec_delete_hit_sp_pair(hip_hit_t *src_hit, hip_hit_t *dst_hit, u8 proto,
				      int use_full_prefix);
int hip_userspace_ipsec_flush_all_policy();
void hip_userspace_ipsec_delete_default_prefix_sp_pair();
int hip_userspace_ipsec_setup_default_sp_prefix_pair();

#endif /*USER_IPSEC_SADB_API_H_*/
