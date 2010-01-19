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

#include "lib/core/protodefs.h"

uint32_t hip_userspace_ipsec_add_sa(const struct in6_addr *saddr,
				    const struct in6_addr *daddr,
				    const struct in6_addr *src_hit,
				    const struct in6_addr *dst_hit,
				    const uint32_t spi, const int ealg,
				    const struct hip_crypto_key *enckey,
				    const struct hip_crypto_key *authkey,
				    const int retransmission,
				    const int direction, const int update,
				    hip_ha_t *entry);
void hip_userspace_ipsec_delete_sa(const uint32_t spi, const struct in6_addr *not_used,
		const struct in6_addr *dst_addr, const int direction, hip_ha_t *entry);
int hip_userspace_ipsec_flush_all_sa(void);
int hip_userspace_ipsec_setup_hit_sp_pair(const hip_hit_t *src_hit,
					  const hip_hit_t *dst_hit,
					  const struct in6_addr *src_addr,
					  const struct in6_addr *dst_addr,
					  const uint8_t proto,
					  const int use_full_prefix,
					  const int update);
void hip_userspace_ipsec_delete_hit_sp_pair(const hip_hit_t *src_hit,
					    const hip_hit_t *dst_hit, const uint8_t proto,
					    const int use_full_prefix);
int hip_userspace_ipsec_flush_all_policy(void);
void hip_userspace_ipsec_delete_default_prefix_sp_pair(void);
int hip_userspace_ipsec_setup_default_sp_prefix_pair(void);

#endif /*USER_IPSEC_SADB_API_H_*/
