#ifndef USER_IPSEC_SADB_API_H_
#define USER_IPSEC_SADB_API_H_

#include "misc.h"
/* used for mapping HIPL ESP ecnryption INDEX to SADB encryption INDEX */
#include <linux/pfkeyv2.h>  /* ESP transform defines */

int hip_userspace_ipsec_send_to_fw(struct hip_common *msg);
int hip_userspace_ipsec_add_sa(struct in6_addr *saddr, struct in6_addr *daddr,
			      struct in6_addr *src_hit, struct in6_addr *dst_hit,
			      uint32_t spi, int ealg,
			      struct hip_crypto_key *enckey,
			      struct hip_crypto_key *authkey,
			      int already_acquired,
			      int direction, int update,
			      hip_ha_t *entry);
void hip_userspace_ipsec_delete_sa(uint32_t spi, struct in6_addr *peer_addr,
		struct in6_addr *dst_addr, int family, int sport, int dport);
int hip_userspace_ipsec_flush_all_sa();
int hip_userspace_ipsec_setup_hit_sp_pair(hip_hit_t *src_hit, hip_hit_t *dst_hit,
				    struct in6_addr *src_addr,
				    struct in6_addr *dst_addr, u8 proto,
				    int use_full_prefix, int update);
void hip_userspace_ipsec_delete_hit_sp_pair(hip_hit_t *src_hit, hip_hit_t *dst_hit, u8 proto,
				      int use_full_prefix);
int hip_userspace_ipsec_flush_all_policy();
uint32_t hip_userspace_ipsec_acquire_spi(hip_hit_t *srchit, hip_hit_t *dsthit);
void hip_userspace_ipsec_delete_default_prefix_sp_pair();
int hip_userspace_ipsec_setup_default_sp_prefix_pair();

#endif /*USER_IPSEC_SADB_API_H_*/
