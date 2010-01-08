/**
 * Messaging required for the userspace IPsec implementation of the hipfw
 *
 * Description:
 *
 * Authors:
 *   - Rene Hummen <rene.hummen@rwth-aachen.de> 2008
 *
 * Licence: GNU/GPL
 *
 */

#ifndef USER_IPSEC_HIPD_MSG_H_
#define USER_IPSEC_HIPD_MSG_H_

#include "libhipcore/protodefs.h"

int hip_userspace_ipsec_activate(const struct hip_common *msg);
struct hip_common * create_add_sa_msg(const struct in6_addr *saddr,
		const struct in6_addr *daddr,
		const struct in6_addr *src_hit,
		const struct in6_addr *dst_hit,
		const uint32_t spi, const int ealg,
		const struct hip_crypto_key *enckey,
		const struct hip_crypto_key *authkey,
		const int retransmission,
		const int direction, const int update,
		hip_ha_t *entry);
struct hip_common * create_delete_sa_msg(const uint32_t spi, const struct in6_addr *peer_addr,
		const struct in6_addr *dst_addr, const int family, const int src_port, const int dst_port);
struct hip_common * create_flush_all_sa_msg(void);

#endif /*USER_IPSEC_HIPD_MSG_H_*/
