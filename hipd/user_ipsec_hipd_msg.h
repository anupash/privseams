#ifndef USER_IPSEC_HIPD_MSG_H_
#define USER_IPSEC_HIPD_MSG_H_

#include "misc.h"

int hip_userspace_ipsec_activate(struct hip_common *msg);
struct hip_common * create_add_sa_msg(struct in6_addr *saddr, 
							    struct in6_addr *daddr,
							    struct in6_addr *src_hit, 
							    struct in6_addr *dst_hit,
							    uint32_t *spi, int ealg,
							    struct hip_crypto_key *enckey,
							    struct hip_crypto_key *authkey,
							    int retransmission,
							    int direction, int update,
							    hip_ha_t *entry);

#endif /*USER_IPSEC_HIPD_MSG_H_*/
