/**
 * @file hipd/user_ipsec_hipd_msg.h
 *
 * <LICENSE TEMLPATE LINE - LEAVE THIS LINE INTACT>
 *
 * Messaging required for the userspace IPsec implementation of the hipfw
 *
 * @brief userspace IPsec hipd <-> hipfw communication
 *
 * @author Rene Hummen <rene.hummen@rwth-aachen.de>
 */

#ifndef HIP_HIPD_USER_IPSEC_HIPD_MSG_H
#define HIP_HIPD_USER_IPSEC_HIPD_MSG_H

#include "lib/core/protodefs.h"

int hip_userspace_ipsec_activate(const struct hip_common *msg);
struct hip_common *create_add_sa_msg(const struct in6_addr *saddr,
                                     const struct in6_addr *daddr,
                                     const struct in6_addr *src_hit,
                                     const struct in6_addr *dst_hit,
                                     const uint32_t spi, const int ealg,
                                     const struct hip_crypto_key *enckey,
                                     const struct hip_crypto_key *authkey,
                                     const int retransmission,
                                     const int direction, const int update,
                                     hip_ha_t *entry);
struct hip_common *create_delete_sa_msg(const uint32_t spi,
                                        const struct in6_addr *peer_addr,
                                        const struct in6_addr *dst_addr,
                                        const int family,
                                        const int src_port,
                                        const int dst_port);
struct hip_common *create_flush_all_sa_msg(void);

#endif /*HIP_HIPD_USER_IPSEC_HIPD_MSG_H*/
