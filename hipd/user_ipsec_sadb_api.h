/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 *
 * Provides the API used by the hipd to set up and maintain the
 * userspace IPsec state in the hipfw.
 *
 * @brief API used by the hipd to set up and maintain userspace IPsec state
 *
 * @author Rene Hummen <rene.hummen@rwth-aachen.de>
 *
 */

#ifndef HIP_HIPD_USER_IPSEC_SADB_API_H
#define HIP_HIPD_USER_IPSEC_SADB_API_H

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

int hip_userspace_ipsec_setup_default_sp_prefix_pair(void);

#endif /*HIP_HIPD_USER_IPSEC_SADB_API_H*/
