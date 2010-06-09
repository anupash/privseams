/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 *
 * Inter-process communication with the hipd for userspace IPsec
 *
 * @brief Inter-process communication with the hipd for userspace IPsec
 *
 * @author Rene Hummen <rene.hummen@rwth-aachen.de>
 */

#ifndef HIP_FIREWALL_USER_IPSEC_FW_MSG_H
#define HIP_FIREWALL_USER_IPSEC_FW_MSG_H

#include "lib/core/protodefs.h"

int send_userspace_ipsec_to_hipd(const int activate);
int handle_sa_add_request(const struct hip_common *msg);
int handle_sa_delete_request(const struct hip_common *msg);
int handle_sa_flush_all_request(void);

#endif /* HIP_FIREWALL_USER_IPSEC_FW_MSG_H */
