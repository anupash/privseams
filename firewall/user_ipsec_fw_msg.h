/**
 * @file firewall/user_ipsec_fw_msg.h
 *
 * <LICENSE TEMLPATE LINE - LEAVE THIS LINE INTACT>
 *
 * Inter-process communication with the hipd for userspace IPsec
 *
 * @brief Inter-process communication with the hipd for userspace IPsec
 *
 * @author Rene Hummen <rene.hummen@rwth-aachen.de>
 **/

#ifndef USER_IPSEC_FW_MSG_H_
#define USER_IPSEC_FW_MSG_H_

#include "lib/core/protodefs.h"

int send_userspace_ipsec_to_hipd(const int activate);
int handle_sa_add_request(const struct hip_common *msg);
int handle_sa_delete_request(const struct hip_common *msg);
int handle_sa_flush_all_request(const struct hip_common *msg);

#endif /* USER_IPSEC_FW_MSG_H_ */
