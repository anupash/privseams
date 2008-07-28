/*
 * user_ipsec_fw_msg.h
 *
 *  Created on: Jul 28, 2008
 *      Author: Rene Hummen
 */

#ifndef USER_IPSEC_FW_MSG_H_
#define USER_IPSEC_FW_MSG_H_

#include "builder.h"

int send_userspace_ipsec_to_hipd(int activate);
int handle_sa_add_request(struct hip_common * msg);
int handle_sa_delete_request(struct hip_common * msg);
int handle_sa_flush_all_request(struct hip_common * msg);

#endif /* USER_IPSEC_FW_MSG_H_ */
