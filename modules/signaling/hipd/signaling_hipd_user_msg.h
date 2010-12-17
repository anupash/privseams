/*
 * signaling_hipd_user_msg.h
 *
 *  Created on: Nov 5, 2010
 *      Author: ziegeldorf
 */


#ifndef HIP_HIPD_SIGNALING_PROT_HIPD_USER_MSG_H
#define HIP_HIPD_SIGNALING_PROT_HIPD_USER_MSG_H

#include <stdint.h>

#include "lib/core/protodefs.h"

/*
 * Handle ports from tigger_bex_msg.
 */
int signaling_handle_new_connection_trigger(struct hip_common *msg, struct sockaddr_in6 *src);

int signaling_handle_bex_update_trigger(struct hip_common *msg, UNUSED struct sockaddr_in6 *src);

#endif /*HIP_HIPD_SIGNALING_PROT_HIPD_USER_MSG_H*/
