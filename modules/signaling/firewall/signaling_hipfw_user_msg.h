/*
 * signaling_hipd_user_msg.h
 *
 *  Created on: Nov 5, 2010
 *      Author: ziegeldorf
 */


#ifndef HIP_HIPD_SIGNALING_PROT_HIPFW_USER_MSG_H
#define HIP_HIPD_SIGNALING_PROT_HIPFW_USER_MSG_H

#include <stdint.h>

#include "lib/core/protodefs.h"

int signaling_hipfw_send_connection_request(const hip_hit_t src_hit,
                                            const hip_hit_t dst_hit,
                                            const uint16_t src_port,
                                            const uint16_t dst_port);
int signaling_handle_hipd_connection_confirmation(struct hip_common *msg);

#endif /*HIP_HIPD_SIGNALING_PROT_HIPFW_USER_MSG_H*/
