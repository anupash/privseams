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
#include "modules/signaling/lib/signaling_prot_common.h"

int signaling_hipfw_request_connection_by_ports(hip_hit_t *src_hit, hip_hit_t *dst_hit,
                                                uint16_t src_port, uint16_t dst_port);

int signaling_hipfw_send_connection_request(const hip_hit_t src_hit,
                                            const hip_hit_t dst_hit,
                                            const uint16_t src_port,
                                            const uint16_t dst_port);

int signaling_hipfw_handle_connection_confirmation(struct hip_common *msg);

int signaling_hipfw_handle_first_connection_request(struct hip_common *msg);

int signaling_hipfw_handle_second_connection_request(struct hip_common *msg);

int signaling_hipfw_handle_connection_update_request(struct hip_common *msg);

#endif /*HIP_HIPD_SIGNALING_PROT_HIPFW_USER_MSG_H*/
