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
#include "modules/signaling/lib/signaling_prot_common.h"

int signaling_send_connection_confirmation(const hip_hit_t *hits, const hip_hit_t *hitr,
                                           const struct signaling_connection_context *ctx);

int signaling_send_connection_context_request(const hip_hit_t *src_hit, const hip_hit_t *dst_hit,
                                              const struct signaling_connection_context *remote_ctx);

int signaling_handle_connection_request(struct hip_common *msg, struct sockaddr_in6 *src);

int signaling_handle_connection_context(struct hip_common *msg, struct sockaddr_in6 *src);

#endif /*HIP_HIPD_SIGNALING_PROT_HIPD_USER_MSG_H*/
