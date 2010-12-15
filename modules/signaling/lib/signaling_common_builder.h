/*
 * signaling_common_builder.h
 *
 *  Created on: Nov 5, 2010
 *      Author: ziegeldorf
 */

#ifndef MODULES_SIGNALING_LIB_SIGNALING_COMMON_BUILDER_H_
#define MODULES_SIGNALING_LIB_SIGNALING_COMMON_BUILDER_H_

#include "signaling_prot_common.h"
#include "modules/signaling/lib/signaling_prot_common.h"

/* Build port info parameter for user messages. */
int signaling_build_param_portinfo(hip_common_t *msg, uint16_t src_port, uint16_t dest_port);

/* Build an appinfo parameter. */
int signaling_build_param_appinfo(hip_common_t *msg, struct signaling_application_context *app_ctx);

int signaling_build_param_user_sig(hip_common_t *msg, const unsigned char *signature, const int sig_len);


#endif // MODULES_SIGNALING_LIB_SIGNALING_COMMON_BUILDER_H_
