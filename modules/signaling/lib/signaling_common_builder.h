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

/* Builders for on the wire parameters */
int signaling_build_param_application_context(hip_common_t *msg, const struct signaling_connection_context *ctx);
int signaling_build_param_user_context(hip_common_t *msg,
                                       const struct signaling_user_context *user_ctx,
                                       const unsigned char *signature, const int sig_len);
int signaling_build_param_user_auth_fail(hip_common_t *msg, const uint16_t reason);

/* Builders for internal state structures */
int signaling_build_application_context(const struct signaling_param_app_context *param_app_ctx,
                                        struct signaling_application_context *app_ctx);
int signaling_build_user_context(const struct signaling_param_user_context *param_usr_ctx,
                                 struct signaling_user_context *usr_ctx);
void signaling_get_hits_from_msg(const hip_common_t *msg, const hip_hit_t **hits, const hip_hit_t **hitr);

#endif // MODULES_SIGNALING_LIB_SIGNALING_COMMON_BUILDER_H_
