/**
 * @file
 *
 * Copyright (c) 2010 Aalto University) and RWTH Aachen University.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * hipd messages to the hipfw and additional parameters for BEX and
 * UPDATE messages.
 *
 * @brief Messaging with hipfw and other HIP instances
 *
 * @author Rene Hummen <rene.hummen@rwth-aachen.de>
 *
 */

#ifndef HIP_HIPFW_SIGNALING_HIPFW_H
#define HIP_HIPFW_SIGNALING_HIPFW_H

#include <stdint.h>

#include "config.h"
#include "firewall/firewall_defines.h"
#include "lib/core/protodefs.h"
#include "lib/core/crypto.h"
#include "modules/signaling/lib/signaling_prot_common.h"
#include "modules/signaling/lib/signaling_common_builder.h"

#define DH_GROUP_ID 3

int signaling_hipfw_init(const char *policy_file);
int signaling_hipfw_uninit(void);

int signaling_hipfw_handle_r1(struct hip_common *common, struct tuple *tuple, struct hip_fw_context *ctx);
int signaling_hipfw_handle_i2(struct hip_common *common, struct tuple *tuple, struct hip_fw_context *ctx);
int signaling_hipfw_handle_r2(struct hip_common *common, struct tuple *tuple, struct hip_fw_context *ctx);
int signaling_hipfw_handle_i3(struct hip_common *common, struct tuple *tuple, const struct hip_fw_context *ctx);
int signaling_hipfw_handle_update(struct hip_common *common, struct tuple *tuple, struct hip_fw_context *ctx);
int signaling_hipfw_handle_notify(struct hip_common *common, struct tuple *tuple, struct hip_fw_context *ctx);

/*Utility Functions*/
int signaling_hipfw_initialize_connection_contexts_and_flags(struct hip_common *common,
                                                             struct signaling_connection         *new_conn,
                                                             struct signaling_connection_context *ctx_in,
                                                             struct signaling_connection_context *ctx_out,
                                                             struct signaling_connection_flags  **ctx_flags,
                                                             int *ret);
int signaling_hipfw_check_policy_and_create_service_offer(struct hip_common *common, struct tuple *tuple,
                                                          struct tuple *other_dir, struct hip_fw_context *ctx,
                                                          struct signaling_connection_context *ctx_in,
                                                          struct signaling_connection_context *ctx_out,
                                                          struct signaling_connection_flags   *ctx_flags,
                                                          struct signaling_connection         *new_conn,
                                                          struct in6_addr                     *hit_i,
                                                          struct in6_addr                     *hit_r,
                                                          int *ret);
int signaling_hipfw_check_policy_and_verify_info_response(struct hip_common *common,
                                                          struct tuple *tuple,
                                                          struct hip_fw_context *ctx,
                                                          struct signaling_connection_context *ctx_in,
                                                          struct signaling_connection_flags   *ctx_flags,
                                                          struct signaling_connection         *new_conn,
                                                          struct in6_addr                     *hit_i,
                                                          struct in6_addr                     *hit_r,
                                                          int *ret);

/* Utility functions*/
int signaling_hipfw_get_dh_shared_key(struct hip_common *msg, DH *dh_key,
                                      unsigned char **dh_shared_key,
                                      uint16_t *dh_shared_len);
int signaling_hipfw_generate_mb_dh_key(const int group_id, DH **dh_key);
DH *signaling_hipfw_get_mb_dh_key(void);
#endif /*HIP_HIPFW_SIGNALING_HIPFW_H*/
