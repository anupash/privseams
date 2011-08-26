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
#include "modules/signaling/hipd/signaling_hipd_state.h"

/* Builders for on the wire parameters */
int signaling_build_param_connection_identifier(hip_common_t *msg,
                                                const struct signaling_connection *conn);
int signaling_build_param_application_context(hip_common_t *msg,
                                              const struct signaling_port_pair *port_list,
                                              const struct signaling_application_context *app_ctx);
int signaling_build_param_user_context(hip_common_t *msg,
                                       struct signaling_user_context *user_ctx,
                                       struct userdb_user_entry *db_entry);
int signaling_build_param_user_signature(hip_common_t *msg, const uid_t uid);
int signaling_build_param_user_auth_fail(hip_common_t *msg, const uint16_t reason);
int signaling_build_param_connection_fail(hip_common_t *msg, const uint16_t reason);
int signaling_build_param_cert_chain(hip_common_t *msg,
                                     STACK_OF(X509) *cert_chain,
                                     int start,
                                     int count,
                                     int freespace);
int signaling_build_param_certificate_chain_identifier(hip_common_t *msg,
                                                       const uint32_t connection_id,
                                                       const uint32_t network_id);
int signaling_build_param_user_auth_req_u(hip_common_t *msg,
                                          uint32_t network_id);
int signaling_build_param_user_auth_req_s(hip_common_t *msg,
                                          uint32_t network_id);


/* Builders for internal state structures */
int signaling_build_application_context(const struct signaling_param_app_context *param_app_ctx,
                                        struct signaling_application_context *app_ctx);
int signaling_build_user_context(const struct signaling_param_user_context *param_usr_ctx,
                                 struct signaling_user_context *usr_ctx);
int signaling_build_port_list(const struct signaling_param_user_context *param_usr_ctx,
                              struct signaling_port_pair *port_list);

/* Utility functions */
int signaling_get_ports_from_param_app_ctx(const struct signaling_param_app_context *const param_app_ctx,
                                           struct signaling_port_pair *const port_list);
void signaling_get_hits_from_msg(const hip_common_t *msg, const hip_hit_t **hits, const hip_hit_t **hitr);
int signaling_get_update_type(const hip_common_t *msg);
int signaling_get_free_message_space(struct hip_common *msg, hip_ha_t *ha);


#endif // MODULES_SIGNALING_LIB_SIGNALING_COMMON_BUILDER_H_
