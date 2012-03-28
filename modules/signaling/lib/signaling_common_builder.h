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
#include "modules/signaling/hipd/signaling.h"

/* Builders for on the wire parameters */
int signaling_build_param_signaling_connection(struct hip_common *msg,
                                               const struct signaling_connection *conn);
int signaling_build_param_application_context(struct hip_common *msg,
                                              const struct signaling_port_pair *port_list,
                                              const struct signaling_application_context *app_ctx);
int signaling_build_param_user_context(struct hip_common *msg,
                                       struct signaling_user_context *user_ctx,
                                       struct userdb_user_entry *db_entry);
int signaling_build_param_user_signature(struct hip_common *msg, const uid_t uid);
int signaling_build_param_user_auth_fail(struct hip_common *msg, const uint16_t reason);
int signaling_build_param_connection_fail(struct hip_common *msg, const uint16_t reason);
int signaling_build_param_cert_chain(struct hip_common *msg,
                                     STACK_OF(X509) * cert_chain,
                                     int start,
                                     int count,
                                     int freespace);
int signaling_build_param_certificate_chain_identifier(struct hip_common *msg,
                                                       const uint32_t connection_id,
                                                       const uint32_t network_id);
int signaling_build_param_user_auth_req_u(struct hip_common *msg,
                                          uint32_t network_id);
int signaling_build_param_user_auth_req_s(struct hip_common *msg,
                                          uint32_t network_id);

//TODO need to check if we will continue to use network_id for the certs parameter
int signaling_add_service_offer_to_msg_u(struct hip_common *msg,
                                         struct signaling_connection_flags *flags,
                                         int service_offer_id,
                                         unsigned char *hash);
int signaling_add_service_offer_to_msg_s(struct hip_common *msg,
                                         struct signaling_connection_flags *flags,
                                         int service_offer_id,
                                         unsigned char *hash,
                                         RSA           *mb_key,
                                         X509          *mb_cert);
int signaling_verify_service_ack(struct hip_common *msg,
                                 unsigned char *stored_hash);

int signaling_build_param_host_info_response(struct hip_common *msg,
                                             struct signaling_connection existing_conn,
                                             struct signaling_connection_context *ctx,
                                             const uint8_t host_info_flag);

int signaling_build_param_app_info_response(struct hip_common *msg,
                                            struct signaling_connection existing_conn,
                                            struct signaling_connection_context *ctx,
                                            const uint8_t app_info_flag);

int signaling_build_param_user_info_response(struct hip_common *msg,
                                             struct signaling_connection existing_conn,
                                             struct signaling_connection_context *ctx,
                                             const uint8_t user_info_flag);
/* Builders for internal state structures */
int signaling_build_host_context(const struct signaling_param_host_context *param_host_ctx,
                                 struct signaling_host_context *host_ctx);
int signaling_build_application_context(const struct signaling_param_app_context *param_app_ctx,
                                        struct signaling_application_context *app_ctx);
int signaling_build_user_context(const struct signaling_param_user_context *param_usr_ctx,
                                 struct signaling_user_context *usr_ctx);
int signaling_build_port_list(const struct signaling_param_user_context *param_usr_ctx,
                              struct signaling_port_pair *port_list);
int signaling_build_response_to_service_offer_u(struct hip_common *msg,
                                                struct signaling_connection conn,
                                                struct signaling_connection_context *ctx_out,
                                                const struct signaling_param_service_offer_u *offer,
                                                struct signaling_flags_info_req    *flags);
int signaling_build_response_to_service_offer_s(struct hip_common *msg,
                                                struct signaling_connection conn,
                                                struct signaling_connection_context *ctx_out,
                                                struct signaling_param_service_offer_s *offer,
                                                struct signaling_flags_info_req    *flags);
int signaling_build_service_ack(struct hip_common *input_msg,
                                struct hip_common *output_msg);

/* Utility functions */
int signaling_get_connection_context(struct signaling_connection *conn,
                                     struct signaling_connection_context *ctx,
                                     uint8_t end_point_role);
int signaling_get_ports_from_param_app_ctx(const struct signaling_param_app_context *const param_app_ctx,
                                           struct signaling_port_pair *const port_list);
void signaling_get_hits_from_msg(const struct hip_common *msg, const hip_hit_t **hits, const hip_hit_t **hitr);
int signaling_get_update_type(const struct hip_common *msg);
int signaling_get_free_message_space(const struct hip_common *msg, struct hip_hadb_state *ha);
int signaling_get_verified_user_context(struct signaling_connection_context *ctx);
/*Utility function*/
int signaling_check_if_user_info_req(struct hip_packet_context *ctx);
int signaling_check_if_app_or_user_info_req(struct hip_packet_context *ctx);
char *signaling_concatenate_paths(const char *str1, char *str2);
unsigned char *signaling_extract_skey_ident_from_cert(X509 *cert, unsigned int *len);
int signaling_verify_service_signature(X509 *cert, uint8_t *verify_it, uint8_t verify_it_len,
                                       uint8_t *signature, uint8_t sig_len);
#endif // MODULES_SIGNALING_LIB_SIGNALING_COMMON_BUILDER_H_
