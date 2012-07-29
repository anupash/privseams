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

#define HIP_DEFAULT_HIPFW_ALGO       HIP_HI_ECDSA
#define SERVICE_RESPONSE_ALGO_DH     0

enum service_offer_type {
    OFFER_SIGNED           = 0,
    OFFER_UNSIGNED         = 1,
    OFFER_SELECTIVE_SIGNED = 2
};

/* Builders for on the wire parameters */
int signaling_build_param_signaling_connection(struct hip_common *output_msg,
                                               const struct signaling_connection *conn);
int signaling_build_param_application_context(struct hip_common *output_msg,
                                              const struct signaling_port_pair *port_list,
                                              const struct signaling_application_context *app_ctx);
int signaling_build_param_user_context(struct hip_common *output_msg,
                                       struct signaling_user_context *user_ctx,
                                       struct userdb_user_entry *db_entry);
int signaling_build_param_user_signature(struct hip_common *output_msg, const uid_t uid,
                                         uint8_t flag_selective_sign);
int signaling_build_param_user_auth_fail(struct hip_common *output_msg, const uint16_t reason);
int signaling_build_param_connection_fail(struct hip_common *output_msg, const uint16_t reason);
int signaling_build_param_cert_chain(struct hip_common *output_msg,
                                     STACK_OF(X509) * cert_chain,
                                     int start,
                                     int count,
                                     int freespace);
int signaling_build_param_certificate_chain_identifier(struct hip_common *output_msg,
                                                       const uint32_t connection_id,
                                                       const uint32_t network_id);
int signaling_build_param_user_auth_req_u(struct hip_common *output_msg,
                                          uint32_t network_id);
int signaling_build_param_user_auth_req_s(struct hip_common *output_msg,
                                          uint32_t network_id);
int signaling_build_param_host_info_response(struct hip_common *output_msg,
                                             struct signaling_connection existing_conn,
                                             struct signaling_connection_context *ctx,
                                             const uint8_t host_info_flag);

int signaling_build_param_app_info_response(struct hip_common *output_msg,
                                            struct signaling_connection existing_conn,
                                            struct signaling_connection_context *ctx,
                                            const uint8_t app_info_flag);

int signaling_build_param_user_info_response(struct hip_common *output_msg,
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
int signaling_build_response_to_service_offer_u(struct hip_common *output_msg,
                                                struct signaling_connection conn,
                                                struct signaling_connection_context *ctx_out,
                                                struct signaling_flags_info_req    *flags);
int signaling_build_response_to_service_offer_s(struct hip_packet_context   *ctx,
                                                struct signaling_connection  conn,
                                                struct signaling_hipd_state *sig_state,
                                                struct signaling_flags_info_req    *flags);
int signaling_build_service_ack_u(struct hip_common *input_msg,
                                  struct hip_common *output_msg);
int signaling_build_service_ack_selective_s(struct hip_common *input_msg,
                                            struct hip_common *output_msg,
                                            struct signaling_hipd_state *sig_state);
int signaling_build_service_ack_s(struct signaling_hipd_state *sig_state,
                                  struct hip_packet_context *ctx,
                                  const uint8_t *mb_dh_pub_key,
                                  const int mb_dh_pub_key_len);
int signaling_build_param_encrypted_aes_sha1(struct hip_common *output_msg,
                                             char *data, int *data_len, unsigned char *key_hint);
int signaling_hip_build_param_selective_sign(struct hip_common *msg,
                                             const void *contents,
                                             hip_tlv_len contents_size,
                                             uint8_t algorithm);
int signaling_build_param_selective_hmac(struct hip_common *msg,
                                         const struct hip_crypto_key *key,
                                         hip_tlv param_type);
int signaling_build_param_selective_hmac2(struct hip_common *msg,
                                          struct hip_crypto_key *key,
                                          struct hip_host_id *host_id);
int signaling_build_hip_packet_from_hip_encrypted_param(struct hip_common *common,    struct hip_common **msg_buf,
                                                        const struct hip_encrypted_aes_sha1 *param,
                                                        unsigned char *symm_key,      uint8_t *symm_key_len,
                                                        unsigned char *symm_key_hint, uint8_t *algo);
int signaling_build_service_offer_u_from_service_offer_s(struct signaling_param_service_offer *offer_u,
                                                         struct signaling_param_service_offer_s *offer_s,
                                                         int end_point_info_len);
int signaling_build_service_offer_u_from_offer_groups(struct signaling_param_service_offer *offer_u,
                                                      struct service_offer_groups *group);
int signaling_build_hash_tree_from_msg(struct hip_common *msg,
                                       unsigned char **concat_of_leaves,
                                       unsigned int   *len_concat_of_leaves);
int signaling_build_hash_tree_and_get_root(struct hip_common *msg,
                                           unsigned char *root_hash_tree);
int signaling_build_offset_list_to_remove_params(struct hip_common *msg,
                                                 int               *offset_list,
                                                 int               *offset_list_len,
                                                 uint8_t           *info_remove,
                                                 uint8_t           *info_rem_len);
int signlaing_insert_service_offer_in_hip_msg(struct hip_common *msg,
                                              struct signaling_param_service_offer *offer);
int signaling_add_service_offer_to_msg(struct hip_common *msg,
                                       struct signaling_connection_flags *flags,
                                       int service_offer_id,
                                       unsigned char *hash,
                                       void          *mb_key,
                                       X509          *mb_cert,
                                       uint8_t        flag_sign);
int signaling_add_service_offer_to_msg_s(struct hip_common *output_msg,
                                         struct signaling_connection_flags *flags,
                                         int service_offer_id,
                                         unsigned char *hash,
                                         void          *mb_key,
                                         X509          *mb_cert,
                                         uint8_t        flag_sign);
int signaling_add_param_dh_to_hip_update(struct hip_common *msg);
int signaling_remove_params_from_hip_msg(struct hip_common *msg,
                                         int               *offset_list,
                                         int               *offset_list_len);
int signaling_verify_service_ack_u(struct hip_common *output_msg,
                                   unsigned char *stored_hash);
int signaling_verify_service_ack_s(struct hip_common *msg,
                                   struct hip_common **msg_buf,
                                   unsigned char *stored_hash,
                                   RSA           *priv_key,
                                   unsigned char *dh_shared_key);
int signaling_verify_service_ack_selective_s(struct hip_common *msg,
                                             UNUSED struct hip_common **msg_buf,
                                             unsigned char *stored_hash,
                                             UNUSED RSA    *priv_key,
                                             int           *offset_list,
                                             int           *offset_list_len);
int signaling_verify_service_signature(X509 *cert, uint8_t *verify_it, uint8_t verify_it_len,
                                       uint8_t *signature, uint8_t sig_len);
int signaling_verify_mb_sig_selective_s(struct signaling_hipd_state          *sig_state,
                                        struct signaling_param_service_offer *offer);
int signaling_verify_packet_selective_hmac(struct hip_common *msg,
                                           const struct hip_crypto_key *crypto_key,
                                           const hip_tlv parameter_type);
int signaling_verify_packet_selective_hmac2(struct hip_common *msg,
                                            struct hip_crypto_key *key,
                                            struct hip_host_id *host_id);
/* Utility functions */
int signaling_get_connection_context(struct signaling_connection *conn,
                                     struct signaling_connection_context *ctx,
                                     uint8_t end_point_role);
int signaling_get_ports_from_param_app_ctx(const struct signaling_param_app_context *const param_app_ctx,
                                           struct signaling_port_pair *const port_list);
void signaling_get_hits_from_msg(const struct hip_common *output_msg, const hip_hit_t **hits, const hip_hit_t **hitr);
int signaling_get_update_type(const struct hip_common *output_msg);
int signaling_get_free_message_space(const struct hip_common *output_msg, struct hip_hadb_state *ha);
int signaling_get_verified_user_context(struct signaling_connection_context *ctx);
X509 *signaling_get_mbox_cert_from_offer_id(struct signaling_hipd_state *sig_state, uint16_t service_offer_id);
int signaling_get_info_req_from_service_offer(const struct signaling_param_service_offer *offer,
                                              struct signaling_flags_info_req    *flags);
int signaling_check_if_user_info_req(struct hip_packet_context *ctx);
int signaling_check_if_app_or_user_info_req(struct hip_packet_context *ctx);
int signaling_check_service_offer_type(const struct signaling_param_service_offer *param_service_offer);
int signaling_check_if_service_ack_signed(const struct signaling_param_service_ack *param_service_ack);
int signaling_check_if_offer_in_nack_list(struct signaling_hipd_state *sig_state, uint16_t service_offer_id);
int signaling_check_if_mb_certificate_available(struct signaling_hipd_state *sig_state,
                                                struct signaling_param_service_offer *offer);
int signaling_hip_rsa_selective_sign(void *const priv_key, struct hip_common *const msg);
int signaling_hip_ecdsa_selective_sign(void *const priv_key, struct hip_common *const msg);
int signaling_hip_dsa_selective_sign(void *const priv_key, struct hip_common *const msg);
int signaling_hip_dsa_selective_verify(void *priv_key, struct hip_common *msg);
int signaling_hip_ecdsa_selective_verify(void *peer_pub, struct hip_common *msg);
int signaling_hip_rsa_selective_verify(void *priv_key, struct hip_common *msg);

int signaling_put_decrypted_secrets_to_msg_buf(struct hip_common *msg,
                                               struct hip_common **msg_buf,
                                               uint8_t *data, uint16_t data_len);
int signaling_hip_msg_contains_signed_service_offer(struct hip_common *msg);
int signaling_split_info_req_to_groups(struct signaling_hipd_state *sig_state,
                                       struct service_offer_groups *offer_groups,
                                       struct hip_packet_context *ctx);
int signaling_merge_info_req_to_similar_groups(struct service_offer_groups *offer_groups,
                                               struct signaling_hipd_state *sig_state);
int signaling_remove_list_info_req(struct service_offer_groups *offer_groups,
                                   struct signaling_hipd_state *sig_state);
int signaling_add_offer_to_nack_list(struct signaling_hipd_state *sig_state,
                                     uint16_t service_offer_id);
char *signaling_concatenate_paths(const char *str1, char *str2);
unsigned char *signaling_extract_skey_ident_from_cert(X509 *cert, unsigned int *len);
int signaling_locate_mb_certificate(X509 **mb_certificate, const char *dir_path,
                                    unsigned char *certificate_hint, uint16_t cert_hint_len);
int generate_key_for_hip_encrypt(unsigned char *key, int *key_len, unsigned char *key_hint);
int signaling_generate_shared_key_from_dh_shared_secret(uint8_t *shared_key,
                                                        int     *shared_key_length,
                                                        const uint8_t *peer_key,
                                                        const int peer_key_len);
int signaling_generate_shared_key_from_ecdh_shared_secret(uint8_t *shared_key,
                                                          int     *shared_key_length,
                                                          const uint8_t *peer_key,
                                                          const int peer_key_len);
int signaling_generate_shared_secret_from_mbox_dh(const int groupid,
                                                  const uint8_t *peer_key,
                                                  size_t peer_len,
                                                  uint8_t *dh_shared_key,
                                                  size_t outlen);
#endif // MODULES_SIGNALING_LIB_SIGNALING_COMMON_BUILDER_H_
