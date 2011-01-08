/*
 * Copyright (c) 2010 Aalto University and RWTH Aachen University.
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
 */

/**
 * @file
 * @author  Miika Komu <miika_iki.fi>
 * @author  Mika Kousa <mkousa_iki.fi>
 * @author  Tobias Heer <heer_tobibox.de>
 * @version 1.0
 */

#ifndef HIP_LIB_CORE_BUILDER_H
#define HIP_LIB_CORE_BUILDER_H

#include <stdint.h>
#include <netinet/in.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>

#include "config.h"
#include "certtools.h"
#include "debug.h"
#include "icomm.h"
#include "state.h"

/* Removed in 2.6.11 - why ? */
extern struct hip_cert_spki_info hip_cert_spki_info;

/** possible service states */
enum hip_srv_status { HIP_SERVICE_OFF = 0, HIP_SERVICE_ON = 1 };

/** HIP service. */
struct hip_srv {
    enum hip_srv_status status;     /**< service status */
    uint8_t             reg_type;
    uint8_t             min_lifetime;
    uint8_t             max_lifetime;
};

int hip_build_netlink_dummy_header(struct hip_common *);
int hip_build_param_heartbeat(struct hip_common *msg, int seconds);
int hip_build_param_transform_order(struct hip_common *msg, int order);
void hip_build_network_hdr(struct hip_common *,
                           uint8_t,
                           uint16_t,
                           const struct in6_addr *,
                           const struct in6_addr *);
int hip_host_id_hits(struct hip_hadb_state *entry, struct hip_common *msg);
int hip_build_param_contents(struct hip_common *,
                             const void *,
                             hip_tlv_type_t,
                             hip_tlv_type_t);
int hip_build_param_diffie_hellman_contents(struct hip_common *,
                                            uint8_t,
                                            void *,
                                            hip_tlv_len_t,
                                            uint8_t,
                                            void *,
                                            hip_tlv_len_t);
int hip_build_param_echo(struct hip_common *, const void *, int, int, int);
int hip_build_param_eid_endpoint(struct hip_common *,
                                 const struct endpoint_hip *);
int hip_build_param_encrypted_3des_sha1(struct hip_common *,
                                        struct hip_tlv_common *);
int hip_build_param_encrypted_aes_sha1(struct hip_common *,
                                       struct hip_tlv_common *);
int hip_build_param_encrypted_null_sha1(struct hip_common *,
                                        struct hip_tlv_common *);
int hip_build_param_esp_info(struct hip_common *, uint16_t, uint32_t, uint32_t);
int hip_build_param_hmac2_contents(struct hip_common *,
                                   struct hip_crypto_key *,
                                   struct hip_host_id *);
int hip_build_param_hmac_contents(struct hip_common *,
                                  const struct hip_crypto_key *);
int hip_create_msg_pseudo_hmac2(const struct hip_common *msg,
                                struct hip_common *msg_copy,
                                struct hip_host_id *host_id);
int hip_build_host_id_from_param(const struct hip_host_id *param,
                                 struct hip_host_id *peer_host_id);
int hip_build_param_host_id(struct hip_common *msg,
                            const struct hip_host_id *const host_id);
void hip_build_param_host_id_hdr(struct hip_host_id *host_id_hdr,
                                 const char *hostname,
                                 hip_tlv_len_t rr_data_len,
                                 uint8_t algorithm);
void hip_build_param_host_id_only(struct hip_host_id *host_id,
                                  const void *rr_data,
                                  const char *fqdn);
int hip_build_param_keys_hdr(struct hip_keys *,
                             uint16_t,
                             uint16_t,
                             struct in6_addr *,
                             struct in6_addr *,
                             struct in6_addr *,
                             uint32_t,
                             uint32_t,
                             uint16_t,
                             struct hip_crypto_key *);
int hip_build_param_cert(struct hip_common *,
                         uint8_t,
                         uint8_t,
                         uint8_t,
                         uint8_t,
                         void *,
                         size_t);
int hip_build_param_puzzle(struct hip_common *,
                           uint8_t,
                           uint8_t,
                           uint32_t,
                           uint64_t);

int hip_build_param_challenge_request(struct hip_common *,
                                      uint8_t,
                                      uint8_t,
                                      uint8_t *,
                                      uint8_t);

int hip_build_param_r1_counter(struct hip_common *, uint64_t);

int hip_build_param_signature2_contents(struct hip_common *,
                                        const void *,
                                        hip_tlv_len_t,
                                        uint8_t);
int hip_build_param_signature_contents(struct hip_common *,
                                       const void *,
                                       hip_tlv_len_t,
                                       uint8_t);
int hip_build_param_solution(struct hip_common *,
                             const struct hip_puzzle *,
                             uint64_t);

int hip_build_param_challenge_response(struct hip_common *,
                                       const struct hip_challenge_request *,
                                       uint64_t);

int hip_build_param(struct hip_common *, const void *);
void hip_set_msg_response(struct hip_common *msg, uint8_t on);
uint8_t hip_get_msg_response(struct hip_common *msg);
int hip_build_param_esp_transform(struct hip_common *,
                                  const hip_transform_suite_t[],
                                  const uint16_t);
int hip_build_param_hip_transform(struct hip_common *,
                                  const hip_transform_suite_t[],
                                  const uint16_t);
int hip_build_param_relay_to(struct hip_common *msg,
                             const struct in6_addr *rvs_addr,
                             const in_port_t port);
int hip_build_param_via_rvs(struct hip_common *msg,
                            const struct in6_addr rvs_addresses[]);
int hip_build_param_cert_spki_info(struct hip_common *msg,
                                   struct hip_cert_spki_info *cert_info);
int hip_build_param_cert_x509_req(struct hip_common *, struct in6_addr *);
int hip_build_param_cert_x509_resp(struct hip_common *, char *, int);
int hip_build_param_cert_x509_ver(struct hip_common *, char *, int);

int hip_build_param_hit_to_ip_set(struct hip_common *, const char *);
int hip_build_user_hdr(struct hip_common *, hip_hdr_type_t, hip_hdr_err_t);
void hip_calc_hdr_len(struct hip_common *);
int hip_check_network_msg(const struct hip_common *);
int hip_verify_network_header(struct hip_common *hip_common,
                              struct sockaddr *src,
                              struct sockaddr *dst,
                              int len);
int hip_check_userspace_msg(const struct hip_common *);
int hip_check_userspace_msg_type(const struct hip_common *);
void hip_dump_msg(const struct hip_common *);
struct hip_dh_public_value
        *hip_dh_select_key(struct hip_diffie_hellman *);
uint8_t hip_get_host_id_algo(const struct hip_host_id *);
int hip_get_lifetime_value(time_t seconds, uint8_t *lifetime);
int hip_get_lifetime_seconds(uint8_t lifetime, time_t *seconds);
int hip_check_network_msg_len(const struct hip_common *msg);
hip_hdr_err_t hip_get_msg_err(const struct hip_common *);
uint16_t hip_get_msg_total_len(const struct hip_common *);
hip_hdr_type_t hip_get_msg_type(const struct hip_common *);
const struct hip_tlv_common *hip_get_next_param(const struct hip_common *,
                                                const struct hip_tlv_common *);
struct hip_tlv_common *hip_get_next_param_readwrite(struct hip_common *,
                                                    struct hip_tlv_common *);
const void *hip_get_param(const struct hip_common *, hip_tlv_type_t);
void *hip_get_param_readwrite(struct hip_common *, hip_tlv_type_t);
const void *hip_get_param_contents(const struct hip_common *, hip_tlv_type_t);
const void *hip_get_param_contents_direct(const void *);
void *hip_get_param_contents_direct_readwrite(void *);
hip_tlv_len_t hip_get_param_contents_len(const void *);
int hip_get_param_host_id_di_type_len(const struct hip_host_id *,
                                      const char **, int *);
const char *hip_get_param_host_id_hostname(const struct hip_host_id *);
hip_tlv_len_t hip_get_param_total_len(const void *);
hip_transform_suite_t hip_get_param_transform_suite_id(const void *);
hip_tlv_type_t hip_get_param_type(const void *);
void hip_set_param_type(struct hip_tlv_common *tlv_generic, hip_tlv_type_t type);
void hip_calc_generic_param_len(struct hip_tlv_common *tlv_common,
                                hip_tlv_len_t tlv_size,
                                hip_tlv_len_t contents_size);
void hip_calc_param_len(struct hip_tlv_common *tlv_common,
                        hip_tlv_len_t contents_size);
uint16_t hip_get_msg_checksum(struct hip_common *msg);
const char *hip_message_type_name(const uint8_t);
struct hip_common *hip_msg_alloc(void);
void hip_msg_init(struct hip_common *);
void hip_set_msg_err(struct hip_common *, hip_hdr_err_t);
void hip_set_msg_checksum(struct hip_common *msg, uint8_t checksum);
void hip_set_msg_total_len(struct hip_common *, uint16_t);
void hip_set_param_contents_len(struct hip_tlv_common *, hip_tlv_len_t);
void hip_set_param_lsi_value(struct hip_esp_info *, uint32_t);
void hip_zero_msg_checksum(struct hip_common *);
int rsa_to_hip_endpoint(const RSA *const rsa,
                        struct endpoint_hip **endpoint,
                        se_hip_flags_t endpoint_flags,
                        const char *const hostname);
int dsa_to_hip_endpoint(const DSA *const dsa,
                        struct endpoint_hip **endpoint,
                        se_hip_flags_t endpoint_flags,
                        const char *const hostname);
int ecdsa_to_hip_endpoint(const EC_KEY *const ecdsa,
                          struct endpoint_hip **endpoint,
                          se_hip_flags_t endpoint_flags,
                          const char *const hostname);
int hip_any_key_to_hit(void *any_key,
                       hip_hit_t *hit,
                       int is_public,
                       int type);
int hip_build_param_reg_info(struct hip_common *msg,
                             const void *service_list,
                             const unsigned int service_count);
int hip_build_param_reg_request(struct hip_common *msg,
                                const uint8_t lifetime,
                                const uint8_t *type_list,
                                const int type_count);
int hip_build_param_reg_response(struct hip_common *msg,
                                 const uint8_t lifetime,
                                 const uint8_t *type_list,
                                 const int type_count);
int hip_build_param_full_relay_hmac_contents(struct hip_common *,
                                             struct hip_crypto_key *);
int hip_build_param_nat_pacing(struct hip_common *msg, uint32_t min_ta);

int hip_build_param_reg_failed(struct hip_common *msg,
                               uint8_t failure_type,
                               uint8_t *type_list,
                               int type_count);

int hip_build_param_esp_prot_transform(struct hip_common *msg,
                                       int num_transforms,
                                       uint8_t *transforms);
int hip_build_param_esp_prot_anchor(struct hip_common *msg,
                                    uint8_t transform,
                                    unsigned char *active_anchor,
                                    unsigned char *next_anchor,
                                    int hash_length,
                                    int hash_item_length);
int hip_build_param_esp_prot_branch(struct hip_common *msg,
                                    int anchor_offset,
                                    int branch_length,
                                    const unsigned char *branch_nodes);
int hip_build_param_esp_prot_secret(struct hip_common *msg,
                                    int secret_length,
                                    const unsigned char *secret);
int hip_build_param_esp_prot_root(struct hip_common *msg,
                                  uint8_t root_length,
                                  unsigned char *root);
int hip_build_param_reg_from(struct hip_common *msg,
                             const struct in6_addr *addr,
                             const in_port_t port);
int hip_build_param_nat_port(struct hip_common *msg,
                             const in_port_t port,
                             hip_tlv_type_t hipparam);
int hip_build_digest(const int type, const void *in, int in_len, void *out);

int hip_build_param_hmac(struct hip_common *msg,
                         const struct hip_crypto_key *key,
                         hip_tlv_type_t param_type);
int hip_build_param_relay_from(struct hip_common *msg,
                               const struct in6_addr *addr,
                               const in_port_t port);
int hip_build_param_from(struct hip_common *msg,
                         const struct in6_addr *addr);

#endif /* HIP_LIB_CORE_BUILDER_H */
