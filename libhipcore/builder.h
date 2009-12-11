/** @file
 * A header file for builder.c.
 *
 * @author  Miika Komu <miika_iki.fi>
 * @author  Mika Kousa <mkousa_iki.fi>
 * @author  Tobias Heer <heer_tobibox.de>
 * @version 1.0
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 */
#ifndef HIP_BUILDER
#define HIP_BUILDER

#ifndef __KERNEL__
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#endif

#ifdef __KERNEL__
#  include "usercompat.h"
#  include "protodefs.h"
#else
#  include "kerncompat.h"
#  include "debug.h"
#  include "misc.h"
#  include "icomm.h"
#  include "certtools.h"
#ifdef ANDROID_CHANGES
#  include "getendpointinfo.h"
#endif
#endif
#include "registration.h"
#include "state.h"

//typedef struct hip_srv hip_srv_t;

/* ARRAY_SIZE is defined in linux/kernel.h, but it is in #ifdef __KERNEL__ */
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif
#define IN6ADDR_ANY_INIT { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 } } }

enum select_dh_key_t { STRONGER_KEY, WEAKER_KEY };

/* Removed in 2.6.11 - why ? */
extern const struct in6_addr in6addr_any;

extern struct hip_cert_spki_info hip_cert_spki_info;

#if 0
uint32_t hip_get_param_spi_value(const struct hip_esp_info *);
uint32_t hip_get_param_lsi_value(const struct hip_esp_info *);
#endif

int hip_build_param_blind_nonce(struct hip_common *msg, uint16_t nonce);

void hip_build_endpoint_hdr(struct endpoint_hip *, const char *, se_hip_flags_t,
                            uint8_t, unsigned int);
void hip_build_endpoint(struct endpoint_hip *, const struct endpoint_hip *,
                        const char *, const unsigned char *, unsigned int);

int hip_build_netlink_dummy_header(struct hip_common *);
int hip_build_param_heartbeat(struct hip_common *msg, int seconds);
int hip_build_param_transform_order(struct hip_common *msg, int order);
void hip_build_network_hdr(struct hip_common *, uint8_t, uint16_t,
                           const struct in6_addr *, const struct in6_addr *);

int hip_host_id_entry_to_endpoint(struct hip_host_id_entry *entry,
				  void *);
int hip_host_id_hits(hip_ha_t *entry,struct hip_common *msg);
/**
 * @addtogroup hip_param_func
 * @{
 */
int hip_build_param_ack(struct hip_common *, uint32_t);
int hip_build_param_contents(struct hip_common *, const void *, hip_tlv_type_t,
                             hip_tlv_type_t);
int hip_build_param_diffie_hellman_contents(struct hip_common *,
				      uint8_t, void *, hip_tlv_len_t,
				      uint8_t, void *, hip_tlv_len_t);
int hip_build_param_echo(struct hip_common *, void *, int, int, int);
int hip_build_param_eid_endpoint(struct hip_common *,
                                 const struct endpoint_hip *);
int hip_build_param_eid_iface(struct hip_common *, hip_eid_iface_type_t);
int hip_build_param_eid_sockaddr(struct hip_common *, struct sockaddr *, size_t);
int hip_build_param_encrypted_3des_sha1(struct hip_common *,
                                        struct hip_tlv_common *);
int hip_build_param_encrypted_aes_sha1(struct hip_common *,
                                       struct hip_tlv_common *);
int hip_build_param_encrypted_null_sha1(struct hip_common *,
                                        struct hip_tlv_common *);
int hip_build_param_esp_info(struct hip_common *, uint16_t, uint32_t, uint32_t);
int hip_build_param_relay_from(struct hip_common *, const struct in6_addr *,
                             const in_port_t);
int hip_build_param_from(struct hip_common *, const struct in6_addr *,
                         const in_port_t);
int hip_build_param_hmac2_contents(struct hip_common *, struct hip_crypto_key *,
                                   struct hip_host_id *);
int hip_build_param_hmac_contents(struct hip_common *, struct hip_crypto_key *);
int hip_create_msg_pseudo_hmac2(const struct hip_common *msg,
		struct hip_common *msg_copy,
		struct hip_host_id *host_id);
int hip_build_param_hmac(struct hip_common *, struct hip_crypto_key *,
                                  hip_tlv_type_t);
void hip_build_param_host_id_hdr(struct hip_host_id *host_id_hdr, const char *hostname,
				 hip_tlv_len_t rr_data_len, uint8_t algorithm);
void hip_build_param_host_id_only(struct hip_host_id *host_id, const void *rr_data,
				    const char *fqdn);
int hip_build_param_keys_hdr(struct hip_keys *, uint16_t, uint16_t,
                             struct in6_addr *, struct in6_addr *,
                             struct in6_addr *, uint32_t, uint32_t, uint16_t,
                             struct hip_crypto_key *);
int hip_build_param_keys(struct hip_common *, uint16_t, uint16_t,
                         struct in6_addr *, struct in6_addr *,
                         struct in6_addr *, uint32_t, uint32_t, uint16_t,
                         struct hip_crypto_key *);
int hip_build_param_locator(struct hip_common *,
                            struct hip_locator_info_addr_item *, int);
int hip_build_param_cert(struct hip_common *, uint8_t, uint8_t, uint8_t,
							uint8_t, void *, size_t);
int hip_build_param_notification(struct hip_common *, uint16_t, void *, size_t);
int hip_build_param_puzzle(struct hip_common *, uint8_t, uint8_t, uint32_t, uint64_t);
#ifdef CONFIG_HIP_MIDAUTH
int hip_build_param_challenge_request(struct hip_common *, uint8_t, uint8_t, uint8_t *,
				      uint8_t);
#endif
int hip_build_param_r1_counter(struct hip_common *, uint64_t);

int hip_build_param_seq(struct hip_common *, uint32_t);
int hip_build_param_signature2_contents(struct hip_common *, const void *,
                                        hip_tlv_len_t, uint8_t);
int hip_build_param_signature_contents(struct hip_common *, const void *,
                                       hip_tlv_len_t, uint8_t);
int hip_build_param_solution(struct hip_common *, struct hip_puzzle *,
                             uint64_t);
#ifdef CONFIG_HIP_MIDAUTH
int hip_build_param_challenge_response(struct hip_common *, struct hip_challenge_request *,
                               uint64_t);
#endif
int hip_build_param(struct hip_common *, const void *);
void hip_set_msg_response(struct hip_common *msg, uint8_t on);
uint8_t hip_get_msg_response(struct hip_common *msg);
int hip_build_param_transform(struct hip_common *, const hip_tlv_type_t,
                              const hip_transform_suite_t[], const uint16_t);
int hip_build_param_unit_test(struct hip_common *, uint16_t, uint16_t);
int hip_build_param_via_rvs_nat(struct hip_common *,
		const struct hip_in6_addr_port[], const int);
int hip_build_param_relay_to(struct hip_common *msg,
			     const in6_addr_t *rvs_addr,
			     const in_port_t port);
int hip_build_param_via_rvs(struct hip_common *msg,
			    const struct in6_addr rvs_addresses[]);

int hip_build_param_cert_spki_info(struct hip_common * msg,
				   struct hip_cert_spki_info * cert_info);
int hip_build_param_cert_x509_req(struct hip_common *,struct in6_addr *);
int hip_build_param_cert_x509_resp(struct hip_common *, char *, int);
int hip_build_param_cert_x509_ver(struct hip_common *, char *, int);

int hip_build_param_opendht_set(struct hip_common *, const char *);
int hip_build_param_opendht_gw_info(struct hip_common *, struct in6_addr *,
		uint32_t, uint16_t, char *);
int hip_build_param_hit_to_ip_set(struct hip_common *, const char *);
/** @} */

int hip_build_user_hdr(struct hip_common *, hip_hdr_type_t, hip_hdr_err_t);
void hip_calc_hdr_len(struct hip_common *);
int hip_check_network_msg(const struct hip_common *);
int hip_verify_network_header(struct hip_common *hip_common,
			      struct sockaddr *src, struct sockaddr *dst,
			      int len);
u16 hip_checksum_packet(char *data, struct sockaddr *src,
			struct sockaddr *dst);
int hip_check_userspace_msg(const struct hip_common *);
int hip_check_userspace_msg_type(const struct hip_common *);
uint16_t hip_convert_msg_total_len_to_bytes(const hip_hdr_len_t);
//uint16_t hip_create_control_flags(int, int, int, int);
void hip_dump_msg(const struct hip_common *);


struct hip_dh_public_value *hip_dh_select_key(
	const struct hip_diffie_hellman *);

uint8_t hip_get_host_id_algo(const struct hip_host_id *);
int hip_build_param_nat_pacing(struct hip_common *msg, uint32_t min_ta);
int hip_get_locator_addr_item_count(const struct hip_locator *);
union hip_locator_info_addr * hip_get_locator_item(void* item_list, int index);
union hip_locator_info_addr * hip_get_locator_item(void* item_list, int index);
int hip_get_lifetime_value(time_t seconds, uint8_t *lifetime);
int hip_get_lifetime_seconds(uint8_t lifetime, time_t *seconds);
int hip_check_network_msg_len(const struct hip_common *msg);

struct hip_locator_info_addr_item *hip_get_locator_first_addr_item(
        const struct hip_locator *);
hip_hdr_err_t hip_get_msg_err(const struct hip_common *);
uint16_t hip_get_msg_total_len(const struct hip_common *);
hip_hdr_type_t hip_get_msg_type(const struct hip_common *);
struct hip_tlv_common *hip_get_next_param(const struct hip_common *,
                                          const struct hip_tlv_common *);
void *hip_get_nth_param(const struct hip_common *, hip_tlv_type_t, int);
void *hip_get_param(const struct hip_common *, hip_tlv_type_t);
void *hip_get_param_contents(const struct hip_common *, hip_tlv_type_t);
void *hip_get_param_contents_direct(const void *);
hip_tlv_len_t hip_get_param_contents_len(const void *);
int hip_get_param_host_id_di_type_len(struct hip_host_id *, char **, int *);
char *hip_get_param_host_id_hostname(struct hip_host_id *);
hip_tlv_len_t hip_get_param_total_len(const void *);
hip_transform_suite_t hip_get_param_transform_suite_id(const void *,
                                                       const uint16_t);
hip_tlv_type_t hip_get_param_type(const void *);
uint16_t hip_get_msg_checksum(struct hip_common *msg);

/* TODO: The unit testing code seems to be unused. Can this be removed */
uint16_t hip_get_unit_test_case_param_id(const struct hip_unit_test *);
uint16_t hip_get_unit_test_suite_param_id(const struct hip_unit_test *);

char* hip_message_type_name(const uint8_t);
struct hip_common *hip_msg_alloc();
void hip_msg_free(struct hip_common *);
void hip_msg_init(struct hip_common *);
char* hip_param_type_name(const hip_tlv_type_t);
void hip_set_msg_err(struct hip_common *, hip_hdr_err_t);
void hip_set_msg_checksum(struct hip_common *msg, u8 checksum);
void hip_set_msg_total_len(struct hip_common *, uint16_t);
void hip_set_msg_type(struct hip_common *, hip_hdr_type_t);
void hip_set_param_contents_len(void *, hip_tlv_len_t);
void hip_set_param_lsi_value(struct hip_esp_info *, uint32_t);
/* TODO: This function is unused. Can it be removed */
void hip_set_param_spi_value(struct hip_esp_info *, uint32_t);
void hip_set_param_type(void *, hip_tlv_type_t);
void hip_zero_msg_checksum(struct hip_common *);
#ifndef __KERNEL__
int hip_write_hmac(int, void *, void *, int, void *);
int rsa_to_hip_endpoint(RSA *rsa, struct endpoint_hip **endpoint,
			se_hip_flags_t endpoint_flags, const char *hostname);
int dsa_to_hip_endpoint(DSA *dsa, struct endpoint_hip **endpoint,
			se_hip_flags_t endpoint_flags, const char *hostname);
int hip_build_param_hip_hdrr_info(struct hip_common * msg,
				    struct hip_hdrr_info * hdrr_info);
#endif
int hip_build_param_hip_uadb_info(struct hip_common *msg,
					struct hip_uadb_info *uadb_info);
int hip_build_param_reg_info(hip_common_t *msg,
			     const void *service_list,
			     const unsigned int service_count);
int hip_build_param_reg_request(hip_common_t *msg, const uint8_t lifetime,
				const uint8_t *type_list, const int type_count);
int hip_build_param_reg_response(hip_common_t *msg, const uint8_t lifetime,
				 const uint8_t *type_list, const int type_count);
int hip_build_param_full_relay_hmac_contents(struct hip_common *,
                                      struct hip_crypto_key *);

int hip_public_rsa_to_hit(RSA *rsa_key, unsigned char *rsa, int type,
			  struct in6_addr *hit);
int hip_private_rsa_to_hit(RSA *rsa_key, unsigned char *rsa, int type,
			  struct in6_addr *hit);
int hip_public_dsa_to_hit(DSA *dsa_key, unsigned char *dsa, int type,
			  struct in6_addr *hit);
int hip_private_dsa_to_hit(DSA *dsa_key, unsigned char *dsa, int type,
			   struct in6_addr *hit);
int hip_build_param_nat_transform(struct hip_common *msg,
				  hip_transform_suite_t *suite,
				  int suite_count);
int hip_build_param_nat_pacing(struct hip_common *msg, uint32_t min_ta);
				  
int hip_build_param_reg_failed(struct hip_common *msg, uint8_t failure_type,
			       uint8_t *type_list, int type_count);

int hip_build_param_esp_prot_transform(struct hip_common *msg, int num_transforms,
		uint8_t *transforms);
int hip_build_param_esp_prot_anchor(struct hip_common *msg, uint8_t transform,
		unsigned char *active_anchor, unsigned char *next_anchor, int hash_length,
		int hash_item_length);
int hip_build_param_esp_prot_branch(struct hip_common *msg, int anchor_offset,
		int branch_length, unsigned char *branch_nodes);
int hip_build_param_esp_prot_secret(struct hip_common *msg, int secret_length,
		unsigned char *secret);
int hip_build_param_esp_prot_root(struct hip_common *msg, uint8_t root_length,
		unsigned char *root);
int hip_build_param_reg_from(struct hip_common *msg,
                const in6_addr_t *addr,
                const in_port_t port);
int hip_build_param_nat_port(hip_common_t *msg, const in_port_t port, 
		hip_tlv_type_t hipparam);
struct in6_addr * hip_get_locator_item_address(void* item);

#endif /* HIP_BUILDER */
