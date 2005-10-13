#ifndef HIP_BUILDER
#define HIP_BUILDER

/*
 * Authors:
 * - Miika Komu <miika@iki.fi>
 * - Mika Kousa <mkousa@cc.hut.fi>
 *
 */

#include <asm/types.h>
#include <sys/errno.h>
#include "../hipd/misc.h"

#include "../hipd/hip.h"
#include "debug.h"
#include "../hipd/crypto.h"
#include "../libinet6/include/bits/socket.h"

/* ARRAY_SIZE is defined in linux/kernel.h, but it is in #ifdef __KERNEL__ */
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

#define IN6ADDR_ANY_INIT { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 } } }
/* Removed in 2.6.11 - why ? */
extern const struct in6_addr in6addr_any;

void hip_msg_init(struct hip_common *msg);
struct hip_common *hip_msg_alloc(void);
void hip_msg_free(struct hip_common *msg);
void hip_build_network_hdr(struct hip_common *msg, uint8_t type_hdr,
			   uint16_t control, const struct in6_addr *hit_sender,
			   const struct in6_addr *hit_receiver);

uint16_t hip_convert_msg_total_len_to_bytes(hip_hdr_len_t len);
uint16_t hip_get_msg_total_len(const struct hip_common *msg);
uint16_t hip_get_msg_contents_len(const struct hip_common *msg);
void hip_set_msg_total_len(struct hip_common *msg, uint16_t len);
hip_hdr_type_t hip_get_msg_type(const struct hip_common *msg);
void hip_set_msg_type(struct hip_common *msg, hip_hdr_type_t type);
hip_hdr_err_t hip_get_msg_err(const struct hip_common *msg);
void hip_set_msg_err(struct hip_common *msg, hip_hdr_err_t err);
void hip_zero_msg_checksum(struct hip_common *msg);
hip_tlv_len_t hip_get_param_total_len(const void *tlv_common);
hip_tlv_len_t hip_get_param_contents_len(const void *tlv_common);
void hip_set_param_contents_len(void *tlv_common, hip_tlv_len_t len);
hip_tlv_type_t hip_get_param_type(const void *tlv_common);
void hip_set_param_type(void *tlv_common, hip_tlv_type_t type);
void *hip_get_diffie_hellman_param_public_value_contents(const void *tlv_common);
hip_tlv_len_t hip_get_diffie_hellman_param_public_value_len(const struct hip_diffie_hellman *dh);


void hip_set_param_spi_value(struct hip_spi *hspi, uint32_t spi);
void hip_set_param_lsi_value(struct hip_spi *hspi, uint32_t lsi);

uint32_t hip_get_param_spi_value(const struct hip_spi *hspi);
uint32_t hip_get_param_lsi_value(const struct hip_spi *hspi);


uint16_t hip_get_unit_test_suite_param_id(const struct hip_unit_test *test);
uint16_t hip_get_unit_test_case_param_id(const struct hip_unit_test *test);
uint8_t hip_get_host_id_algo(const struct hip_host_id *host_id);

int hip_check_msg_len(const struct hip_common *msg);
int hip_check_userspace_msg_type(const struct hip_common *msg);
struct hip_tlv_common *hip_get_next_param(const struct hip_common *msg,
				   const struct hip_tlv_common *current_param);
void *hip_get_param_contents(const struct hip_common *msg,
			    hip_tlv_type_t param_type);
void *hip_get_param_contents_direct(const void *tlv_common);
void *hip_get_param(const struct hip_common *msg,
			      hip_tlv_type_t param_type);
void *hip_get_nth_param(const struct hip_common *msg,
			hip_tlv_type_t param_type, int n);
void *hip_find_free_param(const struct hip_common *msg);
void hip_calc_hdr_len(struct hip_common *msg);
void hip_dump_msg(const struct hip_common *msg);
int hip_check_userspace_msg(const struct hip_common *msg);
int hip_check_network_msg(const struct hip_common *msg);
int hip_build_param_contents(struct hip_common *msg, const void *contents,
	hip_tlv_type_t param_type, hip_tlv_type_t contents_size);
int hip_build_param(struct hip_common *msg, const void *tlv_common);
int hip_build_user_hdr(struct hip_common *msg, hip_hdr_type_t base_type,
	hip_hdr_err_t err_val);
int hip_build_param_keys(struct hip_common *msg, struct hip_crypto_key *enc,
			 struct hip_crypto_key *auth, uint32_t spi, int alg, 
			 int already_acquired, int direction);

int hip_write_hmac(int type, void *key, void *in, int in_len, void *out);
int hip_build_param_hmac2_contents(struct hip_common *msg,
				   struct hip_crypto_key *key,
				   struct hip_host_id *host_id);
int hip_build_param_hmac_contents(struct hip_common *msg,
				  struct hip_crypto_key *key);

int hip_build_param_signature2_contents(struct hip_common *msg,
				      const void *contents,
				      hip_tlv_len_t contents_size,
				      uint8_t algorithm);
int hip_build_param_signature_contents(struct hip_common *msg,
				      const void *contents,
				      hip_tlv_len_t contents_size,
				      uint8_t algorithm);
int hip_build_param_diffie_hellman_contents(struct hip_common *msg,
				      uint8_t group_id,
				      void *pubkey,
				      hip_tlv_len_t pub_len);
int hip_build_param_transform(struct hip_common *msg,
			      const hip_tlv_type_t transform_type,
			      const hip_transform_suite_t transform_suite[],
			      const uint16_t transform_count);
hip_transform_suite_t hip_get_param_transform_suite_id(const void *transform_tlv, const uint16_t index);
int hip_build_param_rea(struct hip_common *msg,
			uint32_t spi,
			struct hip_rea_info_addr_item *addresses,
			int address_count);
int hip_build_param_nes(struct hip_common *msg, uint16_t keymat_index,
			uint32_t old_spi, uint32_t new_spi);
int hip_build_param_seq(struct hip_common *msg, uint32_t update_id);
int hip_build_param_ack(struct hip_common *msg, uint32_t peer_update_id);
int hip_build_param_unit_test(struct hip_common *msg, uint16_t suiteid,
			      uint16_t caseid);
int hip_build_param_spi(struct hip_common *msg, uint32_t spi);
int hip_build_param_encrypted_aes_sha1(struct hip_common *msg,
				      struct hip_host_id *host_id);
int hip_build_param_encrypted_3des_sha1(struct hip_common *msg,
				      struct hip_host_id *host_id);
int hip_build_param_encrypted_null_sha1(struct hip_common *msg,
					struct hip_host_id *host_id);
int hip_build_param_eid_endpoint(struct hip_common *msg,
				 const struct endpoint_hip *endpoint);
void hip_build_endpoint_hdr(struct endpoint_hip *endpoint_hdr,
			    const char *hostname,
			    se_hip_flags_t endpoint_flags,
			    uint8_t host_id_algo,
			    unsigned int rr_data_len);
void hip_build_endpoint(struct endpoint_hip *endpoint,
			const struct endpoint_hip *endpoint_hdr,
			const char *hostname,
			const unsigned char *key_rr,
			unsigned int key_rr_len);
int hip_build_param_eid_iface(struct hip_common *msg,
			      hip_eid_iface_type_t if_index);
int hip_build_param_eid_sockaddr(struct hip_common *msg,
                                 struct sockaddr *sockaddr,
                                 size_t sockaddr_len);

int hip_build_param_puzzle(struct hip_common *msg, uint8_t val_K,
			   uint8_t lifetime, uint32_t opaque, uint64_t random_i);

int hip_build_param_solution(struct hip_common *msg, struct hip_puzzle *puzzle,
			     uint64_t val_J);

int hip_build_param_r1_counter(struct hip_common *msg, uint64_t generation);

int hip_build_param_rva(struct hip_common *msg, uint32_t lifetime,
			int *type_list, int cnt, int request);

int hip_build_param_echo(struct hip_common *msg, void *opaque, int len,
			 int sign, int request);

int hip_build_param_from(struct hip_common *msg, struct in6_addr *addr, int sign);

int hip_get_param_host_id_di_type_len(struct hip_host_id *host, char **id, int *len);
char *hip_get_param_host_id_hostname(struct hip_host_id *hostid);
int hip_build_param_notify(struct hip_common *msg, uint16_t msgtype,
			   void *notification_data, size_t notification_data_len);
uint16_t hip_create_control_flags(int anon, int cert, int sht, int dht);
int hip_build_netlink_dummy_header(struct hip_common *msg);

#endif /* HIP_BUILDER */
