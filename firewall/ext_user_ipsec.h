#ifndef EXT_USER_IPSEC_H_
#define EXT_USER_IPSEC_H_

#include "firewall.h"
#include "ext_user_ipsec_esp.h"
#include "utils.h"
#include "hashchain_store.h"

int userspace_ipsec_init(void);
int hip_firewall_userspace_ipsec_input(hip_fw_context_t *ctx);
int hip_firewall_userspace_ipsec_output(hip_fw_context_t *ctx);
hip_hit_t *hip_fw_get_default_hit(void);
//uint16_t checksum_magic(const struct in6_addr *initiator, const struct in6_addr *receiver);

int handle_sa_add_request(struct hip_common * msg, struct hip_tlv_common *param);
/* openHIP SADB Wrapper function converting from HIPL API */
int hipl_userspace_ipsec_sadb_add_wrapper(struct in6_addr *saddr,
					      struct in6_addr *daddr,
					      struct in6_addr *src_hit, 
					      struct in6_addr *dst_hit,
					      uint32_t spi, uint8_t nat_mode,
					      uint16_t local_port,
					      uint16_t peer_port,
					      uint8_t esp_prot_transform,
					      unsigned char *esp_prot_anchor,
					      int ealg, struct hip_crypto_key *enckey,
					      struct hip_crypto_key *authkey,
					      int already_acquired,
					      int direction, int update);

int send_userspace_ipsec_to_hipd(int activate);

#endif /* HIP_USERIPSEC_H_ */
