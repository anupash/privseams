#ifndef HIP_USERIPSEC_H_
#define HIP_USERIPSEC_H_

#include "firewall.h"

// different hc_length in order not to spoil calculation time for short connections
#define HC_LENGTH_BEX_STORE 1000 
#define HC_LENGTH_STEP1 10000
#define HC_LENGTH_STEP2 100000
#define REMAIN_THRESHOLD 0.2

int hip_firewall_userspace_ipsec_input(hip_fw_context_t *ctx);
int hip_firewall_userspace_ipsec_output(hip_fw_context_t *ctx);
hip_hit_t *hip_fw_get_default_hit(void);

/* openHIP SADB Wrapper function converting from HIPL API */
int hipl_userspace_ipsec_sadb_add_wrapper(struct in6_addr *saddr,
					      struct in6_addr *daddr,
					      struct in6_addr *src_hit, 
					      struct in6_addr *dst_hit,
					      uint32_t *spi, uint8_t nat_mode,
					      uint16_t local_port,
					      uint16_t peer_port,
					      uint32_t hchain_anchor, int ealg,
					      struct hip_crypto_key *enckey,
					      struct hip_crypto_key *authkey,
					      int already_acquired,
					      int direction, int update);

int send_userspace_ipsec_to_hipd(int activate);
int send_esp_protection_extension_to_hipd(void);
int send_next_anchor_to_hipd(unsigned char *anchor);

#endif /* HIP_USERIPSEC_H_ */
