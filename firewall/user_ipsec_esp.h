/**
 * Provides ESP BEET mode IPsec services
 *
 * Description:
 *
 * Authors:
 *   - Rene Hummen <rene.hummen@rwth-aachen.de> 2008
 *
 * Licence: GNU/GPL
 *
 */

#ifndef USER_IPSEC_ESP_H_
#define USER_IPSEC_ESP_H_

#include "user_ipsec_sadb.h"
#include "firewall_defines.h"

/** creates a packet according to BEET mode ESP specification
 *
 * @param	...
 * @return	0, if correct, != 0 else
 */
int hip_beet_mode_output(const hip_fw_context_t *ctx, hip_sa_entry_t *entry,
		const struct in6_addr *preferred_local_addr,
		const struct in6_addr *preferred_peer_addr,
		unsigned char *esp_packet, uint16_t *esp_packet_len);

/** handles a received packet according to BEET mode ESP specification
 *
 * @param	...
 * @return	0, if correct, != 0 else
 */
int hip_beet_mode_input(const hip_fw_context_t *ctx, hip_sa_entry_t *entry,
			unsigned char *decrypted_packet,
			uint16_t *decrypted_packet_len);

/** encrypts the payload of ESP packets and adds authentication
 *
 * @param	in the input-buffer containing the data to be encrypted
 * @param	in_len the length of the input-buffer
 * @param	out the output-buffer
 * @param	out_len the length of the output-buffer
 * @param	entry the SA entry containing information about algorithms
 *          and key to be used
 * @return	0, if correct, != 0 else
 */
int hip_payload_encrypt(unsigned char *in, const uint8_t in_type,
		const uint16_t in_len, unsigned char *out, uint16_t *out_len,
		hip_sa_entry_t *entry);

/** decrypts the payload of ESP packets and verifies authentication
 *
 * @param	in the input-buffer containing the data to be encrypted
 * @param	in_len the length of the input-buffer
 * @param	out the output-buffer
 * @param	out_len the length of the output-buffer
 * @param	entry the SA entry containing information about algorithms
 *          and key to be used
 * @return	0, if correct, != 0 else
 */
int hip_payload_decrypt(const unsigned char *in, const uint16_t in_len,
		unsigned char *out, uint8_t *out_type, uint16_t *out_len,
		hip_sa_entry_t *entry);

/** adds an IPv4-header to the packet */
void add_ipv4_header(struct ip *ip_hdr, const struct in6_addr *src_addr,
		const struct in6_addr *dst_addr, const uint16_t packet_len,
		const uint8_t next_hdr);

/** adds an IPv6-header to the packet */
void add_ipv6_header(struct ip6_hdr *ip6_hdr, const struct in6_addr *src_addr,
		const struct in6_addr *dst_addr, const uint16_t packet_len,
		const uint8_t next_hdr);

#endif /* USER_IPSEC_ESP_H_*/
