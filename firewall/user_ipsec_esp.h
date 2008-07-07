#ifndef USER_IPSEC_ESP_H_
#define USER_IPSEC_ESP_H_

#include "user_ipsec_sadb.h"
#include "firewall.h"

// needed for transport layer checksum calculation
typedef struct _pseudo_header
{
	uint32_t src_addr;
	uint32_t dst_addr;
	uint8_t zero;
	uint8_t protocol;
	uint16_t packet_length;
} pseudo_header;

long g_read_usec;

int hip_beet_mode_output(hip_fw_context_t *ctx, hip_sadb_entry *entry,
		struct in6_addr *preferred_local_addr, struct in6_addr *preferred_peer_addr,
		unsigned char *esp_packet, int *esp_packet_len);
int hip_beet_mode_input(hip_fw_context_t *ctx, hip_sadb_entry *entry,
		struct in6_addr *src_hit, struct in6_addr *dst_hit,
		unsigned char *decrypted_packet, int *decrypted_packet_len);
int hip_payload_encrypt(unsigned char *in, uint8_t in_type, int in_len,
		unsigned char *out, int *out_len, hip_sadb_entry *entry);
int hip_payload_decrypt(unsigned char *in, int in_len, unsigned char *out, uint8_t *out_type,
		int *out_len, hip_sadb_entry *entry);
void add_ipv4_header(struct ip *ip_hdr, struct in6_addr *src_addr, struct in6_addr *dst_addr,
		int packet_len, uint8_t next_hdr);
void add_ipv6_header(struct ip6_hdr *ip6_hdr, struct in6_addr *src_addr, struct in6_addr *dst_addr,
		int packet_len, uint8_t next_hdr);
void add_udp_header(struct udphdr *udp_hdr, int packet_len, hip_sadb_entry *entry,
		struct in6_addr *src_addr, struct in6_addr *dst_addr);
uint16_t checksum_ip(struct ip *ip_hdr, unsigned int ip_hl);
uint16_t checksum_udp(struct udphdr *udp_hdr, struct in6_addr *src_addr,
		struct in6_addr *dst_addr);

#if 0

/*added by Tao Wan pseudo_header6, pseudo_header*/

typedef struct _pseudo_header6
{
	unsigned char src_addr[16];
	unsigned char dst_addr[16];
	uint32_t packet_length;
	char zero[3];
	uint8_t next_hdr;
} pseudo_header6;

#endif

#endif /* USER_IPSEC_ESP_H_*/
