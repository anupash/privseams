#ifndef HIP_ESP_H_
#define HIP_ESP_H_

#include "hip_sadb.h"
#include "firewall/firewall.h"

#define USE_EXTHDR 1

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

int hip_esp_output(hip_fw_context_t *ctx, hip_sadb_entry *entry,
		struct in6_addr *preferred_local_addr, struct in6_addr *preferred_peer_addr,
		unsigned char *esp_packet, int *esp_packet_len);
int hip_esp_input(hip_fw_context_t *ctx, hip_sadb_entry *entry,
		struct in6_addr *src_hit, struct in6_addr *dst_hit,
		unsigned char *decrypted_packet, int *decrypted_packet_len);

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

#endif /*HIP_ESP_H_*/
