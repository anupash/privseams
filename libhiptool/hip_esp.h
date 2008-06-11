#ifndef HIP_ESP_H_
#define HIP_ESP_H_

#include "hip_sadb.h"
#include "firewall/firewall.h"

// needed for transport layer checksum calculation
typedef struct _pseudo_header
{
	uint32_t src_addr;
	uint32_t dst_addr;
	uint8_t zero;
	uint8_t protocol;
	uint16_t packet_length;
} pseudo_header;

// needed for authentication of incoming packets
#define HMAC_SHA_96_BITS 96 /* 12 bytes */


long g_read_usec;

int hip_esp_output(hip_fw_context_t *ctx, hip_sadb_entry *entry,
		struct in6_addr *preferred_local_addr, struct in6_addr *preferred_peer_addr,
		unsigned char *esp_packet, int *esp_packet_len);
int hip_esp_input(hip_fw_context_t *ctx, hip_sadb_entry *entry,
		struct in6_addr *src_hit, struct in6_addr *dst_hit,
		unsigned char *decrypted_packet, int *decrypted_packet_len);

#if 0


#define BUFF_LEN 2000


/* added By Tao Wan*/
#define H_PROTO_UDP 17

/* 
 * Local data types 
 */
struct ip_esp_hdr {
	__u32 spi;
	__u32 seq_no;
	__u8 enc_data[0];
}__attribute__ ((packed)) ;

struct ip_esp_padinfo {
	__u8 pad_length;
	__u8 next_hdr;
}__attribute__ ((packed)) ;


/*added by Tao Wan pseudo_header6, pseudo_header*/

typedef struct _pseudo_header6
{
	unsigned char src_addr[16];
	unsigned char dst_addr[16];
	uint32_t packet_length;
	char zero[3];
	uint8_t next_hdr;
} pseudo_header6;



int handle_nsol(__u8 *in, int len, __u8 *out,int *outlen,struct sockaddr *addr);
__u16 rewrite_checksum(__u8 *data, __u16 magic);
void add_eth_header(__u8 *data, __u64 src, __u64 dst, __u32 type);
void add_ipv4_header(__u8 *new_packet, struct ip *old_ip_hdr, __u32 src_addr, __u32 dst_addr, 
		__u16 packet_len, __u8 next_hdr);
void add_ipv6_pseudo_header(__u8 *data, struct sockaddr *src, 
	struct sockaddr *dst, __u32 len, __u8 proto);
void add_ipv6_header(__u8 *data, struct sockaddr *src, struct sockaddr *dst,
	struct ip6_hdr *old, struct ip *old4, __u16 len, __u8 proto);
__u16 in_cksum(struct ip *iph);
__u64 get_eth_addr(int family, __u8 *addr);

/* void reset_sadbentry_udp_port (__u32 spi_out); */
int send_udp_esp_tunnel_activation (__u32 spi_out);

// extern __u32 get_preferred_lsi();
// extern int do_bcast();
extern int maxof(int num_args, ...);
#endif

#endif /*HIP_ESP_H_*/
