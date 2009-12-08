#ifndef FIREWALL_DEFINES_H_
#define FIREWALL_DEFINES_H_

#include <sys/time.h>
#include "linkedlist.h"
#include "common_defines.h"
#include "esp_prot_common.h"
#include "esp_prot_defines.h"
#include <libipq.h>

//int hip_proxy_status;


#include "common_types.h"

typedef struct hip_fw_context{
	// queued packet
	ipq_packet_msg_t *ipq_packet;

	// IP layer information
	int ip_version; /* 4, 6 */
	int ip_hdr_len;
	struct in6_addr src, dst;
	union {
		struct ip6_hdr *ipv6;
		struct ip *ipv4;
	} ip_hdr;

	// transport layer information
	int packet_type; /* HIP_PACKET, ESP_PACKET, etc  */
	union {
		struct hip_esp *esp;
		struct hip_common *hip;
		struct tcphdr *tcp;
	} transport_hdr;
	struct udphdr *udp_encap_hdr;
	int is_stun;
	int is_turn;
	//uint32_t spi;

	int modified;
} hip_fw_context_t;

/********** State table structures **************/

struct esp_address
{
	struct in6_addr dst_addr;
	uint32_t * update_id; // null or pointer to the update id from the packet
	// that announced this address.
	// when ack with the update id is seen all esp_addresses with
	// null update_id can be removed.
};

struct esp_tuple
{
	uint32_t spi;
	uint32_t new_spi;
	uint32_t spi_update_id;
	SList * dst_addr_list;
	struct tuple * tuple;
	struct decryption_data * dec_data;
	/* tracking of the ESP SEQ number */
	uint32_t seq_no;
	/* members needed for ESP protection extension */
	uint8_t esp_prot_tfm;
	uint32_t hash_item_length;
	uint32_t hash_tree_depth;
	long num_hchains;
	unsigned char active_anchors[MAX_NUM_PARALLEL_HCHAINS][MAX_HASH_LENGTH];
	// need for verification of anchor updates
	unsigned char first_active_anchors[MAX_NUM_PARALLEL_HCHAINS][MAX_HASH_LENGTH];
	unsigned char next_anchors[MAX_NUM_PARALLEL_HCHAINS][MAX_HASH_LENGTH];
	int active_root_length;
	unsigned char *active_roots[MAX_NUM_PARALLEL_HCHAINS];
	int next_root_length[MAX_NUM_PARALLEL_HCHAINS];
	unsigned char *next_roots[MAX_NUM_PARALLEL_HCHAINS];
	/* list temporarily storing anchor elements until the consecutive update
	 * msg reveals that all on-path devices know the new anchor */
	hip_ll_t anchor_cache;
	/* buffer storing hashes of previous packets for cumulative authentication */
	esp_cumulative_item_t hash_buffer[MAX_RING_BUFFER_SIZE];
};

struct decryption_data
{
	int dec_alg;
	int auth_len;
	int key_len;
	struct hip_crypto_key	dec_key;
};

struct hip_data
{
	struct in6_addr src_hit;
	struct in6_addr dst_hit;
	struct hip_host_id * src_hi;
	void * src_pub_key;
	int (*verify)(void *, struct hip_common *);
};

struct hip_tuple
{
	struct hip_data * data;
	struct tuple * tuple;
};

struct tuple
{
	struct hip_tuple * hip_tuple;
	struct in6_addr * src_ip;
	struct in6_addr * dst_ip;
	SList * esp_tuples;
	int direction;
	struct connection * connection;
	int state;
	uint32_t lupdate_seq;
#ifdef CONFIG_HIP_HIPPROXY
	int hipproxy;
#endif
};

struct connection
{
	struct tuple original;
	struct tuple reply;
	int verify_responder;
	int state;
	struct timeval time_stamp;
	/* members needed for ESP protection extension */
	int num_esp_prot_tfms;
	uint8_t esp_prot_tfms[MAX_NUM_TRANSFORMS];
#ifdef CONFIG_HIP_MIDAUTH
	int pisa_state;
#endif
};

struct hip_esp_packet
{
	int packet_length;
	struct hip_esp * esp_data;
};

typedef struct pseudo_v6 {
       struct  in6_addr src;
        struct in6_addr dst;
        u16 length;
        u16 zero1;
        u8 zero2;
        u8 next;
} pseudo_v6;

static inline u16 inchksum(const void *data, u32 length){
	long sum = 0;
    	const u16 *wrd =  (u16 *) data;
    	long slen = (long) length;

    	while (slen > 1) {
        	sum += *wrd++;
        	slen -= 2;
    	}

    	if (slen > 0)
        	sum += * ((u8 *)wrd);

    	while (sum >> 16)
        	sum = (sum & 0xffff) + (sum >> 16);

    	return (u16) sum;
}

static inline u16 ipv6_checksum(u8 protocol, struct in6_addr *src, struct in6_addr *dst, void *data, u16 len)
{
	u32 chksum = 0;
    	pseudo_v6 pseudo;
    	memset(&pseudo, 0, sizeof(pseudo_v6));

    	pseudo.src = *src;
    	pseudo.dst = *dst;
    	pseudo.length = htons(len);
    	pseudo.next = protocol;

    	chksum = inchksum(&pseudo, sizeof(pseudo_v6));
    	chksum += inchksum(data, len);

    	chksum = (chksum >> 16) + (chksum & 0xffff);
    	chksum += (chksum >> 16);

    	chksum = (u16)(~chksum);
    	if (chksum == 0)
    		chksum = 0xffff;

    	return chksum;
}

#endif /*FIREWALL_DEFINES_H_*/
