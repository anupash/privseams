#ifndef FIREWALL_DEFINES_H_
#define FIREWALL_DEFINES_H_

#include <sys/time.h>
#include <libipq.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
  #include "config.h"
#endif /* HAVE_CONFIG_H */

#include "lib/core/linkedlist.h"
#include "lib/core/common_defines.h"
#include "lib/core/esp_prot_common.h"
#include "lib/core/protodefs.h"
#include "esp_prot_defines.h"
#include "common_types.h"

//int hip_proxy_status;


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
	in_port_t relayed_src_port;
	in_port_t relayed_dst_port;
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
        uint16_t length;
        uint16_t zero1;
        uint8_t zero2;
        uint8_t next;
} pseudo_v6;

static inline uint16_t inchksum(const void *data, uint32_t length){
	long sum = 0;
    	const uint16_t *wrd =  (uint16_t *) data;
    	long slen = (long) length;

    	while (slen > 1) {
        	sum += *wrd++;
        	slen -= 2;
    	}

    	if (slen > 0)
        	sum += * ((uint8_t *)wrd);

    	while (sum >> 16)
        	sum = (sum & 0xffff) + (sum >> 16);

    	return (uint16_t) sum;
}

static inline uint16_t ipv6_checksum(uint8_t protocol, struct in6_addr *src, struct in6_addr *dst, void *data, uint16_t len)
{
	uint32_t chksum = 0;
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

    	chksum = (uint16_t)(~chksum);
    	if (chksum == 0)
    		chksum = 0xffff;

    	return chksum;
}

#endif /*FIREWALL_DEFINES_H_*/
