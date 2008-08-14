#ifndef FIREWALL_DEFINES_H_
#define FIREWALL_DEFINES_H_

#include <sys/time.h>
#include "linkedlist.h"

//int hip_proxy_status;


#include "common_types.h"

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
	/* members needed for ESP protection extension */
	uint8_t esp_prot_tfm;
	unsigned char *active_anchor;
	unsigned char *next_anchor;
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
	int (*verify)(struct hip_host_id *, struct hip_common *);
};

struct hip_tuple
{
	struct hip_data * data;
	struct tuple * tuple;
};

struct tuple
{
	struct hip_tuple * hip_tuple;
	SList * esp_tuples;
	int direction;
	struct connection * connection;
	int state;
#ifdef CONFIG_HIP_HIPPROXY
	int hipproxy;
#endif
	/* list temporarily storing anchor elements until the consecutive update
	 * msg reveals which esp_tuple we have to update */
	hip_ll_t anchor_cache;
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
	// transforms + UNUSED
	uint8_t esp_prot_tfms[NUM_TRANSFORMS + 1];
};

struct hip_esp_packet
{
	int packet_length;
	struct hip_esp * esp_data;
};


/*********** ESP structures *************/

struct hip_esp
{
	uint32_t esp_spi;
	uint32_t esp_seq;
} __attribute__ ((packed));

struct hip_esp_tail
{
	 uint8_t esp_padlen;
     uint8_t esp_next;
};


#endif /*FIREWALL_DEFINES_H_*/
