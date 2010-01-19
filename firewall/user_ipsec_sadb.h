/**
 * @file firewall/user_ipsec_sadb.h
 *
 * <LICENSE TEMLPATE LINE - LEAVE THIS LINE INTACT>
 *
 * Stores security association for IPsec connections and makes them
 * accessasible through HITs and (dst IP, spi).
 *
 * @brief Security association database for IPsec connections
 *
 * @author Rene Hummen <rene.hummen@rwth-aachen.de>
 *
 */

#ifndef USER_IPSEC_SADB_H_
#define USER_IPSEC_SADB_H_

#include <openssl/des.h>		/* des_key_schedule */
#include <openssl/aes.h>		/* aes_key */
#ifndef ANDROID_CHANGES
#include <openssl/blowfish.h>	/* bf_key */
#endif
#include <pthread.h>
#include <inttypes.h>
#include "lib/core/hashchain.h"
#include "esp_prot_defines.h"
#include "lib/core/esp_prot_common.h"

#define BEET_MODE 3 /* mode: 1-transport, 2-tunnel, 3-beet -> right now we only support mode 3 */

/* IPsec Security Association entry */
typedef struct hip_sa_entry
{
	pthread_mutex_t rw_lock;				/* keep other threads from modifying */
	int direction;							/* direction of the SA: inbound/outbound */
	uint32_t spi;							/* IPsec SPI number */
	uint32_t mode; 							/* ESP mode :  1-transport, 2-tunnel, 3-beet */
	struct in6_addr *src_addr;				/* source address of outer IP header */
	struct in6_addr *dst_addr;				/* destination address of outer IP header */
	struct in6_addr *inner_src_addr;		/* inner source addresses for tunnel and BEET SAs */
	struct in6_addr *inner_dst_addr;		/* inner destination addresses for tunnel and BEET SAs */
	uint8_t encap_mode;						/* encapsulation mode: 0 - none, 1 - udp */
	uint16_t src_port;						/* src port for UDP encaps. ESP */
	uint16_t dst_port;						/* dst port for UDP encaps. ESP */
	/****************** crypto parameters *******************/
	int ealg;								/* crypto transform in use */
	struct hip_crypto_key *auth_key;		/* raw authentication key */
	struct hip_crypto_key *enc_key;			/* raw encryption key */
	des_key_schedule ks[3];					/* 3-DES keys */
	AES_KEY aes_key;						/* AES key */
#ifndef ANDROID_CHANGES
	BF_KEY bf_key;							/* BLOWFISH key */
#endif
	/******************** statistics *************************/
	uint64_t lifetime;			/* seconds until expiration */
	uint64_t bytes;				/* bytes transmitted */
	struct timeval usetime;		/* last used timestamp */
	struct timeval usetime_ka;	/* last used timestamp, including keep-alives */
	uint32_t sequence;			/* ESP sequence number counter */
	/*********** esp protection extension params *************/
	/* for both directions */
	uint8_t esp_prot_transform;	/* mode used for securing ipsec traffic */
	/* for outbound direction */
	void * active_hash_items[MAX_NUM_PARALLEL_HCHAINS];	/* active item can be a hchain or a htree */
	void * next_hash_items[MAX_NUM_PARALLEL_HCHAINS];	/* update item can be a hchain or a htree */
	int active_item_length;		/* length of the active hash item */
	int update_item_length;		/* length of the update hash item */
	uint8_t update_item_acked[MAX_NUM_PARALLEL_HCHAINS]; /* ack from peer that update succeeded */
	int last_used_chain;		/* in case of parallel hchains, stores last used for round robin */
	esp_cumulative_item_t hash_buffer[MAX_RING_BUFFER_SIZE]; /* packet hash buffer for the cumulative packet auth */
	uint32_t next_free;			/* next buffer entry to be used for cumulative packet auth */
} hip_sa_entry_t;

/* Structure for demultiplexing inbound ipsec packets, indexed by dst_addr and spi */
typedef struct hip_link_entry
{
	struct in6_addr *dst_addr;				/* destination address of outer IP header */
	uint32_t spi;							/* ipsec spi, needed for demultiplexing incoming packets */
	hip_sa_entry_t *linked_sa_entry;		/* direct link to sa entry */
} hip_link_entry_t;


int hip_sadb_init(void);
int hip_sadb_uninit(void);
int hip_sadb_add(int direction, uint32_t spi, uint32_t mode,
		struct in6_addr *src_addr, struct in6_addr *dst_addr,
		struct in6_addr *inner_src_addr, struct in6_addr *inner_dst_addr,
		uint8_t encap_mode, uint16_t local_port, uint16_t peer_port,
		int ealg, struct hip_crypto_key *auth_key, struct hip_crypto_key *enc_key,
		uint64_t lifetime, uint8_t esp_prot_transform, uint32_t hash_item_length,
		uint16_t esp_num_anchors, unsigned char (*esp_prot_anchors)[MAX_HASH_LENGTH],
		int retransmission, int update);
int hip_sadb_delete(struct in6_addr *dst_addr, uint32_t spi);
int hip_sadb_flush(void);
hip_sa_entry_t * hip_sa_entry_find_inbound(const struct in6_addr *dst_addr, uint32_t spi);
hip_sa_entry_t * hip_sa_entry_find_outbound(const struct in6_addr *src_hit,
		const struct in6_addr *dst_hit);
void hip_sadb_print(void);

#endif /* USER_IPSEC_SADB_H_ */

