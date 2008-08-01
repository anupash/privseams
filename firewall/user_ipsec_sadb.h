/*
 * Host Identity Protocol
 * Copyright (C) 2002-04 the Boeing Company
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 *  hip_sadb.h
 *
 *  Authors: Jeff Ahrenholz <jeffrey.m.ahrenholz@boeing.com>
 *
 * the HIP Security Association database
 *
 */

#ifndef USER_IPSEC_SADB_H_
#define USER_IPSEC_SADB_H_

#include <openssl/des.h>		/* des_key_schedule */
#include <openssl/aes.h>		/* aes_key */
#include <openssl/blowfish.h>	/* bf_key */
#include <inttypes.h>
#include "hashchain.h"
#include "hashtable.h"
#include "ife.h"

/* mode: 1-transport, 2-tunnel, 3-beet
 *
 * however right now we only support mode 3, no need for variable yet */
#define BEET_MODE 3
// not implemented yet
#define DEFAULT_LIFETIME 0

/* HIP Security Association entry */
typedef struct hip_sa_entry
{
	pthread_mutex_t rw_lock;				/* keep other threads from modifying */
	int direction;							/* direction of the SA: inbound/outbound */
	uint32_t spi;							/* needed for demultiplexing incoming packets */
	uint32_t mode; 							/* ESP mode :  1-transport, 2-tunnel, 3-beet */
	struct in6_addr *src_addr;				/* source address of outer IP header */
	struct in6_addr *dst_addr;				/* destination address of outer IP header */
	/* inner addresses for BEET SAs (the above addresses
	 * are used as outer addresses) */
	struct in6_addr *inner_src_addr;
	struct in6_addr *inner_dst_addr;
	uint8_t encap_mode;						/* Encapsulation mode: 0 - none, 1 - udp */
	uint16_t src_port;						/* src port for UDP encaps. ESP */
	uint16_t dst_port;						/* dst port for UDP encaps. ESP */
	/****************** crypto parameters *******************/
	int ealg;								/* crypto transform in use */
	struct hip_crypto_key *auth_key;		/* raw crypto keys */
	struct hip_crypto_key *enc_key;
	des_key_schedule ks[3];					/* 3-DES keys */
	AES_KEY *aes_key;						/* AES key */
	BF_KEY *bf_key;							/* BLOWFISH key */
	/*********************************************************/
	uint64_t lifetime;			/* seconds until expiration */
	uint64_t bytes;				/* bytes transmitted */
	struct timeval usetime;		/* last used timestamp */
	struct timeval usetime_ka;	/* last used timestamp, incl keep-alives */
	uint32_t sequence;			/* sequence number counter */
	uint32_t replay_win;		/* anti-replay window */
	uint32_t replay_map;		/* anti-replay bitmap */
	/*********** esp protection extension params *************/
	/* hash chain parameters for this SA used in secure ESP extension */
	/* for outgoing SA */
	hash_chain_t *active_hchain;
	hash_chain_t *next_hchain;
	/* for incoming SA */
	int esp_prot_tolerance;
	unsigned char *active_anchor;
	unsigned char *next_anchor;
	/* for both */
	uint8_t esp_prot_transform;
} hip_sa_entry_t;

typedef struct hip_link_entry
{
	struct in6_addr *dst_addr;				/* destination address of outer IP header */
	uint32_t spi;							/* needed for demultiplexing incoming packets */
	hip_sa_entry_t *linked_sa_entry;		/* direct link to sa entry */
} hip_link_entry_t;

static DECLARE_LHASH_HASH_FN(hip_sa_entry_hash, const hip_sa_entry_t *);
static DECLARE_LHASH_COMP_FN(hip_sa_entries_compare, const hip_sa_entry_t *);
static DECLARE_LHASH_HASH_FN(hip_link_entry_hash, const hip_sa_entry_t *);
static DECLARE_LHASH_COMP_FN(hip_link_entries_compare, const hip_sa_entry_t *);


int hip_sadb_init(void);
int hip_sadb_uninit(void);
int hip_sadb_add(int direction, uint32_t spi, uint32_t mode,
		struct in6_addr *src_addr, struct in6_addr *dst_addr,
		struct in6_addr *inner_src_addr, struct in6_addr *inner_dst_addr,
		uint8_t encap_mode, uint16_t src_port, uint16_t dst_port,
		int ealg, struct hip_crypto_key *auth_key, struct hip_crypto_key *enc_key,
		uint64_t lifetime, uint8_t esp_prot_transform,
		unsigned char *esp_prot_anchor, int retransmission, int update);
int hip_sadb_delete(struct in6_addr *dst_addr, uint32_t spi);
int hip_sadb_flush(void);
void hip_sadb_print(void);


/******** hashtable helper functions *********/
unsigned long hip_sa_entry_hash(const hip_sa_entry_t *sa_entry);
int hip_sa_entries_compare(const hip_sa_entry_t *sa_entry1,
		const hip_sa_entry_t *sa_entry2);
unsigned long hip_link_entry_hash(const hip_link_entry_t *link_entry);
int hip_link_entries_compare(const hip_link_entry_t *link_entry1,
		const hip_link_entry_t *link_entry2);

/******** sadb helper functions *********/
int hip_sa_entry_add(int direction, uint32_t spi, uint32_t mode,
		struct in6_addr *src_addr, struct in6_addr *dst_addr,
		struct in6_addr *inner_src_addr, struct in6_addr *inner_dst_addr,
		uint8_t encap_mode, uint16_t src_port, uint16_t dst_port,
		int ealg, struct hip_crypto_key *auth_key, struct hip_crypto_key *enc_key,
		uint64_t lifetime, uint8_t esp_prot_transform,
		unsigned char *esp_prot_anchor, int update);
int hip_sa_entry_update(int direction, uint32_t spi, uint32_t mode,
		struct in6_addr *src_addr, struct in6_addr *dst_addr,
		struct in6_addr *inner_src_addr, struct in6_addr *inner_dst_addr,
		uint8_t encap_mode, uint16_t src_port, uint16_t dst_port,
		int ealg, struct hip_crypto_key *auth_key, struct hip_crypto_key *enc_key,
		uint64_t lifetime, uint8_t esp_prot_transform,
		unsigned char *esp_prot_anchor, int update);
int hip_sa_entry_set(hip_sa_entry_t *entry, int direction, uint32_t spi,
		uint32_t mode, struct in6_addr *src_addr, struct in6_addr *dst_addr,
		struct in6_addr *inner_src_addr, struct in6_addr *inner_dst_addr,
		uint8_t encap_mode, uint16_t src_port, uint16_t dst_port,
		int ealg, struct hip_crypto_key *auth_key, struct hip_crypto_key *enc_key,
		uint64_t lifetime, uint8_t esp_prot_transform,
		unsigned char *esp_prot_anchor, int update);
hip_sa_entry_t * hip_sa_entry_find_inbound(struct in6_addr *dst_addr, uint32_t spi);
hip_sa_entry_t * hip_sa_entry_find_outbound(struct in6_addr *src_hit,
		struct in6_addr *dst_hit);
int hip_sa_entry_delete(struct in6_addr *src_addr, struct in6_addr *dst_addr);
int hip_link_entry_add(struct in6_addr *dst_addr, hip_sa_entry_t *entry);
int hip_link_entries_add(hip_sa_entry_t *entry);
hip_link_entry_t *hip_link_entry_find(struct in6_addr *dst_addr, uint32_t spi);
int hip_link_entry_delete(struct in6_addr *dst_addr, uint32_t spi);
int hip_link_entries_delete_all(hip_sa_entry_t *entry);
void hip_link_entry_print(hip_link_entry_t *entry);
void hip_sa_entry_free(hip_sa_entry_t * entry);
void hip_sa_entry_print(hip_sa_entry_t *entry);
void hip_linkdb_print(void);

#endif /* USER_IPSEC_SADB_H_ */

