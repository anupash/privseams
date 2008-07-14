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

//#include <asm/types.h>		/* __u16, __u32, etc */
//#include <sys/types.h>		/* for socket.h */
//#include <sys/socket.h>		/* struct sockaddr */
//#include <netinet/in.h>		/* struct sockaddr_in */
#include <openssl/des.h>	/* des_key_schedule */
#include <openssl/aes.h>	/* aes_key */
#include <openssl/blowfish.h>	/* bf_key */
#include <inttypes.h>
//#include <sys/time.h>		/* timeval */
//#include "debug.h"
#include "hashchain.h"
#include "ife.h"

#if 0
/*
 * Macros from hip.h and elsewhere
 */
/* get pointer to IP from a sockaddr 
 *    useful for inet_ntop calls     */
#define SA2IP(x) hip_cast_sa_addr(x)
#define SALEN(x) hip_sockaddr_len(x)
#define SAIPLEN(x) hip_sa_addr_len(x)
#define SA(x) ((struct sockaddr*)x)
#define LSI4(a) (((struct sockaddr_in*)a)->sin_addr.s_addr)

#define HIP_ESP_UDP_PORT       HIP_NAT_UDP_PORT
#define HIP_KEEPALIVE_TIMEOUT  HIP_NAT_KEEP_ALIVE_INTERVAL

/**** end of definitions from hip_types.h ****/


/*
 * definitions
 */
#define SADB_SIZE 512 
#endif

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
	uint32_t a_type;						/* crypto transform in use */
	uint32_t e_type;
	uint32_t a_keylen;						/* length of raw keys */
	uint32_t e_keylen;
	unsigned char *a_key;					/* raw crypto keys */
	unsigned char *e_key;
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
	int tolerance;
	unsigned char *active_anchor;
	unsigned char *next_anchor;
	/* for both */
	uint8_t active_transform;
	uint8_t next_transform;
} hip_sa_entry_t;

typedef struct hip_link_entry
{
	struct in6_addr *dst_addr;				/* destination address of outer IP header */
	uint32_t spi;							/* needed for demultiplexing incoming packets */
	hip_sa_entry_t *linked_sa_entry;		/* direct link to sa entry */
} hip_link_entry_t;


int hip_sadb_init(void);
unsigned long hip_sa_entry_hash(const void *ptr);
int hip_sa_entries_compare(const void *ptr1, const void *ptr2);
unsigned long hip_link_entry_hash(const void *ptr);
int hip_link_entries_compare(const void *ptr1, const void *ptr2);
int hip_sadb_add(int direction, uint32_t spi, uint32_t mode,
		struct in6_addr *src_addr, struct in6_addr *dst_addr,
		struct in6_addr *inner_src_addr, struct in6_addr *inner_dst_addr,
		uint8_t encap_mode, uint16_t src_port, uint16_t dst_port,
		uint32_t a_type, uint32_t e_type, uint32_t a_keylen, uint32_t e_keylen,
		unsigned char *a_key, unsigned char *e_key, uint64_t lifetime,
		uint8_t esp_prot_transform, unsigned char *esp_prot_anchor,
		int retransmission, int update);
int hip_sa_entry_add(int direction, uint32_t spi, uint32_t mode,
		struct in6_addr *src_addr, struct in6_addr *dst_addr,
		struct in6_addr *inner_src_addr, struct in6_addr *inner_dst_addr,
		uint8_t encap_mode, uint16_t src_port, uint16_t dst_port,
		uint32_t a_type, uint32_t e_type, uint32_t a_keylen, uint32_t e_keylen,
		unsigned char *a_key, unsigned char *e_key, uint64_t lifetime,
		uint8_t esp_prot_transform, unsigned char *esp_prot_anchor);
int hip_sa_entry_update(int direction, uint32_t spi, uint32_t mode,
		struct in6_addr *src_addr, struct in6_addr *dst_addr,
		struct in6_addr *inner_src_addr, struct in6_addr *inner_dst_addr,
		uint8_t encap_mode, uint16_t src_port, uint16_t dst_port,
		uint32_t a_type, uint32_t e_type, uint32_t a_keylen, uint32_t e_keylen,
		unsigned char *a_key, unsigned char *e_key, uint64_t lifetime,
		uint8_t esp_prot_transform, unsigned char *esp_prot_anchor);
int hip_sa_entry_set(hip_sa_entry_t *entry, int direction, uint32_t spi, uint32_t mode,
		struct in6_addr *src_addr, struct in6_addr *dst_addr,
		struct in6_addr *inner_src_addr, struct in6_addr *inner_dst_addr,
		uint8_t encap_mode, uint16_t src_port, uint16_t dst_port,
		uint32_t a_type, uint32_t e_type, uint32_t a_keylen, uint32_t e_keylen,
		unsigned char *a_key, unsigned char *e_key, uint64_t lifetime,
		uint8_t esp_prot_transform, unsigned char *esp_prot_anchor);
hip_sa_entry_t * hip_sa_entry_find_inbound(struct in6_addr *dst_addr, uint32_t spi);
hip_sa_entry_t * hip_sa_entry_find_outbound(struct in6_addr *src_addr,
		struct in6_addr *dst_addr);
int hip_sa_entry_delete(struct in6_addr *src_addr, struct in6_addr *dst_addr);
int hip_link_entry_add(struct in6_addr *dst_addr, hip_sa_entry_t *entry);
int hip_link_entries_add(hip_sa_entry_t *entry);
hip_link_entry_t *hip_link_entry_find(struct in6_addr *dst_addr, uint32_t spi);
int hip_link_entry_delete(struct in6_addr *dst_addr, hip_sa_entry_t *entry);
int hip_link_entries_delete_all(hip_sa_entry_t *entry);
void hip_sa_entry_free(hip_sa_entry_t * entry);
int hip_sadb_flush();

#if 0
/* HIP SADB destintation cache entry */
typedef struct _hip_sadb_dst_entry
{
	struct _hip_sadb_dst_entry *next;
	struct sockaddr_storage addr;
	hip_sadb_entry *sadb_entry;
	
} hip_sadb_dst_entry;

/*
 * functions
 */
void hip_sadb_init();
int hip_sadb_add(__u32 type, __u32 mode, struct sockaddr *inner_src,
    struct sockaddr *inner_dst, struct sockaddr *src, struct sockaddr *dst, __u16 sport,
    __u16 dport, int direction, __u32 spi, __u8 *e_key, __u32 e_type, __u32 e_keylen,
    __u8 *a_key, __u32 a_type, __u32 a_keylen, __u32 lifetime, __u16 hitmagic,
    uint8_t nat_mode, uint8_t esp_prot_transform, unsigned char *esp_prot_anchor);
int hip_sadb_delete(__u32 type, struct sockaddr *src, struct sockaddr *dst,
    __u32 spi);
void hip_remove_expired_lsi_entries();
void hip_add_lsi(struct sockaddr *addr, struct sockaddr *lsi4, 
	struct sockaddr *lsi6);
int buffer_packet(struct sockaddr *lsi, __u8 *data, int len);
void unbuffer_packets(hip_lsi_entry *entry);
hip_lsi_entry *hip_lookup_lsi(struct sockaddr *lsi);
hip_sadb_entry *hip_sadb_lookup_spi(__u32 spi);
hip_sadb_entry *hip_sadb_lookup_addr(struct sockaddr *addr);
hip_sadb_entry *hip_sadb_get_next(hip_sadb_entry *placemark);

int hip_select_family_by_proto(__u32 lsi, __u8 proto, __u8 *header,
        struct timeval *now);
int hip_add_proto_sel_entry(__u32 lsi, __u8 proto, __u8 *header, int family,
        int dir, struct timeval *now);
void hip_remove_expired_sel_entries();
#endif

#endif /* USER_IPSEC_SADB_H_ */

