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

#ifndef HIP_SADB_H_
#define HIP_SADB_H_

#include <asm/types.h>		/* __u16, __u32, etc */
#include <sys/types.h>		/* for socket.h */
#include <sys/socket.h>		/* struct sockaddr */
#include <netinet/in.h>		/* struct sockaddr_in */
#include <openssl/des.h>	/* des_key_schedule */
#include <openssl/aes.h>	/* aes_key */
#include <openssl/blowfish.h>	/* bf_key */
//#include "hip_usermode.h"
//#include "utils.h"
#include <sys/time.h>		/* timeval */
#include "debug.h"
#if 0
#include "hashchain.h"
#endif

/**** HIPL <-> OpenHIP compatibility defs ****/

typedef struct _sockaddr_list
{
        struct _sockaddr_list *next;
        struct sockaddr_storage addr; /* 128 bytes, enough to store any size */
        int if_index;   /* link index */
        int lifetime;   /* address lifetime in seconds*/
        int status;     /* status from enum ADDRESS_STATES */
        int preferred;  /* set to TRUE if it's a new pending preferred addr */
        __u32 nonce;    /* random value for address verification */
        struct timeval creation_time;
} sockaddr_list;

/*
 * Macros from hip.h and elsewhere
 */
/* get pointer to IP from a sockaddr 
 *    useful for inet_ntop calls     */
#define SA2IP(x) hip_cast_sa_addr(x)
#define SALEN(x) hip_sockaddr_len(x)
#define SAIPLEN(x) hip_sa_addr_len(x)
#define SA(x) ((struct sockaddr*)x)

#define HIP_ESP_UDP_PORT       HIP_NAT_UDP_PORT
#define HIP_KEEPALIVE_TIMEOUT  HIP_NAT_KEEP_ALIVE_INTERVAL

/**** end of definitions from hip_types.h ****/


/*
 * definitions
 */
#define SADB_SIZE 512 
#define LSI4(a) (((struct sockaddr_in*)a)->sin_addr.s_addr)

/* HIP Security Association entry */
typedef struct _hip_sadb_entry 
{
	struct _hip_sadb_entry *next;
	__u32 spi;			/* primary index into SADB */
	int direction;			/* in/out */
	__u16 hit_magic;		/* for quick checksum calculation */
	sockaddr_list *src_addrs;	/* source addresses 		*/
	sockaddr_list *dst_addrs;	/* destination addresses 	*/
	/* inner addresses for BEET SAs (the above addresses
	 * are used as outer addresses) */
	sockaddr_list *inner_src_addrs;
	sockaddr_list *inner_dst_addrs;
#if 0
	/* hash chain parameters for this SA used in secure ESP extension */
	/* for outgoing SA */
	hash_chain_t *active_hchain;
	hash_chain_t *next_hchain;
	/* for incoming SA */
	int tolerance;
	unsigned char *active_anchor;
	unsigned char *next_anchor;
#endif
	__u32 mode; 	/* ESP mode :  0-default 1-transport 2-tunnel 3-beet */
	// TODO add encap_mode (= UDP / TCP)
	__u16 src_port;
	__u16 dst_port;			/* UDP dest. port for encaps. ESP */
	int encap_mode;			/* 0 - none, 1 - udp
	struct timeval usetime_ka;  /* last used timestamp, incl keep-alives */
	struct sockaddr_storage lsi;	/* LSI 				*/
	struct sockaddr_storage lsi6;	/* IPv6 LSI (peer HIT)		*/
	__u32 a_type;			/* crypto parameters 		*/
	__u32 e_type;
	__u32 a_keylen;
	__u32 e_keylen;
	__u8 *a_key;			/* raw crypto keys */
	__u8 *e_key;
	__u64 lifetime;			/* seconds until expiration */
	__u64 bytes;			/* bytes transmitted */
	struct timeval usetime;		/* last used timestamp */
	__u32 sequence;			/* sequence number counter */
	__u32 replay_win;		/* anti-replay window */
	__u32 replay_map;		/* anti-replay bitmap */
	char iv[8];
	des_key_schedule ks[3];		/* 3-DES keys */
	AES_KEY *aes_key;		/* AES key */
	BF_KEY *bf_key;			/* BLOWFISH key */
	pthread_mutex_t rw_lock;
} hip_sadb_entry;

/* HIP SADB desintation cache entry */
typedef struct _hip_sadb_dst_entry
{
	struct _hip_sadb_dst_entry *next;
	struct sockaddr_storage addr;
	hip_sadb_entry *sadb_entry;
	
} hip_sadb_dst_entry;

/* HIP LSI table entry */
#define LSI_PKT_BUFFER_SIZE 2000
#define LSI_ENTRY_LIFETIME 120
typedef struct _hip_lsi_entry
{
	struct _hip_lsi_entry *next;
	struct sockaddr_storage addr;
	struct sockaddr_storage lsi4;
	struct sockaddr_storage lsi6;
	__u8 packet_buffer[LSI_PKT_BUFFER_SIZE];
	int num_packets;
	int next_packet;
	int send_packets;
	struct timeval creation_time;
} hip_lsi_entry;
/* protocol selector entry */
#define PROTO_SEL_SIZE 512
#define PROTO_SEL_ENTRY_LIFETIME 900
#define PROTO_SEL_DEFAULT_FAMILY AF_INET
#define hip_proto_sel_hash(a) (a % PROTO_SEL_SIZE)
typedef struct _hip_proto_sel_entry
{
        struct _hip_proto_sel_entry *next;
        __u32 selector;         /* upper layer protocol-specific selector */
        int family;             /* guidance on which address family to use */
        struct timeval last_used;
} hip_proto_sel_entry;


/*
 * functions
 */
void hip_sadb_init();
int hip_sadb_add(__u32 type, __u32 mode, struct sockaddr *inner_src,
    struct sockaddr *inner_dst, struct sockaddr *src, struct sockaddr *dst, __u16 sport,
    __u16 dport, int direction,
    __u32 spi, __u8 *e_key, __u32 e_type, __u32 e_keylen, __u8 *a_key,
    __u32 a_type, __u32 a_keylen, __u32 lifetime, __u16 hitmagic, int encap_mode);
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

#endif /* HIP_SADB_H_ */

