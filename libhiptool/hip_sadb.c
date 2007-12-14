/*
 * Host Identity Protocol
 * Copyright (C) 2004-06 the Boeing Company
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
 *  hip_sadb.c
 *
 *  Authors: Jeff Ahrenholz <jeffrey.m.ahrenholz@boeing.com>
 * 
 * the HIP Security Association database
 *
 */

#include <stdio.h>	/* printf() */
#include <stdlib.h>	/* malloc() */
#include <string.h>	/* memset() */
#ifdef __WIN32__
#include <winsock2.h>
#include <ws2tcpip.h>
#include <io.h>
#include <time.h>
#include <win32/types.h>
#include <win32/ip.h>
#else
#include <unistd.h>	/* write() */
#include <sys/errno.h>  /* errno */
#include <sys/time.h>	/* gettimeofday() */
#include <netinet/ip.h> /* struct ip */
#include <netinet/ip6.h> /* struct ip6_hdr */
#include <netinet/tcp.h> /* struct tcphdr */
#include <netinet/udp.h> /* struct udphdr */
#ifdef __MACOSX__
#include <netinet/in_systm.h> /* struct ip */
#include <netinet/in.h> /* struct ip */
#endif
#endif
//#include <hip/hip_service.h>
//#include <hip/hip_types.h>
#include <hip/hip_sadb.h>
//#include <hip/hip_funcs.h> /* gettimeofday() for win32 */
#include "win32-pfkeyv2.h"


/*
 * Globals
 */
extern int readsp[2];
extern long g_read_usec;

/* the SADB hash table */
hip_sadb_entry hip_sadb[SADB_SIZE];
/* the SADB destination cache hash table */
hip_sadb_dst_entry hip_sadb_dst[SADB_SIZE];
/* the temporary LSI table and embargoed packet buffer */
hip_lsi_entry *lsi_temp=NULL;
/* the protocol selector table for determining address family */
hip_proto_sel_entry hip_proto_sel[PROTO_SEL_SIZE];

/* 
 * Local function delcarations
 */
hip_lsi_entry *create_lsi_entry(struct sockaddr *lsi);
void free_addr_list(sockaddr_list *a);
int hip_sadb_delete_entry(hip_sadb_entry *entry);
hip_lsi_entry *hip_lookup_lsi_by_addr(struct sockaddr *addr);
hip_lsi_entry *hip_lookup_lsi(struct sockaddr *lsi);
int hip_sadb_add_dst_entry(struct sockaddr *addr, hip_sadb_entry *entry);
int hip_sadb_delete_dst_entry(struct sockaddr *addr);

hip_proto_sel_entry *hip_lookup_sel_entry(__u32 lsi, __u8 proto, __u8 *header,
	int dir);
__u32 hip_proto_header_to_selector(__u32 lsi, __u8 proto, __u8 *header,int dir);
hip_proto_sel_entry *hip_remove_proto_sel_entry(hip_proto_sel_entry *prev,
	hip_proto_sel_entry *entry);
/*
 * sadb_hashfn()
 *
 * SADB entries are index by hash of their SPI.
 * Since SPIs are assumedly randomly allocated, distribution of this should
 * be uniform and the hash function given here is very simple (and fast!).
 */
int sadb_hashfn(__u32 spi) 
{
	return(spi % SADB_SIZE);
}

/*
 * sadb_dst_hashfn()
 *
 * A destination cache mainains IP to SADB entry mappings, for efficient
 * lookup for outgoing packets.
 */
int sadb_dst_hashfn(struct sockaddr *dst)
{
	__u32 addr;
	struct sockaddr_in6 *addr6;
	
	if (dst->sa_family == AF_INET) {
		addr = htonl(((struct sockaddr_in*)dst)->sin_addr.s_addr);
	} else {
		addr6 = (struct sockaddr_in6*)dst;
#ifdef __MACOSX__
		addr = addr6->sin6_addr.__u6_addr.__u6_addr32[0];
		addr ^= addr6->sin6_addr.__u6_addr.__u6_addr32[1];
		addr ^= addr6->sin6_addr.__u6_addr.__u6_addr32[2];
		addr ^= addr6->sin6_addr.__u6_addr.__u6_addr32[3];
#else
#ifdef __WIN32__
		addr =  (*((__u32 *)&addr6->sin6_addr.s6_addr[0]));
		addr ^= (*((__u32 *)&addr6->sin6_addr.s6_addr[2]));
		addr ^= (*((__u32 *)&addr6->sin6_addr.s6_addr[4]));
		addr ^= (*((__u32 *)&addr6->sin6_addr.s6_addr[6]));
#else 
#if !defined(__MACOSX__)
		addr = addr6->sin6_addr.s6_addr32[0];
		addr ^= addr6->sin6_addr.s6_addr32[1];
		addr ^= addr6->sin6_addr.s6_addr32[2];
		addr ^= addr6->sin6_addr.s6_addr32[3];
#endif
#endif
#endif
	}
	
	return(addr % SADB_SIZE);
}

/*
 * init_sadb()
 *
 * Initialize hash tables.
 */
void hip_sadb_init() {
	memset(hip_sadb, 0, sizeof(hip_sadb));
	memset(hip_sadb_dst, 0, sizeof(hip_sadb_dst));
	lsi_temp = NULL;
        memset(hip_proto_sel, 0, sizeof(hip_proto_sel));
}

/*
 * hip_sadb_add()
 *
 * Add an SADB entry to the SADB hash table.
 */ 
int hip_sadb_add(__u32 type, __u32 mode, struct sockaddr *inner_src,
    struct sockaddr *inner_dst, struct sockaddr *src, struct sockaddr *dst, 
    __u16 port,
    __u32 spi, __u8 *e_key, __u32 e_type, __u32 e_keylen, __u8 *a_key,
    __u32 a_type, __u32 a_keylen, __u32 lifetime, __u16 hitmagic)
{
	hip_sadb_entry *entry;
	hip_lsi_entry *lsi_entry;
	int err, key_len;
	__u8 key1[8], key2[8], key3[8]; /* for 3-DES */
	struct sockaddr *use_dst, *use_src;

	/* type is currently ignored */	
	if (!src || !dst || !a_key)
		return(-1);

	entry = &hip_sadb[sadb_hashfn(spi)];
	if (entry->spi && entry->spi==spi) { /* entry already exists */
		return(-1);
	} else if (entry->spi) { /* another entry matches hash value */
		/* advance to end of linked list */
		for ( ; entry->next; entry=entry->next);
		/* create a new entry at end of list */
		entry->next = malloc(sizeof(hip_sadb_entry));
		if (!entry->next)
			return(-1);
		entry = entry->next;
	}
	/* add the new entry */
	memset(entry, 0, sizeof(hip_sadb_entry));
	pthread_mutex_lock(&entry->rw_lock);
	entry->mode = mode;
	entry->next = NULL;
	entry->spi = spi;
	entry->hit_magic = hitmagic;
	entry->src_addrs = (sockaddr_list*)malloc(sizeof(sockaddr_list));
	entry->dst_addrs = (sockaddr_list*)malloc(sizeof(sockaddr_list));
	entry->inner_src_addrs = (sockaddr_list*)malloc(sizeof(sockaddr_list));
	entry->inner_dst_addrs = (sockaddr_list*)malloc(sizeof(sockaddr_list));
	entry->dst_port = port ;
	entry->usetime_ka.tv_sec = 0;
	entry->usetime_ka.tv_usec = 0;
	memset(&entry->lsi, 0, sizeof(struct sockaddr_storage));
	memset(&entry->lsi6, 0, sizeof(struct sockaddr_storage));
	entry->a_type = a_type;
	entry->e_type = e_type;
	entry->a_keylen = a_keylen;
	entry->e_keylen = e_keylen;
	entry->a_key = (__u8*)malloc(a_keylen);
	if (e_keylen > 0)
		entry->e_key = (__u8*)malloc(e_keylen);
	entry->lifetime = lifetime;
	entry->bytes = 0;
	entry->usetime.tv_sec = 0;
	entry->usetime.tv_usec = 0;
	entry->sequence = 1;
	entry->replay_win = 0;
	entry->replay_map = 0;
	pthread_mutex_unlock(&entry->rw_lock);

	/* malloc error */
	if (!entry->src_addrs || !entry->dst_addrs || !entry->a_key)
		goto hip_sadb_add_error;
	if ((e_keylen > 0) && !entry->e_key)
		goto hip_sadb_add_error;

	/* copy addresses */
	pthread_mutex_lock(&entry->rw_lock);
	memset(entry->src_addrs, 0, sizeof(sockaddr_list));
	memset(entry->dst_addrs, 0, sizeof(sockaddr_list));
	memcpy(&entry->src_addrs->addr, src, SALEN(src));
	memcpy(&entry->dst_addrs->addr, dst, SALEN(dst));
	memset(entry->inner_src_addrs, 0, sizeof(sockaddr_list));
	memset(entry->inner_dst_addrs, 0, sizeof(sockaddr_list));
	if (entry->mode == 3) { /* HIP_ESP_OVER_UDP */
		memcpy(&entry->inner_src_addrs->addr, inner_src,
			SALEN(inner_src));
		memcpy(&entry->inner_dst_addrs->addr, inner_dst,
			SALEN(inner_dst));
	}
	/* copy keys */
	memcpy(entry->a_key, a_key, a_keylen);
	if (e_keylen > 0)
		memcpy(entry->e_key, e_key, e_keylen);
	if ((e_keylen > 0) && (e_type == SADB_EALG_3DESCBC)) {
		key_len = e_keylen/3;
		memcpy(key1, &e_key[0], key_len);
		memcpy(key2, &e_key[8], key_len);
		memcpy(key3, &e_key[16], key_len);
		des_set_odd_parity((des_cblock*)key1);
		des_set_odd_parity((des_cblock*)key2);
		des_set_odd_parity((des_cblock*)key3);
		err = des_set_key_checked((des_cblock*)key1, entry->ks[0]);
		err += des_set_key_checked((des_cblock*)key2, entry->ks[1]);
		err += des_set_key_checked((des_cblock*)key3, entry->ks[2]);
		if (err)
			printf("hip_sadb_add: Warning - 3DES key problem.\n");
	} else if ((e_keylen > 0) && (e_type == SADB_X_EALG_AESCBC)) {
		/* AES key differs for encryption/decryption, so we set
		 * it upon first use in the SA */
		entry->aes_key = NULL;
	} else if ((e_keylen > 0) && (e_type == SADB_X_EALG_BLOWFISHCBC)) {
		entry->bf_key = malloc(sizeof(BF_KEY));
		BF_set_key(entry->bf_key, e_keylen, e_key);
	}
	pthread_mutex_unlock(&entry->rw_lock);

	/* add to destination cache for easy lookup via address
	 * for HIP over UDP, HITs are used and not outer dst addr 
	 * 	which can be the same for multiple hosts 
	 */
	use_src = (entry->mode == 3) ? inner_src : src;
	use_dst = (entry->mode == 3) ? inner_dst : dst;
	if (!use_src || !use_dst)
		goto hip_sadb_add_error;
	
	hip_sadb_add_dst_entry(use_dst, entry);


	/* fill in LSI, add entry to destination cache for outbound;
	 * the LSI is needed for both outbound and inbound SAs */
	if ((lsi_entry = hip_lookup_lsi_by_addr(use_dst))) {
		if (lsi_entry->lsi4.ss_family == AF_INET) { /* lsi exists? */
			memcpy(&entry->lsi,  &lsi_entry->lsi4, 
				SALEN(&lsi_entry->lsi4));
			hip_sadb_add_dst_entry(SA(&lsi_entry->lsi4), entry);
		}
		if (lsi_entry->lsi6.ss_family == AF_INET6) { /* lsi6 exists? */
			memcpy(&entry->lsi6, &lsi_entry->lsi6,
				SALEN(&lsi_entry->lsi6));
			hip_sadb_add_dst_entry(SA(&lsi_entry->lsi6), entry);
		}
	} else if ((lsi_entry = hip_lookup_lsi_by_addr(use_src))) {
		memcpy(&entry->lsi,  &lsi_entry->lsi4, SALEN(&lsi_entry->lsi4));
		memcpy(&entry->lsi6, &lsi_entry->lsi6, SALEN(&lsi_entry->lsi6));
		lsi_entry->send_packets = 1;
		/* Once an incoming SA is added (outgoing is always added 
		 * first in hipd) then we need to send unbuffered packets.
		 * While that could be done here, instead we decrease the
		 * timeout of hip_esp_input so it is done later. Otherwise,
		 * experience shows a race condition where the first
		 * unbuffered packet arrives at the peer before its SAs
		 * are built. */
		g_read_usec = 200000;
	}
	return(0);

hip_sadb_add_error:
	if (entry) /* take care of deallocation and unlinking from list */
		hip_sadb_delete_entry(entry);
		
	return(-1);
}

/*
 * hip_sadb_delete()
 *
 * Remove an SADB entry from the SADB hash table.
 * type, src, dst are provided for compatibility but are currently ignored.
 * First free dynamically-allocated elements, then unlink the entry and
 * either replace it or zero it.
 */ 
int hip_sadb_delete(__u32 type, struct sockaddr *src, struct sockaddr *dst,
    __u32 spi) {
	hip_sadb_entry *entry;
	hip_lsi_entry *lsi_entry;

	if (!(entry = hip_sadb_lookup_spi(spi)))
		return(-1);

	pthread_mutex_lock(&entry->rw_lock);
	if (entry->direction == 2) {
		hip_sadb_delete_dst_entry(SA(&entry->lsi));
		hip_sadb_delete_dst_entry(SA(&entry->lsi6));
	}
	if (entry->mode==3) { /*(HIP_ESP_OVER_UDP) */
		hip_sadb_delete_dst_entry(SA(&entry->inner_dst_addrs->addr));
	} else {
		hip_sadb_delete_dst_entry(dst);
	}

	/* set LSI entry to expire */
	if ((lsi_entry = hip_lookup_lsi(SA(&entry->lsi))))
		lsi_entry->creation_time.tv_sec = 0;

	pthread_mutex_unlock(&entry->rw_lock);
	hip_sadb_delete_entry(entry);

	return(0);
}

int hip_sadb_delete_entry(hip_sadb_entry *entry)
{
	hip_sadb_entry *prev, *tmp;
	int hash;
	if (!entry)
		return(-1);

	pthread_mutex_lock(&entry->rw_lock);
	/* free address lists */
	if (entry->src_addrs)
		free_addr_list(entry->src_addrs); 
	if (entry->dst_addrs)
		free_addr_list(entry->dst_addrs);
	if (entry->inner_src_addrs)
		free_addr_list(entry->inner_src_addrs);
	if (entry->inner_dst_addrs)
		free_addr_list(entry->inner_dst_addrs);
	
	/* securely erase keys */
	if (entry->a_key) {
		memset(entry->a_key, 0, entry->a_keylen);
		free(entry->a_key);
	}
	if (entry->e_key) {
		memset(entry->e_key, 0, entry->e_keylen);
		free(entry->e_key);
	}
	
	/* adjust linked-list pointers */
	hash = sadb_hashfn(entry->spi);
	prev = NULL;
	for (tmp = &hip_sadb[hash]; tmp; tmp=tmp->next) {
		if (tmp == entry)
			break;
		prev = tmp;
	}
	pthread_mutex_unlock(&entry->rw_lock);
	if (prev) { /* unlink the entry from the list */
		prev->next = entry->next;
		memset(entry, 0, sizeof(hip_sadb_entry));
		free(entry);
	} else if (entry->next) { /* replace entry in table w/next in list */
		tmp = entry->next;
		memcpy(&hip_sadb[hash], tmp, sizeof(hip_sadb_entry));
		memset(tmp, 0, sizeof(hip_sadb_entry));
		free(tmp);
	} else { /* no prev or next, just erase single entry */
		memset(entry, 0, sizeof(hip_sadb_entry));
	}
	return(0);
}

void free_addr_list(sockaddr_list *a)
{
	sockaddr_list *a_next;
	while(a) {
		a_next = a->next;
		free(a);
		a = a_next;
	}
}


/*
 * create_lsi_entry()
 *
 * Allocate a new LSI entry and link it in the global list lsi_temp.
 */
hip_lsi_entry *create_lsi_entry(struct sockaddr *lsi)
{
	hip_lsi_entry *entry, *tmp;

	entry = (hip_lsi_entry*) malloc(sizeof(hip_lsi_entry));
	if (!entry) {
		printf("create_lsi_entry: malloc error!\n");
		return NULL;
	}
	memset(entry, 0, sizeof(hip_lsi_entry));
	entry->next = NULL;
	if (lsi->sa_family == AF_INET) {
		memcpy(&entry->lsi4, lsi, SALEN(lsi));
		memset(&entry->lsi6, 0, sizeof(entry->lsi6));
	} else {
		memset(&entry->lsi4, 0, sizeof(entry->lsi4));
		memcpy(&entry->lsi6, lsi, SALEN(lsi));
	}
	entry->num_packets = 0;
	entry->next_packet = 0;
	entry->send_packets = 0;
	gettimeofday(&entry->creation_time, NULL);
	
	/* add it to the list */
	if (!lsi_temp) {
		lsi_temp = entry;
	} else {
		for (tmp = lsi_temp; tmp->next; tmp = tmp->next);
		tmp->next = entry;
	}
	return(entry);
}

/*
 * hip_remove_expired_lsi_entries()
 *
 * LSI entries are only used temporarily, so sadb_add() can know the LSI
 * mapping and for embargoed packets that are buffered. This checks the
 * creation time and removes those entries older than LSI_ENTRY_LIFETIME.
 */
void hip_remove_expired_lsi_entries()
{
	struct timeval now;
	hip_lsi_entry *entry, *tmp, *prev = NULL;

	gettimeofday(&now, NULL);
	entry = lsi_temp;
	while (entry) {
		if (entry->send_packets)
			unbuffer_packets(entry);
		if ((now.tv_sec - entry->creation_time.tv_sec) > 
			LSI_ENTRY_LIFETIME) {
			/* unlink the entry */
			if (prev)
				prev->next = entry->next;
			else 
				lsi_temp = entry->next;
			/* delete the entry */
			tmp = entry;
			entry = entry->next;
			free(tmp);
			continue;
		}
		prev = entry;
		entry = entry->next;
	}
}

/*
 * hip_add_lsi()
 *
 * Adds an <IP,LSI> mapping to the temporary LSI list.
 * This list is used only on SA creation, to provide the <IP,LSI> mapping
 * before an SADB entry exists.
 */
void hip_add_lsi(struct sockaddr *addr, struct sockaddr *lsi4, 
		struct sockaddr *lsi6)
{
	hip_lsi_entry *entry;

	if ( !(entry = hip_lookup_lsi(lsi4)) &&
	     !(entry = hip_lookup_lsi(lsi6)) ) {
		entry = create_lsi_entry(lsi4);
	} else { /* refresh timer for existing LSI entry */
		gettimeofday(&entry->creation_time, NULL);
	}
	if (lsi6)
		memcpy(&entry->lsi6, lsi6, SALEN(lsi6));
	memcpy(&entry->addr, addr, SALEN(addr));
}

/*
 * buffer_packet()
 *
 * Outgoing packets that trigger the HIP exchange are embargoed into
 * a buffer until the SAs are created.
 */
int buffer_packet(struct sockaddr *lsi, __u8 *data, int len)
{
	int is_new_entry = FALSE;
	hip_lsi_entry *entry;

	/* find entry, or create a new one */
	if (!(entry = hip_lookup_lsi(lsi))) {
		entry = create_lsi_entry(lsi);
		is_new_entry = TRUE;
	}

	/* add packet to queue if there is room */
	if ((len + entry->next_packet) > LSI_PKT_BUFFER_SIZE)
		return FALSE;
	/* TODO: log packet buffer overflow, drop newer/older packets? */
	memcpy(&entry->packet_buffer[entry->next_packet], data, len);
	entry->num_packets++;
	entry->next_packet += len;
	return is_new_entry;
}

/*
 * unbuffer_packets()
 *
 * Send embargoed packets that have been buffered, using the 
 * TAP-Win32 interface.
 */
void unbuffer_packets(hip_lsi_entry *entry)
{
	struct ip *iph;
	struct ip6_hdr *ip6h;
	__u8 *data;
	int len, next_hdr = 0;
	char ipstr[5];

	g_read_usec = 1000000;
	entry->send_packets = 0;
	if (entry->num_packets > 0)
		printf("Retransmitting %d user data packets.\n", 
			entry->num_packets);
	while (entry->num_packets > 0) {
		entry->num_packets--;
		data = &entry->packet_buffer[next_hdr];
		/* read first byte to determine if IPv4/IPv6, and get length */
		iph = (struct ip*) &data[14];
		ip6h = (struct ip6_hdr*) &data[14];
		if (iph->ip_v == 4) {/* IPv4 packet */
			len = ntohs(iph->ip_len) + 14;
			sprintf(ipstr, "IPv4");
		} else if ((ip6h->ip6_vfc & 0xF0) == 0x60) {/* IPv6 packet */
			len = ntohs(ip6h->ip6_plen) + 14 + 
				sizeof(struct ip6_hdr);
			sprintf(ipstr, "IPv6");
		} else { /* unknown header! */
			printf("Warning: unknown IP header in buffered "
				"packet, freeing.\n");
			/* cannot determine length, so expire this entry */
			entry->send_packets = 0;
			entry->creation_time.tv_sec = 0;
			break;
		}
		if ((next_hdr + len) > LSI_PKT_BUFFER_SIZE) {
			printf(	"Warning: buffered packet with length=%d "
				"is too large for buffer, dropping.\n", len);
			entry->send_packets = 0;
			entry->creation_time.tv_sec = 0;
			break;
		}
		next_hdr += len;
#ifdef __WIN32__
		if (send(readsp[0], data, len, 0) < 0) {
#else
		if (write(readsp[0], data, len) < 0) {
#endif
			printf("unbuffer_packets: write error: %s",
				strerror(errno));
			break;
		}
	}

	entry->num_packets = 0;
	entry->next_packet = 0;
}

/*
 * hip_lookup_lsi_by_addr()
 *
 * LSI entry lookup based on corresponding destination (peer) address.
 */
hip_lsi_entry *hip_lookup_lsi_by_addr(struct sockaddr *addr)
{
	hip_lsi_entry *entry;
	for (entry = lsi_temp; entry; entry = entry->next) {
		if (memcmp(SA2IP(&entry->addr),
			   SA2IP(addr), SAIPLEN(addr))==0) {
			return(entry);
		}
	}
	return(NULL);
}

/*
 * hip_lookup_lsi()
 *
 * LSI entry lookup based on the LSI.
 */
hip_lsi_entry *hip_lookup_lsi(struct sockaddr *lsi)
{
	hip_lsi_entry *entry;
	struct sockaddr_storage *entry_lsi;

	for (entry = lsi_temp; entry; entry = entry->next) {
		entry_lsi = (lsi->sa_family == AF_INET) ? &entry->lsi4 : 
							  &entry->lsi6;
		if (memcmp(SA2IP(entry_lsi), SA2IP(lsi), SAIPLEN(lsi))==0)
			return(entry);
	}
	return(NULL);
}

/*
 * hip_sadb_lookup_spi()
 *
 * Lookup an SADB entry based on SPI, for incoming ESP packets.
 */ 
hip_sadb_entry *hip_sadb_lookup_spi(__u32 spi) {
	hip_sadb_entry *entry;
	for (entry = &hip_sadb[sadb_hashfn(spi)]; entry; entry = entry->next) {
		if (entry->spi == spi)
			return entry;
	}
	return(NULL);
}

/*
 * hip_sadb_add_dst_entry()
 *
 * Add an address to the destination cache, pointing to corresponding
 * SADB entry. This allows quick lookups based on address (LSI), since
 * the SADB hashes on SPI.
 */
int hip_sadb_add_dst_entry(struct sockaddr *addr, hip_sadb_entry *entry)
{
	hip_sadb_dst_entry *dst_entry, *last;
	
	if (!addr || !entry)
		return(-1);

	/* check for existing entry (address is same) and
	 * just update the entry ptr */
	for (dst_entry = &hip_sadb_dst[sadb_dst_hashfn(addr)];
		dst_entry; dst_entry = dst_entry->next) {
		last = dst_entry;
		if (dst_entry->sadb_entry &&
		   !memcmp(SA2IP(&dst_entry->addr), SA2IP(addr), SALEN(addr))) {
			dst_entry->sadb_entry = entry;
			return(0);
		}
	}

	/* when hash slot is occupied, add to the end of the list */
	if (last->sadb_entry) {
		dst_entry = (hip_sadb_dst_entry*) 
			    malloc(sizeof(hip_sadb_dst_entry));
		last->next = dst_entry;
	} else {
		dst_entry = last;
	}

	memset(dst_entry, 0, sizeof(hip_sadb_dst_entry));
	dst_entry->next = NULL;
	memcpy(&dst_entry->addr, addr, SALEN(addr));
	dst_entry->sadb_entry = entry;
	return(0);
}

/*
 * hip_sadb_delete_dst_entry()
 *
 * Delete an SADB entry based on destination address (LSI).
 */ 
int hip_sadb_delete_dst_entry(struct sockaddr *addr) {
	hip_sadb_dst_entry *entry, *prev, *next;
	
	prev = NULL;
	for (entry = &hip_sadb_dst[sadb_dst_hashfn(addr)]; 
	     entry; entry = entry->next) {
		if (memcmp(SA2IP(addr), SA2IP(&entry->addr), SAIPLEN(addr))) {
			prev = entry;
			continue;
		}
		/* entry was found */
		if (prev) {
			prev->next = entry->next;
			memset(entry, 0, sizeof(hip_sadb_dst_entry));
			free(entry);
		} else if (entry->next) { /* no prev, next replaces it */
			next = entry->next;
			memcpy(entry, next, sizeof(hip_sadb_dst_entry));
			memset(next, 0, sizeof(hip_sadb_dst_entry));
			free(next);
		} else { /* no prev, next - just erase it */
			memset(entry, 0, sizeof(hip_sadb_dst_entry));
		}
		return(0);
	}
	return(-1);
}


/*
 * hip_sadb_lookup_addr()
 *
 * Lookup an SADB entry based on destination address (LSI), for outgoing
 * ESP packets. Uses the destination cache.
 */ 
hip_sadb_entry *hip_sadb_lookup_addr(struct sockaddr *addr) {
	hip_sadb_dst_entry *entry;
	for (entry = &hip_sadb_dst[sadb_dst_hashfn(addr)]; 
	     entry; entry = entry->next) {
		if ((addr->sa_family == entry->addr.ss_family) &&
		    (memcmp(SA2IP(addr), SA2IP(&entry->addr), 
			    SAIPLEN(addr))==0)) {
			return(entry->sadb_entry);
		}
	}
	return(NULL);
}

/*
 * hip_sadb_get_next()
 *
 * Return the next valid outgoing SADB entry from the table, starting from
 * placemark if supplied.
 */
hip_sadb_entry *hip_sadb_get_next(hip_sadb_entry *placemark)
{
	int i;
	hip_sadb_entry *entry, *prev_entry=NULL;

	/* step through entire hash table */
	for (i=0; i < SADB_SIZE; i++) {
		/* no entry in this slot */
		if (!hip_sadb[i].spi) 
			continue;
		/* no placemark, return first valid outgoing entry */
		if (!placemark && hip_sadb[i].direction==2)
			return(&hip_sadb[i]);
		/* search for placemark, set prev_entry to flag that the
		 * next should be returned 
		 */
		for (entry = &hip_sadb[i]; entry; entry = entry->next) {
			/* prev_entry is placemark, return next outgoing entry*/
			if (prev_entry && entry->direction==2) 
				return(entry);
			/* look for placemark */
			else if (entry==placemark)
				prev_entry = entry;
		}
	}
	/* no more entries */
	return(NULL);
}

/*
 * hip_select_family_by_proto()
 *
 * Given an upper-layer protocol number and header, return the
 * address family that should be used. This determines whether
 * an IPv4 or IPv6 header is built upon decrypting a packet.
 */
int hip_select_family_by_proto(__u32 lsi, __u8 proto, __u8 *header,
	struct timeval *now)
{
	hip_proto_sel_entry *sel;

	/* no entry needed for these protocols */
	if (proto == IPPROTO_ICMP)
		return(AF_INET);
	if (proto == IPPROTO_ICMPV6)
		return(AF_INET6);

	/* perform lookup using incoming dir */
	sel = hip_lookup_sel_entry(lsi, proto, header, 1);

	/* protocol selector entry exists, update the time */
	if (sel) {
		sel->last_used.tv_sec = now->tv_sec;
		return (sel->family);
	/* selector entry does not exist, create a new 
	 * entry with the default address family */
	} else {
		hip_add_proto_sel_entry(lsi, proto, header, 
					PROTO_SEL_DEFAULT_FAMILY, 
					1, now);
		return (PROTO_SEL_DEFAULT_FAMILY);
	}
}

/*
 * hip_add_proto_sel_entry()
 *
 * Add a protocol selector entry for the given protocol
 * number, header, and address family. The address family
 * of outgoing packets can then be matched for incoming
 * packets.
 *
 * 	dir = 0 for outgoing, 1 for incoming
 */
int hip_add_proto_sel_entry(__u32 lsi, __u8 proto, __u8 *header, int family,
	int dir, struct timeval *now)
{
	hip_proto_sel_entry *entry;
	__u32 selector = hip_proto_header_to_selector(lsi, proto, header, dir);
	
	entry = &hip_proto_sel[hip_proto_sel_hash(selector)];
	if (entry->family) { /* another entry matches hash value */
		/* advance to end of linked list */
		for ( ; entry->next; entry = entry->next);
		/* create a new entry at end of list */
		entry->next = malloc(sizeof(hip_proto_sel_entry));
		if (!entry->next)
			return(-1);
		entry = entry->next;
	}

	/* add the new entry */
	memset(entry, 0, sizeof(hip_proto_sel_entry));
	entry->next = NULL;
	entry->selector = selector;
	entry->family = family;
	entry->last_used.tv_sec = now->tv_sec;
	return(0);
}

hip_proto_sel_entry *hip_lookup_sel_entry(__u32 lsi, __u8 proto, __u8 *header,
	int dir)
{
	hip_proto_sel_entry *entry;
	__u32 selector = hip_proto_header_to_selector(lsi, proto, header, dir);
	
	entry = &hip_proto_sel[hip_proto_sel_hash(selector)];
	for ( ; entry; entry=entry->next) {
		if (selector == entry->selector)
			return(entry);
	}
	return(NULL);
}

__u32 hip_proto_header_to_selector(__u32 lsi, __u8 proto, __u8 *header, int dir)
{
	struct tcphdr *tcph;
	struct udphdr *udph;
	__u32 selector;
	
	switch (proto) {
	case IPPROTO_TCP:
		tcph = (struct tcphdr *)header;
#ifdef __MACOSX__
		selector = (dir == 1) ? (tcph->th_sport<< 16)+ tcph->th_dport :
					(tcph->th_dport << 16)+ tcph->th_sport;
#else
		selector = (dir == 1) ? (tcph->source<< 16)+ tcph->dest :
					(tcph->dest << 16)+ tcph->source;
#endif
		break;
	case IPPROTO_UDP:
		udph = (struct udphdr *)header;
#ifdef __MACOSX__
		selector = (dir == 1) ? (udph->uh_sport << 16)+ udph->uh_dport :
					(udph->uh_dport << 16)+ udph->uh_sport;
#else
		selector = (dir == 1) ? (udph->source << 16)+ udph->dest :
					(udph->dest << 16)+ udph->source;
#endif
		break;
	case IPPROTO_ESP:
		/* could use SPI for selector, but ESP has different
		 * incoming and outgoing SPIs */
		selector = 1;
		break;
	/* TODO: write other selectors here as needed */
	default:
		selector = 0;
		break;
	}
	selector += lsi;
	return(selector);
}

/*
 * hip_remove_expired_sel_entries()
 */
void hip_remove_expired_sel_entries()
{
	static unsigned int last = 0;
	struct timeval now;
	int i;
	hip_proto_sel_entry *entry, *prev;


	/* rate limit - every 30 seconds */
	gettimeofday(&now, NULL);
	if ((last > 0) && ((now.tv_sec - last) < 30))
		return;
	else
		last = now.tv_sec;
		
		
	for (i=0; i<PROTO_SEL_SIZE; i++) {
		prev = NULL;
		entry = &hip_proto_sel[i]; /* traverse list in each bucket */
		while (entry) {
			if (!entry->family) /* empty bucket, continue to next */
				break;
			/* check for expiration */
			if ((now.tv_sec - entry->last_used.tv_sec) > 
				PROTO_SEL_ENTRY_LIFETIME) {
				entry = hip_remove_proto_sel_entry(prev, entry);
			} else {
				prev = entry;
				entry = entry->next;
			}	
		}
	}
}

hip_proto_sel_entry *hip_remove_proto_sel_entry(hip_proto_sel_entry *prev,
	hip_proto_sel_entry *entry)
{
	hip_proto_sel_entry *next;
	
	if (prev) { /* unlink the entry from the list */
		prev->next = entry->next;
		memset(entry, 0, sizeof(hip_proto_sel_entry));
		free(entry);
		return(prev->next);
	} else if (entry->next) { /* replace entry in table w/next in list */
		next = entry->next;
		memcpy(entry, next, sizeof(hip_proto_sel_entry));
		memset(next, 0, sizeof(hip_proto_sel_entry));
		free(next); /* remove duplicate */
		return(entry);
	} else { /* no prev or next, just erase single entry */
		memset(entry, 0, sizeof(hip_proto_sel_entry));
		return(NULL);
	}
}


