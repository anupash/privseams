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
 *  hip_esp.c
 *
 *  Authors: Jeff Ahrenholz <jeffrey.m.ahrenholz@boeing.com>
 *           Tao Wan        <simonwantao@yahoo.com>  
 * 
 * User-mode HIP ESP implementation.
 *
 * tunreader portions Copyright (C) 2004 UC Berkeley
 */



#if 0
#include <stdio.h>		/* HIP_DEBUG() */
#include <unistd.h>		/* write() */
#include <pthread.h>		/* pthread_exit() */
#include <sys/time.h>		/* gettimeofday() */
#include <sys/errno.h>		/* errno, etc */
#include <netinet/ip.h>		/* struct ip */
#include <netinet/ip6.h>	/* struct ip6_hdr */
#include <netinet/icmp6.h>	/* struct icmp6_hdr */
#include <netinet/tcp.h>	/* struct tcphdr */
#include <netinet/udp.h>	/* struct udphdr */
#include <arpa/inet.h>		
#include <linux/types.h>	/* for pfkeyv2.h types */
#include <netinet/udp.h>	/* struct udphdr */
#include <string.h>		/* memset, etc */
#include <openssl/hmac.h>	/* HMAC algorithms */
#include <openssl/sha.h>	/* SHA1 algorithms */
#include <openssl/des.h>	/* 3DES algorithms */
#include <openssl/rand.h>	/* RAND_bytes() */

//#include <hip/hip_types.h>
//#include <hip/hip_funcs.h>
#include "hip_usermode.h"
#include "hip_sadb.h"



#include <sys/time.h>
#include <sys/wait.h>		/* waitpid()	*/
#include <pthread.h>		/* pthreads support*/
#endif

#if 0
#if defined(__BIG_ENDIAN__) || defined( __MACOSX__)
#include <mac/checksum_mac.h>
#else
#include "win32-checksum.h"
#endif
#endif

#include "hip_esp.h"
#include "utils.h"

int hip_esp_encrypt(unsigned char *in, uint8_t in_type, int in_len,
		unsigned char *out, int *out_len, hip_sadb_entry *entry);
int hip_esp_decrypt(unsigned char *in, int in_len, unsigned char *out, uint8_t *out_type,
		int *out_len, hip_sadb_entry *entry);
void add_ipv4_header(struct ip *ip_hdr, struct in6_addr *src_addr, struct in6_addr *dst_addr,
		int packet_len, uint8_t next_hdr);
void add_ipv6_header(struct ip6_hdr *ip6_hdr, struct in6_addr *src_addr, struct in6_addr *dst_addr,
		int packet_len, uint8_t next_hdr);
void add_udp_header(struct udphdr *udp_hdr, int packet_len, hip_sadb_entry *entry,
		struct in6_addr *src_addr, struct in6_addr *dst_addr);
uint16_t checksum_ip(struct ip *ip_hdr, unsigned int ip_hl);
u_int16_t checksum_udp(struct udphdr *udp_hdr, struct in6_addr *src_addr,
		struct in6_addr *dst_addr);

/*
 * hip_esp_output()
 *
 * The ESP output thread. Reads ethernet packets from the socketpair
 * connected to the TAP-Win32 interface, and performs necessary ESP
 * encryption. Also handles ARP requests with artificial replies.
 */

/* - encrypt payload
 * - set up other headers */
int hip_esp_output(hip_fw_context_t *ctx, hip_sadb_entry *entry,
		int udp_encap, struct timeval *now, struct in6_addr *preferred_local_addr,
		struct in6_addr *preferred_peer_addr, unsigned char *esp_packet, int *esp_packet_len)
{
	struct ip *out_ip_hdr = NULL;
	struct ip6_hdr *out_ip6_hdr = NULL; 
	struct udphdr *out_udp_hdr = NULL;
	struct hip_esp *out_esp_hdr = NULL;
	unsigned char *in_transport_hdr = NULL;
	uint8_t in_transport_type = 0;
	int next_hdr_offset = 0;
	int elen = 0;
	int encryption_len = 0;
	int err = 0;
	
	// distinguish IPv4 and IPv6 output
	if (IN6_IS_ADDR_V4MAPPED(preferred_peer_addr))
	{
		// calculate offset at which esp data should be located
		// NOTE: this does _not_ include IPv4 options for the original packet
		out_ip_hdr = (struct ip *)esp_packet;
		next_hdr_offset = sizeof(struct ip);
		
		// check whether to use UDP encapsulation or not
		if (udp_encap)
		{
			out_udp_hdr = (struct udphdr *) (esp_packet + next_hdr_offset);
			next_hdr_offset += sizeof(struct udphdr);
		}
		
		_HIP_DEBUG("spi no.: %u\n", entry->spi);
		_HIP_DEBUG("seq no.: %u\n", entry->sequence);
		
		// set up esp header
		out_esp_hdr = (struct hip_esp *) (esp_packet + next_hdr_offset);
		out_esp_hdr->esp_spi = htonl(entry->spi);
		out_esp_hdr->esp_seq = htonl(entry->sequence++);
		
		_HIP_HEXDUMP("new packet (with esp header): ", esp_packet,
					next_hdr_offset + sizeof(struct hip_esp));
		
		// packet to be re-inserted into network stack has at least
		// length of defined headers
		*esp_packet_len += next_hdr_offset + sizeof(struct hip_esp);

		
		/* Set up information needed for ESP encryption */
		
		/* get pointer to data, right behind IPv6 header
		 * 
		 * NOTE: we are only dealing with HIT-based (-> IPv6) data traffic */
		in_transport_hdr = ((unsigned char *) ctx->ipq_packet->payload)
								+ sizeof(struct ip6_hdr);
		
		in_transport_type = ((struct ip6_hdr *) ctx->ipq_packet->payload)->ip6_ctlun.ip6_un1.ip6_un1_nxt;
		
		/* length of data to be encrypted is length of the original packet
		 * starting at the transport layer header */
		elen = ctx->ipq_packet->data_len - sizeof(struct ip6_hdr);		
		
		/* encrypt data now */
		pthread_mutex_lock(&entry->rw_lock);
			
		HIP_DEBUG("encrypting data...\n");
		
		/* encrypts the payload and puts the encrypted data right
		 * behind the ESP header
		 * 
		 * NOTE: we are implicitely passing the previously set up ESP header */
		HIP_IFEL(hip_esp_encrypt(in_transport_hdr, in_transport_type, elen,
				      esp_packet + next_hdr_offset, &encryption_len, entry), -1,
				      "failed to encrypt data");
		
		pthread_mutex_unlock(&entry->rw_lock);
		
		_HIP_HEXDUMP("new packet (with esp): ", esp_packet,
					next_hdr_offset + sizeof(struct hip_esp) + encryption_len);
		
		// this also includes the ESP tail
		*esp_packet_len += encryption_len;
		
#if 0	
		/* Record the address family of this packet, so incoming
		 * replies of the same protocol/ports can be matched to
		 * the same family.
		 */
		// TODO find out what that does
		if (hip_add_proto_sel_entry(LSI4(&entry->lsi), 
					(__u8)(iph ? iph->ip_p : ip6h->ip6_nxt), 
					iph ? (__u8*)(iph+1) : (__u8*)(ip6h+1),
					family, 0, now	) < 0)
			printf("hip_esp_encrypt(): error adding sel entry.\n");
#endif

		// finally we have all the information to set up the missing headers
		if (udp_encap) {
			// the length field covers everything starting with UDP header
			add_udp_header(out_udp_hdr, *esp_packet_len - sizeof(struct ip), entry,
					preferred_local_addr, preferred_peer_addr);
			_HIP_HEXDUMP("new packet (with udp header): ", esp_packet, *esp_packet_len);
			
			// now we can also calculate the csum of the new packet
			add_ipv4_header(out_ip_hdr, preferred_local_addr, preferred_peer_addr,
								*esp_packet_len, IPPROTO_UDP);
			_HIP_HEXDUMP("new packet (with ipv4 header): ", esp_packet, *esp_packet_len);
		} else
		{
			add_ipv4_header(out_ip_hdr, preferred_local_addr, preferred_peer_addr,
								*esp_packet_len, IPPROTO_ESP);
			_HIP_HEXDUMP("new packet (with ipv4 header): ", esp_packet, *esp_packet_len);
		}
	} else
	{
		/* this is IPv6 */
		
		/* calculate offset at which esp data should be located
		 * 
		 * NOTE: this does _not_ include IPv6 extension headers for the original packet */
		out_ip6_hdr = (struct ip6_hdr *)esp_packet;
		next_hdr_offset = sizeof(struct ip6_hdr);
		
		/* 
		 * NOTE: we don't support UDP encapsulation for IPv6 right now.
		 * 		 this would be the place to add it
		 */

		// set up esp header
		out_esp_hdr = (struct hip_esp *) (esp_packet + next_hdr_offset);
		out_esp_hdr->esp_spi = htonl(entry->spi);
		out_esp_hdr->esp_seq = htonl(entry->sequence++);
		
		_HIP_HEXDUMP("new packet (with esp header): ", esp_packet,
				next_hdr_offset + sizeof(struct hip_esp));
		
		// packet to be re-inserted into network stack has at least
		// length of defined headers
		*esp_packet_len += next_hdr_offset + sizeof(struct hip_esp);
		
		
		/* Set up information needed for ESP encryption */
				
		/* get pointer to data, right behind IPv6 header
		 * 
		 * NOTE: we are only dealing with HIT-based (-> IPv6) data traffic */
		in_transport_hdr = ((unsigned char *) ctx->ipq_packet->payload)
								+ sizeof(struct ip6_hdr);
		
		in_transport_type = ((struct ip6_hdr *) ctx->ipq_packet->payload)->ip6_ctlun.ip6_un1.ip6_un1_nxt;
		
		/* length of data to be encrypted is length of the original packet
		 * starting at the transport layer header */
		elen = ctx->ipq_packet->data_len - sizeof(struct ip6_hdr);	
			
		pthread_mutex_lock(&entry->rw_lock);
			
		HIP_DEBUG("encrypting data...\n");
		
		/* encrypts the payload and puts the encrypted data right
		 * behind the ESP header
		 * 
		 * NOTE: we are implicitely passing the previously set up ESP header */
		HIP_IFEL(hip_esp_encrypt(in_transport_hdr, in_transport_type, elen,
				      esp_packet + next_hdr_offset, &encryption_len, entry), -1,
				      "failed to encrypt data");
		
		pthread_mutex_unlock(&entry->rw_lock);
		
		_HIP_HEXDUMP("new packet (with esp): ", esp_packet,
				next_hdr_offset + sizeof(struct hip_esp) + encryption_len);
		
		// this also includes the ESP tail
		*esp_packet_len += encryption_len;
		
		// now we know the packet length
		add_ipv6_header(out_ip6_hdr, preferred_local_addr, preferred_peer_addr,
							*esp_packet_len, IPPROTO_UDP);
		HIP_HEXDUMP("new packet (with ipv6 header): ", esp_packet, *esp_packet_len);
	}
	
  out_err:
  	return err;
}

/*
 * hip_esp_input()
 *
 * The ESP input thread. Reads ESP packets from the network and decrypts
 * them, adding HIT or LSI headers and sending them out the TAP-Win32 interface.
 * Also, expires temporary LSI entries and retransmits buffered packets.
 */
int hip_esp_input(hip_fw_context_t *ctx, hip_sadb_entry *entry,
		struct in6_addr *src_hit, struct in6_addr *dst_hit,
		unsigned char *decrypted_packet, int *decrypted_packet_len)
{
	int next_hdr_offset = 0;
	int esp_len = 0;
	int decrypted_data_len = 0;
	uint8_t next_hdr = 0;
	int err = 0;
	
	// the decrypted data will be placed behind the HIT-based IPv6 header
	next_hdr_offset = sizeof(struct ip6_hdr);
	
	decrypted_packet_len += next_hdr_offset;

	// calculate esp data length
	if (ctx->ip_version == 4)
	{
		esp_len = ctx->ipq_packet->data_len - sizeof(struct ip);
		// check if ESP packet is UDP encapsulated
		if (ctx->udp_encap_hdr)
			esp_len -= sizeof(struct udphdr);
	}
	else
		esp_len = ctx->ipq_packet->data_len - sizeof(struct ip6_hdr);
	
	// decrypt now
	pthread_mutex_lock(&entry->rw_lock);
	
	HIP_DEBUG("decrypting ESP packet...");
	
	HIP_IFEL(hip_esp_decrypt((unsigned char *)ctx->transport_hdr.esp, esp_len,
			decrypted_packet + next_hdr_offset, &next_hdr,
			&decrypted_data_len, entry), -1, "ESP decryption is not successful\n");
	
	pthread_mutex_unlock(&entry->rw_lock);
	
	decrypted_packet_len += decrypted_data_len;
	
	// now we know the next_hdr and can set up the IPv6 header
	add_ipv6_header((struct ip6_hdr *)decrypted_packet, src_hit, dst_hit,
			*decrypted_packet_len, next_hdr);
	
  out_err:
  	return err;
}

/*
 * hip_esp_encrypt()
 * 
 * in:	in		pointer to data to encrypt
 * 		in_len	length of input-data
 * 		out		pointer to where to store encrypted data
 * 		out_len	length of encrypted data
 * 		entry 	the SADB entry
 *
 * out:	Encrypted data out, out_len.
 * 		Returns 0 on success, -1 otherwise.
 * 
 * Perform actual ESP encryption and authentication of packets.
 */
int hip_esp_encrypt(unsigned char *in, uint8_t in_type, int in_len,
		unsigned char *out, int *out_len, hip_sadb_entry *entry)
{
	/* elen is length of data to encrypt */
	int elen = in_len;
	/* length of auth output */
	int alen = 0;
	/* initialization vector */
	int iv_len = 0;
	unsigned char cbc_iv[16];
	/* ESP tail information */
	int pad_len = 0;
	struct hip_esp_tail *esp_tail = NULL;
	int esp_data_offset = 0;
	int i = 0;
	int err = 0;
	
	//unsigned int hmac_md_len;
	//unsigned char hmac_md[EVP_MAX_MD_SIZE];
	
	esp_data_offset = sizeof(struct hip_esp);

	/* 
	 * Encryption 
	 */

	/* Check keys and set initialisation vector length */
	switch (entry->e_type)
	{
		case SADB_EALG_3DESCBC:
			iv_len = 8;
			if (!entry->e_key || entry->e_keylen==0) {
				HIP_ERROR("3-DES key missing.\n");
				
				err = -1;
				goto out_err;
			}
			break;
		case SADB_X_EALG_BLOWFISHCBC:
			iv_len = 8;
			if (!entry->bf_key) {
				HIP_ERROR("BLOWFISH key missing.\n");
				
				err = -1;
				goto out_err;
			}
			break;
		case SADB_EALG_NULL:
			iv_len = 0;
			break;
		case SADB_X_EALG_AESCBC:
			iv_len = 16;
			if (!entry->aes_key && entry->e_key) {
				entry->aes_key = malloc(sizeof(AES_KEY));
				if (AES_set_encrypt_key(entry->e_key, 8*entry->e_keylen,
							entry->aes_key)) {
					HIP_ERROR("AES key problem!\n");
					
					err = -1;
					goto out_err;
				}
			} else if (!entry->aes_key) {
				HIP_ERROR("AES key missing.\n");
				 
				err = -1;
				goto out_err;
			}
			break;
		case SADB_EALG_NONE:
		case SADB_EALG_DESCBC:
		case SADB_X_EALG_CASTCBC:
		case SADB_X_EALG_SERPENTCBC:
		case SADB_X_EALG_TWOFISHCBC:
		default:
			HIP_DEBUG("Unsupported encryption transform (%d).\n",
				entry->e_type);
			
			err = -1;
			goto out_err;
		}
	
	/* Add initialization vector (random value) in the beginning of
	 * out and calculate padding
	 * 
	 * NOTE: this will _NOT_ be encrypted */
	if (iv_len > 0) {
		RAND_bytes(cbc_iv, iv_len);
		memcpy(&out[esp_data_offset], cbc_iv, iv_len);
		pad_len = iv_len - ((elen + 2) % iv_len);
	} else {
		/* Padding with NULL not based on IV length */
		pad_len = 4 - ((elen + 2) % 4);
	}
	
	// FIXME this can cause buffer overflows
	/* add padding to the end of input data and set esp_tail */
	// padding itself
	for (i = 0; i < pad_len; i++)
	{
		in[elen + i] = i + 1;
	}
	// add meta-info
	esp_tail = (struct hip_esp_tail *) &in[elen + pad_len];
	esp_tail->esp_padlen = pad_len;
	esp_tail->esp_next = in_type;
	/* esp_tail is encrypted too */
	elen += pad_len + sizeof(struct hip_esp_tail);
	
	/* Apply the encryption cipher directly into out buffer
	 * to avoid extra copying */
	switch (entry->e_type)
	{
		case SADB_EALG_3DESCBC:
			des_ede3_cbc_encrypt(in, &out[esp_data_offset + iv_len], elen,
					     entry->ks[0], entry->ks[1], entry->ks[2],
					     (des_cblock *) cbc_iv, DES_ENCRYPT);
			
			break;
		case SADB_X_EALG_BLOWFISHCBC:
			BF_cbc_encrypt(in, &out[esp_data_offset + iv_len], elen,
					entry->bf_key, cbc_iv, BF_ENCRYPT);
			
			break;
		case SADB_EALG_NULL:
			// TODO check if we should really overwrite IV
			memcpy(out, in, elen);
			
			break;
		case SADB_X_EALG_AESCBC:
			AES_cbc_encrypt(in, &out[esp_data_offset + iv_len], elen, 
					entry->aes_key, cbc_iv, AES_ENCRYPT);
			
			break;
		default:
			HIP_DEBUG("Unsupported encryption transform (%d).\n",
					entry->e_type);
						
			err = -1;
			goto out_err;
	}
	
	/* auth will include IV */
	// TODO at least here it will break with NULL encryption
	elen += iv_len;
	*out_len += elen;
	
	
	
	/* 
	 * Authentication 
	 */
	
	/* the authentication covers the whole esp part starting with the header */
	elen += esp_data_offset;
	/* Check keys and calculate hashes */
	switch (entry->a_type)
	{
		case SADB_AALG_NONE:
			break;
		case SADB_AALG_MD5HMAC:
			if (!entry->a_key || entry->a_keylen == 0) {
				HIP_ERROR("authentication keys missing\n");
				
				err = -1;
				goto out_err;
			}
			
			HMAC(EVP_md5(), entry->a_key, entry->a_keylen,
				out, elen, &out[elen], &alen);
			
			break;
		case SADB_AALG_SHA1HMAC:
			//alen = HMAC_SHA_96_BITS / 8; /* 12 bytes */
			if (!entry->a_key || entry->a_keylen == 0) {
				HIP_ERROR("authentication keys missing\n");
				
				err = -1;
				goto out_err;
			}
			
			HMAC(EVP_sha1(), entry->a_key, entry->a_keylen,
					out, elen, &out[elen], &alen);
			
			break;
		case SADB_X_AALG_SHA2_256HMAC:
		case SADB_X_AALG_SHA2_384HMAC:
		case SADB_X_AALG_SHA2_512HMAC:
		case SADB_X_AALG_RIPEMD160HMAC:
		case SADB_X_AALG_NULL:
		default:
			HIP_DEBUG("Unsupported authentication algorithm (%d).\n",
							entry->a_type);
			
			err = -1;
			goto out_err;
	}
	
	*out_len += alen;

  out_err:
	return err;
}

/*
 * hip_esp_decrypt()
 *
 * in:	in	pointer to IP header of ESP packet to decrypt
 * 		len	packet length
 * 		out	pointer of where to build decrypted packet
 * 		offset	offset where decrypted packet is stored: &out[offset]
 * 		outlen	length of new packet
 * 		entry	the SADB entry
 * 		iph     IPv4 header or NULL for IPv6
 * 		now	pointer to current time (avoid extra gettimeofday call)
 *
 * out:		New packet is built in out, outlen.
 * 		Returns 0 on success, -1 otherwise.
 * 
 * Perform authentication and decryption of ESP packets.
 */
int hip_esp_decrypt(unsigned char *in, int in_len, unsigned char *out, uint8_t *out_type,
		int *out_len, hip_sadb_entry *entry)
{
	/* elen is length of data to encrypt */
	int elen = 0;
	// length of authentication protection field
	int alen = 0;
	// authentication data
	unsigned int hmac_md_len;
	unsigned char hmac_md[EVP_MAX_MD_SIZE];
	/* initialization vector */
	int iv_len = 0;
	unsigned char cbc_iv[16];
	/* ESP tail information */
	int pad_len = 0;
	struct hip_esp_tail *esp_tail = NULL;
	int esp_data_offset = 0;
	int err = 0;

	esp_data_offset = sizeof(struct hip_esp);
	
	/* 
	 *   Authentication 
	 */
	
	/* check keys, set up auth environment and finally auth */
	switch (entry->a_type) {
		case SADB_AALG_NONE:
			break;
		case SADB_AALG_MD5HMAC:
			alen = HMAC_SHA_96_BITS / 8; /* 12 bytes */
			// length of the authenticated payload, includes ESP header
			elen = in_len - alen;
			
			if (!entry->a_key || entry->a_keylen == 0) {
				HIP_ERROR("authentication keys missing\n");
				
				err = -1;
				goto out_err;
			}
			
			HMAC(EVP_md5(), entry->a_key, entry->a_keylen, 
				in, elen, hmac_md, &hmac_md_len);
			
			// actual auth verification
			if (memcmp(&in[elen], hmac_md, hmac_md_len) != 0)
			{
				HIP_DEBUG("ESP packet could not be authenticated\n");
				
				err = 1;
				goto out_err;
			}
			break;
		case SADB_AALG_SHA1HMAC:
			alen = HMAC_SHA_96_BITS / 8; /* 12 bytes */
			// length of the encrypted payload
			elen = in_len - alen;
			
			if (!entry->a_key || entry->a_keylen == 0) {
				HIP_ERROR("authentication keys missing\n");
				
				err = -1;
				goto out_err;
			}
			
			HMAC(EVP_sha1(), entry->a_key, entry->a_keylen, 
				in, elen, hmac_md, &hmac_md_len);
			
			// actual auth verification
			if (memcmp(&in[elen], hmac_md, hmac_md_len) != 0)
			{
				HIP_DEBUG("ESP packet could not be authenticated\n");
				
				err = 1;
				goto out_err;
			}
			break;
		case SADB_X_AALG_SHA2_256HMAC:
		case SADB_X_AALG_SHA2_384HMAC:
		case SADB_X_AALG_SHA2_512HMAC:
		case SADB_X_AALG_RIPEMD160HMAC:
		case SADB_X_AALG_NULL:
		default:
			HIP_ERROR("Unsupported authentication algorithm (%d).\n",
										entry->a_type);
						
			err = -1;
			goto out_err;
	}
	
	

	/*
	 *   Decryption
	 */
	
	elen -= esp_data_offset;

	/* Check keys and set initialisation vector length */
	switch (entry->e_type) {
		case SADB_EALG_3DESCBC:
			iv_len = 8;
			if (!entry->e_key || entry->e_keylen == 0) {
				HIP_ERROR("3-DES key missing.\n");

				err = -1;
				goto out_err;
			}
			break;
		case SADB_X_EALG_BLOWFISHCBC:
			iv_len = 8;
			if (!entry->bf_key) {
				HIP_ERROR("BLOWFISH key missing.\n");

				err = -1;
				goto out_err;
			}
			break;
		case SADB_EALG_NULL:
			iv_len = 0;
			break;
		case SADB_X_EALG_AESCBC:
			iv_len = 16;
			if (!entry->aes_key && entry->e_key) {
				entry->aes_key = malloc(sizeof(AES_KEY));
				
				if (AES_set_decrypt_key(entry->e_key, 8*entry->e_keylen,
							entry->aes_key)) {
					HIP_ERROR("AES key problem!\n");
					
					err = -1;
					goto out_err;
				}
				
			} else if (!entry->aes_key) {
				HIP_ERROR("AES key missing.\n");

				err = -1;
				goto out_err;
			}
			break;
		case SADB_EALG_NONE:
		case SADB_EALG_DESCBC:
		case SADB_X_EALG_CASTCBC:
		case SADB_X_EALG_SERPENTCBC:
		case SADB_X_EALG_TWOFISHCBC:
		default:
			HIP_ERROR("Unsupported decryption algorithm (%d)\n", 
				entry->e_type);

			err = -1;
			goto out_err;
	}
	
	/* get the initialisation vector located right behind the ESP header */
	memcpy(cbc_iv, in + esp_data_offset, iv_len);
	
	/* also don't include IV as part of ciphertext */
	elen -= iv_len; 
	
	switch (entry->e_type) {
		case SADB_EALG_3DESCBC:
			des_ede3_cbc_encrypt(&in[esp_data_offset + iv_len], out, elen,
					     entry->ks[0], entry->ks[1], entry->ks[2],
					     (des_cblock *) cbc_iv, DES_DECRYPT);
			break;
		case SADB_X_EALG_BLOWFISHCBC:
			BF_cbc_encrypt(&in[esp_data_offset + iv_len], out, elen,
					entry->bf_key, cbc_iv, BF_DECRYPT);
			break;
		case SADB_EALG_NULL:
			memcpy(out, &in[esp_data_offset], elen);
			break;
		case SADB_X_EALG_AESCBC:
			AES_cbc_encrypt(&in[esp_data_offset + iv_len], out, elen,
					entry->aes_key, cbc_iv, AES_DECRYPT);
			break;
		default:
			HIP_ERROR("Unsupported decryption algorithm (%d)\n", 
					entry->e_type);

			err = -1;
			goto out_err;
	}

	/* remove padding */
	esp_tail = (struct hip_esp_tail *) &out[elen - sizeof(struct hip_esp_tail)];
	*out_type = esp_tail->esp_next;
	*out_len = elen - (esp_tail->esp_padlen + sizeof(struct hip_esp_tail));

#if 0
	// TODO do we need this?
	/* determine address family for new packet based on 
	 * decrypted upper layer protocol header
	 */
	family_out = hip_select_family_by_proto(LSI4(&entry->lsi), 
					padinfo->next_hdr, &out[*offset], now);
#endif

  out_err:
	return err;
}


#if 0
void reset_sadbentry_udp_port (__u32 spi_out)
{
	hip_sadb_entry *entry;
	entry = hip_sadb_lookup_spi (spi_out);
	if (entry) {
		entry->dst_port = 0;
		HIP_DEBUG ("SADB-entry dst_port reset for spi: 0x%x.\n",spi_out);
	}
}
#endif

#if 0
/* debug */
extern hip_sadb_entry hip_sadb[SADB_SIZE];

void print_sadb()
{
	int i;
	hip_sadb_entry *entry;

	for (i=0; i < SADB_SIZE; i++) {
		for (	entry = &hip_sadb[i]; entry && entry->spi; 
				entry=entry->next ) {
			HIP_DEBUG("entry(%d): ", i);
			HIP_DEBUG("SPI=0x%x dir=%d magic=0x%x mode=%d lsi=%x ",
				entry->spi, entry->direction, entry->hit_magic,
				entry->mode, 
				((struct sockaddr_in*)&entry->lsi)->sin_addr.s_addr);
			HIP_DEBUG("lsi6= a_type=%d e_type=%d a_keylen=%d "
				"e_keylen=%d lifetime=%llu seq=%d\n",
				entry->a_type, entry->e_type,
				entry->a_keylen, entry->e_keylen,
				entry->lifetime, entry->sequence  );
		}
	}
}
#endif


/* TODO copy as much header information as possible */

/*
 * add_ipv4_header()
 *
 * Build an IPv4 header, copying some parameters from an old ip header,
 * src and dst in host byte order. old may be NULL.
 */
void add_ipv4_header(struct ip *ip_hdr, struct in6_addr *src_addr, struct in6_addr *dst_addr,
		int packet_len, uint8_t next_hdr)
{
	struct in_addr src_in_addr;
	struct in_addr dst_in_addr;
	IPV6_TO_IPV4_MAP(src_addr, &src_in_addr);
	IPV6_TO_IPV4_MAP(dst_addr, &dst_in_addr);
	
	// set changed values
	ip_hdr->ip_v = 4;
	/* assume no options */
	ip_hdr->ip_hl = 5;
	ip_hdr->ip_tos = 0;
	ip_hdr->ip_len = packet_len;
	/* assume that we have no fragmentation */
	ip_hdr->ip_id  = 0;
	ip_hdr->ip_off = 0;
	ip_hdr->ip_ttl = 255;
	ip_hdr->ip_p = next_hdr;
	ip_hdr->ip_sum = 0;
	ip_hdr->ip_src.s_addr = src_in_addr.s_addr;
	ip_hdr->ip_dst.s_addr = dst_in_addr.s_addr;

	/* recalculate the header checksum, does not include payload */
	ip_hdr->ip_sum = checksum_ip(ip_hdr, ip_hdr->ip_hl);
}

#if 0
/* OLD CODE TAKEN FROM OPENHIP -> will be usefull for UDP encapsulation with IPv6
 * 
 * add_ipv6_pseudo_header()
 *
 * Build an IPv6 pseudo-header for upper-layer checksum calculation.
 */
void add_ipv6_pseudo_header(__u8 *data, struct sockaddr *src, 
	struct sockaddr *dst, __u32 len, __u8 proto)
{
	int l;
	struct _ph {
		__u32 ph_len;
		__u8 ph_zero[3];
		__u8 ph_next_header;
	} *ph;
	memset(data, 0, 40);

	/* 16 bytes source address, 16 bytes destination address */
	l = sizeof(struct in6_addr);
	memcpy(&data[0], SA2IP(src), l);
	memcpy(&data[l], SA2IP(dst), l);
	l += sizeof(struct in6_addr);
	/* upper-layer packet length, zero, next header */
	ph = (struct _ph*) &data[l];
	ph->ph_len = htonl(len);
	memset(ph->ph_zero, 0, 3);
	ph->ph_next_header = proto;
}
#endif

/*
 * add_ipv6_header()
 *
 * Build an IPv6 header, copying some parameters from an old header (old),
 * src and dst in network byte order.
 */
void add_ipv6_header(struct ip6_hdr *ip6_hdr, struct in6_addr *src_addr, struct in6_addr *dst_addr,
		int packet_len, uint8_t next_hdr)
{
	ip6_hdr->ip6_flow = 0; /* zero the version (4), TC (8) and flow-ID (20) */
	/* only set 4 bits version and top 4 bits tclass */
	ip6_hdr->ip6_vfc = 0x60;
	ip6_hdr->ip6_plen = packet_len;
	ip6_hdr->ip6_nxt = next_hdr;
	ip6_hdr->ip6_hlim = 255;
	memcpy(&ip6_hdr->ip6_src, src_addr, sizeof(struct in6_addr));
	memcpy(&ip6_hdr->ip6_dst, dst_addr, sizeof(struct in6_addr));
}

void add_udp_header(struct udphdr *udp_hdr, int packet_len, hip_sadb_entry *entry,
		struct in6_addr *src_addr, struct in6_addr *dst_addr)
{
	udp_hdr->source = htons(HIP_ESP_UDP_PORT);
	
	if ((udp_hdr->dest = htons(entry->dst_port)) == 0) {
		HIP_ERROR("bad UDP dst port number: %u\n", entry->dst_port);
	}
	
	udp_hdr->len = htons((u_int16_t)packet_len);
	
	// this will create a pseudo header using some information from the ip layer
	udp_hdr->check = checksum_udp(udp_hdr, src_addr, dst_addr);
}

/* TODO put checksums in one function and copy add function from openhip
 * needed for UDP */

/* This isn't the 'fast' checksum, since the GCC inline ASM version is not 
 * available in Windows; this is the same code from hip_util.c */
uint16_t checksum_ip(struct ip *ip_hdr, unsigned int ip_hl)
{
	uint16_t checksum;
	unsigned long sum = 0;
	int count = ip_hl*4;
	unsigned short *p = (unsigned short *) ip_hdr;

	/* 
	 * this checksum algorithm can be found 
	 * in RFC 1071 section 4.1
	 */

	/* one's complement sum 16-bit words of data */
	while (count > 1)  {
		sum += *p++;
		count -= 2;
	}
	/* add left-over byte, if any */
	if (count > 0)
		sum += (unsigned char)*p;
 
	/*  Fold 32-bit sum to 16 bits */
	while (sum>>16)
		sum = (sum & 0xffff) + (sum >> 16);
	/* take the one's complement of the sum */ 
	checksum = (uint16_t)(~sum);
    
	return checksum;
}

/*
 * function checksum_udp_packet()
 *
 * Calculates the checksum of a UDP packet with pseudo-header
 * src and dst are IPv4 addresses in network byte order
 */
uint16_t checksum_udp(struct udphdr *udp_hdr, struct in6_addr *src_addr,
		struct in6_addr *dst_addr)
{
	uint16_t checksum = 0;
	unsigned long sum = 0;
	int count, length;
	unsigned short *p; /* 16-bit */
	pseudo_header pseudo_hdr;
	struct in_addr src_in_addr;
	struct in_addr dst_in_addr;

	/* IPv4 checksum based on UDP-- Section 6.1.2 */
	
	// setting up pseudo header
	memset(&pseudo_hdr, 0, sizeof(pseudo_header));
	IPV6_TO_IPV4_MAP(src_addr, &src_in_addr);
	IPV6_TO_IPV4_MAP(dst_addr, &dst_in_addr);
	/* assume host byte order */
	pseudo_hdr.src_addr = htonl(src_in_addr.s_addr);
	pseudo_hdr.dst_addr = htonl(dst_in_addr.s_addr);
	pseudo_hdr.protocol = IPPROTO_UDP;
	pseudo_hdr.packet_length = udp_hdr->len;

	count = sizeof(pseudo_header); /* count always even number */
	p = (unsigned short*) &pseudo_hdr;
	
	/* 
	 * this checksum algorithm can be found 
	 * in RFC 1071 section 4.1
	 */

	/* sum the psuedo-header */
	/* count and p are initialized above per protocol */
	while (count > 1) {
		sum += *p++;
		count -= 2;
	}
    
	/* one's complement sum 16-bit words of data */
	/* log_(NORM, "checksumming %d bytes of data.\n", length); */
	count = length;
	p = (unsigned short*) udp_hdr;
	while (count > 1)  {
		sum += *p++;
		count -= 2;
	}
	/* add left-over byte, if any */
	if (count > 0)
		sum += (unsigned char)*p;
 
	/*  Fold 32-bit sum to 16 bits */
	while (sum>>16)
		sum = (sum & 0xffff) + (sum >> 16);
	/* take the one's complement of the sum */ 
	checksum = (u_int16_t)(~sum);
    
	return checksum;
}
