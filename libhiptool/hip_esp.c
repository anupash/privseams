
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
#include "misc.h"


#include <sys/time.h>
#include <sys/wait.h>		/* waitpid()	*/
#include <pthread.h>		/* pthreads support*/


#if defined(__BIG_ENDIAN__) || defined( __MACOSX__)
#include <mac/checksum_mac.h>
#else
#include "win32-checksum.h"
#endif




/* 
 * Globals
 */

#ifdef __WIN32__
HANDLE tapfd;
#else
int tapfd;
#endif
int readsp[2] = {0,0};
int s_esp, s_esp_udp, s_esp6;
int s_udp;
#ifdef DEBUG_EVERY_PACKET
FILE *debugfp;
#endif

extern hip_sadb_dst_entry hip_sadb_dst[SADB_SIZE];
#ifdef __MACOSX__
extern char *logaddr(struct sockaddr *addr);
#endif

__u32 g_tap_lsi;
__u64 g_tap_mac;
long g_read_usec;

#define BUFF_LEN 2000
#define HMAC_SHA_96_BITS 96 /* 12 bytes */

/* added By Tao Wan*/
#define H_PROTO_UDP 17

/* array of Ethernet addresses used by get_eth_addr() */
#define MAX_ETH_ADDRS 255
__u8 eth_addrs[6 * MAX_ETH_ADDRS]; /* must be initialized to random values */


/* Prototype of checksum function defined in hip_util.c */
__u16 checksum_udp_packet(__u8 *data, struct sockaddr *src, struct sockaddr *dst);


/* added by Tao Wan, define g_state to be 1 */
/* status kernelspace ipsec */
int g_state = 0;


/* defined RAW socket IP out */
#define RAW_IP_OUT 1


/*HIP ESP output using socket binding */
// #define USE_BINDING 1


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

struct eth_hdr {
	__u8 dst[6];
	__u8 src[6];
	__u16 type;
}__attribute__ ((packed));

/* ARP header - RFC 826, STD 37 */
struct arp_hdr {
	__u16 ar_hrd;
	__u16 ar_pro;
	__u8 ar_hln;
	__u8 ar_pln;
	__u16 ar_op;
};

/*added by Tao Wan pseudo_header6, pseudo_header*/

typedef struct _pseudo_header6
{
	unsigned char src_addr[16];
	unsigned char dst_addr[16];
	__u32 packet_length;
	char zero[3];
	__u8 next_hdr;
} pseudo_header6;

typedef struct _pseudo_header
{
	unsigned char src_addr[4];
	unsigned char dst_addr[4];
	__u8 zero;
	__u8 protocol;
	__u16 packet_length;
} pseudo_header;

/* 
 * Local function declarations
 */

int handle_nsol(__u8 *in, int len, __u8 *out,int *outlen,struct sockaddr *addr);
int hip_esp_encrypt(__u8 *in, int len, __u8 *out, 
		hip_sadb_entry *entry, struct timeval *now, int *outlen);
int hip_esp_decrypt(__u8 *in, int len, __u8 *out, int *offset, int *outlen,
    hip_sadb_entry *entry, struct ip *iph, struct timeval *now);

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


/*
 * function checksum_udp_packet()
 *
 * XXX TODO: combine with other checksum functions
 *
 * Calculates the checksum of a UDP packet with pseudo-header
 * src and dst are IPv4 or IPv6 addresses in network byte order
 */
__u16 checksum_udp_packet(__u8 *data, struct sockaddr *src, struct sockaddr *dst)
{
	__u16 checksum;
	unsigned long sum = 0;
	int count, length;
	unsigned short *p; /* 16-bit */
	pseudo_header pseudoh;
	pseudo_header6 pseudoh6;
	__u32 src_network, dst_network;
	struct in6_addr *src6, *dst6;
	struct udphdr* udph = (struct udphdr*) data;

	if (src->sa_family == AF_INET) {
		/* IPv4 checksum based on UDP-- Section 6.1.2 */
		src_network = ((struct sockaddr_in*)src)->sin_addr.s_addr;
		dst_network = ((struct sockaddr_in*)dst)->sin_addr.s_addr;
	
		memset(&pseudoh, 0, sizeof(pseudo_header));
		memcpy(&pseudoh.src_addr, &src_network, 4);
		memcpy(&pseudoh.dst_addr, &dst_network, 4);
		pseudoh.protocol = H_PROTO_UDP;
		length = ntohs(udph->len);
		pseudoh.packet_length = htons((__u16)length);

		count = sizeof(pseudo_header); /* count always even number */
		p = (unsigned short*) &pseudoh;
	} else {
		/* IPv6 checksum based on IPv6 pseudo-header */
		src6 = &((struct sockaddr_in6*)src)->sin6_addr;
		dst6 = &((struct sockaddr_in6*)dst)->sin6_addr;
	
		memset(&pseudoh6, 0, sizeof(pseudo_header6));
		memcpy(&pseudoh6.src_addr[0], src6, 16);
		memcpy(&pseudoh6.dst_addr[0], dst6, 16);
		length = ntohs(udph->len);
		pseudoh6.next_hdr = H_PROTO_UDP;
		pseudoh6.packet_length = htonl(length);
		
		count = sizeof(pseudo_header6); /* count always even number */
		p = (unsigned short*) &pseudoh6;
	}
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
	p = (unsigned short*) data;
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
	checksum = (__u16)(~sum);
    
	return(checksum);
}


/* added by Tao Wan, different from boeing implemenation */

int get_preferred_lsi(struct sockaddr *lsi) {

   if (lsi != NULL) {
    struct in_addr *lsi_in = hip_cast_sa_addr(lsi);
    lsi_in->s_addr = 0;
    return (0);
} else
  
	return (-1); 

}

#if 0
/*
 * hip_esp_output()
 *
 * The ESP output thread. Reads ethernet packets from the socketpair
 * connected to the TAP-Win32 interface, and performs necessary ESP
 * encryption. Also handles ARP requests with artificial replies.
 */

/* - encrypt payload
 * - set up other headers */
int hip_esp_output(hip_fw_context_t *ctx, hip_sadb_entry *entry, __u8 *esp_packet,
		int udp_encap, struct timeval *now)
{
	int esp_packet_len = 0;
	
	int err = 0;
	
	// resolve HITs to routable addresses and select the prefered ones
	hip_addr_to_sockaddr(&ctx->src, &sockaddr_local);
	hip_addr_to_sockaddr(&ctx->dst, &sockaddr_peer);
	
	// TODO get preferred addresses from the entry
	
	// check preferred addresses for the address type of the output
	if (sockaddr_local_hit->sa_family == AF_INET && sockaddr_peer_hit->sa_family == AF_INET)
	{
		HIP_DEBUG("out_ip_version is IPv4");
		out_ip_version = 4;
	} else if (sockaddr_local_hit->sa_family == AF_INET6 && sockaddr_peer_hit->sa_family == AF_INET6)
	{
		HIP_DEBUG("out_ip_version is IPv6");
		out_ip_version = 6;
	} else
	{
		HIP_ERROR("bad address combination");
		
		err = 1;
		goto end_err;
	}
	
	// distinguish IPv4 and IPv6 output
	if (out_ip_version == 4)
	{
		// calculate offset at which esp data should be located
		// NOTE: this does _not_ include IPv4 options for the original packet
		next_hdr_offset = sizeof(struct ip);
		
		// check whether to use UDP encapsulation or not
		if (udp_encap)
			next_hdr_offset += sizeof(struct udphdr);
		
		
		__u16 checksum_fix = 0;
			
			
			int family, use_udp = FALSE;


			if ((in[12] == 0x86) && (in[13] == 0xdd))
				family = AF_INET6;
			else
				family = AF_INET;

			switch (family) {
			case AF_INET:
				iph = (struct ip*) &in[sizeof(struct eth_hdr)];
				eth_ip_hdr_len = sizeof(struct eth_hdr) + sizeof(struct ip);
				/* rewrite transport-layer checksum, so it is based on HITs */
				checksum_fix = rewrite_checksum((__u8*)iph, entry->hit_magic);
				break;
			case AF_INET6:
				ip6h = (struct ip6_hdr*) &in[sizeof(struct eth_hdr)];
				eth_ip_hdr_len = sizeof(struct eth_hdr)+sizeof(struct ip6_hdr);
				/* assume HITs are used as v6 src/dst, no checksum rewrite */
				break;
			}
			
			/* setup ESP header, common to all algorithms */
			// TODO this is not the way you learn about UDP encap
			if (entry->mode == 3) { /*(HIP_ESP_OVER_UDP)*/
				// add udp and esp header
				udph = (udphdr*) out;
				esp = (struct ip_esp_hdr*) &out[sizeof(udphdr)];
				use_udp = TRUE;
			} else {
				// only add esp header
				esp = (struct ip_esp_hdr*) out;
			}

			// set up esp header
			esp->spi = htonl(entry->spi);
			esp->seq_no = htonl(entry->sequence++);

			/* encrypted data length is everything starting at transport layer header */
			elen = len - eth_ip_hdr_len;
			
			// calculate first part of the output length
			*outlen = sizeof(struct ip_esp_hdr);
			if (use_udp) /* (HIP_ESP_OVER_UDP) */
				*outlen += sizeof(udphdr);
		
		
		// encrypt data now
		pthread_mutex_lock(&entry->rw_lock);
			
		HIP_DEBUG("encrypting data...\n");
		
		// TODO check if parameters are correct
		// encrypts the payload and puts esp header and encrypted data right
		// behind the IP/UDP headers
		err = hip_esp_encrypt(ctx->ipq_packet, ctx->ipq_packet->data_len,
				      esp_packet + next_hdr_offset, entry, &now, &esp_packet_len);
		
		pthread_mutex_unlock(&entry->rw_lock);
		
		
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


		/* Restore the checksum in the input data, in case this is
		 * a broadcast packet that needs to be re-sent to some other
		 * destination.
		 */
		if (checksum_fix > 0) {
			if (iph->ip_p == IPPROTO_UDP)
	#ifdef __MACOSX__
				((struct udphdr*)(iph + 1))->uh_sum = checksum_fix;
	#else
				((struct udphdr*)(iph + 1))->check = checksum_fix;
	#endif
			else if (iph->ip_p == IPPROTO_TCP)
	#ifdef __MACOSX__
				((struct tcphdr*)(iph + 1))->th_sum = checksum_fix;
	#else
				((struct tcphdr*)(iph + 1))->check = checksum_fix;
	#endif
		}

		if (use_udp) { /* (HIP_ESP_OVER_UDP) */
			/* Set up UDP header at the beginning of out */
			memset (udph, 0, sizeof(udphdr));
			udph->src_port = htons(HIP_ESP_UDP_PORT);
			if ( (udph->dst_port = htons(entry->dst_port))==0) {
				printf ("ESP encrypt : bad UDP dst port number (%u).\n",
					entry->dst_port);
			}
			udph->len = htons ((__u16)*outlen);
			udph->checksum = checksum_udp_packet (out, 
					    (struct sockaddr*)&entry->src_addrs->addr,
					    (struct sockaddr*)&entry->dst_addrs->addr);
		}
		
		
		
		if (udp_encap)
		{
			// add the IPv4 header at the beginning of the new packet
			// NOTE: we got the overall packet length from hip_esp_encrypt
			add_ipv4_header(esp_packet, ctx, preferred src, preferred dst, 
					esp_packet_len + sizeof(udp), IPPROTO_UDP);
			
			next_hdr_offset -= sizeof(udp)
			add_udp_header
		} else
		{
			add_ipv4_header(esp_packet, ctx, preferred src, preferred dst, 
					esp_packet_len, IPPROTO_ESP);
		}			
	} else if (out_ip_version == 6)
	{
		/* we don't support UDP encapsulation for IPv6 right now
		 * 
		 * this would be the place to add it */
		next_hdr_offset = ctx->ip_hdr_len;
			
		pthread_mutex_lock(&entry->rw_lock);
			
		HIP_DEBUG("encrypting data...\n");
		
		// TODO check if parameters are correct
		// encrypts the payload and puts esp header and encrypted data right
		// behind the previous headers
		err = hip_esp_encrypt(ctx->ipq_packet, ctx->ipq_packet->data_len,
				      esp_packet, next_hdr_offset, entry, &now, &esp_packet_len);
		
		pthread_mutex_unlock(&entry->rw_lock);
		
		add_ipv6_header
	}
	
  end_err:
  	return err;
}
#endif
	
#if 0	
/* We do not use TAP-Win32 interface here, FIXME: SOCK_RAW IP out 
* should be rewritten:(
*/
#ifdef __WIN32__
void hip_esp_output(void *arg)
#else
int hip_esp_output(struct sockaddr *ss_lsi, 
		     u8 *raw_buff, int len)
#endif
{
	int i, err = 0, flags, raw_len, is_broadcast, s, offset=0;
	int on = 1;
	int out_enc_len; /* returned length of encrypted data*/
	int ipv4_s_raw = 0; /* ipv4 raw socket */
	int ipv6_s_raw = 0; /* ipv6 raw socket */
	struct sockaddr_in *ipv4_binding;
	struct sockaddr_in6 *ipv6_binding;

	struct sockaddr_in ipv4_src_addr;
	struct sockaddr_in6 ipv6_src_addr;

	
	size_t sa_size_v4 = sizeof(struct sockaddr_in);
	size_t sa_size_v6 = sizeof(struct sockaddr_in6);
	size_t sent = 0; 
	int dst_is_ipv4 = 0;
	struct ip *iphdr; 
	struct ip6_hdr *ip6_hdr;
	struct tcphdr *tcphdr;
	int hdr_size;
	fd_set fd;
	struct timeval timeout, now;
	__u8 data[BUFF_LEN];
	struct ip *iph;
#ifdef __WIN32__
	DWORD lenin;
	OVERLAPPED overlapped = {0};
#endif
	//struct ip6_hdr *ip6h;
	static hip_sadb_entry *entry;
	//struct sockaddr_storage ss_lsi;
	struct sockaddr *lsi = (struct sockaddr *) ss_lsi;
	struct ip_esp_hdr *esph;

	memset(data, 0, sizeof(data));

	_HIP_DEBUG("the AF_INET value is %d\n", AF_INET);
	_HIP_DEBUG("the AF_INET6 value is %d\n", AF_INET6);
	
	
	HIP_DEBUG_SOCKADDR("LSI address is: ",  lsi);

	
	__u32 lsi_ip;
#ifdef __MACOSX__
        __u32 saddr, daddr;
#endif
#ifdef RAW_IP_OUT

#if 0	

	HIP_DEBUG("Get into RAW_IP_OUT\n");
	
	int s_raw = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (s_raw < 0) {
		HIP_DEBUG("*** socket() error for raw socket in hip_esp_output\n");
	}
	flags = 1;
	if (setsockopt(s_raw, IPPROTO_IP, IP_HDRINCL, (char *)&flags, 
		       sizeof(flags)) < 0) {
		HIP_DEBUG("*** setsockopt() error for raw socket in "
			  "hip_esp_output\n");
	}
	

#endif 	
	
	/* open ipv4 raw socket */
	ipv4_s_raw = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (ipv4_s_raw < 0) {
		HIP_DEBUG("*** ipv4_s_raw socket() error for raw socket in hip_esp_output\n");
	}
	
	/* open ipv6 raw socket*/
	ipv6_s_raw = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
	if (ipv6_s_raw < 0) {
		HIP_DEBUG("*** ipv6_s_raw socket() error for raw socket in hip_esp_output\n");
	}


#endif /* RAW_IP_OUT */

#ifdef DEBUG_EVERY_PACKET
	if (!(debugfp = fopen("esp.log", "w"))) {
		HIP_DEBUG("********* error opening debug log!\n");
	}
#endif

	/* we do not need create a pair of connected scokets*/
	// init_readsp();

	
	/* For HIPL implementation,  lsi->sa_family is AF_INET6*/
	HIP_DEBUG("lsi->sa_family value is %d\n",  lsi->sa_family );
	

	/* HIPL does not use tap driver here */

	// lsi->sa_family = AF_INET;
	// get_preferred_lsi(lsi);
	// g_tap_lsi = LSI4(lsi);
	
	
	/* Try to get HIP security association entry (userspace ipsec) */
	

	/* unicast packets */

	/* we only do the unicast, the entry length is only 1 */
	

	if (!(entry = hip_sadb_lookup_addr(lsi))) {
		/* No SADB entry. Send ACQUIRE if we haven't
		 * already, i.e. a new lsi_entry was created */
		HIP_DEBUG("HIP ipsec userspace sadb is not ready!!\n");

		if (buffer_packet(lsi, raw_buff, len))
			pfkey_send_acquire(lsi);
		// continue;
		return;
	}


	raw_len = len;
	
	HIP_DEBUG("hip_esp_output() thread started...\n");
       
	while(entry) {


		
		
		pthread_mutex_lock(&entry->rw_lock);
		
		/* RAW IP out */

		/* This is for IPv4, need LSI support */
		// offset = sizeof(struct ip);
		
		/* This is for IPv6 header */
		// offset = sizeof(struct ip6_hdr);

		HIP_DEBUG("start encrypt data......\n");

		err = hip_esp_encrypt(raw_buff, raw_len,
				      data, &out_enc_len, entry, &now);
		
		pthread_mutex_unlock(&entry->rw_lock);

                 /*
		   
		 
		 if (err) { 
		 break;
		 }
			
		 flags = 0;
		 */
		
	/* catch empty entries */
	if (!entry->src_addrs || !entry->dst_addrs)
			continue;		

	HIP_DEBUG_SOCKADDR("src addr: ", (struct sockaddr *) &entry->src_addrs->addr);
	HIP_DEBUG_SOCKADDR("dst addr: ", (struct sockaddr *) &entry->dst_addrs->addr);
	
	/* FIXME if src family is IPv4, dst family is IPv6
	*  or src family is IPv6, dst family is IPv4
	*
	*/

	if ((entry->src_addrs->addr).ss_family == AF_INET
	    && (entry->dst_addrs->addr).ss_family == AF_INET)	
	{
		HIP_DEBUG(" Both IP addresses belong to IPv4\n"); 
	

		dst_is_ipv4 = 1; /* Here we know dst is IPv4 address*/
		
		/* raw_buff only includes HITS, FIXME, if support LSI */
	
		//get the ip header
		ip6_hdr = (struct ip6_hdr *) &raw_buff[0];
		
		
		/* get the tcp header pointer */
		hdr_size = (ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_plen * 4);
		tcphdr = ((struct tcphdr *) (((char *) ip6_hdr) + hdr_size));	
		
	    		
		
#ifdef USE_BINDING /* Using binding */
		
		/* my localhost address is entry->dst_addrs->addr 
		 * FIX ME if using UDP socket, can not use raw_socket here!!!!!!
		 *
		 */
		ipv4_binding = (struct sockaddr_in *) &entry->dst_addrs->addr;
		

		HIP_DEBUG_SOCKADDR("src addr: ", ipv4_binding);
		
		HIP_IFEL(bind(ipv4_s_raw, (struct sockaddr *) ipv4_binding, sa_size_v4), -1,
			 "Binding to ipv4 raw sock failed\n");
		flags = 0;
		
#else
		
		if(setsockopt(ipv4_s_raw, IPPROTO_IP, IP_HDRINCL, 
			      (char *)&on, sizeof(on)) < 0 )
		{
			HIP_DEBUG("ipv4 Error setting an option to raw socket\n"); 
			goto out_err;
			
		}
		
		flags = 0;

		/* the peer address is entry->src_addrs->addr*/
		/* IP header + udp header + ESP packet */
    
		__u8 new_raw_ip_output[sizeof(struct ip) + out_enc_len];

		iph = (struct ip *) new_raw_ip_output;
		

		/* copy memory (data) udp header + ESP packet */
		memcpy(&new_raw_ip_output[sizeof(struct ip)], data, out_enc_len);


		/* Local IP address: &entry->dst_addrs->addr  */
		/* Remote IP address: &entry->src_addrs->addr */

	      
		/* FIXME, Replace NULL pointer with LSI if LSI support*/
		/*  ESP_OVER_UDP */
		
		if(entry->mode == 3) 
		{
		add_ipv4_header(new_raw_ip_output,
			       ntohl(LSI4(&entry->dst_addrs->addr)), 
			       ntohl(LSI4(&entry->src_addrs->addr)), 
			       (struct ip*) NULL,
			       sizeof(struct ip) + out_enc_len,
			       IPPROTO_UDP);
		
		} else 
		{
			
			add_ipv4_header(new_raw_ip_output,
					ntohl(LSI4(&entry->dst_addrs->addr)), 
					ntohl(LSI4(&entry->src_addrs->addr)), 
					(struct ip*) NULL,
					sizeof(struct ip) + out_enc_len,
					IPPROTO_ESP);
		}

		
		
#endif 
		
		HIP_HEXDUMP("The output encrypted packet (UDP + ESP)  is ", data, out_enc_len);

		esph = (struct ip_esp_hdr *) (((char *)data) + sizeof(struct udphdr));

 
		HIP_DEBUG("output packet spi value is 0x%x\n", ntohl(esph->spi));
		
		HIP_HEXDUMP("the output IPv4 header + UDP header + ESP packet is",
			    new_raw_ip_output, sizeof(struct ip) + out_enc_len);


		
		err = sendto(ipv4_s_raw, new_raw_ip_output, 
			     sizeof(struct ip) + out_enc_len , 
			     flags,
			     SA(&entry->src_addrs->addr),
			     SALEN(&entry->src_addrs->addr));
 
		if (err < 0)
		{	
			HIP_DEBUG("hip_esp_output IPv4 sendto() failed:"
				  " %s\n",strerror(errno));
			goto out_err;
			
		}
		
	 	
		

	}
	
	if ((entry->src_addrs->addr).ss_family == AF_INET6
	    &&(entry->dst_addrs->addr).ss_family == AF_INET6)	 
		
	{
		HIP_DEBUG(" Both IP addresses belong to IPv6\n"); 
		
		
		//get the ip header
		ip6_hdr = (struct ip6_hdr *) &raw_buff[0];
		
		
		/* get the tcp header pointer
		 */		
		hdr_size = (ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_plen * 4);
		tcphdr = ((struct tcphdr *) (((char *) ip6_hdr) + hdr_size));	
		

		
#ifdef USE_BINDING 
		
		ipv6_binding = (struct sockaddr_in6 *) &entry->dst_addrs->addr;
		HIP_IFEL(bind(ipv6_s_raw, (struct sockaddr *) ipv6_binding, sa_size_v6), -1,
			 "Binding to ipv4 raw sock failed");
		flags = 0;

#else

		if(setsockopt(ipv6_s_raw, IPPROTO_IPV6, IP_HDRINCL, 
			      (char *)&on, sizeof(on)) < 0 )
		{
			HIP_DEBUG("ipv6 Error setting an option to raw socket\n"); 
			goto out_err;
			
		}
		
		flags = 0;

		/* the peer address is entry->src_addrs->addr*/
		/* IP header + udp header + ESP packet */
    
		__u8 new_raw_ip_output[sizeof(struct ip6_hdr) + out_enc_len];

		
		/* copy memory (data) udp header + ESP packet */
		memcpy(&new_raw_ip_output[sizeof(struct ip6_hdr)], data, out_enc_len);


		/* Local IP address: &entry->dst_addrs->addr  */
		/* Remote IP address: &entry->src_addrs->addr */
	       
		
		HIP_DEBUG("The IPPROTO_ESP value is %d\n", IPPROTO_ESP);
		
		
		add_ipv6_header(new_raw_ip_output, 
				SA(&entry->src_addrs->addr),
				SA(&entry->dst_addrs->addr),
				(struct ip6_hdr *) ip6_hdr, (struct ip*) NULL,
				sizeof(struct ip6_hdr) + out_enc_len,
				IPPROTO_ESP);
		

#endif 


		HIP_HEXDUMP("The output encrypted packet ( if ESP_OVER_UDP /UDP + ESP)  is ", 
			    data, out_enc_len);
	       
	       struct ip_esp_hdr *esph = (struct ip_esp_hdr *) ((char *) data);
	       
	       
	       HIP_DEBUG("output packet spi value is 0x%x\n", ntohl(esph->spi));
	       
	       HIP_HEXDUMP("the output IPv6 header +  ESP packet is",
			   new_raw_ip_output, sizeof(struct ip6_hdr) + out_enc_len);
	       
	       
	       err = sendto(ipv6_s_raw, new_raw_ip_output, 
			    sizeof(struct ip6_hdr) + out_enc_len , 
			    flags,
			    SA(&entry->src_addrs->addr),
			    SALEN(&entry->src_addrs->addr));
	       
	       
	       if (err < 0)
	       {	
		       HIP_DEBUG("hip_esp_output IPv6 sendto() failed:"
				 " %s\n",strerror(errno));
		       goto out_err;
		       
	       }
	       
	       
	}
	
	
	entry=hip_sadb_get_next(entry);
	
	
	}



	
	



	// if ((raw_buff[12] == 0x08) && (raw_buff[13] == 0x00)) 
	       

	// HIP_DEBUG("Print out some raw bufer values....\n");
	//HIP_DEBUG("raw_buffer[12] is Ox%x\n", raw_buff[12]);
	// HIP_DEBUG("raw_buffer[13] is Ox%x\n", raw_buff[13]);
	
/*
	for(i = 0; i < len ; i++) {
	
	HIP_DEBUG("raw_buffer[%d] is Ox%x\n", i, raw_buff[i]);
	
	
	}
*/

	


#if 0



	//while (g_state == 0) {
	{


#if 0 /* disable OPENHIP implemenation */
		/* periodic select loop */
		gettimeofday(&now, NULL); /* XXX does this cause perf. hit? */
		FD_ZERO(&fd);
		FD_SET((unsigned)readsp[1], &fd);
#ifdef __MACOSX__
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;
#else
		timeout.tv_sec = 0;
		timeout.tv_usec = g_read_usec;
#endif
		if ((err = select(readsp[1]+1, &fd, NULL, NULL, &timeout))< 0) {
#ifdef __WIN32__
			if (WSAGetLastError() == WSAEINTR)
#else
			if (errno == EINTR)
#endif
				continue;
			HIP_DEBUG("hip_esp_output(): select() error\n");
		} else if (err == 0) {
			/* idle cycle */
			continue;
		}

		/* output data on socket */
		memset(raw_buff, 0, sizeof(raw_buff));
		memset(data, 0, sizeof(data));
		memset(lsi, 0, sizeof(struct sockaddr_storage));

#ifdef __WIN32__
		if ((len = recv(readsp[1], raw_buff, BUFF_LEN, 0)) == SOCKET_ERROR) {
			if (WSAGetLastError() == WSAEINTR)
#else
		if ((len = read(readsp[1], raw_buff, BUFF_LEN)) < 0) {
			if (errno == EINTR)
#endif
				continue;
			HIP_DEBUG("hip_esp_output(): read() failed: %s\n",
				  strerror(errno));
			exit(0);
		}
#endif /* 0 */
			
			/* 
			 * IPv4 
			 */
			if ((raw_buff[12] == 0x08) && (raw_buff[13] == 0x00)) {
				iph = (struct ip*) &raw_buff[14];
				/* accept IPv4 traffic to 1.x.x.x here */
				if (((iph->ip_v) == IPVERSION) &&
#if defined(__MACOSX__) && defined(__BIG_ENDIAN__)
				    (iph->ip_dst.s_addr >> 24 & 0xFF)!=0x01)
#else
					(iph->ip_dst.s_addr & 0xFF)!=0x01)
#endif
			
			     /*  continue; */
			    return;
										      
			    lsi_ip = ntohl(iph->ip_dst.s_addr);
			    lsi->sa_family = AF_INET;
			    LSI4(lsi) = lsi_ip;
			    is_broadcast = 0;
			
			/* We do not have broadcast packets,  added by Tao
			Wan on 27th, Feb */
			/* broadcast packets */
					
        
		// if ((lsi_ip & 0x00FFFFFF)==0x00FFFFFF) {
		//		if (!do_bcast())
		//			continue;
				/* unicast the broadcast to each entry */
		//		entry = hip_sadb_get_next(NULL);
		//		is_broadcast = TRUE;
			
		//	} 


                      /* unicast packets */
			if (!(entry = hip_sadb_lookup_addr(lsi))) {
		/* No SADB entry. Send ACQUIRE if we haven't
		* already, i.e. a new lsi_entry was created */
				if (buffer_packet(lsi, raw_buff, len))
					pfkey_send_acquire(lsi);
				// continue;
				return;
			}
			raw_len = len;
			while (entry) {
				pthread_mutex_lock(&entry->rw_lock);
#ifdef RAW_IP_OUT
				offset = sizeof(struct ip);
#else
				offset = 0;
#endif
				err = hip_esp_encrypt(raw_buff, raw_len,
					&data[offset], &len, entry, &now);
				pthread_mutex_unlock(&entry->rw_lock);
				if (err) {
					if (!is_broadcast)
						break;
					entry=hip_sadb_get_next(entry);
					continue;
				}
				flags = 0;
				/* catch empty entries */
				if (!entry->src_addrs || !entry->dst_addrs)
					continue;	
#ifdef RAW_IP_OUT
				/* Build IPv4 header and send out raw socket.
				 * Use this to override OS source address
				 * selection problems.
				 */
				add_ipv4_header(data,
					ntohl(LSI4(&entry->src_addrs->addr)), 
					ntohl(LSI4(&entry->dst_addrs->addr)), 
					(struct ip*)
					&raw_buff[sizeof(struct eth_hdr)],
					sizeof(struct ip) + len,
					IPPROTO_ESP);
				err = sendto(s_raw, data, 
					sizeof(struct ip) + len, flags,
					SA(&entry->dst_addrs->addr),
					SALEN(&entry->dst_addrs->addr));
#else
#ifdef __MACOSX__ 
/*I need to build an IP header and write it to a different address!*/
			/* TODO: use offset above, and LSI4 macro instead
			 *       of calls to inet_addr()
			 */
				memmove(&data[20],&data,len);
				saddr = inet_addr(
					logaddr((struct sockaddr*)&entry->src_addrs->addr));
				daddr = inet_addr(
					logaddr((struct sockaddr*)&entry->dst_addrs->addr));
				
				add_outgoing_esp_header(data, saddr,daddr,len);
				
				err=sendto(s_esp,data,len+sizeof(struct ip),flags,0,0);
				if(err < 0)
					perror("sendto()");
#else /* __MACOSX__ */
				if (entry->mode == 3)
					s = s_esp_udp;
				else if (entry->dst_addrs->addr.ss_family ==
					 AF_INET)
					s = s_esp;
				else
					s = s_esp6;
				err = sendto(s, data, len, flags,
					     SA(&entry->dst_addrs->addr),
					     SALEN(&entry->dst_addrs->addr));
#endif /* __MACOSX__ */
#endif /* RAW_IP_OUT */
				if (err < 0) {
					HIP_DEBUG("hip_esp_output(): sendto() "
						  "failed: %s\n", strerror(errno));
				} else {
					pthread_mutex_lock(&entry->rw_lock);
					entry->bytes += sizeof(struct ip) + err;
					entry->usetime.tv_sec = now.tv_sec;
					entry->usetime.tv_usec = now.tv_usec;
					entry->usetime_ka.tv_sec = now.tv_sec;
					entry->usetime_ka.tv_usec = now.tv_usec;
					pthread_mutex_unlock(&entry->rw_lock);
				}
				/* broadcasts are unicast to each association */
				if (!is_broadcast)
					break;
				entry = hip_sadb_get_next(entry);
			} /* end while */
			/* 
			 * IPv6 
			 */
		} else if ((raw_buff[12] == 0x86) && (raw_buff[13] == 0xdd)) {
			ip6h = (struct ip6_hdr*) &raw_buff[14];
			/* accept IPv6 traffic to 2001:10::/28 here */
			if ((ip6h->ip6_vfc & 0xF0) != 0x60)
				// continue;
				return;
			/* Look for all-nodes multicast address */
			if (IN6_IS_ADDR_MC_LINKLOCAL(&ip6h->ip6_dst) &&
			    (ip6h->ip6_nxt == IPPROTO_ICMPV6)) {
				err = handle_nsol(raw_buff, len, data,&len,lsi);
				if (err)
					//continue;
					return;
#ifdef __WIN32__
				if (!WriteFile(tapfd, data, len, &lenin, 
							&overlapped)){
					HIP_DEBUG( "hip_esp_output WriteFile() " \
						"failed.\n");
				}
#else
				if (write(tapfd, data, len) < 0) {
					HIP_DEBUG( "hip_esp_output write() " \
						"failed.\n");
				}
#endif
				//continue;
				return;
			} else if (!IS_HIT(&ip6h->ip6_dst)) {
				// continue;
				return;
			}
			/* HIT prefix */
			lsi->sa_family = AF_INET6;
			memcpy(SA2IP(lsi), &ip6h->ip6_dst, SAIPLEN(lsi));
			if (!(entry = hip_sadb_lookup_addr(lsi))) {
				/* No SADB entry. Send ACQUIRE if we haven't
				 * already, i.e. a new lsi_entry was created */
				if (buffer_packet(lsi, raw_buff, len))
					pfkey_send_acquire(lsi);
				//continue;
				return;
			} 
			raw_len = len;
			pthread_mutex_lock(&entry->rw_lock);
			err = hip_esp_encrypt(raw_buff, raw_len,
					      data, &len, entry, &now);
			pthread_mutex_unlock(&entry->rw_lock);
			flags = 0;
			if (entry->mode == 3)
				s = s_esp_udp;
			else if (entry->dst_addrs->addr.ss_family == AF_INET)
				s = s_esp;
			else
				s = s_esp6;
			err = sendto(	s, data, len, flags, 
					SA(&entry->dst_addrs->addr), 
					SALEN(&entry->dst_addrs->addr));
			if (err < 0) {
				HIP_DEBUG("hip_esp_output IPv6 sendto() failed:"
					" %s\n",strerror(errno));
			} else {
				pthread_mutex_lock(&entry->rw_lock);
				entry->bytes += sizeof(struct ip6_hdr) + err;
				entry->usetime.tv_sec = now.tv_sec;
				entry->usetime.tv_usec = now.tv_usec;
				pthread_mutex_unlock(&entry->rw_lock);
			}
		/* 
		 * ARP 
		 */
		} else if ((raw_buff[12] == 0x08) && (raw_buff[13] == 0x06)) {
			err = handle_arp(raw_buff, len, data, &len, lsi);
			if (err)
				//continue;
				return;
#ifdef __WIN32__
			if (!WriteFile(tapfd, data, len, &lenin, &overlapped)){
				HIP_DEBUG("hip_esp_output WriteFile() failed.\n");
			}
#else
			if (write(tapfd, data, len) < 0) {
				HIP_DEBUG("hip_esp_output write() failed.\n");
			}
#endif
			/* Why send acquire during ARP? */
			/*if (!hip_sadb_lookup_addr(lsi))
				pfkey_send_acquire(lsi);*/
			// continue;
			return;
		} else {
			/* debug other eth headers here */
			/*int i;
			HIP_DEBUG("<unknown traffic> (len=%d)\n", len);
			for (i = 0; i < len; i++)
				HIP_DEBUG("%x", raw_buff[i] & 0xFF);
			HIP_DEBUG("\n");*/
			
		}
	
	}
	/* write some data to flush waiting TAP threads, speed up exit */
	data[0] = 0;
	len = 1;
#ifdef __WIN32__
	WriteFile(tapfd, data, len, &lenin, &overlapped);
	CloseHandle(tapfd);
#else
	write(tapfd, data, len);
	close(tapfd);
#endif
	

#endif /* end disable OPENHIP implementation */



	
	
 out_err:

	/* added by Tao Wan*/

	/* Reset the interface to wildcard or otherwise receiving
	   broadcast messages fails from the raw sockets. A better
	   solution would be to have separate sockets for sending
	   and receiving because we cannot receive a broadcast while
	   sending */ 
	

	
	HIP_DEBUG("Print out any erro message :%s\n",strerror(errno));

#ifdef USE_BINDING
	if (dst_is_ipv4) {
		ipv4_src_addr.sin_addr.s_addr = INADDR_ANY;
		ipv4_src_addr.sin_family = AF_INET;
		bind(ipv4_s_raw, (struct sockaddr *) &ipv4_binding, sa_size_v4);

		
	} else {
		struct in6_addr any = IN6ADDR_ANY_INIT;
		ipv6_src_addr.sin6_family = AF_INET6;
		ipv6_addr_copy(&ipv6_src_addr.sin6_addr, &any);
		bind(ipv6_s_raw, (struct sockaddr *) &ipv6_binding, sa_size_v6);
		
	}

#endif
	
	HIP_DEBUG("hip_esp_output() thread shutdown...\n");
	fflush(stdout);
	return (NULL);
	

// tunreader_shutdown();

#ifndef __WIN32__
	pthread_exit((void *) 0);
	return(NULL);
#endif
}
#endif


/*
 * hip_esp_input()
 *
 * The ESP input thread. Reads ESP packets from the network and decrypts
 * them, adding HIT or LSI headers and sending them out the TAP-Win32 interface.
 * Also, expires temporary LSI entries and retransmits buffered packets.
 */



/* This does not support HIPL ipsec userspace, it needs to write */


#ifdef __WIN32__
void hip_esp_input(void *arg)
#else
// void *hip_esp_input(void *arg)
/* beuff: raw encrypted data buffer 
 * len: /*length of buffer */
/* ss_lsi is the source ip address structure for hipl*/
int hip_esp_input(struct sockaddr *ss_lsi, u8 *buff, int len)
#endif
{
	int err = 0, max_fd, offset;
	int dec_len; /*lenth of HIT pairs + tcp header + payload */
	fd_set fd;
	struct timeval timeout, now;
	// __u8 buff[BUFF_LEN]; /* raw, encrypted data buffer */
	__u8 data[BUFF_LEN]; /* decrypted data buffer */
	// struct sockaddr_storage ss_lsi;
	struct sockaddr *lsi = (struct sockaddr*) ss_lsi;
	struct ip *iph;
	struct ip6_hdr *ip6_header;
	struct ip_esp_hdr *esph;
	hip_sadb_entry *inverse_entry;
	struct udphdr *udph;
	__u32 spi, seq_no;
	hip_sadb_entry *entry;
	int ipv4_s_raw = 0; /* ipv4 raw socket */
	int ipv6_s_raw = 0; /* ipv6 raw socket */
	int on;
	struct sockaddr_in6 *to_local_hit;
	socklen_t sa_size_v6 = sizeof(struct sockaddr_in6);
	struct ip6_hdr *test_ip6_hdr;
	struct tcphdr *test_tcphdr;

	HIP_DEBUG("open a raw socket! \n");

	/* hipl uses HITs,  open IPv6 raw socket 
	 * FIXME if using LSI
	 */

	ipv6_s_raw = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
	if (ipv6_s_raw < 0) {
		HIP_DEBUG("--- socket() error for ipv6 (HITs) raw socket in hip_esp_output\n");
	}
	on = 1;
	if (setsockopt(ipv6_s_raw, IPPROTO_IPV6, IP_HDRINCL, (char *)&on,
		       sizeof(on)) < 0) {
		HIP_DEBUG("*** setsockopt() error for raw socket in "
		  "hip_input_output\n");

	}

	
	HIP_DEBUG("what is the value of sa_family: %d\n", lsi->sa_family);


	memset(data, 0, sizeof(data)); /* memset zero */

	/* Firewall checking is it ipv4 or ipv6 address */



	HIP_HEXDUMP("hello: the whole packet\n", buff, len); 



	
	if (lsi->sa_family == AF_INET) {
		
		HIP_DEBUG("It is the IPv4 traffic\n");
		iph = (struct ip*) buff;

		
		/* ESP_OVER_UDP */

		HIP_HEXDUMP("hello: the IPv4 header\n", iph, sizeof(struct ip)); 
		
		udph = (struct udphdr*) (buff + sizeof(struct ip));

		HIP_HEXDUMP("hellp: the UDP header\n", udph, sizeof(struct udphdr));


		/*hard coded, FIXME offset with 8 bytes!!!!! */
		/* When Testing HIPL kernel IPsec and HIPL userspace it needs add
		 * 8 bytes. Why????????
		 */

		// esph = (struct ip_esp_hdr *) (((char *)udph) + sizeof(udphdr) + 8);
		esph = (struct ip_esp_hdr *) (((char *)udph) + sizeof(struct udphdr));
		
		


		if (((int)(len - sizeof(struct ip) - sizeof(struct udphdr)) ==
		     1) && (((__u8*)esph)[0] == 0xFF)) {
			HIP_DEBUG ("Keepalive packet received.\n");
			goto out_err;
		}
		
		HIP_HEXDUMP("hello: the whole esp packet\n", esph, len - sizeof(struct ip) - sizeof(struct udphdr));
		
		spi = ntohl(esph->spi);
		
		HIP_DEBUG("Input esp packet SPI value is 0x%x with UDP encapuslation\n", spi);
		seq_no 	= ntohl(esph->seq_no);
		if (!(entry = hip_sadb_lookup_spi(spi))) {
			HIP_DEBUG("Warning: SA not found for SPI 0x%x  with UDP encapuslation\n", spi);
			esph = (struct ip_esp_hdr *) (buff + sizeof(struct ip));
			spi = ntohl(esph->spi);
			seq_no 	= ntohl(esph->seq_no);
			HIP_DEBUG("Input esp packet SPI value is 0x%x\n", spi);
			if (!(entry = hip_sadb_lookup_spi(spi))) {
				HIP_DEBUG("Warning: SA not found for SPI 0x%x\n", spi);
				goto out_err;
			}
			
		}

	}
	

	
	/* FIXME when using IPv6 header*/


	if(lsi->sa_family == AF_INET6) {
		HIP_DEBUG("It is the IPv6 traffic\n");
		ip6_header = (struct ip6_hdr *) &buff[0];
		/*
		  udph = (udphdr*) &buff[sizeof(struct ip6_hdr)];
		esph = (struct ip_esp_hdr *) &buff[sizeof(struct ip6_hdr) + sizeof(udphdr)]
		*/
		
		esph = (struct ip_esp_hdr *) &buff[sizeof(struct ip6_hdr)];
		
		HIP_HEXDUMP("hello: the whole esp packet with UDP encapsulation\n", esph, 
			    len - sizeof(struct ip6_hdr));

		spi = ntohl(esph->spi);
	
		HIP_DEBUG("IPV6 input esp packet SPI value is 0x%x\n", spi);
		seq_no 	= ntohl(esph->seq_no);
		if (!(entry = hip_sadb_lookup_spi(spi))) {
			HIP_DEBUG("Warning: IPv6 SA not found for SPI 0x%xn", spi);
			goto out_err;
		}
		
		if (((int)(len - sizeof(struct ip6_hdr) - sizeof(struct udphdr)) ==
		     1) && (((__u8*)esph)[0] == 0xFF)) {
			HIP_DEBUG ("Keepalive packet received.\n");
			goto out_err;
		}

	}

	HIP_DEBUG("input entry->SPI value is 0x%x\n", entry->spi);
	
	if (!entry->inner_src_addrs) { 
		HIP_DEBUG("we do not have inner src addrs \n");
		goto out_err; 
	}
	


	/* THis only is used for multi-cast */
	

	/*
	while(entry) {	

	HIP_DEBUG_SOCKADDR("local inner addr ", &entry->inner_dst_addrs->addr);
	HIP_DEBUG_SOCKADDR("remote inner addr ", &entry->inner_src_addrs->addr);
	
		entry=hip_sadb_get_next(entry);
	}
	*/	

	HIP_DEBUG_SOCKADDR("local inner addr ",
			   (struct sockaddr *) &entry->inner_src_addrs->addr);
	HIP_DEBUG_SOCKADDR("remote inner addr ",
			   (struct sockaddr *) &entry->inner_dst_addrs->addr);
	
	
	if (!(inverse_entry = hip_sadb_lookup_addr(
		      SA( &entry->inner_src_addrs->addr )))) {
		
		HIP_DEBUG ("Corresponding sadb entry for "
			   "outgoing packets not found.\n");
		goto out_err;
	}

	
	HIP_DEBUG("destination port is %d\n", inverse_entry->dst_port);

	HIP_DEBUG("get src port from udp header is %d\n", ntohs(udph->source));
		  

	/*HIP_DEBUG ( "DST_PORT = %u\n", 
	 * inverse_entry->dst_port);*/
	if (inverse_entry->dst_port == 0) {
		HIP_DEBUG ("ESP channel - Setting dst_port "
			   "to %u\n",ntohs(udph->source));
		inverse_entry->dst_port = ntohs(udph->source);
	}
	
	pthread_mutex_lock(&entry->rw_lock);
	err = hip_esp_decrypt(buff, len, data, &offset, &dec_len,
			      entry, iph, &now);
	pthread_mutex_unlock(&entry->rw_lock);
	if (err) {
		HIP_DEBUG("HIP ESP decryption is not successful\n");
		goto out_err;
	}

	to_local_hit = (struct sockaddr_in6 *)  &entry->inner_src_addrs->addr;
	
	HIP_DEBUG_SOCKADDR("hip_esp_input: to_local HIT is", (struct sockaddr *) to_local_hit);

	HIP_HEXDUMP("hip_esp_input: content of HITs + TCP + payload:", data, 
		    dec_len); 
	
	/* Test contetnt of HITs + TCP + payload*/

	test_ip6_hdr = (struct ip6_hdr *) data;
	
	HIP_DEBUG_IN6ADDR("HIT pairs src hit: ", &test_ip6_hdr->ip6_src);
	HIP_DEBUG_IN6ADDR("HIT pairs dst hit: ", &test_ip6_hdr->ip6_dst);
	
	
	test_tcphdr  = (struct tcphdr *) &data[sizeof(struct ip6_hdr)];
	HIP_DEBUG("size of struct ipv6_hdr is: %d\n ", sizeof(struct ip6_hdr));


	HIP_HEXDUMP("hip_esp_input: content of HITs (IP header):", data, 
		    sizeof(struct ip6_hdr)); 
	HIP_HEXDUMP("hip_esp_input: rest of pakcet: TCP + payload:" ,
		    &data[sizeof(struct ip6_hdr)], 
		    dec_len - sizeof(struct ip6_hdr)); 


	HIP_DEBUG("hip_esp_input: TCP soruce port is %hu\n", ntohs(test_tcphdr->source));
	HIP_DEBUG("hip_esp_input: TCP dst port is %hu\n", ntohs(test_tcphdr->dest));
	
	
	
	
	/* Firewall will capture this again,	* deadloop should happen. FIXME:!!!
	*/
	err = sendto(ipv6_s_raw, data, dec_len, 0,
		     SA(to_local_hit),
		     SALEN(to_local_hit));
	
	if (err < 0)
		{	
			HIP_DEBUG("hip_esp_input IPv6 sendto() failed:"
				  " %s\n",strerror(errno));
			goto out_err;
			
		}

	HIP_DEBUG("DO I come here?\n");

#if 0 /*disable openhip implementation */

#ifdef __WIN32__
	DWORD lenin;
	OVERLAPPED overlapped = {0};
#endif
	g_read_usec = 1000000;
	
	HIP_DEBUG("hip_esp_input() thread started...\n");
	lsi->sa_family = AF_INET;
	get_preferred_lsi(lsi);
	g_tap_lsi = LSI4(lsi);
	
	while (g_state == 0) {
		gettimeofday(&now, NULL); /* XXX does this cause perf. hit? */
		FD_ZERO(&fd);
		FD_SET((unsigned)s_esp, &fd);
		FD_SET((unsigned)s_esp_udp, &fd);
#ifndef __WIN32__
		/* IPv6 ESP not available in Windows */
		FD_SET((unsigned)s_esp6, &fd);
		max_fd = maxof(3, s_esp, s_esp6, s_esp_udp);
#else
		max_fd = (s_esp > s_esp_udp) ? s_esp : s_esp_udp;
#endif
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;
		memset(buff, 0, sizeof(buff));
		memset(data, 0, sizeof(data));

		if ((err = select(max_fd+1, &fd, NULL, NULL, &timeout)) < 0 ) {
#ifdef __WIN32__
			if (WSAGetLastError() == WSAEINTR)
				continue;
			HIP_DEBUG("hip_esp_input(): select() error %d\n",
			       WSAGetLastError());
#else
			if (errno == EINTR)
				continue;
			HIP_DEBUG("hip_esp_input(): select() error %s\n",
			       strerror(errno));
#endif
		} else if (FD_ISSET(s_esp, &fd)) {
#ifdef __WIN32__
			len = recv(s_esp, buff, sizeof(buff), 0);
#else
			len = read(s_esp, buff, sizeof(buff));
#endif
			iph = (struct ip *) &buff[0];
			esph = (struct ip_esp_hdr *) &buff[sizeof(struct ip)];
			spi 	= ntohl(esph->spi);
			seq_no 	= ntohl(esph->seq_no);
			if (!(entry = hip_sadb_lookup_spi(spi))) {
				/*HIP_DEBUG("Warning: SA not found for SPI 0x%x\n",
					spi);*/
				continue;
			}

			pthread_mutex_lock(&entry->rw_lock);
			err = hip_esp_decrypt(buff, len, data, &offset, &len,
						entry, iph, &now);
			pthread_mutex_unlock(&entry->rw_lock);
			if (err)
				continue;

#ifdef __WIN32__
			if (!WriteFile(tapfd, &data[offset], len, &lenin,
					&overlapped)){
				HIP_DEBUG("hip_esp_input() WriteFile() failed.\n");
				continue;
			}
#else
			if (write(tapfd, &data[offset], len) < 0) {
				HIP_DEBUG("hip_esp_input() write() failed.\n");
			}
#endif
		} else if (FD_ISSET(s_esp_udp, &fd)) {
#ifdef __WIN32__
			len = recv(s_esp_udp, buff, sizeof(buff), 0);
#else
			len = read(s_esp_udp, buff, sizeof(buff));
#endif

			/* XXX clean this up XXX */
			iph = (struct ip*) &buff[0];
			udph = (struct udphdr*) &buff[sizeof(struct ip)];
			esph = (struct ip_esp_hdr *) \
				&buff[sizeof(struct ip)+sizeof(struct udphdr)];

			if (((int)(len - sizeof(struct ip) - sizeof(struct udphdr)) ==
				1) && (((__u8*)esph)[0] == 0xFF)) {
				HIP_DEBUG ("Keepalive packet received.\n");
				continue;
			}
			spi 	= ntohl(esph->spi);
			seq_no 	= ntohl(esph->seq_no);
			if (!(entry = hip_sadb_lookup_spi(spi))) {
				/*HIP_DEBUG("Warning: SA not found for SPI 0x%x\n",
					spi);*/
				continue;
			}

			if (!entry->inner_src_addrs)
				continue;

			if (!(inverse_entry = hip_sadb_lookup_addr(
				SA( &(entry->inner_src_addrs->addr) )))) {
				HIP_DEBUG ("Corresponding sadb entry for "
					"outgoing packets not found.\n");
				continue;
			}
			/*HIP_DEBUG ( "DST_PORT = %u\n", 
			 * inverse_entry->dst_port);*/
			if (inverse_entry->dst_port == 0) {
				HIP_DEBUG ("ESP channel - Setting dst_port "
					"to %u\n",ntohs(udph->source));
				inverse_entry->dst_port = ntohs(udph->source);
			}

			pthread_mutex_lock(&entry->rw_lock);
			err = hip_esp_decrypt(buff, len, data, &offset, &len,
						entry, iph, &now);
			pthread_mutex_unlock(&entry->rw_lock);
			if (err)
				continue;

			if (len==35 && data[34]==0xFF) {
				HIP_DEBUG ("Reception of udp-tunnel activation "
					"packet for spi:0x%x.\n",
					inverse_entry->spi);
				if (ntohs(udph->source) != 0) {
					HIP_DEBUG ("ESP channel : Updating "
						"dst_port: %u=>%u.\n",
						inverse_entry->dst_port,
						ntohs(udph->source));
					inverse_entry->dst_port = 
						ntohs( udph->source );
				}
				continue;
			}
			if (inverse_entry->dst_port != ntohs(udph->source)) {
				HIP_DEBUG ("ESP channel : unexpected change of "
					"dst_port : %u=>%u\n",
					inverse_entry->dst_port,
					ntohs( udph->source ));
				inverse_entry->dst_port = ntohs(udph->source);
			}
			 
#ifdef __WIN32__
			if (!WriteFile(tapfd, &data[offset], len, &lenin, 
				&overlapped)){
				HIP_DEBUG("hip_esp_input() WriteFile() failed.\n");
				continue;
			}
#else
			if (write(tapfd, &data[offset], len) < 0) {
				HIP_DEBUG("hip_esp_input() write() failed.\n");
			}
#endif

#ifndef __WIN32__
		} else if (FD_ISSET(s_esp6, &fd)) {
			len = read(s_esp6, buff, sizeof(buff));
			/* there is no IPv6 header supplied */
#ifdef DEBUG_EVERY_PACKET
			fHIP_DEBUG(debugfp, "read() %d bytes\n", len);
#endif

			esph = (struct ip_esp_hdr *) &buff[0];
			spi 	= ntohl(esph->spi);
			seq_no 	= ntohl(esph->seq_no);
			if (!(entry = hip_sadb_lookup_spi(spi))) {
				HIP_DEBUG("Warning: SA not found for SPI 0x%x\n",
					spi);
				continue;
			}
			pthread_mutex_lock(&entry->rw_lock);
			err = hip_esp_decrypt(buff, len, data, &offset, &len,
						entry, NULL, &now);
			pthread_mutex_unlock(&entry->rw_lock);
			if (err)
				continue;
			if (write(tapfd, &data[offset], len) < 0) {
				HIP_DEBUG("hip_esp_input() write() failed.\n");
			}
#endif /* !__WIN32__ */
		} else if (err == 0) {
			/* idle cycle */
			hip_remove_expired_lsi_entries();
			hip_remove_expired_sel_entries();
			/* TODO: implement SA timeout here */
		}
	}

	HIP_DEBUG("hip_esp_input() thread shutdown.\n");
	fflush(stdout);
#ifndef __WIN32__
	pthread_exit((void *) 0);
	return 0;
#endif

#endif /* the endif of disable openhip implementation */

 out_err:
	
	HIP_DEBUG("hip_esp_input() thread shutdown.\n");
	fflush(stdout);
	return err;
}

#if 0
void *udp_esp_keepalive (void *arg) {
	int i, err;
	hip_sadb_dst_entry *entry;
	struct timeval now;
	__u8 buff[9];
	struct udphdr *udph;
	__u8 *data;
	

	HIP_DEBUG("udp_esp_keepalive() thread started...\n");

	memset(buff,0,sizeof(buff));
	udph = (struct udphdr*) buff;
	data = &buff[sizeof(struct udphdr)];
	udph->source = htons(HIP_ESP_UDP_PORT);
	udph->len = htons((__u16) 9);
	udph->check = 0;
	data[0]=0xFF;

	while (g_state == 0) {
		gettimeofday(&now, NULL);

		for (i=0; i < SADB_SIZE; i++) {
			for (	entry = &hip_sadb_dst[i]; 
				entry && entry->sadb_entry; 
				entry=entry->next	) {
				if (entry->sadb_entry->mode != 3) {
					/*HIP_DEBUG ("Keepalive test for non-"
					 * 	"BEET-mode entry.\n");*/
					continue;
				}
				if (entry->sadb_entry->direction != 2) {
					/*HIP_DEBUG ("Keepalive test for non-"
					 * 	"outgoing entry.\n");*/
					continue;
				}
				if (entry->sadb_entry->dst_port == 0) {
					/*HIP_DEBUG("Keepalive test : bad "
					 * "dst_port.\n"); */
					continue;
				}
				/*HIP_DEBUG ("Keepalive test for BEET-mode "
				 * 	"outgoing entry.\n");*/
				/* XXX TODO: clean this up */
				if (entry->sadb_entry->usetime_ka.tv_sec + 
						HIP_KEEPALIVE_TIMEOUT < now.tv_sec) {
					udph->dest = htons (entry->sadb_entry->dst_port);
					err = sendto(s_esp_udp, buff, sizeof(buff), 0,
						(struct sockaddr*)&entry->sadb_entry->dst_addrs->addr,
						SALEN(&entry->sadb_entry->dst_addrs->addr));
					if (err < 0) {
						HIP_DEBUG("Keepalive sendto() failed: %s\n",
							strerror(errno));
					} else {
						/*HIP_DEBUG("Keepalive sent.\n");*/
						entry->sadb_entry->bytes += sizeof(struct ip) + err;
						entry->sadb_entry->usetime_ka.tv_sec = now.tv_sec;
						entry->sadb_entry->usetime_ka.tv_usec = now.tv_usec;
					}
					udph->dest = 0;
				}
			}
		}
		hip_sleep(1);
	}
	HIP_DEBUG("udp_esp_keepalive() thread shutdown.\n");

	pthread_exit((void *) 0);
	return (NULL);
}
#endif

/*
void reset_sadbentry_udp_port (__u32 spi_out)
{
	hip_sadb_entry *entry;
	entry = hip_sadb_lookup_spi (spi_out);
	if (entry) {
		entry->dst_port = 0;
		HIP_DEBUG ("SADB-entry dst_port reset for spi: 0x%x.\n",spi_out);
	}
}
*/

int send_udp_esp_tunnel_activation (__u32 spi_out)
{
#if 0
	hip_sadb_entry *entry;
	struct timeval now;
	int err, len;
	int raw_len = 35 ;
	__u8 raw_buff[35];
	__u8 *payload;
	struct ip *iph;
	__u8 data[BUFF_LEN];

	memset(raw_buff,0,sizeof(raw_buff));
	iph = (struct ip*) &raw_buff[14];
	iph->ip_p = IPPROTO_RAW;
	payload = &raw_buff[34];
	payload[0]=0xFF;

/* ugly hack... 
 * since there is no "ACK" from the responder to signal that its SADB is 
 * uptodate, the "moving" initiator sends the activation packet directly
 * after its own SADB is updated... */
/* so this hack just add a small delay */
/* wait 0.2sec to give enough time to the peer for finishing the SADB update */
#ifdef __WIN32__
	Sleep(200);
#else
	struct timespec delay;
	delay.tv_sec = 0 ;
	delay.tv_nsec = 200000000;
	nanosleep (&delay, NULL);
#endif
/* end of ugly hack :-) */

	gettimeofday(&now, NULL);

	entry = hip_sadb_lookup_spi (spi_out);

	if (entry) {
		if (entry->mode != 3) {
			return(-1);
		}
		if (entry->direction != 2) {
			return(-1);
		}
		if (entry->dst_port == 0) {
			return(-1);
		}

		pthread_mutex_lock(&entry->rw_lock);
		err = hip_esp_encrypt(raw_buff, raw_len, data, 
					&len, entry, &now);
		pthread_mutex_unlock(&entry->rw_lock);
		if (err) {
			HIP_DEBUG ("Error in send_udp_esp_tunnel_activation(). "
				"hip_esp_encrypt failed.\n");
			return (-1);
		}
		err = sendto(s_esp_udp, data, len, 0,
			(struct sockaddr*)&entry->dst_addrs->addr,
			SALEN(&entry->dst_addrs->addr));
		if (err < 0) {
			HIP_DEBUG("send_udp_esp_tunnel_activation sendto() "
				"failed: %s\n",
				strerror(errno));
			return (-1);
		} else {
			HIP_DEBUG("send_udp_esp_tunnel_activation packet sent.\n");
			entry->bytes += sizeof(struct ip) + err;
			entry->usetime_ka.tv_sec = now.tv_sec;
			entry->usetime_ka.tv_usec = now.tv_usec;
			return (0);
		}
	}
#endif
	return (-1);
}

/*
 * handle_nsol()
 * 
 * Handle ICMPv6 Neighbor Solicitations for HITs.
 * Right now this is called from the esp_output thread when an 
 * application wants to send data to a HIT.
 */
int handle_nsol(__u8 *in, int len, __u8 *out, int *outlen,struct sockaddr *addr)
{
	struct eth_hdr *eth = (struct eth_hdr*)in;
	struct ip6_hdr *ip6h = (struct ip6_hdr*) &in[sizeof(struct eth_hdr)];
	__u64 esrc=0, edst=0;
	struct icmp6_hdr *nsol, *nadv;
	struct in6_addr *target, *adv_target;
	struct nd_opt_hdr *adv_target_opts;
	__u8 *p;
	__u16 payload_len;
	int location;
	struct sockaddr_storage src_ss;
	struct sockaddr_storage dst_ss;
	struct sockaddr *src = (struct sockaddr *) &src_ss;
	struct sockaddr *dst = (struct sockaddr *) &dst_ss;

	nsol = (struct icmp6_hdr *)&in[ sizeof(struct eth_hdr) + 
					sizeof(struct ip6_hdr) ];

	/* Only allow ICMPv6 Neighbor Soliciations for HITs */
	if (nsol->icmp6_type != ND_NEIGHBOR_SOLICIT)
		return(1);
	target = (struct in6_addr*) (nsol + 1);
	if (!IS_HIT(target)) /* target must be HIT */
		return(1);
	/* don't answer requests for self */
	src->sa_family = AF_INET6;
	get_preferred_lsi(src);
#ifdef __MACOSX__
/* XXX portability issue with the macro IN6_ARE_ADDR_EQUAL*/
	if (IN6_ARE_ADDR_EQUAL(target, &((struct sockaddr_in6*)src)->sin6_addr))
		return(1);
#else
	if (IN6_ARE_ADDR_EQUAL(target, SA2IP(src)))
		return(1);
#endif

	/* for now, replied MAC addr  */
	esrc = get_eth_addr(AF_INET6, &target->s6_addr[0]);
	memcpy(&edst, eth->src, 6);
	add_eth_header(out, esrc, edst, 0x86dd);
	location = sizeof(struct eth_hdr);

	/* IPv6 header added after length is calculated */
	memset(src, 0, sizeof(struct sockaddr_storage));
	memset(dst, 0, sizeof(struct sockaddr_storage));
	src->sa_family = AF_INET6;
	memcpy(SA2IP(src), &target->s6_addr[0], sizeof(struct in6_addr));
	dst->sa_family = AF_INET6;
	memcpy(SA2IP(dst), &ip6h->ip6_src.s6_addr[0], sizeof(struct in6_addr));
	location += sizeof(struct ip6_hdr);
	
	/* build neighbor advertisement reply */
	nadv = (struct icmp6_hdr *)&out[location];
	nadv->icmp6_type = ND_NEIGHBOR_ADVERT;
	nadv->icmp6_code = 0;
	nadv->icmp6_cksum = 0;
	nadv->icmp6_data32[0] = ND_NA_FLAG_SOLICITED | ND_NA_FLAG_OVERRIDE;
	location += sizeof(struct icmp6_hdr);
	adv_target = (struct in6_addr*) &out[location];
	memcpy(adv_target, target, sizeof(struct in6_addr));
	location += sizeof(struct in6_addr);
	adv_target_opts = (struct nd_opt_hdr*) &out[location];
	adv_target_opts->nd_opt_type = ND_OPT_TARGET_LINKADDR;
	adv_target_opts->nd_opt_len = 1; /* 1x(8 octets) */
	location += sizeof(struct nd_opt_hdr);
	memcpy(&out[location], &esrc, 6);
	location += 6;

	/* return the HIT */
	if (addr)
		memcpy(addr, src, sizeof(struct sockaddr_storage));
	
	/* pseudo-header for upper-layer checksum calculation */
	p = (__u8*)nadv - 40;
	payload_len = &out[location] - (__u8*)nadv;
	add_ipv6_pseudo_header(p, src, dst, (__u32)payload_len, IPPROTO_ICMPV6);
	nadv->icmp6_cksum = ip_fast_csum(p, &out[location] - p);
	/* real IPv6 header */
	add_ipv6_header(&out[sizeof(struct eth_hdr)], src, dst, ip6h, NULL,
			payload_len, IPPROTO_ICMPV6);

	*outlen = location;
	return(0);
}


#ifdef CURRENTLY_UNUSED
extern __u32 get_preferred_addr();
/*
 * handle_broadcasts()
 *
 * This code leaks broadcast packets outside of the association.
 * Unfortunately, the receiving end will see a different source address
 * (not the source LSI) so the packet may be meaningless.
 */
void handle_broadcasts(__u8 *data, int len)
{
	struct ip iph_old;
	struct sockaddr_in to;
	int s, val;
	__u8 proto, mdata[32];
	__u16 magic;
	__u32 src_ip, dst_ip;
	__u64 sum;
	
	/* save IPv4 header before it is zeroed */
	memcpy(&iph_old, &data[14], sizeof(struct ip));
	proto = iph_old.ip_p;
	len -= 14; /* subtract eth header */

	/* 
	 * form a broadcast address, fixup TCP/UDP checksum
	 */
	src_ip = get_preferred_addr();
	if (!src_ip)	/* preferred address not found! */
		return;
	dst_ip = src_ip | 0xFF000000L;
	
	/* IP header */
	memset(mdata, 0, sizeof(mdata));
	memcpy(&mdata[0], &src_ip, sizeof(src_ip));
	memcpy(&mdata[16], &dst_ip, sizeof(dst_ip));
	sum = htonl(src_ip) + htonl(dst_ip);
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);
	magic = (__u16)sum;
	magic = htons(magic+1);
	rewrite_checksum(&data[14], magic);

	/* 
	 * send it out on a raw socket 
	 */
	memset(&to, 0, sizeof(to));
	to.sin_family = AF_INET;
	to.sin_addr.s_addr = dst_ip;

	s = socket(PF_INET, SOCK_RAW, proto);
	val = 1;
	setsockopt(s, SOL_SOCKET, SO_BROADCAST, &val, sizeof(val));
	if (sendto(s, &data[34], len, 0, 
	    (struct sockaddr *)&to, sizeof(to)) < 0) {
		HIP_DEBUG("broadcast sendto() failed: proto=%d len=%d err:%s\n",
			proto, len, strerror(errno));
	}
	close(s);
}
#endif



/*
 * hip_esp_encrypt()
 * 
 * in:	in	pointer of data to encrypt
 * 		len	length of data
 * 		out	pointer of where to store encrypted data
 * 		outlen	returned length of encrypted data
 * 		entry 	the SADB entry
 *
 * out:	Encrypted data in out, outlen. entry statistics are modified.
 * 		Returns 0 on success, -1 otherwise.
 * 
 * Perform actual ESP encryption and authentication of packets.
 */
int hip_esp_encrypt(__u8 *in, int len, __u8 *out, 
	hip_sadb_entry *entry, struct timeval *now, int *outlen)
{
#if 0
	/* length of data to auth */
	int alen=0;
	/* elen is length of data to encrypt */
	elen=0;
	unsigned int hmac_md_len;
	int i, iv_len=0, padlen, location, eth_ip_hdr_len;
	struct ip *iph=NULL;
	struct ip6_hdr *ip6h=NULL;
	struct ip_esp_hdr *esp;
	udphdr *udph = NULL;

	struct ip_esp_padinfo *padinfo=0;
	__u8 cbc_iv[16];
	__u8 hmac_md[EVP_MAX_MD_SIZE];
	
	padlen = 0;

	/* 
	 * Encryption 
	 */

	/* Check keys and set IV length */
	switch (entry->e_type)
	{
		case SADB_EALG_3DESCBC:
			iv_len = 8;
			if (!entry->e_key || entry->e_keylen==0) {
				HIP_DEBUG("hip_esp_encrypt: 3-DES key missing.\n");
				return(-1);
			}
			break;
		case SADB_X_EALG_BLOWFISHCBC:
			iv_len = 8;
			if (!entry->bf_key) {
				HIP_DEBUG("hip_esp_encrypt: BLOWFISH key missing.\n");
				return(-1);
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
					HIP_DEBUG("hip_esp_encrypt: AES key problem!\n");
				}
			} else if (!entry->aes_key) {
				HIP_DEBUG("hip_esp_encrypt: AES key missing.\n");
				return(-1);
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
			return(-1);
			break;
	}

	// TODO set elen (hip_esp_output)
	
	/* Add initialization vector (random value) */
	if (iv_len > 0) {
		RAND_bytes(cbc_iv, iv_len);
		memcpy(esp->enc_data, cbc_iv, iv_len);
		padlen = iv_len - ((elen + 2) % iv_len);
	} else {
		/* Padding with NULL not based on IV length */
		padlen = 4 - ((elen + 2) % 4);
	}
	
	/* add padding to input data, set padinfo */
	location = eth_ip_hdr_len + elen;
	for (i=0; i<padlen; i++)
		in[location + i] = i+1;
	padinfo = (struct ip_esp_padinfo*) &in[location + padlen];
	padinfo->pad_length = padlen;
	padinfo->next_hdr = (family == AF_INET) ? iph->ip_p : ip6h->ip6_nxt;
	/* padinfo is encrypted too */
	elen += padlen + 2;
	
	/* Apply the encryption cipher directly into out buffer
	 * to avoid extra copying */
	switch (entry->e_type)
	{
		case SADB_EALG_3DESCBC:
			des_ede3_cbc_encrypt(&in[eth_ip_hdr_len],
					     &esp->enc_data[iv_len], elen,
					     entry->ks[0], entry->ks[1], entry->ks[2],
					     (des_cblock*)cbc_iv, DES_ENCRYPT);
			break;
		case SADB_X_EALG_BLOWFISHCBC:
			BF_cbc_encrypt(&in[eth_ip_hdr_len],
					&esp->enc_data[iv_len], elen,
					entry->bf_key, cbc_iv, BF_ENCRYPT);
			break;
		case SADB_EALG_NULL:
			memcpy(esp->enc_data, &in[eth_ip_hdr_len], elen);
			break;
		case SADB_X_EALG_AESCBC:
			AES_cbc_encrypt(&in[eth_ip_hdr_len], 
					&esp->enc_data[iv_len], elen, 
					entry->aes_key, cbc_iv, AES_ENCRYPT);
			break;
		default:
			break;
	}
	elen += iv_len; /* auth will include IV */
	*outlen += elen;
	
	/* 
	 * Authentication 
	 */
	switch (entry->a_type)
	{
		case SADB_AALG_NONE:
			break;
		case SADB_AALG_MD5HMAC:
			alen = HMAC_SHA_96_BITS / 8; /* 12 bytes */
			if (!entry->a_key || entry->a_keylen==0) {
				HIP_DEBUG("auth err: missing keys\n");
				return(-1);
			}
			elen += sizeof(struct ip_esp_hdr);
			HMAC(	EVP_md5(), entry->a_key, entry->a_keylen,
				(__u8*)esp, elen, hmac_md, &hmac_md_len);
			memcpy(&out[elen + (use_udp ? sizeof(udphdr) : 0)], 
				hmac_md, alen);
			*outlen += alen;
			break;
		case SADB_AALG_SHA1HMAC:
			alen = HMAC_SHA_96_BITS / 8; /* 12 bytes */
			if (!entry->a_key || entry->a_keylen==0) {
				HIP_DEBUG("auth err: missing keys\n");
				return(-1);
			}
			elen += sizeof(struct ip_esp_hdr);
	#ifdef DEBUG_EVERY_PACKET
			fprintf(debugfp, "SPI=0x%x out a_key(%d): 0x",
				entry->spi, entry->a_keylen);
			for (i=0; i < entry->a_keylen; i++) {
				if (i%4==0) fprintf(debugfp, " ");
				fprintf(debugfp,"%.2x",entry->a_key[i] & 0xFF);
			}
			fprintf(debugfp, "\n");
	#endif /* DEBUG_EVERY_PACKET */
			HMAC(	EVP_sha1(), entry->a_key, entry->a_keylen,
				(__u8*)esp, elen, hmac_md, &hmac_md_len);
			memcpy(&out[elen + (use_udp ? sizeof(udphdr) : 0)],
				hmac_md, alen);
			*outlen += alen;
	#ifdef DEBUG_EVERY_PACKET
			fprintf(debugfp, "SHA1: (pkt %d) 0x", *outlen);
			for (i=0; i < alen; i++) {
				if (i%4==0) fprintf(debugfp, " ");
				fprintf(debugfp, "%.2x", hmac_md[i] & 0xFF);
			}
			fprintf(debugfp, "\n");
			fprintf(debugfp, "bytes(%d): ", elen);
			for (i=0; i < elen; i++) {
				if (i && i%8==0) fprintf(debugfp, " ");
				fprintf(debugfp, "%.2x",((__u8*)esp)[i] & 0xFF);
			}
			fprintf(debugfp, "\n\n");
	#endif /* DEBUG_EVERY_PACKET */
			break;
		case SADB_X_AALG_SHA2_256HMAC:
		case SADB_X_AALG_SHA2_384HMAC:
		case SADB_X_AALG_SHA2_512HMAC:
		case SADB_X_AALG_RIPEMD160HMAC:
		case SADB_X_AALG_NULL:
			break;
		default:
			break;
	}
		
#endif
	return(0);
}




#if 0
/* rewrite this function to fit the hipl ipsec implementation*/
int hip_esp_encrypt(__u8 *in, int len, __u8 *out,  
	hip_sadb_entry *entry, struct timeval *now, int *outlen)
{
	int alen=0, elen=0;
	unsigned int hmac_md_len;
	int i, iv_len=0, padlen, location, eth_ip_hdr_len;
	struct ip *iph=NULL;
	struct ip6_hdr *ip6h=NULL;
	struct ip_esp_hdr *esp;
	struct udphdr *udph = NULL;

	struct ip_esp_padinfo *padinfo=0;
	__u8 cbc_iv[16];
	__u8 hmac_md[EVP_MAX_MD_SIZE];
	__u16 checksum_fix = 0;
	int family, use_udp = 0;


	/* Because we do not have LSI support right now, so 
	 *  family is only equal to AF_INET6. FIXME!!!
	 *  checksum_fix is probably needed if using LSI.
	 *
	 */
	
	family = AF_INET6;
	


/* openHIP uses this hard coded that we do not want*/

#if 0 /* start 0*/
	if ((in[12] == 0x86) && (in[13] == 0xdd))
		family = AF_INET6;
	else
		family = AF_INET;
	
#endif /* end 0 */
	
	
	
	
	switch (family) {
	case AF_INET:
		iph = (struct ip*) &in[sizeof(struct eth_hdr)];
		eth_ip_hdr_len = sizeof(struct eth_hdr) + sizeof(struct ip);
		/* rewrite upper-layer checksum, so it is based on HITs */
		checksum_fix = rewrite_checksum((__u8*)iph, entry->hit_magic);
		break;
	case AF_INET6:
		
		
		/* FIXME, because __u8 *in is a packet, 
		 * len is the whole packet length
		 */
		
#if 0
		/*openhip implememtation does not suit for us*/
		ip6h = (struct ip6_hdr*) &in[sizeof(struct eth_hdr)];
		eth_ip_hdr_len = sizeof(struct eth_hdr)+sizeof(struct ip6_hdr);
		/* assume HITs are used as v6 src/dst, no checksum rewrite */
#endif 		
		/* For HIPL IPsec implementation */
		ip6h = (struct ip6_hdr*) in;
		eth_ip_hdr_len = sizeof(struct ip6_hdr);

		break;
	}

	/* elen is length of data to encrypt */
	elen = len - eth_ip_hdr_len;


	/*  HOW to make ESP OVER TCP, openhip use mode 3 for NAT 
	 *  transverse
	 *
	 */



	/* FOR HIPL */

	


	/* setup ESP header, common to all algorithms */


	if (entry->mode == 3) { /*(HIP_ESP_OVER_UDP)*/
		udph = (struct udphdr*) out;
		/*esp pointer points to out address*/
		esp = (struct ip_esp_hdr*) &out[sizeof(struct udphdr)]; 
		// esp += HIP_UDP_ZERO_BYTES_LEN;
		use_udp = 1;
	} else {
		esp = (struct ip_esp_hdr*) out;
	}
	esp->spi = htonl(entry->spi);
	esp->seq_no = htonl(entry->sequence++);
	padlen = 0;
	*outlen = sizeof(struct ip_esp_hdr);
	
	if (use_udp) /* (HIP_ESP_OVER_UDP) */
		// *outlen += (sizeof(udphdr)  + sizeof(HIP_UDP_ZERO_BYTES_LEN));
		*outlen += sizeof(struct udphdr);
		
	
	/* 
	 * Encryption 
	 */

	/* Check keys and set IV length */
	switch (entry->e_type) {
	case SADB_EALG_3DESCBC:
		iv_len = 8;
		if (!entry->e_key || entry->e_keylen==0) {
			HIP_DEBUG("hip_esp_encrypt: 3-DES key missing.\n");
			return(-1);
		}
		break;
	case SADB_X_EALG_BLOWFISHCBC:
		iv_len = 8;
		if (!entry->bf_key) {
			HIP_DEBUG("hip_esp_encrypt: BLOWFISH key missing.\n");
			return(-1);
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
				HIP_DEBUG("hip_esp_encrypt: AES key problem!\n");
			}
		} else if (!entry->aes_key) {
			HIP_DEBUG("hip_esp_encrypt: AES key missing.\n");
			return(-1);
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
		return(-1);
		break;
	}

	/* Add initialization vector (random value) */
	if (iv_len > 0) {
		RAND_bytes(cbc_iv, iv_len);
		memcpy(esp->enc_data, cbc_iv, iv_len);
		padlen = iv_len - ((elen + 2) % iv_len);
	} else {
		/* Padding with NULL not based on IV length */
		padlen = 4 - ((elen + 2) % 4);
	}
	/* add padding to input data, set padinfo */
	location = eth_ip_hdr_len + elen;
	for (i=0; i<padlen; i++)
		in[location + i] = i+1;
	padinfo = (struct ip_esp_padinfo*) &in[location + padlen];
	padinfo->pad_length = padlen;
	

	/* where is ip6h->ip6_nxt from? added by Tao Wan*/
	padinfo->next_hdr = (family == AF_INET) ? iph->ip_p : ip6h->ip6_nxt;
	/* padinfo is encrypted too */
	elen += padlen + 2;
	
	/* Apply the encryption cipher directly into out buffer
	 * to avoid extra copying */
	switch (entry->e_type) {
	case SADB_EALG_3DESCBC:
		des_ede3_cbc_encrypt(&in[eth_ip_hdr_len],
				     &esp->enc_data[iv_len], elen,
				     entry->ks[0], entry->ks[1], entry->ks[2],
				     (des_cblock*)cbc_iv, DES_ENCRYPT);
		break;
	case SADB_X_EALG_BLOWFISHCBC:
		BF_cbc_encrypt(&in[eth_ip_hdr_len],
				&esp->enc_data[iv_len], elen,
				entry->bf_key, cbc_iv, BF_ENCRYPT);
		break;
	case SADB_EALG_NULL:
		memcpy(esp->enc_data, &in[eth_ip_hdr_len], elen);
		break;
	case SADB_X_EALG_AESCBC:
		AES_cbc_encrypt(&in[eth_ip_hdr_len], 
				&esp->enc_data[iv_len], elen, 
				entry->aes_key, cbc_iv, AES_ENCRYPT);
		break;
	default:
		break;
	}
	elen += iv_len; /* auth will include IV */
	*outlen += elen;
	
	/* 
	 * Authentication 
	 */
	switch (entry->a_type) {
	case SADB_AALG_NONE:
		break;
	case SADB_AALG_MD5HMAC:
		alen = HMAC_SHA_96_BITS / 8; /* 12 bytes */
		if (!entry->a_key || entry->a_keylen==0) {
			HIP_DEBUG("auth err: missing keys\n");
			return(-1);
		}
		elen += sizeof(struct ip_esp_hdr);
		HMAC(	EVP_md5(), entry->a_key, entry->a_keylen,
			(__u8*)esp, elen, hmac_md, &hmac_md_len);
		memcpy(&out[elen + (use_udp ? sizeof(struct udphdr) : 0)], 
			hmac_md, alen);
		*outlen += alen;
		break;
	case SADB_AALG_SHA1HMAC:
		alen = HMAC_SHA_96_BITS / 8; /* 12 bytes */
		if (!entry->a_key || entry->a_keylen==0) {
			HIP_DEBUG("auth err: missing keys\n");
			return(-1);
		}
		elen += sizeof(struct ip_esp_hdr);
#ifdef DEBUG_EVERY_PACKET
		fprintf(debugfp, "SPI=0x%x out a_key(%d): 0x",
			entry->spi, entry->a_keylen);
		for (i=0; i < entry->a_keylen; i++) {
			if (i%4==0) fprintf(debugfp, " ");
			fprintf(debugfp,"%.2x",entry->a_key[i] & 0xFF);
		}
		fprintf(debugfp, "\n");
#endif /* DEBUG_EVERY_PACKET */
		HMAC(	EVP_sha1(), entry->a_key, entry->a_keylen,
			(__u8*)esp, elen, hmac_md, &hmac_md_len);
		memcpy(&out[elen + (use_udp ? sizeof(struct udphdr) : 0)],
			hmac_md, alen);
		*outlen += alen;
#ifdef DEBUG_EVERY_PACKET
		fprintf(debugfp, "SHA1: (pkt %d) 0x", *outlen);
		for (i=0; i < alen; i++) {
			if (i%4==0) fprintf(debugfp, " ");
			fprintf(debugfp, "%.2x", hmac_md[i] & 0xFF);
		}
		fprintf(debugfp, "\n");
		fprintf(debugfp, "bytes(%d): ", elen);
		for (i=0; i < elen; i++) {
			if (i && i%8==0) fprintf(debugfp, " ");
			fprintf(debugfp, "%.2x",((__u8*)esp)[i] & 0xFF);
		}
		fprintf(debugfp, "\n\n");
#endif /* DEBUG_EVERY_PACKET */
		break;
	case SADB_X_AALG_SHA2_256HMAC:
	case SADB_X_AALG_SHA2_384HMAC:
	case SADB_X_AALG_SHA2_512HMAC:
	case SADB_X_AALG_RIPEMD160HMAC:
	case SADB_X_AALG_NULL:
		break;
	default:
		break;
	}

	/* Record the address family of this packet, so incoming
	 * replies of the same protocol/ports can be matched to
	 * the same family.
	 */
	if (hip_add_proto_sel_entry(LSI4(&entry->lsi), 
				(__u8)(iph ? iph->ip_p : ip6h->ip6_nxt), 
				iph ? (__u8*)(iph+1) : (__u8*)(ip6h+1),
				family, 0, now	) < 0)
		HIP_DEBUG("hip_esp_encrypt(): error adding sel entry.\n");


	/* Restore the checksum in the input data, in case this is
	 * a broadcast packet that needs to be re-sent to some other
	 * destination.
	 */
	if (checksum_fix > 0) {
		if (iph->ip_p == IPPROTO_UDP)
#ifdef __MACOSX__
			((struct udphdr*)(iph + 1))->uh_sum = checksum_fix;
#else
			((struct udphdr*)(iph + 1))->check = checksum_fix;
#endif
		else if (iph->ip_p == IPPROTO_TCP)
#ifdef __MACOSX__
			((struct tcphdr*)(iph + 1))->th_sum = checksum_fix;
#else
			((struct tcphdr*)(iph + 1))->check = checksum_fix;
#endif
	}

	if (use_udp) { /* (HIP_ESP_OVER_UDP) */
		/* Set up UDP header at the beginning of out */
		memset (udph, 0, sizeof(struct udphdr));
		udph->source = htons(HIP_ESP_UDP_PORT);
		if ( (udph->dest = htons(entry->dst_port))==0) {
			HIP_DEBUG ("ESP encrypt : bad UDP dst port number (%u).\n",
				entry->dst_port);
		}
		udph->len = htons ((__u16)*outlen);
		udph->check = checksum_udp_packet (out, 
						   (struct sockaddr*)&entry->src_addrs->addr,
						   (struct sockaddr*)&entry->dst_addrs->addr);
	}
		
	return(0);
}
#endif

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

/*
 * hip_esp_decrypt()
 *
 * in:		in	pointer to IP header of ESP packet to decrypt
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
int hip_esp_decrypt(__u8 *in, int len, __u8 *out, int *offset, int *outlen,
    hip_sadb_entry *entry, struct ip *iph, struct timeval *now)
{
	int alen=0, elen=0, iv_len=0;
	unsigned int hmac_md_len;
	struct ip_esp_hdr *esp;
	struct udphdr *udph;

	struct ip_esp_padinfo *padinfo=0;
	struct tcphdr *tcp=NULL;
	struct udphdr *udp=NULL;
	__u8 cbc_iv[16];
	__u8 hmac_md[EVP_MAX_MD_SIZE];
	__u64 dst_mac;
	__u16 sum;
	int family_out;
	struct sockaddr_storage taplsi6;
	// struct sockaddr_storage hit_ip_hdr;

	struct sockaddr_in6 *src_hit;
	struct sockaddr_in6 *dst_hit;

	int use_udp = 0;
	
	if (!in || !out || !entry)
		return(-1);


	HIP_HEXDUMP("hello: the whole packet:", in, len);
	
	HIP_HEXDUMP("hello: the IP header:", in, sizeof (struct ip));

	if (entry->mode == 3) {	/*(HIP_ESP_OVER_UDP) */
		use_udp = 1;
		udph = (struct udphdr*) (in + sizeof(struct ip));
		
		
		HIP_HEXDUMP("hello: the udp header:", udph, 
			    sizeof(struct udphdr)); 
		
		/* hard code here, if the offset is added 8 more bytes  
		 * FIXME, why do we need that 8 more bytes?
		 *
		 * Why need add 8 bytes
		 *
		 */
		
		/*
		esp = (struct ip_esp_hdr*) (((char *) udph) + 
		                            sizeof(udphdr) +
					    8);
		*/
		
		esp = (struct ip_esp_hdr*) (((char *) udph) + 
		                         sizeof(struct udphdr));
		
	} else { 		
		/* Todo: Test if it is not UDP-encapsulated */
		/* not UDP-encapsulated */
		HIP_DEBUG("It does not use this HIP_ESP_OVER_UDP\n");

		if ( iph ) {	/* IPv4 */
			esp = (struct ip_esp_hdr*) &in[sizeof(struct ip)];
		} else { 	/* IPv6 - header not included */
			esp = (struct ip_esp_hdr*) &in[0];
		}
	}


	

	HIP_DEBUG("the decrypt SPI value is Ox%x\n", ntohl(esp->spi));


	HIP_DEBUG("ESP authtication type is %d\n", entry->a_type);
	HIP_DEBUG("ESP encryption type is %d\n", entry->e_type);
	
	
	
	HIP_DEBUG("Is the IPv6 or IPv4 address to sent: %s \n",  
		  (entry->dst_addrs->addr).ss_family == AF_INET ? 
		  "IPv4" : "IPv6");	
	
	


	/* if (ntohl(esp->spi) != entry->spi)
		return(-1); *//* this check might be excessive */

	/* An IPv6 header is larger than an IPv4 header, so data
	 * is decrypted into a buffer at the larger offset, since
	 * we do not know the (inner) IP version before decryption. */
	

	// *offset = sizeof(struct eth_hdr) + sizeof(struct ip6_hdr); /* 54 */


	/* since HIPL does not need test ethernet header here */
	
	 *offset = sizeof(struct ip6_hdr); 

	/* 
	 *   Authentication 
	 */
	switch (entry->a_type) {
	case SADB_AALG_NONE:
		break;
	case SADB_AALG_MD5HMAC:
		alen = HMAC_SHA_96_BITS / 8; /* 12 bytes */
		elen = len - sizeof(struct ip_esp_hdr) - alen;
		if (iph)
			elen -= sizeof(struct ip);
		if (use_udp) /* HIP_ESP_OVER_UDP */
			elen -= sizeof(struct udphdr);
		if (!entry->a_key || entry->a_keylen==0) {
			HIP_DEBUG("auth err: missing keys\n");
			return(-1);
		}
		HMAC(	EVP_md5(), entry->a_key, entry->a_keylen, 
			(__u8*)esp, elen + sizeof(struct ip_esp_hdr),
			hmac_md, &hmac_md_len);
		if (memcmp(&in[len - alen], hmac_md, alen) != 0) {
			HIP_DEBUG("auth err: MD5 auth failure\n");
			return(-1);
		}
		break;
	case SADB_AALG_SHA1HMAC:
		alen = HMAC_SHA_96_BITS / 8; /* 12 bytes */
		elen = len - sizeof(struct ip_esp_hdr) - alen;
		if (iph)
			elen -= sizeof(struct ip);
		if (use_udp) /* HIP_ESP_OVER_UDP */
			elen -= sizeof(struct udphdr);
		if (!entry->a_key || entry->a_keylen==0) {
			HIP_DEBUG("auth err: missing keys\n");
			return(-1);
		}
#ifdef DEBUG_EVERY_PACKET
		{ 
			int i;
			fprintf(debugfp, "SPI=0x%x in a_key(%d): 0x",
				entry->spi, entry->a_keylen);
			for (i=0; i < entry->a_keylen; i++) {
				if (i%4==0) fprintf(debugfp, " ");
				fprintf(debugfp,"%.2x",entry->a_key[i] & 0xFF);
			}
			fprintf(debugfp, "\n");
			fprintf(debugfp, "len=%d elen=%d alen=%d iph=%p use_udp=%d \n", len, elen, alen, iph, use_udp);
		}
#endif /* DEBUG_EVERY_PACKET */
		HMAC(	EVP_sha1(), entry->a_key, entry->a_keylen, 
			(__u8*)esp, elen + sizeof(struct ip_esp_hdr),
			hmac_md, &hmac_md_len);
#ifdef DEBUG_EVERY_PACKET
		{
			int i;
			fprintf(debugfp, "SHA1: 0x");
			for (i=0; i < alen; i++) {
				if (i%4==0) fprintf(debugfp, " ");
				fprintf(debugfp, "%.2x", hmac_md[i] & 0xFF);
			}
			fprintf(debugfp, "\n");
			fprintf(debugfp, "(pkt(%d): 0x", len);
			for (i=0; i < alen; i++) {
				if (i%4==0) fprintf(debugfp, " ");
				fprintf(debugfp, "%.2x", in[i+len-alen] & 0xFF);
			}
			fprintf(debugfp, ")\n");
			fprintf(debugfp, "bytes(%d): ", elen);
			for (i=0; i < elen; i++) {
				if (i && i%8==0) fprintf(debugfp, " ");
				fprintf(debugfp, "%.2x",((__u8*)esp)[i] & 0xFF);
			}
			fprintf(debugfp, "\n\n");
		}
#endif /* DEBUG_EVERY_PACKET */
		


		HIP_HEXDUMP("data from buffer: ", &in[len - alen], alen);
		HIP_HEXDUMP("data from hmac_md: ", hmac_md, alen);
		
		

		if (memcmp(&in[len - alen], hmac_md, alen) !=0) {
			HIP_DEBUG("auth err: SHA1 auth failure SPI=0x%x\n", 
				entry->spi);
			return(-1);
		}
		break;
	case SADB_X_AALG_SHA2_256HMAC:
	case SADB_X_AALG_SHA2_384HMAC:
	case SADB_X_AALG_SHA2_512HMAC:
	case SADB_X_AALG_RIPEMD160HMAC:
	case SADB_X_AALG_NULL:
		break;
	default:
		break;
	}
	
	/*
	 *   Decryption
	 */
	switch (entry->e_type) {
	case SADB_EALG_3DESCBC:
		iv_len = 8;
		if (!entry->e_key || entry->e_keylen==0) {
			HIP_DEBUG("hip_esp_decrypt: 3-DES key missing.\n");
			return(-1);
		}
		break;
	case SADB_X_EALG_BLOWFISHCBC:
		iv_len = 8;
		if (!entry->bf_key) {
			HIP_DEBUG("hip_esp_decrypt: BLOWFISH key missing.\n");
			return(-1);
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
				HIP_DEBUG("hip_esp_decrypt: AES key problem!\n");
			}
		} else if (!entry->aes_key) {
			HIP_DEBUG("hip_esp_decrypt: AES key missing.\n");
			return(-1);
		}
		break;
	case SADB_EALG_NONE:
	case SADB_EALG_DESCBC:
	case SADB_X_EALG_CASTCBC:
	case SADB_X_EALG_SERPENTCBC:
	case SADB_X_EALG_TWOFISHCBC:
	default:
		HIP_DEBUG("Unsupported decryption algorithm (%d)\n", 
			entry->e_type);
		break;
	}
	memcpy(cbc_iv, esp->enc_data, iv_len);
	elen -= iv_len; /* don't include iv as part of ciphertext */
	
	switch (entry->e_type) {
	case SADB_EALG_3DESCBC:
		des_ede3_cbc_encrypt(&esp->enc_data[iv_len], &out[*offset],elen,
				     entry->ks[0], entry->ks[1], entry->ks[2],
				     (des_cblock*)cbc_iv, DES_DECRYPT);
		break;
	case SADB_X_EALG_BLOWFISHCBC:
		BF_cbc_encrypt(&esp->enc_data[iv_len], &out[*offset], elen,
				entry->bf_key, cbc_iv, BF_DECRYPT);
		break;
	case SADB_EALG_NULL:
		memcpy(&out[*offset], esp->enc_data, elen);
		//padinfo = (struct ip_esp_padinfo*) &in[len - alen - 2];
		break;
	case SADB_X_EALG_AESCBC:
		AES_cbc_encrypt(&esp->enc_data[iv_len], &out[*offset], elen,
				entry->aes_key, cbc_iv, AES_DECRYPT);
		break;
	default:
		return(-1);
	}

	/* remove padding */
	padinfo = (struct ip_esp_padinfo*) &out[*offset + elen - 2];
	elen -= 2 + padinfo->pad_length;

	/* determine address family for new packet based on 
	 * decrypted upper layer protocol header
	 */
	

	

	/* LSI is not used here, FIXME if used later !!! */ 
	
	HIP_DEBUG_SOCKADDR("local HIT ",
			   (struct sockaddr *) &entry->inner_src_addrs->addr);
	HIP_DEBUG_SOCKADDR("remote HIT ",
			   (struct sockaddr *) &entry->inner_dst_addrs->addr);
	
	src_hit = (struct sockaddr_in6 *) &entry->inner_src_addrs->addr;
	dst_hit = (struct sockaddr_in6 *) &entry->inner_dst_addrs->addr;

	HIP_DEBUG(" Is it TCP and UDP packet:?  %s ", 
		 padinfo->next_hdr == IPPROTO_TCP? "TCP" : "UDP");


       
	switch (padinfo->next_hdr) {

	case IPPROTO_TCP:
		tcp = (struct tcphdr*)&out[*offset];
		sum = htons(tcp->check);
		sum = csum_hip_revert6 (&src_hit->sin6_addr,
					&dst_hit->sin6_addr,
					sum, htons(entry->hit_magic));
		tcp->check = htons(sum);
		break;
	case IPPROTO_UDP:
		udp = (struct udphdr*)&out[*offset];
		sum = htons(udp->check);
		sum = csum_hip_revert6 (&src_hit->sin6_addr,
					&dst_hit->sin6_addr,
					sum, htons(entry->hit_magic));
		udp->check = htons(sum);
		break;
	default:

		HIP_DEBUG("It does not belong to neither TCP or UDP packet \n");
		break;

	}
 


#if 0 /* disable LSI code */

	family_out = hip_select_family_by_proto(LSI4(&entry->lsi), 
						padinfo->next_hdr, &out[*offset], now);
	
	/* rewrite upper-layer checksum 
	 * checksum based on HITs --> based on LSIs */
	if (family_out == AF_INET) {
		switch (padinfo->next_hdr) {
#ifdef __MACOSX__
	case IPPROTO_TCP:
		tcp = (struct tcphdr*)&out[*offset];
		sum = htons(tcp->th_sum);
		sum = csum_hip_revert(	LSI4(&entry->lsi), htonl(g_tap_lsi),
					sum, htons(entry->hit_magic));
		tcp->th_sum = htons(sum);
		break;
	case IPPROTO_UDP:
		udp = (struct udphdr*)&out[*offset];
		sum = htons(udp->uh_sum);
		sum = csum_hip_revert(	LSI4(&entry->lsi), htonl(g_tap_lsi),
					sum, htons(entry->hit_magic));
		udp->uh_sum = htons(sum);
		break;
#else
	case IPPROTO_TCP:
		tcp = (struct tcphdr*)&out[*offset];
		sum = htons(tcp->check);
		sum = csum_hip_revert(	LSI4(&entry->lsi), htonl(g_tap_lsi),
					sum, htons(entry->hit_magic));
		tcp->check = htons(sum);
		break;
	case IPPROTO_UDP:
		udp = (struct udphdr*)&out[*offset];
		sum = htons(udp->check);
		sum = csum_hip_revert(	LSI4(&entry->lsi), htonl(g_tap_lsi),
					sum, htons(entry->hit_magic));
		udp->check = htons(sum);
#endif
	default:
		break;
		}
	}
	

#endif /* end of LSI */



	/* HIPL does not use TAP driver, eth_hdr is not needed */
	
	/* set offset to index the beginning of the packet */


#if 0

	if (family_out == AF_INET) /* offset = 20 */
		*offset -= (sizeof(struct eth_hdr) + sizeof(struct ip));
	else	/* offset = 0 */
		*offset -= (sizeof(struct eth_hdr) + sizeof(struct ip6_hdr));
	
#endif 


	/* HIPL compatiable  code */
	*offset -= sizeof(struct ip6_hdr);
	

	/* Ethernet header */

/* For HIPL we do not use ethernet header for TAP driver */

/*
	dst_mac = get_eth_addr(family_out, 
	(family_out==AF_INET) ? SA2IP(&entry->lsi) : SA2IP(&entry->lsi6));
	add_eth_header(&out[*offset], dst_mac, g_tap_mac, 
	(family_out == AF_INET) ? 0x0800 : 0x86dd);
*/
	/* IP header */



/* add IP header for HIPL with HITS, FIXME, LSI support */
	
	
	add_ipv6_header(&out[*offset],
			SA(src_hit),SA(dst_hit),
			NULL, iph, (__u16)elen, padinfo->next_hdr);
	*outlen = sizeof(struct ip6_hdr)+ elen;
	




#if 0 /* openhip code does not support HIPL */

	if (family_out == AF_INET) {
		add_ipv4_header(&out[*offset+sizeof(struct eth_hdr)],
				LSI4(&entry->lsi), htonl(g_tap_lsi), iph,
				(__u16)(sizeof(struct ip) + elen),
				padinfo->next_hdr);
		*outlen = sizeof(struct eth_hdr) + sizeof(struct ip) + elen;
	} else {
		taplsi6.ss_family = AF_INET6;
		get_preferred_lsi(SA(&taplsi6));
		add_ipv6_header(&out[*offset+sizeof(struct eth_hdr)],
				SA(&entry->lsi6), SA(&taplsi6),
				NULL, iph, (__u16)elen, padinfo->next_hdr);
		*outlen = sizeof(struct eth_hdr) + sizeof(struct ip6_hdr)+ elen;
	}

#endif 	
	/* previously, this happened after write(), but there
	 * is some problem with using the entry ptr then */
	//entry->bytes += *outlen - sizeof(struct eth_hdr);
	entry->bytes += *outlen;
	entry->usetime.tv_sec = now->tv_sec;
	entry->usetime.tv_usec = now->tv_usec;
	entry->usetime_ka.tv_sec = now->tv_sec;
	entry->usetime_ka.tv_usec = now->tv_usec;

	return(0);
}

/*
 * rewrite_checksum()
 * 
 * Rewrite the upper-later TCP/UDP checksum so it is based on the HITs
 * (which are summed and passed in as __u16 magic).
 * Returns the old checksum value, so it can be restored.
 */
__u16 rewrite_checksum(__u8 *data, __u16 magic)
{
	struct ip *iph = (struct ip *)data;
	struct tcphdr *tcp;
	struct udphdr *udp;
	__u16 ret=0;


	/* rewrite upper-layer checksum, so it is based on HITs */
	switch (iph->ip_p) {
	case IPPROTO_TCP:
		tcp = (struct tcphdr*)(iph + 1);
#ifdef __MACOSX__
		ret = tcp->th_sum;
		tcp->th_sum = csum_tcpudp_hip_nofold(
				iph->ip_src.s_addr, iph->ip_dst.s_addr,
				tcp->th_sum, magic);
#else
		ret = tcp->check;
		tcp->check = csum_tcpudp_hip_nofold(
				iph->ip_src.s_addr, iph->ip_dst.s_addr,
				tcp->check, magic);
#endif
		break;
	case IPPROTO_UDP:
		udp = (struct udphdr*)(iph + 1);
#ifdef __MACOSX__
		ret = udp->uh_sum;
		udp->uh_sum = csum_tcpudp_hip_nofold(
				iph->ip_src.s_addr, iph->ip_dst.s_addr,
				udp->uh_sum, magic);
#else
		ret = udp->check;
		udp->check = csum_tcpudp_hip_nofold(
				iph->ip_src.s_addr, iph->ip_dst.s_addr,
				udp->check, magic);
#endif
		break;
	default:
		break;
	}
	return(ret);
}


/*
 * add_eth_header()
 *
 * Build an Ethernet header.
 */
void add_eth_header(__u8 *data, __u64 src, __u64 dst, __u32 type)
{
	struct eth_hdr *eth = (struct eth_hdr*)data;

	memcpy(eth->dst, &dst, 6);
	memcpy(eth->src, &src, 6);
	eth->type = htons((__u16)type);
}

/*
 * add_ipv4_header()
 *
 * Build an IPv4 header, copying some parameters from an old ip header (old),
 * src and dst in host byte order. old may be NULL.
 */
void add_ipv4_header(__u8 *new_packet, struct ip *old_ip_hdr, __u32 src_addr, __u32 dst_addr, 
	__u16 packet_len, __u8 next_hdr)
{
#if 0
	// copy old header to new packet
	// this will also copy further ip options
	memcpy(new_packet, old_ip_hdr, old_ip_hdr->ip_hl * 4);
	struct ip *new_ip_hdr = (struct ip*)new_packet;
	
	// set changed values
	//new_ip_hdr->ip_v = 4;
	//new_ip_hdr->ip_hl = 5;
	//new_ip_hdr->ip_tos = old ? old->ip_tos : 0; /* preserve TOS field */
	new_ip_hdr->ip_len = htons(packet_len);
	//new_ip_hdr->ip_id  = old ? old->ip_id : 0;  /* copy identification */
	//new_ip_hdr->ip_off = old ? old->ip_off : 0; /* copy fragmentation offset */
	//new_ip_hdr->ip_ttl = old ? old->ip_ttl : 255; /* preserve TTL */
	new_ip_hdr->ip_p = next_hdr;
	new_ip_hdr->ip_sum = 0;
	new_ip_hdr->ip_src.s_addr = htonl(src); /* assume host byte order */
	new_ip_hdr->ip_dst.s_addr = htonl(dst);

	/* recalculate the header checksum */
	new_ip_hdr->ip_sum = ip_fast_csum((__u8*)iph, iph->ip_hl);
#endif
}

/*
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

/*
 * add_ipv6_header()
 *
 * Build an IPv6 header, copying some parameters from an old header (old),
 * src and dst in network byte order.
 */
void add_ipv6_header(__u8 *data, struct sockaddr *src, struct sockaddr *dst,
		struct ip6_hdr *old, struct ip *old4, __u16 len, __u8 proto)
{
	struct ip6_hdr *ip6h = (struct ip6_hdr*)data;
		__u32 tc;

		memset(ip6h, 0, sizeof(struct ip6_hdr));
		ip6h->ip6_flow = 0; /* zero the version (4), TC (8), flow-ID (20) */
		ip6h->ip6_vfc = 0x60;
		ip6h->ip6_plen = htons(len);
		ip6h->ip6_nxt = proto;
		ip6h->ip6_hlim = 255;
		memcpy(&ip6h->ip6_src, SA2IP(src), sizeof(struct in6_addr));
		memcpy(&ip6h->ip6_dst, SA2IP(dst), sizeof(struct in6_addr));

		/* Try to preserve flow label and hop limit where possible. */
		if (old) {
			ip6h->ip6_flow = old->ip6_flow;
			ip6h->ip6_hlim = old->ip6_hlim;
		} else if (old4) {
			tc = old4->ip_tos << 24;
			ip6h->ip6_flow |= tc; 	/* 8 bits traffic class */
			ip6h->ip6_hlim = old4->ip_ttl;		/* __u8 */
		}
}


#ifdef __MACOSX__

void add_outgoing_esp_header(__u8 *data, __u32 src, __u32 dst, __u16 len)
{
	struct ip *iph = (struct ip*)data;

	memset(iph, 0, sizeof(struct ip));
	iph->ip_v = 4;
	iph->ip_hl = 5;
	iph->ip_tos = 0;
	iph->ip_len = htons(len + sizeof(struct ip));
	iph->ip_id  = 1337;
	iph->ip_off = htons(0x4000);
	iph->ip_ttl = 64;
	iph->ip_p = IPPROTO_ESP;
	iph->ip_sum = 0;
	iph->ip_src.s_addr = src; 
	iph->ip_dst.s_addr = dst;

	/* add the header checksum */
	iph->ip_sum = ip_fast_csum((__u8*)iph, iph->ip_hl);
}



#endif

/*
 * get_mac_addr()
 * Give a random 6-bit Ethernet address given an IPv4/IPv6 address.
 */
__u64 get_eth_addr(int family, __u8 *addr)
{
	__u32 index=0, *p;
	int i, len;
	__u64 r=0;
	
	if (!addr)
		return 0;
	
	/* sum the 32-bit words in address */
	p = (__u32*) addr;
	len = (family == AF_INET) ? 4 : 16;
	for (i = 0; i < len; i+=4) {
		index += *p++;
	}

	/* use sum as index into array of Ethernet addresses */
	index %= MAX_ETH_ADDRS;
	memcpy(&r, &eth_addrs[index], 6);
	((char *)&r)[0] &= 0xFE; /* clear the multicast bit */
	
	return(r);
}
