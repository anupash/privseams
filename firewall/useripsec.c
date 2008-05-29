#include "useripsec.h"
#include <sys/socket.h>		/* socket() */
#include "misc.h"			/* hip conversion functions */
#include "hip_esp.h"
#include "utils.h"
#include <sys/time.h>		/* timeval */

#define ESP_PACKET_SIZE 2500

// this is the ESP packet we are about to build
unsigned char *esp_packet = NULL;
// the routable addresses
struct in6_addr *preferred_local_addr = NULL;
struct in6_addr *preferred_peer_addr = NULL;
// open sockets in order to re-insert the esp packet into the stack
int raw_sock_v4 = 0, raw_sock_v6 = 0;
int is_init = 0;

__u16 checksum_magic(const hip_hit *i, const hip_hit *r);

/* this will initialize the esp_packet buffer and the sockets,
 * they are not set yet */
int userspace_ipsec_init()
{	
	int flags = 0;
	int err = 0;
	
	HIP_DEBUG("\n");
	
	if (!is_init)
	{
		HIP_IFE(!(esp_packet = (unsigned char *)malloc(ESP_PACKET_SIZE)), -1);
		HIP_IFE(!(preferred_local_addr = (struct in6_addr *)malloc(sizeof(struct in6_addr))), -1);
		HIP_IFE(!(preferred_peer_addr = (struct in6_addr *)malloc(sizeof(struct in6_addr))), -1);
		
		// open IPv4 raw socket
		raw_sock_v4 = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
		if (raw_sock_v4 < 0)
		{
			HIP_DEBUG("*** ipv4_raw_socket socket() error for raw socket\n");
			
			err = -1;
			goto out_err;
		}
		
		// this option allows us to add the IP header ourselves
		flags = 1;
		if (setsockopt(raw_sock_v4, IPPROTO_IP, IP_HDRINCL, (char *)&flags, 
					sizeof(flags)) < 0)
		{
			HIP_DEBUG("*** setsockopt() error for IPv4 raw socket\n");

			err = 1;
			goto out_err;
		}
		
		// open IPv6 raw socket, no options needed here
		raw_sock_v6 = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
		if (raw_sock_v6 < 0) {
			HIP_DEBUG("*** ipv6_raw_socket socket() error for raw socket\n");
			
			err = 1;
			goto out_err;
		}
		
		is_init = 1;
		
		HIP_DEBUG("userspace IPsec successfully initialised\n");
	}
	
  out_err:
  	return err;
}

hip_hit_t *hip_fw_get_default_hit(void) {
	if (ipv6_addr_is_null(&default_hit)) {
		_HIP_DEBUG("Querying hipd for default hit\n");
		if (hip_query_default_local_hit_from_hipd(&default_hit))
			return NULL;
	}
	return &default_hit;
}

/* Get default HIT*/
int hip_query_default_local_hit_from_hipd(hip_hit_t *hit)
{
	 
	int err = 0;
	struct hip_common *msg = NULL;
	struct hip_tlv_common *current_param = NULL;
	hip_hit_t *defhit  = NULL;	
	struct endpoint_hip *endp=NULL;
	
	HIP_IFE(!(msg = hip_msg_alloc()), -1);
	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_DEFAULT_HIT,0),-1,
		 "Fail to get hits");
	HIP_IFEL(hip_send_recv_daemon_info(msg), -1,
		 "send/recv daemon info\n");
	
	while((current_param = hip_get_next_param(msg, current_param)) != NULL)
	{
		defhit = (in6_addr_t *)hip_get_param_contents_direct(current_param);
		//set_hit_prefix(defhit); // miika: what the heck?
		HIP_DEBUG_HIT("default hi is ",defhit);
	}

	ipv6_addr_copy(hit, defhit);

out_err:
	return err;

}

/* prepares the environment for esp encryption */
int hip_fw_userspace_ipsec_output(hip_fw_context_t *ctx)
{
	// peer HIT, sockaddr does not provide enough space for _in6
	struct sockaddr_storage sockaddr_peer_hit;
	// entry matching the peer HIT
	hip_sadb_entry *entry = NULL;
	struct timeval now;
	// TODO hipd should add this info to the SA entries
	int udp_encap = 0;
	int esp_packet_len = 0;
	int out_ip_version = 0;
	int err = 0;
	
	/* we should only get HIT addresses here
	 * LSI have been handled by LSI module before and converted to HITs */
	HIP_ASSERT(ipv6_addr_is_hit(&ctx->src) && ipv6_addr_is_hit(&ctx->dst));
	
	HIP_DEBUG_HIT("src_hit: ", &ctx->src);
	HIP_DEBUG_HIT("dst_hit: ", &ctx->dst);

	HIP_IFEL(userspace_ipsec_init(), -1, "failed to initialize userspace ipsec");
	
	// re-use allocated esp_packet memory space
	memset(esp_packet, 0, ESP_PACKET_SIZE);
	memset(preferred_local_addr, 0, sizeof(struct in6_addr));
	memset(preferred_peer_addr, 0, sizeof(struct in6_addr));
	gettimeofday(&now, NULL);
	
	// SAs directing outwards are indexed with the peer's HIT
	// FIXME this will only allow one connection to this peer HIT
	hip_addr_to_sockaddr(&ctx->dst, &sockaddr_peer_hit);
	entry = hip_sadb_lookup_addr((struct sockaddr *) &sockaddr_peer_hit);
	
	// create new SA entry, if none exists yet
	if (entry == NULL)
	{
			HIP_DEBUG("pfkey send acquire\n");
			
			// no SADB entry -> buffer triggering packet and send ACQUIRE
			// FIXME checks for SA entry again
			// TODO this will result in a SEGFAULT
			//if (buffer_packet(&sockaddr_peer_hit, ctx->ipq_packet->payload, ctx->ipq_packet->data_len))
				err = pfkey_send_acquire((struct sockaddr *) &sockaddr_peer_hit);
				
			// as we don't buffer the packet right now, we have to drop it
			// due to not routable addresses
			err = 1;
			
			// don't process this message any further
			goto out_err;
	}
		
	HIP_DEBUG("we have found a SA entry\n");
	
	// unbuffer and process buffered packets
	//unbuffer_packets(entry);
	
	// get preferred routable addresses
	HIP_IFE(get_preferred_addr(entry->src_addrs, preferred_local_addr), -1);
	HIP_IFE(get_preferred_addr(entry->dst_addrs, preferred_peer_addr), -1);	
	
	// check preferred addresses for the address type of the output
	if (IN6_IS_ADDR_V4MAPPED(preferred_local_addr)
			&& IN6_IS_ADDR_V4MAPPED(preferred_peer_addr))
	{
		HIP_DEBUG("out_ip_version is IPv4\n");
		out_ip_version = 4;
	} else if (!IN6_IS_ADDR_V4MAPPED(preferred_local_addr)
			&& !IN6_IS_ADDR_V4MAPPED(preferred_peer_addr))
	{
		HIP_DEBUG("out_ip_version is IPv6\n");
		out_ip_version = 6;
	} else
	{
		HIP_ERROR("bad address combination\n");
		
		err = 1;
		goto out_err;
	}
		
	err = hip_esp_output(ctx, entry, out_ip_version, udp_encap, &now,
			preferred_local_addr, preferred_peer_addr,
			esp_packet, &esp_packet_len);
	
#if 0
	// send the raw packet -> returns size of the sent packet
	// TODO check flags
	if (out_ip_version == 4)
		err = sendto(raw_sock_v4, esp_packet, esp_packet_len, 0,
				(struct sockaddr *)preferred_peer_addr,
				hip_sockaddr_len(preferred_peer_addr));
	else
		err = sendto(raw_sock_v6, esp_packet, esp_packet_len, 0,
						(struct sockaddr *)preferred_peer_addr),
						hip_sockaddr_len(preferred_peer_addr));
#endif
	
	if (err) {
		HIP_DEBUG("hip_esp_output(): sendto() failed\n");
	} else
	{
		// update SA statistics for replay protection etc
		pthread_mutex_lock(&entry->rw_lock);
		entry->bytes += err;
		entry->usetime.tv_sec = now.tv_sec;
		entry->usetime.tv_usec = now.tv_usec;
		entry->usetime_ka.tv_sec = now.tv_sec;
		entry->usetime_ka.tv_usec = now.tv_usec;
		pthread_mutex_unlock(&entry->rw_lock);
	}
	
  out_err:
  	return err;
}

/* added by Tao Wan, This is the function for hip userspace ipsec input 
 *
 **/
int hip_fw_userspace_ipsec_input(int ip_version,
				 void *hdr,
				 ipq_packet_msg_t *ip_packet_in_the_queue)
{
#if 0
	int ipv6_hdr_size = 0;
	int tcp_hdr_size = 0;
	int length_of_packet = 0;
        int i, optLen, hdr_size, optionsLen;
	char 	       *hdrBytes = NULL;
	struct tcphdr  *tcphdr;
	struct ip      *iphdr;
	struct ip6_hdr *ip6_hdr;
	
        //fields for temporary values
	// u_int16_t       portTemp;
	// struct in_addr  addrTemp;
	// struct in6_addr addr6Temp;
	/* the following vars are needed for
	 * sending the i1 - initiating the exchange
	 * in case we see that the peer supports hip*/
	// struct in6_addr peer_ip;
	// struct in6_addr peer_hit;
	// in_port_t        src_tcp_port;
	// in_port_t        dst_tcp_port;

	struct sockaddr_storage ipv6_src_addr;
	struct sockaddr_storage ipv4_src_addr;
	struct in6_addr ipv4_to_ipv6_conversion;
	int err = 0;

	if(ip_version == 4){
		iphdr = (struct ip *)hdr;
		//get the tcp header
		hdr_size = (iphdr->ip_hl * 4);
		tcphdr = ((struct tcphdr *) (((char *) iphdr) + hdr_size));
		hdrBytes = ((char *) iphdr) + hdr_size;
		
		HIP_DEBUG_INADDR("IPv4 from peer address ", &iphdr->ip_src); /* From peer */
		HIP_DEBUG_INADDR("IPv4 local address ", &iphdr->ip_dst); /* it is local */
		
		length_of_packet = ip_packet_in_the_queue->data_len;		
		
		
		IPV4_TO_IPV6_MAP(&iphdr->ip_dst, &ipv4_to_ipv6_conversion);

		hip_addr_to_sockaddr((struct in6_addr *) &ipv4_to_ipv6_conversion,
				     (struct sockaddr *) &ipv4_src_addr);
		
		HIP_DEBUG("hello: the number of sa_family is %s\n", 
			  ipv4_src_addr.ss_family == AF_INET? "ipv4" : "ipv6");

		err = hip_esp_input((struct sockaddr *) &ipv4_src_addr, 
				    (u8 *) iphdr, length_of_packet); 

}
	else if(ip_version == 6){
		ip6_hdr = (struct ip6_hdr *)hdr;
		
		ipv6_hdr_size = sizeof(struct ip6_hdr);
		tcp_hdr_size = sizeof(struct tcphdr);
		
		
		if(ip_packet_in_the_queue->data_len >= 
		   (ipv6_hdr_size + tcp_hdr_size)) 
		{
			
			length_of_packet = ip_packet_in_the_queue->data_len;  
			HIP_DEBUG("length of packet is %d \n", length_of_packet);
			_HIP_DEBUG("ipv6 header size  is %d \n", ipv6_hdr_size);
			_HIP_DEBUG("tcp header size is %d \n", tcp_hdr_size);
		}
		 		
                 //get the tcp header		
		hdr_size = (ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_plen * 4);
		tcphdr = ((struct tcphdr *) (((char *) ip6_hdr) + hdr_size));
		hdrBytes = ((char *) ip6_hdr) + hdr_size;
		
                //peer and local ip needed for sending the i1 through hipd
		//peer_ip = &ip6_hdr->ip6_src;//TO  BE FIXED obtain the pseudo hit instead

		// ipv6_addr_copy(&peer_hit, &ip6_hdr->ip6_dst);
		HIP_DEBUG_IN6ADDR("IPv6 from peer address ", &ip6_hdr->ip6_src); /* From peer */
		HIP_DEBUG_IN6ADDR("IPv6 local address ", &ip6_hdr->ip6_dst); /* it is local */

		
		hip_addr_to_sockaddr((struct in6_addr *)&ip6_hdr->ip6_dst,
				     (struct sockaddr *) &ipv6_src_addr);
		
		err = hip_esp_input((struct sockaddr *) &ipv6_src_addr, 
				    (char *) ip6_hdr, length_of_packet); 
	}
			

	return err;
#endif
	
	return 1;
}

/* userspace IPsec trigger for the base exchange */
int pfkey_send_acquire(struct sockaddr *target)
{
	hip_hit_t *hit = NULL;
	int err = 0;
	
	// NOTE: this will always return an in6_addr as we are only dealing with HITs here
	hit = hip_cast_sa_addr(target);
	
	HIP_DEBUG_HIT("pfkey_send_acquire hit is: ", hit);

	/* Trigger base exchange */
	HIP_IFEL(hip_trigger_bex(NULL, hit, NULL, NULL), -1,
		 "trigger bex\n");
	
  out_err:
	return err;
}

int hipl_userspace_ipsec_sadb_add_wrapper(struct in6_addr *saddr,
					      struct in6_addr *daddr,
					      struct in6_addr *src_hit, 
					      struct in6_addr *dst_hit,
					      uint32_t *spi, int ealg,
					      struct hip_crypto_key *enckey,
					      struct hip_crypto_key *authkey,
					      int already_acquired,
					      int direction, int update,
					      int sport, int dport) 
{
	__u16 hit_magic = 0;
	__u8 *ipsec_e_key; 
	__u8 *ipsec_a_key;
	__u32 ipsec_e_keylen = HIP_MAX_KEY_LEN; 
	__u32 ipsec_a_keylen = HIP_MAX_KEY_LEN;
	/*HIT address,  inner addresses*/
	struct sockaddr_storage inner_src, inner_dst; 
	struct sockaddr_storage src, dst; /* IP address*/
	__u32 ipsec_spi = (__u32) *spi; /*IPsec SPI*/
	__u32 ipsec_e_type ; /* encryption type */
	__u32 ipsec_a_type ; /* authentication type is equal to encryption type */
	int err = 0;

	/* MAP HIP ESP encryption INDEX to SADB encryption INDEX */
	switch(ealg) {
		case HIP_ESP_AES_SHA1:
			ipsec_e_type = SADB_X_EALG_AESCBC;
			ipsec_a_type = SADB_AALG_SHA1HMAC;
			break;
		case HIP_HIP_3DES_SHA1:
			ipsec_e_type = SADB_EALG_3DESCBC;
			ipsec_a_type = SADB_AALG_SHA1HMAC;
			break;
		case HIP_HIP_BLOWFISH_SHA1:
			ipsec_e_type = SADB_X_EALG_BLOWFISHCBC;
			ipsec_a_type = SADB_AALG_SHA1HMAC;
			break;
	}
	
	HIP_DEBUG_HIT("source hit: ", src_hit);
	HIP_DEBUG_IN6ADDR("source ip: ", saddr);
	HIP_DEBUG_HIT("dest hit: ", dst_hit);
	HIP_DEBUG_IN6ADDR("dest ip: ", daddr);

	/* ip6/ip4 (in6_addr) address conversion to sockddr_storage */
	hip_addr_to_sockaddr(saddr, &src); /* source ip address conversion */
	hip_addr_to_sockaddr(daddr, &dst); /* destination ip address conversion */
	hip_addr_to_sockaddr(src_hit, &inner_src); /* source HIT conversion */
	hip_addr_to_sockaddr(dst_hit, &inner_dst); /* destination HIT conversion */
	
	struct in_addr * in_src = hip_cast_sa_addr(&src);
	
	HIP_DEBUG_INADDR("source sockaddr (IPv4): ", in_src);
	
	/* hit_magic is the 16-bit sum of the bytes of both HITs. 
	 * the checksum is calculated as other Internet checksum, according to 
	 * the HIP spec this is the sum of 16-bit words from the input data a 
	 * 32-bit accumulator is used but the end result is folded into a 16-bit
	 * sum
	 */
	// TODO find correct implementation
	//hit_magic = checksum_magic((hip_hit *) src_hit->s6_addr, (hip_hit *) dst_hit->s6_addr);
	
	
	/* a_type is for crypto parameters, but type is currently ignored  */
	/* struct hip_crypto_key {
	 *  char key[HIP_MAX_KEY_LEN]
	 *  }
	 *  HIP_MAX_KEY_LEN 32 // max. draw: 256 bits!
	 */
	
	/* struct hip_crypto_key *enckey ---> __u8 *e_key */
	/* struct hip_crypto_key *authkey  ---> __u8 *a_key */
	
	ipsec_e_key = (__u8 *) enckey->key;
	ipsec_a_key = (__u8 *) authkey->key;
	/* 
	   int hip_sadb_add(__u32 type, __u32 mode, struct sockaddr *inner_src,
	   struct sockaddr *inner_dst, struct sockaddr *src, struct sockaddr *dst,
	   __u16 port,
	   __u32 spi, __u8 *e_key, __u32 e_type, __u32 e_keylen, __u8 *a_key,
	   __u32 a_type, __u32 a_keylen, __u32 lifetime, __u16 hitmagic)
	   
	*/
	
	/* looking at the usermode code, it may be that the lifetime is stored in
	 * the hip_sadb_entry but never used. It is supposed to be the value in
	 * seconds after which the SA expires but I don't think this is
	 * implemented. It is a preserved field from the kernel API, from the
	 * PFKEY messages.
	 * 
	 * Here just give a value 100 to lifetime
	 * */
	
	// Tao: check return argument
	err = hip_sadb_add(TYPE_USERSPACE_IPSEC, IPSEC_MODE, (struct sockaddr *) &inner_src,
			(struct sockaddr *) &inner_dst, (struct sockaddr *) &src, (struct sockaddr *) &dst,
			   (__u16) dport, ipsec_spi, ipsec_e_key, ipsec_e_type, ipsec_e_keylen,
			   ipsec_a_key, ipsec_a_type, ipsec_a_keylen, 100 , hit_magic);
	
	// Tell firewall that HIT SRC + DST HAS A SECURITY ASSOCIATION
	HIP_DEBUG("HIP IPsec userspace SA add return value %d\n", err);

	if(err == -1)
	{
		
		HIP_ERROR("HIP user_space IPsec security association DB add is not successful\n");
		goto out_err;
		
	} 	
	HIP_DEBUG(" HIP user space IPsec security sadb is done \n\n");

 out_err:
	
	return err;
}

#if 0
/*
 * * function checksum_magic()
 * *
 * * Calculates the hitMagic value given two HITs.
 * * Note that since this is simple addition, it doesn't matter
 * * which HIT is given first, and the one's complement is not
 * * taken.
 */
__u16 checksum_magic(const hip_hit *i, const hip_hit *r)
{
	int count;
	unsigned long sum = 0;
	unsigned short *p; /* 16-bit */
	
	/* 
	 * 	 * this checksum algorithm can be found 
	 * 	 * in RFC 1071 section 4.1, pseudo-header
	 * 	* from RFC 2460
	 * */
	
	/* one's complement sum 16-bit words of data */
	/* sum initiator's HIT */
	count = HIT_SIZE;
	p = (unsigned short*) i;
	while (count > 1)  {
		sum += *p++;
		count -= 2;
	}
	/* sum responder's HIT */
	count = HIT_SIZE;
	p = (unsigned short*) r;
	while (count > 1)  {
		sum += *p++;
		count -= 2;
	}
	
	/*  Fold 32-bit sum to 16 bits */
	while (sum>>16)
		sum = (sum & 0xffff) + (sum >> 16);
	
	HIP_DEBUG("hitMagic checksum over %d bytes: 0x%x\n",
		  2*HIT_SIZE, (__u16)sum);
	
	/* don't take the one's complement of the sum */
	return((__u16)sum);
}
#endif

// resolve HIT to routable addresses and select the preferred ones
int get_preferred_addr(sockaddr_list *addr_list, struct in6_addr *preferred_addr)
{
	int err = 0;
	
	while (addr_list != NULL)
	{
		// TODO find preferred address and don't select first one in list
		//if (addr_list->preferred)
		//{
		//	HIP_DEBUG("found preferred src_addr\n");
		
			if (addr_list->addr.ss_family == AF_INET)
			{
				IPV4_TO_IPV6_MAP((struct in_addr *)hip_cast_sa_addr(&addr_list->addr),
						preferred_addr);
				
				HIP_DEBUG_HIT("preferred_addr (IPv4): ", preferred_addr);
				
			} else if (addr_list->addr.ss_family == AF_INET6)
			{
				preferred_addr = (struct in6_addr *)hip_cast_sa_addr(&addr_list->addr);

				HIP_DEBUG_HIT("preferred_addr (IPv6): ", preferred_addr);
				
			} else
			{
				err = 1;
				goto out_err;
			}
			
			break;
		//}

		addr_list = addr_list->next;
	}
	
  out_err:
  	return err;
}
