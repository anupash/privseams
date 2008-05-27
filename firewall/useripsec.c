#include "useripsec.h"
#include <sys/socket.h>		/* socket() */
#include "misc.h"			/* hip conversion functions */
#include "hip_esp.h"
#include "utils.h"
#include <sys/time.h>		/* timeval */

#define ESP_PACKET_SIZE 2500

// this is the ESP packet we are about to build
unsigned char *esp_packet;
// open sockets in order to re-insert the esp packet into the stack
int raw_sock_v4 = 0, raw_sock_v6 = 0;
int is_init = 0;

/* this will initialize the esp_packet buffer and the sockets,
 * they are not set yet */
int userspace_ipsec_init()
{	
	int flags = 0;
	int err = 0;
	
	HIP_DEBUG("\n");
	
	if (!is_init)
	{
		esp_packet = (unsigned char *)malloc(ESP_PACKET_SIZE);
		if (!esp_packet)
		{
			HIP_ERROR("failed to allocate buffer memory");
			
			err = -1;
			goto out_err;
		}
		
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
	// peer HIT
	// sockaddr does not provide enough space for _in6
	struct sockaddr_in6 sockaddr_peer_hit;
	// entry matching the peer HIT
	hip_sadb_entry *entry = NULL;
	struct timeval now;
	// TODO hipd should add this info to the SA entries
	int udp_encap = 0;
	int esp_packet_len = 0;
	int out_ip_version = 0;
	struct in6_addr *preferred_local_addr = NULL;
	struct in6_addr *preferred_peer_addr = NULL;
	int err = 0;
	
	/* we should only get HIT addresses
	 * LSI have been handled by LSI module before and converted to HITs */
	// TODO check for IPv6 first?
	HIP_ASSERT(ipv6_addr_is_hit(&ctx->src) && ipv6_addr_is_hit(&ctx->dst));

	err = userspace_ipsec_init();
	if (err)
		goto end_err;
	
	HIP_DEBUG("\n");

	// re-use allocated esp_packet memory space
	memset(esp_packet, 0, ESP_PACKET_SIZE);
	gettimeofday(&now, NULL);
	preferred_local_addr = (struct in6_addr*)malloc(sizeof(struct in6_addr));
	preferred_peer_addr = (struct in6_addr*)malloc(sizeof(struct in6_addr));
	memset(preferred_local_addr, 0, sizeof(struct in6_addr));
	memset(	preferred_peer_addr, 0, sizeof(struct in6_addr));
			
	HIP_DEBUG_HIT("src_hit: ", &ctx->src);
	HIP_DEBUG_HIT("dst_hit: ", &ctx->dst);
	
	// SAs directing outwards are indexed with the peer's HIT
	// FIXME this will only allow one connection to this peer HIT
	hip_addr_to_sockaddr(&ctx->dst, (struct sockaddr *) &sockaddr_peer_hit);
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
			
			// don't process this message any further for now
			goto end_err;
	}
		
	HIP_DEBUG("we have found a SA entry\n");
	
	// unbuffer and process buffered packets
	//unbuffer_packets(entry);
	
	// get preferred routable addresses
	err = get_preferred_addr(entry->src_addrs, preferred_local_addr);
	if (err)
		goto end_err;
	err = get_preferred_addr(entry->dst_addrs, preferred_peer_addr);	
	if (err)
		goto end_err;
	
	// check preferred addresses for the address type of the output
	if (IN6_IS_ADDR_V4MAPPED(preferred_local_addr)
			&& IN6_IS_ADDR_V4MAPPED(preferred_peer_addr))
	{
		HIP_DEBUG("out_ip_version is IPv4");
		out_ip_version = 4;
	} else if (!IN6_IS_ADDR_V4MAPPED(preferred_local_addr)
			&& !IN6_IS_ADDR_V4MAPPED(preferred_peer_addr))
	{
		HIP_DEBUG("out_ip_version is IPv6");
		out_ip_version = 6;
	} else
	{
		HIP_ERROR("bad address combination");
		
		err = 1;
		goto end_err;
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
	
	if (err < 0) {
		HIP_DEBUG("hip_esp_output(): sendto() failed \n");
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
	
  end_err:
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
	
	hit = hip_cast_sa_addr(target);
	
	HIP_DEBUG_HIT("pfkey_send_acquire hit is: ", hit);

	/* Trigger base exchange */
	HIP_IFEL(hip_trigger_bex(NULL, hit, NULL, NULL), -1,
		 "trigger bex\n");
	
  out_err:
	return err;
}

// resolve HIT to routable addresses and select the preferred ones
int get_preferred_addr(sockaddr_list *addr_list, struct in6_addr *preferred_addr)
{
	int err = 0;
	struct sockaddr_in sockaddr_in;
	struct sockaddr_in6 sockaddr_in6;
	preferred_addr = NULL;
	
	while (addr_list != NULL)
	{
		if (addr_list->preferred)
		{
			HIP_DEBUG("found preferred src_addr");
			
			if (addr_list->addr.ss_family == AF_INET)
			{
				sockaddr_in = (struct sockaddr_in)addr_list->addr;
				IPV4_TO_IPV6_MAP(sockaddr_in.sin_addr, preferred_addr);
				
			} else if (addr_list->addr.ss_family == AF_INET6)
			{
				sockaddr_in6 = (struct sockaddr_in6)addr_list->addr;
				ipv6_addr_copy(preferred_addr, sockaddr_in6.sin6_addr);
				
			} else
			{
				err = 1;
				goto out_err;
			}
			
			break;
		}

		addr_list = addr_list->next;
	}
	
  out_err:
  	return err;
}
