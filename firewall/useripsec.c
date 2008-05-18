#include "useripsec.h"

hip_hit_t *hip_fw_get_default_hit(void) {
	if (ipv6_addr_is_null) {
		_HIP_DEBUG("Querying hipd for default hit\n");
		if (hip_query_default_local_hit_from_hipd())
			return NULL;
	}
	return &default_hit;
}

/* Get default HIT*/
int hip_query_default_local_hit_from_hipd(void)
{
	 
	int err = 0;
	struct hip_common *msg = NULL;
	struct hip_tlv_common *current_param = NULL;
	in6_addr_t *defhit;	
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
		_HIP_DEBUG_HIT("default hi is ",defhit);
	}


out_err:
	return err;

}


/* added by Tao Wan, This is the function for hip userspace ipsec output
 * Todo: How to do hip_sadb_lookup_addr() or  hip_sadb_lookup_spi(spi)
 *   hip_sadb_lookup_addr(struct sockaddr *addr)
 **/

int hip_fw_userspace_ipsec_output(int ip_version,
					void *hdr,
					ipq_packet_msg_t *ip_packet_in_the_queue)
{
	int ipv6_hdr_size = 0;
	int tcp_hdr_size = 0;
	int length_of_packet = 0;
        int i, optLen, hdr_size, optionsLen;
	char 	       *hdrBytes = NULL;
	struct tcphdr  *tcphdr;
	struct ip      *iphdr;
	struct ip6_hdr *ip6_hdr;
	struct in6_addr peer_ip;
	struct in6_addr peer_hit;
	struct sockaddr_in6 ipv6_addr_to_sockaddr_hit;
	struct sockaddr_in6 sockaddr_local_default_hit;
	struct hip_tlv_common *current_param = NULL;
	hip_hit_t *def_hit;
	int err = 0;

	HIP_DEBUG("Try to get peer_hit\n");

	// XX FIXME: TAO ALLOCATE STATICALLY TO AVOID SILLY MEM LEAKS
	//peer_ip  = HIP_MALLOC(sizeof(struct in6_xaddr), 0);
	//peer_hit = HIP_MALLOC(16, 0);

	if(ip_version == 4){
		iphdr = (struct ip *)hdr;
		//get the tcp header
		hdr_size = (iphdr->ip_hl * 4);
		tcphdr = ((struct tcphdr *) (((char *) iphdr) + hdr_size));
		hdrBytes = ((char *) iphdr) + hdr_size;
		
		HIP_DEBUG_INADDR("the src", &iphdr->ip_src);
		HIP_DEBUG_INADDR("the dst", &iphdr->ip_dst);
		
		//peer and local ip needed for sending the i1 through hipd
		//IPV4_TO_IPV6_MAP(&iphdr->ip_src, &peer_ip); //TO  BE FIXED obtain the pseudo hit instead
	
		/* To be fixed, Need LSI support */

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

		_HIP_HEXDUMP("whole packet content:", 
			    &ip_packet_in_the_queue->payload, 
			    ip_packet_in_the_queue->data_len);
		
		_HIP_HEXDUMP("whole packet content:", 
			    ip6_hdr, 
			    ip_packet_in_the_queue->data_len);
		
		 
	 		
                 //get the tcp header		
		hdr_size = (ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_plen * 4);
		tcphdr = ((struct tcphdr *) (((char *) ip6_hdr) + hdr_size));
		hdrBytes = ((char *) ip6_hdr) + hdr_size;
		
	
		
                //peer and local ip needed for sending the i1 through hipd
		//peer_ip = &ip6_hdr->ip6_src;//TO  BE FIXED obtain the pseudo hit instead
		ipv6_addr_copy(&peer_hit, &ip6_hdr->ip6_dst);
	}
	
		
	//memcpy(peer_hit, &hdrBytes[20 + 4], 16);
			
	/* convert in6_addr to sockaddr */

	
	
	HIP_DEBUG_HIT("peer hit from ipsec_output: ", &peer_hit);
	HIP_DEBUG_HIT("source hit from ipsec_output: ", &ip6_hdr->ip6_src);

	hip_addr_to_sockaddr(&peer_hit, (struct sockaddr *) &ipv6_addr_to_sockaddr_hit);     

	HIP_DEBUG_SOCKADDR("ipv6_addr_to_sockaddr_hit value is :",
			   (struct sockaddr *) &ipv6_addr_to_sockaddr_hit);

	
	HIP_DEBUG("Can hip_sadb_lookup_addr() find hip_sadb_entry? : %s\n",
		hip_sadb_lookup_addr((struct sockaddr *) &ipv6_addr_to_sockaddr_hit) ? "YES" : "NO");
	

	if (hip_sadb_lookup_addr((struct sockaddr *) &ipv6_addr_to_sockaddr_hit) == NULL) {
		HIP_DEBUG("pfkey send acquire\n");
		err = pfkey_send_acquire((struct sockaddr *) &ipv6_addr_to_sockaddr_hit);
	} else {
		// TAO XX FIXME: READ LOCAL HIT AND PASS IT AS SOCKADDR STRUCTURE
		// TO hip_esp_output
	
		//hip_esp_traffic_userspace_handler(&hip_esp_output_id, 
		//				     hip_esp_output, 
		//				  NULL);
	
		/*
		HIP_DEBUG("Sending esp output......");
		
		HIP_IFE(!(msg = hip_msg_alloc()), -1);
		HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_DEFAULT_HIT,0),-1,
		"Fail to get hits");
		HIP_IFEL(hip_send_recv_daemon_info(msg), -1,
		"send/recv daemon info\n");
		
		
		defhit = hip_get_param_contents(msg, HIP_PARAM_HIT);
		*/

		HIP_IFEL(!(def_hit = hip_fw_get_default_hit()), -1,
			 "Failed to get default hit - is hipd running?\n");
		HIP_INFO_HIT("hip_esp_out: default hit is ", def_hit);
		
		hip_addr_to_sockaddr(def_hit, (struct sockaddr *) &sockaddr_local_default_hit);
		//hip_addr_to_sockaddr(&ip6_hdr->ip6_src, &sockaddr_local_default_hit);
		
		err = hip_esp_output((struct sockaddr *) &sockaddr_local_default_hit, 
				     (u8 *) ip6_hdr, length_of_packet); /* XX FIXME: LSI */
	}
	
	HIP_DEBUG("Can hip_sadb_lookup_addr() find hip_sadb_entry? : %s\n",
		  hip_sadb_lookup_addr((struct sockaddr *) &ipv6_addr_to_sockaddr_hit) ? "YES" : "NO");
	
	
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
}
