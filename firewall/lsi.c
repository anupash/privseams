#include "lsi.h"

#define BUFSIZE HIP_MAX_PACKET

/**
 * Checks if the packet is a reinjection

 * @param ip_src      pointer to the source address
 * @return	      1 if the source address is a local lsi
 * 		      0 otherwise
 */

int is_packet_reinjection(struct in_addr *ip_src)
{
	HIP_DEBUG_LSI("is_packet already reinjected with lsi dst",ip_src);
	return hip_find_local_lsi(ip_src);
}

/**
 * Analyzes if the incoming packet with hits must be translated to lsis
 * If it must be translated, calls to reinject_packet in order to execute 
 * the packet reinjection
 *
 * @param m           pointer to the packet
 * @param ip_src      ipv6 source address 
 * @param ip_dst      ipv6 destination address
 * @return	      1 if translation not done
 * 		      0 if packet reinjected with lsis as addresses
 */

int hip_fw_handle_incoming_hit(ipq_packet_msg_t *m, struct in6_addr *ip_src, struct in6_addr *ip_dst)
{
        int proto6 = 0, proto4_LSI = 0, ip_hdr_size = 0, portDest = 0;
	char *proto;
	hip_lsi_t *lsi_our = NULL, *lsi_peer = NULL;
	struct in6_addr src_addr, dst_addr;
	
	struct ip6_hdr* ip6_hdr = (struct ip6_hdr*) m->payload;
	ip_hdr_size = sizeof(struct ip6_hdr);

	switch(ip6_hdr->ip6_nxt){
		case IPPROTO_UDP:
			portDest = ((struct udphdr*)((m->payload) + ip_hdr_size))->dest;
			proto = "udp6";
			break;
	       case IPPROTO_TCP:
			portDest = ((struct tcphdr*)((m->payload) + ip_hdr_size))->dest;
			proto = "tcp6";
			break;
	       case IPPROTO_ICMPV6:
		        proto6 = 1;
			break;
	       default:
		 	break;
	}
    
	if(portDest)
		proto6 = getproto_info(ntohs(portDest), proto);

	if(proto6)
		return proto6;


	if(portDest){
		proto = "tcp";
		proto4_LSI = getproto_info(ntohs(portDest), proto);
	}
	
/*
	if (!proto6){
HIP_DEBUG_HIT("#### SRC HIT", ip_src);
HIP_DEBUG_HIT("#### DST HIT", ip_dst);
	        lsi_our = (hip_lsi_t *)hip_get_lsi_our_by_hits(ip_src, ip_dst);
		lsi_peer = (hip_lsi_t *)hip_get_lsi_peer_by_hits(ip_src, ip_dst);
		if(lsi_our && lsi_peer){
		        IPV4_TO_IPV6_MAP(lsi_our, &src_addr);
			IPV4_TO_IPV6_MAP(lsi_peer, &dst_addr);
			HIP_DEBUG_LSI("******lsi_src : ", lsi_our);
			HIP_DEBUG_LSI("******lsi_dst : ", lsi_peer);
			reinject_packet(dst_addr, src_addr, m, 6, 1);
		}
	}
*/

	if (!proto6){
HIP_DEBUG_HIT("#### SRC HIT", ip_src);
HIP_DEBUG_HIT("#### DST HIT", ip_dst);
		int res = hip_get_ips_by_hits(ip_src, ip_dst, &src_addr, &dst_addr);
		if(res > -1){
			HIP_DEBUG_IN6ADDR("******ip_src : ", src_addr);
			HIP_DEBUG_IN6ADDR("******ip_dst : ", dst_addr);
			reinject_packet(dst_addr, src_addr, m, 6, 1);
		}
	}
	return proto6;
}

/**
 * Checks if the outgoing packet with lsis has already ESTABLISHED the Base Exchange
 * with the peer host. In case the BEX is not done, it triggers it. Otherwise, it looks up 
 * in the local database the necessary information for doing the packet reinjection with HITs.
 *
 * @param m           pointer to the packet
 * @param lsi_src     source LSI 
 * @param lsi_dst     destination LSI
 * @return	      err during the BEX
 */
int hip_fw_handle_outgoing_lsi(ipq_packet_msg_t *m, struct in_addr *lsi_src, struct in_addr *lsi_dst)
{
	int err, msg_type;
	struct in6_addr src_lsi, dst_lsi;
	struct in6_addr src_hit, dst_hit;
	struct in6_addr dst_ip;
	firewall_hl_t *entry_peer = NULL;

	HIP_DEBUG("FIREWALL_TRIGGERING OUTGOING LSI %s\n",inet_ntoa(*lsi_dst));

	IPV4_TO_IPV6_MAP(lsi_dst, &dst_lsi);
	IPV4_TO_IPV6_MAP(lsi_src, &src_lsi);

	hip_firewall_hldb_dump();
	//get the corresponding ip address for this lsi
	hip_get_peerIP_from_peerLSI(lsi_dst, &dst_ip);
	//get firewall db entry
	entry_peer = (firewall_hl_t *)firewall_ip_db_match(&dst_ip);	

	if (entry_peer){
		HIP_IFEL(entry_peer->bex_state == FIREWALL_STATE_BEX_UNDEFINED, -1, "Base Exchange Failed");
	  	if (entry_peer->bex_state == FIREWALL_STATE_BEX_ESTABLISHED)
			reinject_packet(entry_peer->hit_our, entry_peer->hit_peer, m, 4, 0);
		else if (entry_peer->bex_state == FIREWALL_STATE_BEX_NOT_ESTABLISHED){
		        /*Case after the connections established are reseted*/
		        HIP_IFEL(hip_trigger_bex(&entry_peer->hit_our, &entry_peer->hit_peer, 
						 &src_lsi, &dst_lsi, NULL, NULL), -1, 
			 	 "Base Exchange Trigger failed\n"); 
		}
	}else{
	        /*Check if bex is already established: Server case*/
	        int state_ha = hip_trigger_is_bex_established(&src_hit, &dst_hit, lsi_src, lsi_dst);
		if (state_ha){
		        HIP_DEBUG("ha is ESTABLISHED!\n");
			firewall_add_hit_lsi_ip(&src_hit, &dst_hit, lsi_dst, lsi_dst, state_ha);
			reinject_packet(src_hit, dst_hit, m, 4, 0);
		}
		else{
			// Run bex to initialize SP and SA
			HIP_INFO("Firewall_db empty and no ha ESTABLISHED. Triggering Base Exchange\n");
			err = hip_get_hit_peer_by_lsi_pair(lsi_src, lsi_dst, &src_hit, &dst_hit);
			HIP_IFEL(hip_trigger_bex(&src_hit, &dst_hit, &src_lsi, &dst_lsi, NULL, NULL),
				 -1, "Base Exchange Trigger failed\n");
		  	firewall_add_hit_lsi_ip(&src_hit, &dst_hit, lsi_dst, lsi_dst, 2);
		}
	}
out_err: 
	return err;
}













//#######################################################


/*
 * exactly the same function as hip_request_peer_hit_from_hipd(...)
 * 
 */
int hip_request_peer_hit_from_hipd_at_firewall(const struct in6_addr *peer_ip,
				         struct in6_addr *peer_hit,
				   const struct in6_addr *local_hit,
				   in_port_t src_tcp_port,
				   in_port_t dst_tcp_port,
				   int *fallback,
				   int *reject)
{
	struct hip_common *msg = NULL;
	struct in6_addr *hit_recv = NULL;
	hip_hit_t *ptr = NULL;
	int err = 0;
	int ret = 0;

	*fallback = 1;
	*reject = 0;

	HIP_IFE(!(msg = hip_msg_alloc()), -1);
	
	HIP_IFEL(hip_build_param_contents(msg, (void *)(local_hit),
					  HIP_PARAM_HIT,
					  sizeof(struct in6_addr)), -1,
		 "build param HIP_PARAM_HIT  failed\n");
	HIP_IFEL(hip_build_param_contents(msg, (void *)(peer_ip),
					  HIP_PARAM_IPV6_ADDR,
					  sizeof(struct in6_addr)), -1,
		 "build param HIP_PARAM_IPV6_ADDR failed\n");

	HIP_IFEL(hip_build_param_contents(msg, (void *)(&src_tcp_port),
					  HIP_PARAM_SRC_TCP_PORT,
					  sizeof(in_port_t)), -1,
		 "build param HIP_PARAM_SRC_TCP_PORT failed\n");

	HIP_IFEL(hip_build_param_contents(msg, (void *)(&dst_tcp_port),
					  HIP_PARAM_DST_TCP_PORT,
					  sizeof(in_port_t)), -1,
		 "build param HIP_PARAM_DST_TCP_PORT failed\n");
	
	/* build the message header */
	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_GET_PEER_HIT_AT_FIREWALL, 0), -1,
		 "build hdr failed\n");

	/* send and receive msg to/from hipd */
	HIP_IFEL(hip_send_recv_daemon_info(msg), -1, "send_recv msg failed\n");
	_HIP_DEBUG("send_recv msg succeed\n");

/*#################
	// check error value 
	HIP_IFEL(hip_get_msg_err(msg), -1, "Got erroneous message!\n");
	
	ptr = (hip_hit_t *) hip_get_param_contents(msg, HIP_PARAM_HIT);
	if (ptr) {
		memcpy(peer_hit, ptr, sizeof(hip_hit_t));
		HIP_DEBUG_HIT("peer_hit", peer_hit);
		*fallback = 0;
	}

	ptr = hip_get_param(msg, HIP_PARAM_AGENT_REJECT);
	if (ptr)
	{
		HIP_DEBUG("Connection is to be rejected\n");
		*reject = 1;
	}
#################*/

 out_err:
	
	if(msg)
		free(msg);
	
	return err;
}

//#######################################################















/**
 * Executes the packet reinjection
 *

 * @param src_hit              ipv6 source address 
 * @param dst_hit              ipv6 destination address
 * @param m                    pointer to the packet
 * @param ipOrigTraffic        type of Traffic (IPv4 or IPv6)
 * @param incoming             packet direction
 * @return	               err during the reinjection
 */
int reinject_packet(struct in6_addr src_hit, struct in6_addr dst_hit, ipq_packet_msg_t *m, int ipOrigTraffic, int incoming)
{
        int err, ip_hdr_size, packet_length = 0, protocol, ttl;
	u8 *msg;  
	struct icmphdr *icmp = NULL;

	if (ipOrigTraffic == 4){
		struct ip *iphdr = (struct ip*) m->payload;
		ip_hdr_size = (iphdr->ip_hl * 4);  
		protocol = iphdr->ip_p;
		ttl = iphdr->ip_ttl;
        	HIP_DEBUG_LSI("Ipv4 address src ", &(iphdr->ip_src));
	        HIP_DEBUG_LSI("Ipv4 address dst ", &(iphdr->ip_dst));
	}else{
	        struct ip6_hdr* ip6_hdr = (struct ip6_hdr*) m->payload;
		ip_hdr_size = sizeof(struct ip6_hdr); //Fixed size
		protocol = ip6_hdr->ip6_nxt;
		ttl = ip6_hdr->ip6_hlim;
		HIP_DEBUG_IN6ADDR("Orig packet src address: ", &(ip6_hdr->ip6_src));
		HIP_DEBUG_IN6ADDR("Orig packet dst address: ", &(ip6_hdr->ip6_dst));
		HIP_DEBUG_IN6ADDR("New packet src address:", &src_hit);
		HIP_DEBUG_IN6ADDR("New packet dst address: ", &dst_hit);
	}
	
	if (m->data_len <= (BUFSIZE - ip_hdr_size)){
		packet_length = m->data_len - ip_hdr_size; 	
	  	HIP_DEBUG("packet size smaller than buffer size\n");
	}
	else { 
	  	packet_length = BUFSIZE - ip_hdr_size;
		HIP_DEBUG("HIP packet size greater than buffer size\n");
	}

	_HIP_DEBUG("Reinject packet packet length (%d)\n", packet_length);
	_HIP_DEBUG("      Protocol %d\n", protocol);
	_HIP_DEBUG("      ipOrigTraffic %d \n", ipOrigTraffic);

	msg = (u8 *)HIP_MALLOC(packet_length, 0);
	memcpy(msg, (m->payload)+ip_hdr_size, packet_length);

	if (protocol == IPPROTO_ICMP && incoming){	          		  
		  icmp = (struct icmphdr *)msg;
		  HIP_DEBUG("protocol == IPPROTO_ICMP && incoming && type=%d code=%d\n",icmp->type,icmp->code);
		  /*Manually built due to kernel messed up with the ECHO_REPLY message.
		   Kernel was building an answer message with equals @src and @dst*/
		  if (icmp->type == ICMP_ECHO){
		  	icmp->type = ICMP_ECHOREPLY;
		    	err = firewall_send_outgoing_pkt(&dst_hit, &src_hit, msg, packet_length, protocol);
		  }
		  else{
		    	err = firewall_send_incoming_pkt(&src_hit, &dst_hit, msg, packet_length, protocol, ttl);
		  }
	}else{
		  if (incoming){
			    HIP_DEBUG("Firewall send to the kernel an incoming packet\n");
			    err = firewall_send_incoming_pkt(&src_hit, &dst_hit, msg, packet_length, protocol, ttl);
		  }else{
			    HIP_DEBUG("Firewall send to the kernel an outgoing packet\n");
			    err = firewall_send_outgoing_pkt(&src_hit, &dst_hit, msg, packet_length, protocol);
		  }
	}

	return err;	
}
