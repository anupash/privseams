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
        int proto6 = 0, ip_hdr_size = 0, portDest = 0;
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
	       default:
		 break;
	}
    
	if (portDest)
	        proto6 = getproto_info(ntohs(portDest), proto);

	if (!proto6){
	        lsi_our = (hip_lsi_t *)hip_get_lsi_our_by_hits(ip_src, ip_dst);
		lsi_peer = (hip_lsi_t *)hip_get_lsi_peer_by_hits(ip_src, ip_dst);

		if(lsi_our && lsi_peer){
		        IPV4_TO_IPV6_MAP(lsi_our, &src_addr);
			IPV4_TO_IPV6_MAP(lsi_peer, &dst_addr);
			_HIP_DEBUG_LSI("******lsi_src : ", lsi_our);
			_HIP_DEBUG_LSI("******lsi_dst : ", lsi_peer);
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
 * @param ip_src      ipv6 source address 
 * @param ip_dst      ipv6 destination address
 * @return	      err during the BEX
 */
int hip_fw_handle_outgoing_lsi(ipq_packet_msg_t *m, struct in_addr *ip_src, struct in_addr *ip_dst)
{
	int err, msg_type;
	struct in6_addr src_addr, dst_addr;
	struct in6_addr *src_hit = NULL, *dst_hit = NULL;
	firewall_hl_t *entry_peer = NULL;


	IPV4_TO_IPV6_MAP(ip_dst, &dst_addr);
	IPV4_TO_IPV6_MAP(ip_src, &src_addr);

	hip_firewall_hldb_dump();
	entry_peer = (firewall_hl_t *)firewall_hit_lsi_db_match(ip_dst);

	HIP_DEBUG("1. FIREWALL_TRIGGERING OUTGOING LSI %s\n",inet_ntoa(*ip_dst));

	if (entry_peer){
	        HIP_DEBUG("Firewall_db HIT ???? %d \n", entry_peer->bex_state);
		HIP_IFEL(entry_peer->bex_state == -1, -1, "Base Exchange Failed");
	  	if(entry_peer->bex_state)
			reinject_packet(entry_peer->hit_our, entry_peer->hit_peer, m, 4, 0);
	}else{
	        //Check if bex is already established: Server case
	        int state_ha = hip_trigger_is_bex_established(&src_hit, &dst_hit, ip_src, ip_dst);
		if (state_ha){
			HIP_DEBUG("ha is ESTABLISHED!\n");
			firewall_add_hit_lsi(src_hit, dst_hit, ip_dst, state_ha);
			reinject_packet(*src_hit, *dst_hit, m, 4, 0);
		}
		else{
			// Run bex to initialize SP and SA
			HIP_DEBUG("Firewall_db empty and no ha. Triggering Base Exchange\n");
			HIP_IFEL(hip_trigger_bex(&src_hit, &dst_hit, &src_addr, &dst_addr), -1, 
			 	 "Base Exchange Trigger failed");
		  	firewall_add_hit_lsi(src_hit, dst_hit, ip_dst, 0);
		}
	}
out_err: 
	return err;
}

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

	if (ipOrigTraffic == 4){
		struct ip *iphdr = (struct ip*) m->payload;
		ip_hdr_size = (iphdr->ip_hl * 4);  
		protocol = iphdr->ip_p;
		ttl = iphdr->ip_ttl;
        	HIP_DEBUG_LSI("Ipv4 address src ", &(iphdr->ip_src));
	        HIP_DEBUG_LSI("Ipv4 address dst ", &(iphdr->ip_dst));
	}else{
	        struct ip6_hdr* ip6_hdr = (struct ip6_hdr*) m->payload;
		ip_hdr_size = sizeof(struct ip6_hdr);
		protocol = ip6_hdr->ip6_nxt;
		ttl = ip6_hdr->ip6_hlim;
		HIP_DEBUG("ip_hdr_size %d\n",ip_hdr_size);
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

	HIP_DEBUG("-Reinject packet packet length is %d\n", packet_length);
	HIP_DEBUG("      Protocol used is %d\n", protocol);
	HIP_DEBUG("      ipOrigTraffic %d \n", ipOrigTraffic);

	msg = (u8 *)HIP_MALLOC(packet_length, 0);
	memcpy(msg, (m->payload)+ip_hdr_size, packet_length);

	//HIP_DUMP_MSG(msg);


	if (protocol == IPPROTO_ICMP && incoming){
		  HIP_DEBUG("protocol == IPPROTO_ICMP && incoming\n");
		  struct icmphdr *icmp = NULL;
		  icmp = (struct icmphdr *)msg;
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
