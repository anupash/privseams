/*
 * HIP proxy
 */

#include "proxy.h"

int handle_proxy_inbound_traffic(ipq_packet_msg_t *m,
				  struct in6_addr *src_addr)
{
	//struct in6_addr client_addr;
	//HIP PROXY INBOUND PROCESS
	int port_client, port_peer, protocol, err = 0;
	struct ip6_hdr* ipheader;
	//struct in6_addr proxy_hit;
	struct hip_conn_t* conn_entry = NULL;
	ipheader = (struct ip6_hdr*) m->payload;
	protocol = ipheader->ip6_ctlun.ip6_un1.ip6_un1_nxt;
	
	HIP_DEBUG("HIP PROXY INBOUND PROCESS:\n");
	HIP_DEBUG("receiving ESP packets from firewall!\n");
	
	if(protocol == IPPROTO_TCP)
	{
		port_peer = ((struct tcphdr *) (m->payload + 40))->source;
		port_client = ((struct tcphdr *) (m->payload + 40))->dest;
	}
	
	if(protocol == IPPROTO_UDP)
	{
		port_peer = ((struct udphdr *) (m->payload + 40))->source;
		port_client = ((struct udphdr *) (m->payload + 40))->dest;
	}
	
	//hip_get_local_hit_wrapper(&proxy_hit);
	conn_entry = hip_conn_find_by_portinfo(&proxy_hit, &src_addr, protocol, port_client, port_peer); 
	
	if(conn_entry)
	{
		if(conn_entry->state == HIP_PROXY_TRANSLATE)
		{
			int packet_length = 0;
			u16 * msg;
			int i;
			
			HIP_DEBUG("We are translating esp packet!\n");	
			HIP_DEBUG_IN6ADDR("inbound address 1:", &conn_entry->addr_peer);
			HIP_DEBUG_IN6ADDR("inbound address 2:", &conn_entry->addr_client);
			hip_proxy_send_to_client_pkt(&conn_entry->addr_peer, &conn_entry->addr_client,(u8*) ipheader, m->data_len);
			/* drop packet */
			err = 0;
		}
		
		if (conn_entry->state == HIP_PROXY_PASSTHROUGH) {
			/* allow packet */
			err = -1;
		}
	}
	else
	{
		//allow esp packet
		HIP_DEBUG("Can't find entry in ConnDB!\n");
		err = -1;
	}

out_err:
	return err;
}

int handle_proxy_outbound_traffic(ipq_packet_msg_t *m,
				  struct in6_addr *src_addr,
				  struct in6_addr *dst_addr,
				  int hdr_size,
				  int ip_version)
{
	//HIP PROXY OUTBOUND PROCESS
	//the destination ip address should be checked first to ensure it supports hip
	//if the destination ip does not support hip, drop the packet
	int err = 0;
	int protocol;
	int port_client;
	int port_peer;
	//struct in6_addr proxy_hit;
	struct in6_addr dst_hit;
	struct in6_addr proxy_addr;
	struct hip_proxy_t* entry = NULL;	
	struct hip_conn_t* conn_entry = NULL;
	
	if(ip_version == 4)
		protocol = ((struct ip *) (m->payload))->ip_p;
	
	if(ip_version == 6)
		protocol = ((struct ip6_hdr *) (m->payload))->ip6_ctlun.ip6_un1.ip6_un1_nxt;
	
	if(protocol == IPPROTO_TCP)
	{
		port_client = ((struct tcphdr *) (m->payload + hdr_size))->source;
		port_peer = ((struct tcphdr *) (m->payload + hdr_size))->dest;
	}
	
	if(protocol == IPPROTO_UDP)
	{
		port_client = ((struct udphdr *) (m->payload + hdr_size))->source;
		port_peer = ((struct udphdr *) (m->payload + hdr_size))->dest;
	}
	
	HIP_DEBUG("HIP PROXY OUTBOUND PROCESS:\n");
	entry = hip_proxy_find_by_addr(&src_addr, &dst_addr);
	//hip_get_local_hit_wrapper(&proxy_hit);
	if (entry == NULL)
	{
		int fallback, reject;
		
		hip_proxy_add_entry(&src_addr, &dst_addr);
		
		//hip_request_peer_hit_from_hipd();
		
		/* Request a HIT of the peer from hipd. This will possibly
		   launch an I1 with NULL HIT that will block until R1 is
		   received. Called e.g. in connect() or sendto(). If
		   opportunistic HIP fails, it can return an IP address
		   instead of a HIT */
		HIP_DEBUG("requesting hit from hipd\n");
		HIP_DEBUG_IN6ADDR("ip addr", &dst_addr);
		HIP_IFEL(hip_proxy_request_peer_hit_from_hipd(&dst_addr,
							      &dst_hit,
							      &proxy_hit,
							      &fallback,
							      &reject),
			 -1, "Request from hipd failed\n");
		if (reject)
		{
			HIP_DEBUG("Connection should be rejected\n");
			err = -1;
			goto out_err;
		}
		
		if (fallback)
		{
			HIP_DEBUG("Peer does not support HIP, fallback\n");
			//update the state of the ip pair
			if(hip_proxy_update_state(&src_addr, &dst_addr, NULL, NULL, NULL, NULL, HIP_PROXY_PASSTHROUGH))
				HIP_DEBUG("Proxy update Failed!\n");
			
			//let the packet pass
			err = -1;
		}
		else
		{
			hip_proxy_request_local_address_from_hipd(&proxy_hit, &dst_hit, &proxy_addr, &fallback, &reject);
			if(hip_proxy_update_state(&src_addr, &dst_addr, &proxy_addr, NULL, &dst_hit, &proxy_hit, HIP_PROXY_TRANSLATE))
				HIP_DEBUG("Proxy update Failed!\n");
			
			if(hip_conn_add_entry(&src_addr, &dst_addr, &proxy_hit, &dst_hit, protocol, port_client, port_peer, HIP_PROXY_TRANSLATE))
				HIP_DEBUG("ConnDB add entry Failed!\n");;
			
			/* Let packet pass */
			err = 0;
		}
	}
	else
	{			
		//check if the entry state is PASSTHROUGH
		if(entry->state == HIP_PROXY_PASSTHROUGH)
		{
			HIP_DEBUG("PASSTHROUGH!\n");
			err = -1;
		}
		
		
		if(entry->state == HIP_PROXY_TRANSLATE)
		{
			int packet_length = 0;
			u16 * msg;
			
			//TODO: check the connection with same ip but different port, should be added into conndb
			if(hip_conn_find_by_portinfo(&entry->hit_proxy, &entry->hit_peer, protocol, port_client, port_peer))
			{
				HIP_DEBUG("find same connection  in connDB\n");
			}
			else
			{
				//add conndb_entry here
				if(hip_conn_add_entry(&entry->addr_our, &entry->addr_peer, &entry->hit_proxy, &entry->hit_peer, protocol, port_client, port_peer, HIP_PROXY_TRANSLATE))
					HIP_DEBUG("ConnDB add entry Failed!\n");
				else
					HIP_DEBUG("ConnDB add entry Successful!\n");
			}
			
			HIP_DEBUG("We are in right place!\n");
			
			if((protocol == IPPROTO_ICMP) || (protocol == IPPROTO_ICMPV6))
			{
				hip_proxy_send_inbound_icmp_pkt(&proxy_hit, &entry->hit_peer, (u8*) m->payload, m->data_len);
				/* drop packet */
				err = 0;
			}
			else
			{
				packet_length = m->data_len - hdr_size;								
				msg = (u16 *) HIP_MALLOC(packet_length, 0);
				memcpy(msg, (m->payload) + hdr_size,
				       packet_length);
				
				HIP_DEBUG("Packet Length: %d\n", packet_length);
				HIP_HEXDUMP("ipv6 msg dump: ", msg, packet_length);
				hip_proxy_send_pkt(&proxy_hit, &entry->hit_peer, msg, packet_length, protocol);
				/* drop packet */
				err = 0;
			}
		}
	}
	
out_err:
	return err;			
}

