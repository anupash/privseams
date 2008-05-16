/*
 * This code is GNU/GPL.
 *
 * Firewall requires: 
 * modprobe ip6_queue
 * ip6tables -A FORWARD -m hip -j QUEUE
 * (ip6tables -A INPUT -p 99 -j QUEUE)
 * 
 */

#include "firewall.h"
#include <sys/types.h>

//#define HIP_HEADER_START 128 //bytes
#define BUFSIZE 2048

int statefulFiltering = 1;
int escrow_active = 0;
int accept_normal_traffic = 1;
int accept_hip_esp_traffic = 0;
int flush_iptables = 1;
int counter = 0;
int hip_proxy_status = 0;
int foreground = 1;


void print_usage()
{
	printf("HIP Firewall\n");
	printf("Usage: hipfw [-f file_name] [-t timeout] [-d|-v] [-F] [-H] [-A] [-b] [-k] [-h]\n");
	printf("      -H drop non-HIP traffic by default (default: accept non-hip traffic)\n");
	printf("      -A accept HIP traffic by default (default: drop all hip traffic)\n");
	printf("      -f file_name is a path to a file containing firewall filtering rules (default %s)\n", HIP_FW_DEFAULT_RULE_FILE);
	printf("      -t timeout is connection timeout value in seconds\n");
	printf("      -d = debugging output\n");
	printf("      -v = verbose output\n");
	printf("      -t = timeout for packet capture (default %d secs)\n", 
	HIP_FW_DEFAULT_TIMEOUT);
	printf("      -F = do not flush iptables rules\n");
	printf("      -b = fork the firewall to background\n");
	printf("      -k = kill running firewall pid\n");
	printf("      -h = print this help\n\n");
}

//currently done at all times, rule_management 
//delete rule needs checking for state options in 
//all chains
void set_stateful_filtering(int v)
{
	statefulFiltering = 1;
}

int get_stateful_filtering()
{
	return statefulFiltering;
}

void set_escrow_active(int active)
{
	escrow_active = active;
}

int is_escrow_active()
{
	return escrow_active;
}

/*----------------INIT/EXIT FUNCTIONS----------------------*/

int firewall_init_rules()
{
	HIP_DEBUG("Initializing firewall\n");

	HIP_DEBUG("Enabling forwarding for IPv4 and IPv6\n");
	system("echo 1 >/proc/sys/net/ipv4/conf/all/forwarding");
	system("echo 1 >/proc/sys/net/ipv6/conf/all/forwarding");

	if (flush_iptables)
	{
		HIP_DEBUG("Flushing all rules\n");
		system("iptables -F INPUT");
		system("iptables -F OUTPUT");
		system("iptables -F FORWARD");
		system("ip6tables -F INPUT");
		system("ip6tables -F OUTPUT");
		system("ip6tables -F FORWARD");
	}

	/* Register signal handlers */
	signal(SIGINT, firewall_close);
	signal(SIGTERM, firewall_close);

	// TARGET (-j) QUEUE will transfer matching packets to userspace
	// these packets will be handled using libipq
	
	if(hip_proxy_status)
	{
		//allow forward hip packets
		system("iptables -I FORWARD -p 139 -j ACCEPT");
		system("iptables -I FORWARD -p 139 -j ACCEPT");
		
		system("iptables -I FORWARD -p tcp -j QUEUE");
		system("iptables -I FORWARD -p udp -j QUEUE");
		//system("iptables -I FORWARD -p icmp -j QUEUE");
		//system("iptables -I FORWARD -p icmpv6 -j QUEUE");
		
		//system("iptables -t nat -A POSTROUTING -o vmnet2 -j SNAT --to-source 10.0.0.1");

		//allow forward hip packets
		system("ip6tables -I FORWARD -p 139 -j ACCEPT");
		system("ip6tables -I FORWARD -p 139 -j ACCEPT");
		
		system("ip6tables -I FORWARD -p tcp -j QUEUE");
		system("ip6tables -I FORWARD -p udp -j QUEUE");
		//system("ip6tables -I FORWARD -p icmp -j QUEUE");
		//system("ip6tables -I FORWARD -p icmpv6 -j QUEUE");
		
		system("ip6tables -I INPUT -p tcp -d 2001:0010::/28 -j QUEUE");
		system("ip6tables -I INPUT -p udp -d 2001:0010::/28 -j QUEUE");
		//system("ip6tables -I INPUT -p tcp  -j QUEUE");
		//system("ip6tables -I INPUT -p udp -j QUEUE");
		//system("ip6tables -I INPUT -p icmp -j QUEUE");
		//system("ip6tables -I INPUT -p icmpv6 -j QUEUE");

		hip_init_proxy_db();
		hip_init_conn_db();
	}
	else
	{
		if (!accept_normal_traffic)
		{
			system("iptables -I FORWARD -j DROP");
			system("iptables -I INPUT -j DROP");
			system("iptables -I OUTPUT -j DROP");
		}

		if (!accept_hip_esp_traffic)
		{
			system("iptables -I FORWARD -p 139 -j QUEUE");
			system("iptables -I FORWARD -p 50 -j QUEUE");
			system("iptables -I FORWARD -p 17 --dport 50500 -j QUEUE");
			system("iptables -I FORWARD -p 17 --sport 50500 -j QUEUE");

			system("iptables -I INPUT -p 139 -j QUEUE");
			system("iptables -I INPUT -p 50 -j QUEUE");
			system("iptables -I INPUT -p 17 --dport 50500 -j QUEUE");
			system("iptables -I INPUT -p 17 --sport 50500 -j QUEUE");

			system("iptables -I OUTPUT -p 139  -j QUEUE");
			system("iptables -I OUTPUT -p 50 -j QUEUE");
			system("iptables -I OUTPUT -p 17 --dport 50500 -j QUEUE");
			system("iptables -I OUTPUT -p 17 --sport 50500 -j QUEUE");
				
// TODO Rene: Miika, I don't this should be dependent on "accept_hip_esp_traffic"
#ifdef CONFIG_HIP_OPPTCP//tcp over ipv4
				system("iptables -I FORWARD -p 6 -j QUEUE");
				system("iptables -I INPUT -p 6 -j QUEUE");
				system("iptables -I OUTPUT -p 6 -j QUEUE");
#endif
		}
	}
	
			if (!accept_normal_traffic)
			{
				system("ip6tables -I FORWARD -j DROP");
				system("ip6tables -I INPUT -j DROP");
				system("ip6tables -I OUTPUT -j DROP");
			}
			else
			{
				if (!accept_hip_esp_traffic)
				{
					system("ip6tables -I FORWARD -p 139 -j QUEUE");
					system("ip6tables -I FORWARD -p 50 -j QUEUE");
					system("ip6tables -I FORWARD -p 17 --dport 50500 -j QUEUE");
					system("ip6tables -I FORWARD -p 17 --sport 50500 -j QUEUE");
	
					system("ip6tables -I INPUT -p 139 -j QUEUE");
					system("ip6tables -I INPUT -p 50 -j QUEUE");
					system("ip6tables -I INPUT -p 17 --dport 50500 -j QUEUE");
					system("ip6tables -I INPUT -p 17 --sport 50500 -j QUEUE");
	
					system("ip6tables -I OUTPUT -p 139  -j QUEUE");
					system("ip6tables -I OUTPUT -p 50 -j QUEUE");
					system("ip6tables -I OUTPUT -p 17 --dport 50500 -j QUEUE");
					system("ip6tables -I OUTPUT -p 17 --sport 50500 -j QUEUE");
				}
	#ifdef CONFIG_HIP_OPPTCP//tcp over ipv6
				system("ip6tables -I FORWARD -p 6 -j QUEUE");
				system("ip6tables -I INPUT -p 6 -j QUEUE");
				system("ip6tables -I OUTPUT -p 6 -j QUEUE");
	#endif
				
			}

 out_err:
	return 0;
}

void firewall_close(int signal)
{
	HIP_DEBUG("Closing firewall...\n");
	//hip_uninit_proxy_db();
	//hip_uninit_conn_db();
	firewall_exit();
	exit(signal);
}

void firewall_exit()
{
	HIP_DEBUG("Firewall exit\n");

	if (flush_iptables)
	{
		HIP_DEBUG("Flushing all rules\n");
		system("iptables -F INPUT");
		system("iptables -F OUTPUT");
		system("iptables -F FORWARD");
		system("ip6tables -F INPUT");
		system("ip6tables -F OUTPUT");
		system("ip6tables -F FORWARD");
//		system("iptables -t nat -F");
//		system("ip6tables -t nat -F");
	}
	else
	{
		HIP_DEBUG("Some dagling iptables rules may be present!\n");
	}

	hip_remove_lock_file(HIP_FIREWALL_LOCK_FILE);
}

/*-------------PACKET FILTERING FUNCTIONS------------------*/
int match_hit(struct in6_addr match_hit, struct in6_addr packet_hit, int boolean)
{
	int i= IN6_ARE_ADDR_EQUAL(&match_hit, &packet_hit);
	HIP_DEBUG("match_hit: hit1: %s hit2: %s bool: %d match: %d\n",
			addr_to_numeric(&match_hit), addr_to_numeric(&packet_hit), boolean, i);
	if (boolean)
		return i;
	else
		return !i;
}

/**
 *inspects host identity by verifying sender signature
 * returns 1 if verified succesfully otherwise 0
 */
int match_hi(struct hip_host_id * hi, struct hip_common * packet)
{
	int value = 0;
	if (packet->type_hdr == HIP_I1)
	{
		_HIP_DEBUG("match_hi: I1\n");
		return 1;
	}
	value = verify_packet_signature(hi, packet);
	if (value == 0)
		_HIP_DEBUG("match_hi: verify ok\n");
	else
		_HIP_DEBUG("match_hi: verify failed\n");
	if (value == 0)
		return 1;
	return 0;
}

int match_int(int match, int packet, int boolean)
{
	if (boolean)
		return match == packet;
	else
		return !(match == packet);
}

int match_string(const char * match, const char * packet, int boolean)
{
	if (boolean)
		return !strcmp(match, packet);
	else
		return strcmp(match, packet);
}

/*------------------------------------------------*/

static void die(struct ipq_handle *h)
{
	HIP_DEBUG("dying\n");
	ipq_perror("passer");
	ipq_destroy_handle(h);
	firewall_close(1);
}

/**
 * Returns the packet type of an IP packet.
 * 
 * Currently supported types:				type
 * - plain HIP control packet				  1
 * - STUN packet				  			  1 (UDP encapsulated HIP control)
 * - ESP packet								  2
 * - TCP packet								  3 (for opportunistic TCP handshake)
 * 
 * Unsupported types -> type 0
 *
 * @param  hdr        a pointer to a IP packet.
 * @param ipVersion	  the IP version for this packet
 * @return            One if @c hdr is a HIP packet, zero otherwise.
 */ 
int return_packet_type(void * hdr, int ipVersion){
	struct udphdr *udphdr = NULL;
	int hdr_size;
	int udp_spi_is_zero = 0;
	uint16_t plen;

	HIP_DEBUG("\n");

	if(ipVersion == 4){
		struct ip *iphdr = (struct ip *)hdr;
		
		_HIP_DEBUG("the IPv4 next header protocol number is %d\n", iphdr->ip_p);

		if(iphdr->ip_p == IPPROTO_HIP)
		{
			// we have found a plain HIP control packet
			HIP_DEBUG("plain HIP packet\n");
			return 1;
		} else if (iphdr->ip_p == IPPROTO_ESP)
		{
			// this is an ESP packet
			HIP_DEBUG("plain ESP packet\n");
			return 2;
#ifdef CONFIG_HIP_OPPTCP
		} else if(iphdr->ip_p == IPPROTO_TCP)
		{
			return 3;
#endif
		} else if (iphdr->ip_p != IPPROTO_UDP)
		{
			// if it's not UDP either, it's unsupported
			return 0;
		}

		// need UDP header to look for encapsulated ESP or STUN
		hdr_size = (iphdr->ip_hl * 4);
		
		HIP_DEBUG("hdr_size is %d\n", hdr_size);
		plen = iphdr->ip_len;
		udphdr = ((struct udphdr *) (((char *) iphdr) + hdr_size));
	} else if (ipVersion == 6)
	{
		struct ip6_hdr * ip6_hdr = (struct ip6_hdr *)hdr;

		HIP_DEBUG("the IPv6 next header protocol number is %d\n",
			  ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt);

		if(ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_HIP)
		{
			return 1;
		} else if (ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_ESP)
		{
			return 2;
#ifdef CONFIG_HIP_OPPTCP
		} else if(ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_TCP)
		{
			return 3;
#endif
		} else if (ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt != IPPROTO_UDP)
		{
			return 0;
		}
	
		hdr_size = (ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_plen * 4);
		plen = ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_plen;
		udphdr = ((struct udphdr *) (((char *) ip6_hdr) + hdr_size));
	}

	HIP_DEBUG("UDP header size  is %d\n", sizeof(struct udphdr));

	// TODO what does that "if" check?
	if (ipVersion == 4 &&
	    (plen >= sizeof(struct ip) + sizeof(struct udphdr) + HIP_UDP_ZERO_BYTES_LEN))
	{
		uint32_t *zero_bytes = NULL;
		// uint32_t *ip_esp_hdr = NULL;
		
		/* something wrong here?*/
		// zero_bytes = (uint32_t *) ((char *)udphdr + 1);

		// FIXME this does _NOT_ work
		zero_bytes = (uint32_t *) ((char *)udphdr + sizeof(struct udphdr));
	  
		HIP_DEBUG("zero_bytes address is Ox%x, value is %d\n", zero_bytes, 
			  *zero_bytes);
		
		/*Check whether SPI number is zero or not */
		if (*zero_bytes == 0) {
			// we have most probably found a STUN message
			udp_spi_is_zero = 1;
			HIP_DEBUG("Zero SPI found\n");
		}
	}

	if(udphdr
			&& ((udphdr->source == ntohs(HIP_NAT_UDP_PORT)) || 
		        (udphdr->dest == ntohs(HIP_NAT_UDP_PORT)))
		    && udp_spi_is_zero)
		
	{	
		/* check for HIP control message */
		if (!hip_check_network_msg((struct hip_common *) (((char *)udphdr) 
								     + 
								     sizeof(struct udphdr) 
								     + 
								     HIP_UDP_ZERO_BYTES_LEN)))
		{
			HIP_DEBUG("STUN packet\n");
			return 1;
		}
		HIP_DEBUG("FIXME zero bytes recognition obbiously not working\n");
	} else if (udphdr
				&& ((udphdr->source == ntohs(HIP_NAT_UDP_PORT)) || 
		            (udphdr->dest == ntohs(HIP_NAT_UDP_PORT)))
		        && !udp_spi_is_zero)
    {
    	/* from the ports and the non zero SPI we can tell that this
    	 * is an ESP packet */
		HIP_DEBUG("UDP encapsulated ESP packet\n");
   		return 2;
	}
	
	// plain UDP packet -> nothing to play around with
	HIP_DEBUG("unsupported UDP packet\n");
	return 0;
}

/**
 * Allow a packet to pass
 * 
 * @param handle	the handle for the packets.
 * @param packetId	the packet ID.
 * @return		nothing
 */
void allow_packet(struct ipq_handle *handle, unsigned long packetId)
{
	ipq_set_verdict(handle, packetId, NF_ACCEPT, 0, NULL);
	HIP_DEBUG("Packet accepted \n\n");
}

/**
 * Not allow a packet to pass
 * 
 * @param handle	the handle for the packets.
 * @param packetId	the packet ID.
 * @return		nothing
 */
void drop_packet(struct ipq_handle *handle, unsigned long packetId)
{
	ipq_set_verdict(handle, packetId, NF_DROP, 0, NULL);
	HIP_DEBUG("Packet dropped \n\n");
}

#ifdef CONFIG_HIP_OPPTCP

/**
 * Returns whether a packet is incoming
 * 
 * @param theHook	the packet hook.
 * @return		1 if incoming packet, 0 otherwise.
 */
int is_incoming_packet(unsigned int theHook)
{
	if(theHook == NF_IP_LOCAL_IN)
	return 1;
	return 0;
}

/**
 * Returns whether a packet is outgoing
 * 
 * @param theHook	the packet hook.
 * @return		1 if outgoing packet, 0 otherwise.
 */
int is_outgoing_packet(unsigned int theHook)
{
	if(theHook == NF_IP_LOCAL_OUT)
	return 1;
	return 0;
}

/**
 * Analyzes incoming TCP packets
 * 
 * @param *handle	the handle that has grabbed the packet, needed when allowing or dropping the packet.
 * @param packetId	the ID of the packet.
 * @param hdr		pointer to the ip packet being examined.
 * @param trafficType	ipv4 or ipv6 type of traffic.
 * @return		nothing
 */
void examine_incoming_tcp_packet(struct ipq_handle *handle,
				 unsigned long	    packetId,
				 void		   *hdr,
				 int		    trafficType,
				 int		    header_size){
	int i, optLen, optionsLen;
	char 	       *hdrBytes = NULL;
	struct tcphdr  *tcphdr;
	struct ip      *iphdr;
	struct ip6_hdr *ip6_hdr;
	//fields for temporary values
	u_int16_t       portTemp;
	struct in_addr  addrTemp;
	struct in6_addr addr6Temp;
	/* the following vars are needed for
	 * sending the i1 - initiating the exchange
	 * in case we see that the peer supports hip*/
	struct in6_addr *peer_ip  = NULL;
	struct in6_addr *peer_hit = NULL;
	in_port_t        src_tcp_port;
	in_port_t        dst_tcp_port;

	HIP_DEBUG("\n");

	peer_ip  = HIP_MALLOC(sizeof(struct in6_addr), 0);
	peer_hit = HIP_MALLOC(16, 0);

	if(trafficType == 4){
		iphdr = (struct ip *)hdr;
		//get the tcp header
		tcphdr = ((struct tcphdr *) (((char *) iphdr) + header_size));
		hdrBytes = ((char *) iphdr) + header_size;
		HIP_DEBUG_INADDR("the destination", &iphdr->ip_src);
		//peer and local ip needed for sending the i1 through hipd
		IPV4_TO_IPV6_MAP(&iphdr->ip_src, peer_ip);//TO  BE FIXED obtain the pseudo hit instead
	}
	else if(trafficType == 6){
		ip6_hdr = (struct ip6_hdr *)hdr;
		//get the tcp header
		tcphdr = ((struct tcphdr *) (((char *) ip6_hdr) + header_size));
		hdrBytes = ((char *) ip6_hdr) + header_size;
		//peer and local ip needed for sending the i1 through hipd
		peer_ip = &ip6_hdr->ip6_src;//TO  BE FIXED obtain the pseudo hit instead
	}

	/* this condition was originally only for SYN 0
	 * but below we added a condition for RST 1 and ACK 1
	 * So, in order for the RST ACK condition to be reachable,
	 * we added the condition for RST 0 here.
	 * The purpose is to process the packets as soon as possible.
	 * Many packets have SYN 0 and RST 0, so they get accepted quickly. 
	 */
	if((tcphdr->syn == 0) && (tcphdr->rst == 0)){
		allow_packet(handle, packetId);
		return;
	}

	//check that there are no options
	if(tcphdr->doff == 5){
		allow_packet(handle, packetId);
		return;
	}

	if((tcphdr->syn == 1) && (tcphdr->ack == 0)){	//incoming, syn=1 and ack=0
		if(tcp_packet_has_i1_option(hdrBytes, 4*tcphdr->doff)){
			/*//swap the ports
			portTemp = tcphdr->source;
			tcphdr->source = tcphdr->dest;
			tcphdr->dest = portTemp;
			//swap the ip addresses
			if(trafficType == 4){
				addrTemp = iphdr->ip_src;
				iphdr->ip_src = iphdr->ip_dst;
				iphdr->ip_dst = addrTemp;
			}
			else if(trafficType == 6){
				addr6Temp = ip6_hdr->ip6_src;
				ip6_hdr->ip6_src = ip6_hdr->ip6_dst;
				ip6_hdr->ip6_dst = addr6Temp;
			}
			//set ack field
			tcphdr->ack_seq = tcphdr->seq + 1;
			//set seq field
			tcphdr->seq = htonl(0);
			//set flags
			tcphdr->syn = 1;
			tcphdr->ack = 1;

			// send packet out after adding HIT
			// the option is already there but
			// it has to be added again since
			// if only the HIT is added, it will
			// overwrite the i1 option that is
			// in the options of TCP
			hip_request_send_tcp_packet(hdr, hdr_size + 4*tcphdr->doff, trafficType, 1, 1);
			*/
			//drop original packet
			drop_packet(handle, packetId);
			return;
		}
		else{
			allow_packet(handle, packetId);
			return;
		}
	}
	else if(((tcphdr->syn == 1) && (tcphdr->ack == 1)) ||	//incoming, syn=1 and ack=1
		((tcphdr->rst == 1) && (tcphdr->ack == 1))){	//incoming, rst=1 and ack=1
		//with the new implementation, the i1 is sent out directly
		/*if(tcp_packet_has_i1_option(hdrBytes, 4*tcphdr->doff)){
			// tcp header pointer + 20(minimum header length)
			// + 4(i1 option length in the TCP options)
			memcpy(peer_hit, &hdrBytes[20 + 4], 16);
			hip_request_send_i1_to_hip_peer_from_hipd(
					peer_hit,
					peer_ip);
			//the packet is no more needed
			drop_packet(handle, packetId);
			return;
		}
		else{*/
			//signal for the normal TCP packets not to be blocked for this peer
			//save in db that peer does not support hip
			hipd_unblock_app_AND_oppipdb_add_entry(peer_ip);

			//normal traffic connections should be allowed to be created
			allow_packet(handle, packetId);
			return;
		/*}*/
	}
	//allow all the rest
	allow_packet(handle, packetId);
}

/**
 * checks for the i1 option in a packet
 *
 * @param  tcphdrBytes	a pointer to the TCP header that is examined.
 * @param  hdrLen  	the length of the TCP header in bytes.
 * @return 		zero if i1 option not found in the options, or 1 if it is found.
 */
int tcp_packet_has_i1_option(void * tcphdrBytes, int hdrLen)
{
	int i = 20;//the initial obligatory part of the TCP header
	int foundHipOpp = 0, len = 0;
	char *bytes =(char*)tcphdrBytes;

	HIP_DEBUG("\n");

	while((i < hdrLen) && (foundHipOpp == 0))
	{
		switch (bytes[i])
		{
			//options with one-byte length
			case 0:
			break;
			break;
			case 1: i++; break;
			case 11: i++; break;
			case 12: i++; break;
			case 13: i++; break;
			case 16: i++; break;
			case 17: i++; break;
			case 20: i++; break;
			case 21: i++; break;
			case 22: i++; break;
			case 23: i++; break;
			case 24: i++; break;
			//case 25: i++; break;  //unassigned
			case 26: i++; break;
			case 2: len = bytes[i+1]; i += len; break;
			case 3: len = bytes[i+1]; i += len; break;
			case 4: len = bytes[i+1]; i += len; break;
			case 5: len = bytes[i+1]; i += len; break;
			case 6: len = bytes[i+1]; i += len; break;
			case 7: len = bytes[i+1]; i += len; break;
			case 8: len = bytes[i+1]; i += len; break;
			case 9: len = bytes[i+1]; i += len; break;
			case 10: len = bytes[i+1]; i += len; break;
			case 14: len = bytes[i+1]; i += len; break;
			case 15: len = bytes[i+1]; i += len; break;
			case 18: len = bytes[i+1]; i += len; break;
			case 19: len = bytes[i+1]; i += len; break;
			case 27: len = bytes[i+1]; i += len; break;
			case 253: len = bytes[i+1]; i += len; break;
			case 254: len = bytes[i+1]; i += len; break;
			case HIP_OPTION_KIND: //hip option
			return 1;
		break;
		//options with one-byte length
		case 0: i++; break;
		case 1: i++; break;
		case 11: i++; break;
		case 12: i++; break;
		case 13: i++; break;
		case 16: i++; break;
		case 17: i++; break;
		case 20: i++; break;
		case 21: i++; break;
		case 22: i++; break;
		case 23: i++; break;
		case 24: i++; break;
		//case 25: i++; break;  //unassigned
		case 26: i++; break;
		case 2:	len = bytes[i+1]; i += len; break;
		case 3:	len = bytes[i+1]; i += len; break;
		case 4:	len = bytes[i+1]; i += len; break;
		case 5:	len = bytes[i+1]; i += len; break;
		case 6:	len = bytes[i+1]; i += len; break;
		case 7:	len = bytes[i+1]; i += len; break;
		case 8:	len = bytes[i+1]; i += len; break;
		case 9:	len = bytes[i+1]; i += len; break;
		case 10: len = bytes[i+1]; i += len; break;
		case 14: len = bytes[i+1]; i += len; break;
		case 15: len = bytes[i+1]; i += len; break;
		case 18: len = bytes[i+1]; i += len; break;
		case 19: len = bytes[i+1]; i += len; break;
		case 27: len = bytes[i+1]; i += len; break;
		case 253: len = bytes[i+1]; i += len; break;
		case 254: len = bytes[i+1]; i += len; break;
		default:  len = bytes[i+1]; i += len; break;
		}
	}
	return foundHipOpp;
}

/**
 * Sends a message to hipd so that hipd initiates the basic exchange, sending the i1. In this message, the ports are 0, so that at the hip_send_i1 function we know we don't need to send the TCP SYN_i1 again.
 * 
 * @param peer_hit	the peer hit that has been obtained from the TCP SYN_ACK_i1 packet.
 * @param peer_ip	the peer ip to send the i1 packet to.
 * @return		nothing.
 */
void hip_request_send_i1_to_hip_peer_from_hipd(struct in6_addr *peer_hit,
		struct in6_addr *peer_ip)
{
	struct hip_common *msg = NULL;
	int err = 0;
	in_port_t src_tcp_port = (in_port_t)0;
	in_port_t dst_tcp_port = (in_port_t)0;

	HIP_DEBUG("\n");

	HIP_IFE(!(msg = hip_msg_alloc()), -1);

	/*	HIP_IFEL(hip_build_param_contents(msg, (void *)(peer_hit),
	 HIP_PARAM_PEER_HIT,
	 sizeof(struct in6_addr)),
	 -1, "build param HIP_PARAM_PEER_HIT failed\n");
	 */
	HIP_IFEL(hip_build_param_contents(msg, (void *)(peer_ip),
					HIP_PARAM_IPV6_ADDR,
					sizeof(struct in6_addr)),
			-1, "build param HIP_PARAM_IPV6_ADDR failed\n");

	/*both ports are 0 here so that we don't send the TCp SYN_i1 in hip_send_i1*/
	HIP_IFEL(hip_build_param_contents(msg, (in_port_t *)(&src_tcp_port),
					HIP_PARAM_SRC_TCP_PORT,
					sizeof(in_port_t)),
			-1, "build param HIP_PARAM_SRC_TCP_PORT failed\n");

	HIP_IFEL(hip_build_param_contents(msg, (in_port_t *)(&dst_tcp_port),
					HIP_PARAM_DST_TCP_PORT,
					sizeof(in_port_t)),
			-1, "build param HIP_PARAM_DST_TCP_PORT failed\n");

	/* build the message header */
	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_GET_PEER_HIT_FROM_FIREWALL, 0), -1, "build hdr failed\n");
	HIP_DUMP_MSG(msg);

	/* send and receive msg to/from hipd */
	HIP_IFEL(hip_send_recv_daemon_info(msg), -1, "send_recv msg failed\n");
	_HIP_DEBUG("send_recv msg succeed\n");

	/* check error value */
	HIP_IFEL(hip_get_msg_err(msg), -1, "Got erroneous message!\n");

 out_err:
	return err;
}

/**
 * Send the ip of a peer to hipd, so that it can:
 * - unblock the packets that are sent to a particular peer.
 * - add it to the blacklist database.
 *
 * @param peer_ip	peer ip.
 * @return		nothing
 */
void hipd_unblock_app_AND_oppipdb_add_entry(const struct in6_addr *peer_ip){
	struct hip_common *msg = NULL;
	int err = 0;

	HIP_DEBUG("\n");

	HIP_IFE(!(msg = hip_msg_alloc()), -1);

	HIP_IFEL(hip_build_param_contents(msg, (void *)(peer_ip),
					HIP_PARAM_IPV6_ADDR,
					sizeof(struct in6_addr)),
			-1, "build param HIP_PARAM_IPV6_ADDR failed\n");

	/* build the message header */
	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_OPPTCP_UNBLOCK_APP_and_OPPIPDB_ADD_ENTRY, 0),
		 -1, "build hdr failed\n");
	HIP_DUMP_MSG(msg);

	/* send and receive msg to/from hipd */
	HIP_IFEL(hip_send_recv_daemon_info(msg), -1, "send_recv msg failed\n");
	_HIP_DEBUG("send_recv msg succeed\n");
	/* check error value */
	HIP_IFEL(hip_get_msg_err(msg), -1, "Got erroneous message!\n");

	out_err:
	return err;
}

/**
 * Send the ip of a peer to hipd, so that it can add it to the blacklist database.
 * 
 * @param peer_ip	peer ip.
 * @return		nothing
 */
void hip_request_oppipdb_add_entry(struct in6_addr *peer_ip)
{
	struct hip_common *msg = NULL;
	int err = 0;

	HIP_DEBUG("\n");

	HIP_IFE(!(msg = hip_msg_alloc()), -1);

	HIP_IFEL(hip_build_param_contents(msg, (void *)(peer_ip),
					HIP_PARAM_IPV6_ADDR,
					sizeof(struct in6_addr)),
			-1, "build param HIP_PARAM_IPV6_ADDR failed\n");

	/* build the message header */
	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_OPPTCP_OPPIPDB_ADD_ENTRY, 0), -1,
			"build hdr failed\n");
	HIP_DUMP_MSG(msg);
	/* send and receive msg to/from hipd */
	HIP_IFEL(hip_send_recv_daemon_info(msg), -1, "send_recv msg failed\n");
	_HIP_DEBUG("send_recv msg succeed\n");
	/* check error value */
	HIP_IFEL(hip_get_msg_err(msg), -1, "Got erroneous message!\n");

	out_err:
	return err;
}

/**
 * Send the necessary data to hipd, so that a tcp packet is sent from there. This was done because it was not possible to send a packet directly from here.
 * 
 * @param *hdr		pointer to the packet that is to be sent.
 * @param packet_size	the size of the packet.
 * @param trafficType	ipv4 or ipv6.
 * @param addHit	whether the local HIT is to be added at the tcp options
 * @param addOption	whether the i1 option is to be added at the tcp options
 * @return		nothing
 */
/**
 * Send the necessary data to hipd, so that a tcp packet is sent from there. This was done because it was not possible to send a packet directly from here.
 * 
 * @param *hdr		pointer to the packet that is to be sent.
 * @param packet_size	the size of the packet.
 * @param trafficType	ipv4 or ipv6.
 * @param addHit	whether the local HIT is to be added at the tcp options
 * @param addOption	whether the i1 option is to be added at the tcp options
 * @return		nothing
 */
void hip_request_send_tcp_packet(void *hdr,
				 int   packet_size,
				 int   trafficType,
				 int   addHit,
				 int   addOption){
	const struct hip_common *msg = NULL;
	int err = 0;
	
	HIP_DEBUG("\n");

	HIP_IFE(!(msg = hip_msg_alloc()), -1);

	HIP_IFEL(hip_build_param_contents(msg, (void *)hdr,
					  HIP_PARAM_IP_HEADER,
					  packet_size),
		-1, "build param HIP_PARAM_IP_HEADER failed\n");
	
	HIP_IFEL(hip_build_param_contents(msg, (int *)(&packet_size),
					  HIP_PARAM_PACKET_SIZE,
					  sizeof(int)),
		-1, "build param HIP_PARAM_PACKET_SIZE failed\n");

	HIP_IFEL(hip_build_param_contents(msg, (int *)(&trafficType),
					  HIP_PARAM_TRAFFIC_TYPE,
					  sizeof(int)),
		-1, "build param HIP_PARAM_TRAFFIC_TYPE failed\n");

	HIP_IFEL(hip_build_param_contents(msg, (int *)(&addHit),
					  HIP_PARAM_ADD_HIT,
					  sizeof(int)),
		-1, "build param HIP_PARAM_ADD_HIT failed\n");

	HIP_IFEL(hip_build_param_contents(msg, (int *)(&addOption),
					  HIP_PARAM_ADD_OPTION,
					  sizeof(int)),
		-1, "build param HIP_PARAM_ADD_OPTION failed\n");

	/* build the message header */
	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_OPPTCP_SEND_TCP_PACKET, 0),
		-1, "build hdr failed\n");
	HIP_DUMP_MSG(msg);
	/* send and receive msg to/from hipd */
	HIP_IFEL(hip_send_daemon_info_wrapper(msg, 1), -1, "send_recv msg failed\n");
	_HIP_DEBUG("send_recv msg succeed\n");
	/* check error value */
	//HIP_IFEL(hip_get_msg_err(msg), -1, "Got erroneous message!\n");

 out_err:
	return;
}

/**
 * Analyzes outgoing TCP packets. We decided to send the TCP SYN_i1
 * from hip_send_i1 in hipd, so for the moment this is not being used.
 * 
 * @param *handle	the handle that has grabbed the packet,
 * 			needed when allowing or dropping the packet.
 * @param packetId	the ID of the packet.
 * @param hdr		pointer to the ip packet being examined.
 * @param trafficType	ipv4 or ipv6 type of traffic.
 * @return		nothing
 */
void examine_outgoing_tcp_packet(struct ipq_handle *handle,
		unsigned long packetId,
		void *hdr,
		int trafficType)
{
	int i, optLen, hdr_size, optionsLen;
	char *hdrBytes = NULL;
	struct tcphdr *tcphdr;

	HIP_DEBUG("\n");

	if(trafficType == 4)
	{
		struct ip * iphdr = (struct ip *)hdr;
		//get the tcp header
		hdr_size = (iphdr->ip_hl * 4);
		tcphdr = ((struct tcphdr *) (((char *) iphdr) + hdr_size));
		hdrBytes = ((char *) iphdr) + hdr_size;
	}
	if(trafficType == 6)
	{
		struct ip6_hdr * ip6_hdr = (struct ip6_hdr *)hdr;
		//get the tcp header		
		hdr_size = (ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_plen * 4);
		tcphdr = ((struct tcphdr *) (((char *) ip6_hdr) + hdr_size));
		hdrBytes = ((char *) ip6_hdr) + hdr_size;
	}

	//check if SYN field is 0
	if(tcphdr->syn == 0)
	{
		allow_packet(handle, packetId);
		return;
	}

	//outgoing, syn=1 and ack=0
	/*	if(((tcphdr->syn == 1) && (tcphdr->ack == 0))){
	 if(tcp_packet_has_i1_option(hdrBytes, 4*tcphdr->doff)){
	 allow_packet(handle, packetId);
	 return;
	 }
	 //add the option to the packet
	 send_tcp_packet(&hip_nl_route, hdr, hdr_size + 4*tcphdr->doff, trafficType, sockfd, 1, 0);//1, 0
	 //drop original packet
	 drop_packet(handle, packetId);
	 return;
	 }*/

	//allow all the rest
	allow_packet(handle, packetId);
}
#endif /* CONFIG_HIP_OPPTCP */

/* filter hip packet according to rules.
 * return verdict
 */
int filter_esp(const struct in6_addr * dst_addr, struct hip_esp_packet * esp,
		unsigned int hook, const char * in_if, const char * out_if)
{
	struct _GList * list = (struct _GList *) read_rules(hook);
	struct rule * rule= NULL;
	int match = 1; // is the packet still a potential match to current rule
	int ret_val = 0;
	uint32_t spi = esp->esp_data->esp_spi;

	_HIP_DEBUG("filter_esp:\n");
	while (list != NULL)
	{
		match = 1;
		rule = (struct rule *) list->data;
		_HIP_DEBUG("   filter_esp: checking for:\n");
		//print_rule(rule);
		HIP_DEBUG_HIT("dst addr: ", dst_addr);
		HIP_DEBUG("SPI: %d\n", ntohl(spi));

		//type not valid with ESP packets
		if (rule->type)
		{
			//not valid with ESP packet
			_HIP_DEBUG("filter_esp: type option not valid for esp\n");
			match = 0;
		}
		//src and dst hits are matched with state option
		if ((rule->src_hit || rule->dst_hit) && !rule->state)
		{
			//not valid with ESP packet
			_HIP_DEBUG("filter_esp: hit options without state option not valid for esp\n");
			match = 0;
		}
		if (match && rule->in_if)
		{
			if (!match_string(rule->in_if->value, in_if,
					rule->in_if->boolean))
				match = 0;
			_HIP_DEBUG("filter_esp: in_if rule: %s, packet: %s, boolean: %d, match: %d \n",
					rule->in_if->value,
					in_if, rule->in_if->boolean, match);
		}
		if (match && rule->out_if)
		{
			if (!match_string(rule->out_if->value, out_if,
					rule->out_if->boolean))
				match = 0;
			_HIP_DEBUG("filter_esp: out_if rule: %s, packet: %s, boolean: %d, match: %d \n",
					rule->out_if->value, out_if, rule->out_if->boolean, match);
		}
		//must be last, so match and verdict known here
		if (match && rule->state)
		{
			//the entire rule os passed as argument as hits can only be 
			//filtered whit the state information
			if (!filter_esp_state(dst_addr, esp, rule))
			{//rule->state, rule->accept))
				match = 0;
				_HIP_DEBUG("filter_esp: state, rule %d, boolean %d match %d\n",
						rule->state->int_opt.value,
						rule->state->int_opt.boolean,
						match);
				break;
			}
		}
		// if a match, no need to check further rules
		if (match)
		{
			_HIP_DEBUG("filter_esp: match found\n");
			break;
		}
		list = list->next;
	}
	//was there a rule matching the packet
	if (rule && match)
	{
		_HIP_DEBUG("filter_esp: packet matched rule, target %d\n", rule->accept);
		ret_val = rule->accept;
	}
	else
		ret_val = 0;
	//release rule list
	read_rules_exit(0);
	//return the target of the the matched rule or true if no rule matched
	return ret_val;
}

/* filter hip packet according to rules.
 * return verdict
 */
int filter_hip(const struct in6_addr * ip6_src,
               const struct in6_addr * ip6_dst, 
	       struct hip_common *buf, 
	       unsigned int hook, 
	       const char * in_if, 
	       const char * out_if)
{
  	struct _GList * list = (struct _GList *) read_rules(hook);
  	struct rule * rule = NULL;
  	int match = 1; // is the packet still a potential match to current rule
  	int conntracked = 0;
  	int ret_val = 0;

	HIP_DEBUG("\n");

  	//if dynamically changing rules possible 
  	//int hip_packet = is_hip_packet(), ..if(hip_packet && rule->src_hit)
  	//+ filter_state käsittelemään myös esp paketit
  	_HIP_DEBUG("filter_hip: \n");
  	while (list != NULL)
    	{
      		match = 1;
      		rule = (struct rule *) list->data;
      		_HIP_DEBUG("   filter_hip: checking for \n");     
      		//print_rule(rule);
        	if (buf->type_hdr == HIP_I1)
			HIP_DEBUG("packet type: I1\n");
        	else if (buf->type_hdr == HIP_R1)
			HIP_DEBUG("packet type: R1\n");
        	else if (buf->type_hdr == HIP_I2)
			HIP_DEBUG("packet type: I2\n");
        	else if (buf->type_hdr == HIP_R2)
			HIP_DEBUG("packet type: R2\n");
        	else if (buf->type_hdr == HIP_UPDATE)
			HIP_DEBUG("packet type: UPDATE\n");

                          
		HIP_DEBUG_HIT("src hit: ", &(buf->hits));
        	HIP_DEBUG_HIT("dst hit: ", &(buf->hitr));

      		if(match && rule->src_hit)
	  	{
	    		HIP_DEBUG("filter_hip: src_hit ");
	    		if(!match_hit(rule->src_hit->value, 
			  		buf->hits, 
			  		rule->src_hit->boolean))
	      			match = 0;
		}
	    	//if HIT has matched and HI defined, verify signature 
	    	if(match && rule->src_hi)
	      	{
			_HIP_DEBUG("filter_hip: src_hi \n");
			if(!match_hi(rule->src_hi, buf))
		  		match = 0;	
	      	}
      		if(match && rule->dst_hit)
		{
        		HIP_DEBUG("filter_hip: dst_hit \n");
	    		if(!match_hit(rule->dst_hit->value, 
			  		buf->hitr, 
			  		rule->dst_hit->boolean))
	    			match = 0;	
	  	}
      		if(match && rule->type)
	  	{
	    		HIP_DEBUG("filter_hip: type ");
	    		if(!match_int(rule->type->value, 
			  		buf->type_hdr, 
			  		rule->type->boolean))
	     			match = 0;	
	    		HIP_DEBUG("filter_hip: type rule: %d, packet: %d, boolean: %d, match: %d\n",
		      			rule->type->value, 
		      			buf->type_hdr,
		      			rule->type->boolean,
		      			match);
	  	}      
      		if(match && rule->in_if)
	  	{
	    		if(!match_string(rule->in_if->value, in_if, rule->in_if->boolean))
	      			match = 0;
	    		HIP_DEBUG("filter_hip: in_if rule: %s, packet: %s, boolean: %d, match: %d \n",
		      			rule->in_if->value, 
		      			in_if, rule->in_if->boolean, match);
	  	}
      		if(match && rule->out_if)
	  	{
	    		if(!match_string(rule->out_if->value, 
			     		out_if, 
			     		rule->out_if->boolean))
	      			match = 0;
	    		HIP_DEBUG("filter_hip: out_if rule: %s, packet: %s, boolean: %d, match: %d \n",
		      			rule->out_if->value, out_if, rule->out_if->boolean, match);
	  	}
	
		//must be last, so not called if packet is going to be dropped
      		if(match && rule->state)
	  	{
	    		if(!filter_state(ip6_src, ip6_dst, buf, rule->state, rule->accept))
	    			match = 0;
	    		else
	    			conntracked = 1;
	    		HIP_DEBUG("filter_hip: state, rule %d, boolean %d match %d\n", 
		      			rule->state->int_opt.value,
		      			rule->state->int_opt.boolean, 
		      			match);
		}
		// if a match, no need to check further rules
		if(match){
			HIP_DEBUG("filter_hip: match found\n");
			break;
 		}
    		list = list->next;
    	}
  	//was there a rule matching the packet
  	if(rule && match)
    	{
    		HIP_DEBUG("filter_hip: packet matched rule, target %d\n", rule->accept);
    		ret_val = rule->accept; 
    	}
 	else
    		ret_val = 0; 
  	//release rule list
  	read_rules_exit(0);
  	// if packet will be accepted and connection tracking is used
  	// but the packet has not been analysed by the conntrack module
  	// show the packet to conntracking
  	if(statefulFiltering && ret_val && !conntracked){
    		conntrack(ip6_src, ip6_dst, buf);
  	}
  	//return the target of the the matched rule
  	return ret_val; 
}

/**
 * Analyzes outgoing TCP packets. We decided to send the TCP SYN_i1
 * from hip_send_i1 in hipd, so for the moment this is not being used.
 * 
 * @param *ptr	pointer to an integer that indicates
 * 		the type of traffic: 4 - ipv4; 6 - ipv6.
 * @return	nothing, this function loops forever,
 * 		until the firewall is stopped.
 */
static void *handle_ip_traffic(struct ipq_handle *hndl, int traffic_type)
{
	int status;
	unsigned char buf[BUFSIZE];
	struct hip_esp * esp_data= NULL;
	struct hip_esp_packet * esp= NULL;
	struct hip_common * hip_common= NULL;
	struct in6_addr src_addr;
	struct in6_addr dst_addr;
	struct in6_addr proxy_addr;
	struct in6_addr src_hit;
	struct in6_addr dst_hit;
	struct in6_addr proxy_hit;
	struct hip_proxy_t* entry = NULL;	
	struct hip_conn_t* conn_entry = NULL;
	unsigned int packetHook;
	
	HIP_DEBUG("thread for traffic_type=IPv%d traffic started\n", traffic_type);

	do
	{
		/* waits for queue messages to arrive from ip_queue and
		 * copies them into a supplied buffer */
		status = ipq_read(hndl, buf, BUFSIZE, 0);
		if (status < 0)
			die(hndl);
		/* queued messages may be a packet messages or an error messages */
		switch (ipq_message_type(buf))
		{
			case NLMSG_ERROR:
				fprintf(stderr, "Received error message (%d): %s\n", ipq_get_msgerr(buf), ipq_errstr());
				break;

		case IPQM_PACKET:
		{
			struct ip6_hdr * ip6_hdr= NULL;
			struct ip * iphdr= NULL;
			struct udphdr * udptemp = NULL;
			void * packet_hdr= NULL;
			int hdr_size = 0;

			ipq_packet_msg_t *m = ipq_get_packet(buf);
			packetHook = m->hook;
			
			// HIP and ESP headers have different offset for IPv4 and IPv6
			if (traffic_type == 4){
               	_HIP_DEBUG("ipv4\n");
               	iphdr = (struct ip *) m->payload; 
				//fields needed for analysis of tcp packets
               	packet_hdr = (void *)iphdr;
               	hdr_size = (iphdr->ip_hl * 4);

               	// IPv4 traffic might be UDP encasulated HIP or ESP
               	// TODO check where used due to zero bytes
               	if (iphdr->ip_p == IPPROTO_UDP){
					hdr_size += sizeof(struct udphdr) + HIP_UDP_ZERO_BYTES_LEN;
				}
               	
                _HIP_DEBUG("header size: %d\n", hdr_size);
               	IPV4_TO_IPV6_MAP(&iphdr->ip_src, &src_addr);
                IPV4_TO_IPV6_MAP(&iphdr->ip_dst, &dst_addr);
        	} else if(traffic_type == 6)
        	{
            	_HIP_DEBUG("ipv6\n");
            	ip6_hdr = (struct ip6_hdr *) m->payload;
				//fields needed for analysis of tcp packets
                packet_hdr = (void *)ip6_hdr;
				hdr_size = sizeof(struct ip6_hdr);

               	_HIP_DEBUG("header size: %d\n", hdr_size);
                ipv6_addr_copy(&src_addr, &ip6_hdr->ip6_src);
                ipv6_addr_copy(&dst_addr, &ip6_hdr->ip6_dst);
        	}
      
			// handle all different kind of packets
			switch (return_packet_type(packet_hdr, traffic_type))
			{
				case 1:
				{
      				// handle HIP packets
      				HIP_DEBUG("****** Received HIP packet ******\n");
					int packet_length = 0;
					struct hip_sig * sig = NULL;

					if (m->data_len <= (BUFSIZE - hdr_size))
					{
		  				packet_length = m->data_len - hdr_size; 	
		  				_HIP_DEBUG("HIP packet size smaller than buffer size\n");
		  			} else
		  			{
		  				/* packet is too long -> drop as max_size is well defined in RFC */
		  				//packet_length = BUFSIZE - hdr_size;
		  				_HIP_DEBUG("HIP packet size greater than buffer size\n");
		  				drop_packet(hndl, m->packet_id);
		  				
		  				break;
		  			}
				
					hip_common = (struct hip_common *)HIP_MALLOC(packet_length, 0);
	
					//hip_common = (struct hip_common*) (m->payload + sizeof (struct ip6_hdr));
	
					memcpy(hip_common, m->payload + hdr_size, packet_length);		
				
					// TODO check if signature is verified somewhere
					sig = (struct hip_sig *) hip_get_param(hip_common, HIP_PARAM_HIP_SIGNATURE);
					if(sig == NULL)
		  				_HIP_DEBUG("no signature\n");
					else
		  				_HIP_DEBUG("signature exists\n");
	
					// check HIP packet against firewall rules
					if(filter_hip(&src_addr, 
						      &dst_addr, 
						      hip_common, 
						      m->hook,
						      m->indev_name,
						      m->outdev_name))
		  			{
						allow_packet(hndl, m->packet_id);
					} else
		  			{
						drop_packet(hndl, m->packet_id);
		  			}
					
					HIP_FREE(hip_common);
					hip_common = NULL;
					
					break;
      			}
				case 2:
				{
					// handle ESP packet for HITs
      				HIP_DEBUG("****** Received ESP packet ******\n");
      				
      				//TODO prettier way to get spi
      				uint32_t spi_val;
      				memcpy(&spi_val, 
      						(m->payload + sizeof(struct ip6_hdr)), 
      						sizeof(__u32));
      				/*
      				if(filter_esp(&ip6_hdr->ip6_dst, 
      						spi_val,
      						m->hook,
      						m->indev_name,
      						m->outdev_name))
      				{
      				*/
      				
      					allow_packet(hndl, m->packet_id);
      					
      				/*
      				} else
      				{
      					drop_packet(hndl, m->packet_id);
      				}
      				*/
      				break;
				}	
#ifdef CONFIG_HIP_OPPTCP
				/* OPPORTUNISTIC MODE HACKS */
				/*
				if((ipv4Traffic && iphdr->ip_p != IPPROTO_TCP) ||
						(ipv6Traffic && ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt != IPPROTO_TCP))
				{
					if(accept_normal_traffic)
						allow_packet(hndl, m->packet_id);
					else
						drop_packet(hndl, m->packet_id);
				} else if(is_incoming_packet(packetHook))
				{
					examine_incoming_tcp_packet(hndl, m->packet_id, packet_hdr, type);
				} else if(is_outgoing_packet(packetHook))
				{
					//examine_outgoing_tcp_packet(hndl, m->packet_id, packet_hdr, type);
					allow_packet(hndl, m->packet_id);
				} else
				{
				*/
				case 3:
				{
					// TODO what happens to normal TCP?
					if(is_incoming_packet(packetHook))
					{
						examine_incoming_tcp_packet(hndl, m->packet_id, packet_hdr, type);
					} else if(is_outgoing_packet(packetHook))
					{
						//examine_outgoing_tcp_packet(hndl, m->packet_id, packet_hdr, type);
						allow_packet(hndl, m->packet_id);
					}
				}
#endif
					
				default:
				{
//#ifdef CONFIG_HIP_HIPPROXY
					//inbound process
					//static int ipv6_addr_is_hit(const struct in6_addr *hit);
					//if src and dst are HIT, then go for inbound process
					if(hip_proxy_status)
					{				
						HIP_DEBUG("HIP PROXY! \n");
						
						if(IN6_IS_ADDR_V4MAPPED(&src_addr))
							HIP_DEBUG("Source address is IPV4!\n");
						if(IN6_IS_ADDR_V4MAPPED(&dst_addr))
							HIP_DEBUG("Destination address is IPV4!\n");
						
						
						HIP_DEBUG_IN6ADDR("src_addr", &src_addr);
						HIP_DEBUG_IN6ADDR("dst_addr", &dst_addr);
						
						if(ipv6_addr_is_hit(&src_addr))
							HIP_DEBUG("Source address is HIT!\n");
						if(ipv6_addr_is_hit(&dst_addr))
							HIP_DEBUG("Destination address is HIT!\n");
						
						HIP_DEBUG_HIT("src_addr", &src_hit);
						HIP_DEBUG_HIT("dst_addr", &dst_hit);
						
						HIP_DEBUG("HIP PROXY OK! \n");
						
						
						if(ipv6_addr_is_hit(&src_addr) && ipv6_addr_is_hit(&dst_addr))
						{
							//struct in6_addr client_addr;
							//HIP PROXY INBOUND PROCESS
							handle_proxy_inbound_traffic(m, hndl, src_addr);
						}
						else
						{		
							//HIP PROXY OUTBOUND PROCESS
							//the destination ip address should be checked first to ensure it supports hip
							//if the destination ip does not support hip, drop the packet						
							if(handle_proxy_outbound_traffic(m, hndl,	src_addr, dst_addr, hdr_size, traffic_type))
								HIP_DEBUG("handle proxy outbound traffic error!\n");
						}
						
						// TODO check default behaviour
					} else
					{
//#else
						// default behaviour depends on command line options being set
						if (accept_normal_traffic)
							allow_packet(hndl, m->packet_id);
						else
							drop_packet(hndl, m->packet_id);
//#endif //ifdef CONFIG_HIP_HIPPROXY
				}

//#ifdef CONFIG_HIP_OPPTCP
			}
//#endif
			
		}
		if (status < 0)
			die(hndl);
		break;
	}
	default:
		HIP_DEBUG("unknown msg\n");
		fprintf(stderr, "Unknown message type!\n");
			break;
		}
	} while (1);

 out_err:

	if (hip_common)
		free(hip_common);
	if (esp)
	{
		if (esp_data)
		{
			esp->esp_data = NULL;
			free(esp_data);
		}
		free(esp);
	}
	ipq_destroy_handle(hndl);

	return;
}

void check_and_write_default_config()
{
	struct stat status;
	FILE *fp= NULL;
	ssize_t items;
	char *file= HIP_FW_DEFAULT_RULE_FILE;

	_HIP_DEBUG("\n");

	if (stat(file, &status) && errno == ENOENT)
	{
		errno = 0;
		fp = fopen(file, "w" /* mode */);
		if (!fp)
			HIP_PERROR("Failed to write config file\n");
		HIP_ASSERT(fp);
		items = fwrite(HIP_FW_CONFIG_FILE_EX,
		strlen(HIP_FW_CONFIG_FILE_EX), 1, fp);
		HIP_ASSERT(items > 0);
		fclose(fp);
	}
}

int main(int argc, char **argv)
{
	int err = 0, highest_descriptor;
	int status, n, len;
	long int hip_ha_timeout = 1;
	//unsigned char buf[BUFSIZE];
	struct ipq_handle *h4= NULL, *h6= NULL;
	struct rule * rule= NULL;
	struct _GList * temp_list= NULL;
	//struct hip_common * hip_common = NULL;
	//struct hip_esp * esp_data = NULL;
	//struct hip_esp_packet * esp = NULL;
	int escrow_active = 0;
	const int family4 = 4, family6 = 6;
	int ch, tmp;
	const char *default_rule_file= HIP_FW_DEFAULT_RULE_FILE;
	char *rule_file = (char *) default_rule_file;
	char *traffic;
	extern char *optarg;
	extern int optind, optopt;
	int errflg = 0, killold = 0;
	struct hip_common *msg = NULL;
	struct sockaddr_in6 sock_addr;
	socklen_t alen;
	fd_set read_fdset;
	struct timeval timeout;

	if (geteuid() != 0) {
		HIP_ERROR("firewall must be run as root\n");
		exit(-1);
	}

	check_and_write_default_config();

	hip_set_logdebug(LOGDEBUG_NONE);

	while ((ch = getopt(argc, argv, "f:t:vdFHAbkh")) != -1)
	{
		switch (ch)
		{
		case 'v':
			hip_set_logdebug(LOGDEBUG_MEDIUM);
			break;
		case 'd':
			hip_set_logdebug(LOGDEBUG_ALL);
			break;
		case 'H':
			accept_normal_traffic = 0;
			break;
		case 'A':
			accept_hip_esp_traffic = 1;
			break;
		case 'f':
			rule_file = optarg;
			break;
		case 't':
			hip_ha_timeout = atol(argv[optind]);
			break;
		case 'F':
			flush_iptables = 0;
			break;
		case ':': /* -f or -p without operand */
			printf("Option -%c requires an operand\n", optopt);
			errflg++;
			break;
		case 'b':
			foreground = 0;
			break;
		case 'k':
			killold = 1;
			break;
		case 'h':
			print_usage();
			exit(2);
			break;
		case '?':
			printf("Unrecognized option: -%c\n", optopt);
			errflg++;
		}
	}

	if (errflg)
	{
		print_usage();
		printf("Invalid argument. Closing. \n\n");
		exit(2);
	}

	if (!foreground)
	{
		hip_set_logtype(LOGTYPE_SYSLOG);
		if (fork() > 0)
			return 0;
	}

	HIP_IFEL(hip_create_lock_file(HIP_FIREWALL_LOCK_FILE, killold), -1,
			"Failed to obtain firewall lock.\n");

	HIP_INFO("firewall pid=%d starting\n", getpid());

	//use by default both ipv4 and ipv6
	HIP_DEBUG("Using ipv4 and ipv6\n");

	read_file(rule_file);
	HIP_DEBUG("Firewall rule table: \n");
	print_rule_tables();
	//running test functions for rule handling
	//  test_parse_copy();
	//  test_rule_management();

	HIP_DEBUG("starting up with rule_file: %s and connection timeout: %d\n",
			rule_file, timeout);

	firewall_increase_netlink_buffers();
	firewall_probe_kernel_modules();

	h4 = ipq_create_handle(0, PF_INET);
	if (!h4)
		die(h4);
	status = ipq_set_mode(h4, IPQ_COPY_PACKET, BUFSIZE);
	if (status < 0)
		die(h4);

	h6 = ipq_create_handle(0, PF_INET6);
	if (!h6)
		die(h6);
	status = ipq_set_mode(h6, IPQ_COPY_PACKET, BUFSIZE);
	if (status < 0)
		die(h6);

	firewall_init_rules();
	//get default HIT
	hip_get_local_hit_wrapper(&proxy_hit);

	/* Allocate message. */
	msg = hip_msg_alloc();
	if (!msg) {
		err = -1;
		return err;
	}

	/*New UDP socket for communication with HIPD*/
	hip_firewall_sock = socket(AF_INET6, SOCK_DGRAM, 0);
	HIP_IFEL((hip_firewall_sock < 0), 1, "Could not create socket for firewall.\n");
	memset(&sock_addr, 0, sizeof(sock_addr));
	sock_addr.sin6_family = AF_INET6;
	sock_addr.sin6_port = htons(HIP_FIREWALL_PORT);
	sock_addr.sin6_addr = in6addr_loopback;
	HIP_IFEL(bind(hip_firewall_sock, (struct sockaddr *)& sock_addr,
		      sizeof(sock_addr)), -1, "Bind on firewall socket addr failed\n");


	//init_timeout_checking(timeout);
	
#ifdef CONFIG_HIP_HIPPROXY	
	request_hipproxy_status(); //send hipproxy status request before the control thread running.
#endif /* CONFIG_HIP_HIPPROXY */

	highest_descriptor = maxof(3, hip_firewall_sock, h4->fd, h6->fd);

	while (1) {
		FD_ZERO(&read_fdset);
		FD_SET(hip_firewall_sock, &read_fdset);
		FD_SET(h4->fd, &read_fdset);
		FD_SET(h6->fd, &read_fdset);

		timeout.tv_sec = HIP_SELECT_TIMEOUT;
		timeout.tv_usec = 0;

		_HIP_DEBUG("HIP fw select\n");

		if ((err = HIPD_SELECT((highest_descriptor + 1), &read_fdset, 
				       NULL, NULL, &timeout)) < 0) {
			HIP_PERROR("select error, ignoring\n");
			continue;
		}

		if (FD_ISSET(h4->fd, &read_fdset)) {
			handle_ip_traffic(h4, 4);
		}

		if (FD_ISSET(h6->fd, &read_fdset)) {
			handle_ip_traffic(h6, 6);
		}

		if (FD_ISSET(hip_firewall_sock, &read_fdset)) {
			HIP_DEBUG("****** Received HIPD message ******\n");
			bzero(&sock_addr, sizeof(sock_addr));
			alen = sizeof(sock_addr);
			n = recvfrom(hip_firewall_sock, msg, sizeof(struct hip_common), MSG_PEEK,
		             (struct sockaddr *)&sock_addr, &alen);
			if (n < 0)
			{
				HIP_ERROR("Error receiving message header from daemon.\n");
				err = -1;
				goto out_err;
			}


			_HIP_DEBUG("Header received successfully\n");
			alen = sizeof(sock_addr);
			len = hip_get_msg_total_len(msg);

			_HIP_DEBUG("Receiving message (%d bytes)\n", len);
			n = recvfrom(hip_firewall_sock, msg, len, 0,
		             (struct sockaddr *)&sock_addr, &alen);

			if (n < 0)
			{
				HIP_ERROR("Error receiving message parameters from daemon.\n");
				err = -1;
				continue;
			}

			HIP_ASSERT(n == len);

			if (ntohs(sock_addr.sin6_port) != HIP_DAEMON_LOCAL_PORT) {
				HIP_DEBUG("Drop, message not from hipd\n");
				err = -1;
				continue;
				
			}

			err = handle_msg(msg, &sock_addr);
			if (err < 0){
				HIP_ERROR("Error handling message\n");
				continue;
				//goto out_err;	 
			}
		}

	}

 out_err:
	if (hip_firewall_sock)
		close(hip_firewall_sock);
	if (msg != NULL)
		HIP_FREE(msg);

	firewall_exit();
	return 0;
}

/**
 * Loads several modules that are neede by th firewall.
 * 
 * @return	nothing.
 */
void firewall_probe_kernel_modules()
{
	int count, err, status;
	char cmd[40];
	int mod_total;
	char *mod_name[] =
	{ "ip_queue", "ip6_queue", "iptable_filter", "ip6table_filter" };

	mod_total = sizeof(mod_name) / sizeof(char *);

	HIP_DEBUG("Probing for %d modules. When the modules are built-in, the errors can be ignored\n", mod_total);

	for (count = 0; count < mod_total; count++)
	{
		snprintf(cmd, sizeof(cmd), "%s %s", "/sbin/modprobe",
				mod_name[count]);
		HIP_DEBUG("%s\n", cmd);
		err = fork();
		if (err < 0)
			HIP_ERROR("Failed to fork() for modprobe!\n");
		else if (err == 0)
		{
			/* Redirect stderr, so few non fatal errors wont show up. */
			stderr = freopen("/dev/null", "w", stderr);
			execlp("/sbin/modprobe", "/sbin/modprobe",
					mod_name[count], (char *)NULL);
		}
		else
			waitpid(err, &status, 0);
	}
	HIP_DEBUG("Probing completed\n");
}

/**
 * Increases the netlink buffer capacity.
 * 
 * The previous default values were:
 *
 * /proc/sys/net/core/rmem_default - 110592
 * /proc/sys/net/core/rmem_max     - 131071
 * /proc/sys/net/core/wmem_default - 110592
 * /proc/sys/net/core/wmem_max     - 131071
 *
 * The new value 1048576=1024*1024 was assigned to all of them
 *
 * @return	nothing.
 */
void firewall_increase_netlink_buffers(){
	HIP_DEBUG("Increasing the netlink buffers\n");

	popen("echo 1048576 > /proc/sys/net/core/rmem_default; echo 1048576 > /proc/sys/net/core/rmem_max;echo 1048576 > /proc/sys/net/core/wmem_default;echo 1048576 > /proc/sys/net/core/wmem_max", "r");
}

void handle_proxy_inbound_traffic(ipq_packet_msg_t *m, struct ipq_handle *hndl,	struct in6_addr src_addr)
{
		//struct in6_addr client_addr;
		//HIP PROXY INBOUND PROCESS

		int port_client;
		int port_peer;
		int protocol;
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
				drop_packet(hndl, m->packet_id);
			}
			
			if (conn_entry->state == HIP_PROXY_PASSTHROUGH)
				allow_packet(hndl, m->packet_id);				
		}
		else
		{
			//allow esp packet
			HIP_DEBUG("Can't find entry in ConnDB!\n");
			allow_packet(hndl, m->packet_id);
		}
}

int handle_proxy_outbound_traffic(ipq_packet_msg_t *m, struct ipq_handle *hndl, struct in6_addr src_addr, struct in6_addr dst_addr,int hdr_size, int traffic_type)
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
		
		if(traffic_type == 4)
			protocol = ((struct ip *) (m->payload))->ip_p;

		if(traffic_type == 6)
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

				allow_packet(hndl, m->packet_id);	//let the packet pass								
			}
			else
			{
				hip_proxy_request_local_address_from_hipd(&proxy_hit, &dst_hit, &proxy_addr, &fallback, &reject);
				if(hip_proxy_update_state(&src_addr, &dst_addr, &proxy_addr, NULL, &dst_hit, &proxy_hit, HIP_PROXY_TRANSLATE))
					HIP_DEBUG("Proxy update Failed!\n");
														
				if(hip_conn_add_entry(&src_addr, &dst_addr, &proxy_hit, &dst_hit, protocol, port_client, port_peer, HIP_PROXY_TRANSLATE))
					HIP_DEBUG("ConnDB add entry Failed!\n");;
											
				drop_packet(hndl, m->packet_id);	//drop the packet
			}
		}
		else
		{			
			//check if the entry state is PASSTHROUGH
			if(entry->state == HIP_PROXY_PASSTHROUGH)
			{
				HIP_DEBUG("PASSTHROUGH!\n");
				allow_packet(hndl, m->packet_id);	//let the packet pass
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
					drop_packet(hndl, m->packet_id);
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
					drop_packet(hndl, m->packet_id);
				}
			}
		}
		
		out_err:
			return err;			
}
