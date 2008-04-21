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
/* #include <libiptc/libiptc.h> */

//#include <hipd/netdev.h>

//#define HIP_HEADER_START 128 //bytes
#define BUFSIZE 2048

struct ipq_handle *h4 = NULL, *h6 = NULL;
int statefulFiltering = 1; 
int escrow_active = 0;
int use_ipv4 = 0;
int use_ipv6 = 0;
int accept_normal_traffic  = 1;
int accept_hip_esp_traffic = 0;
int flush_iptables = 1;
pthread_t ipv4Thread, ipv6Thread;


/* Thread ID for hip_esp_output_id and hip_esp_inputput_id 
 * Added by Tao, 13, Mar, 2008
 * */
pthread_t hip_esp_ouput_id, hip_esp_input_id;


int counter = 0;
int foreground = 1;
#ifdef CONFIG_HIP_OPPTCP
int hip_opptcp = 1;
#else
int hip_opptcp = 0;
#endif
int hip_userspace_ipsec = 1;

void print_usage()
{
	printf("HIP Firewall\n");
	printf("Usage: firewall [-f file_name] [-t timeout] [-d|-v] [-F|-H]\n");
	printf("      - H drop non-HIP traffic by default (default: accept non-hip traffic)\n");
	printf("      - A accept HIP traffic by default (default: drop all hip traffic)\n");
	printf("      - f file_name is a path to a file containing firewall filtering rules (default %s)\n", HIP_FW_DEFAULT_RULE_FILE);
	printf("      - timeout is connection timeout value in seconds\n");
	printf("      - d = debugging output\n");
	printf("      - v = verbose output\n");
	printf("      - t = timeout for packet capture (default %d secs)\n",
	       HIP_FW_DEFAULT_TIMEOUT);
	printf("      - F = do not flush iptables rules\n");
	printf("      - b = fork the firewall to background\n");
	printf("      - k = kill running firewall pid\n\n");
}

//currently done at all times, rule_management 
//delete rule needs checking for state options in 
//all chains
void set_stateful_filtering(int v){
	statefulFiltering = 1;
}

int get_stateful_filtering(){
	return statefulFiltering;
}

void set_escrow_active(int active){
	escrow_active = active;
}

int is_escrow_active(){
	return escrow_active;
}

/*----------------INIT/EXIT FUNCTIONS----------------------*/


int firewall_init(){
	HIP_DEBUG("Initializing firewall\n");

	HIP_DEBUG("Enabling forwarding for IPv4 and IPv6\n");
	system("echo 1 >/proc/sys/net/ipv4/conf/all/forwarding");
	system("echo 1 >/proc/sys/net/ipv6/conf/all/forwarding");

	if (flush_iptables) {
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


	//ipv4 traffic
	if(use_ipv4){
		if (hip_opptcp) {
			system("iptables -I FORWARD -p 6 -j QUEUE");
			system("iptables -I INPUT -p 6 -j QUEUE");
			system("iptables -I OUTPUT -p 6 -j QUEUE");
		}
		if (hip_userspace_ipsec) {
			//system("iptables -I FORWARD -p 6 -j QUEUE"); // do we need this???
			system("iptables -I INPUT -p 50 -j QUEUE"); /* ESP over IPv4 */
			system("iptables -I INPUT -p 17 --dport 50500 -j QUEUE");
			system("iptables -I INPUT -p 17 --sport 50500 -j QUEUE");
			//system("iptables -I OUTPUT -p 6 ! -d 127.0.0.1 -j QUEUE"); // XX FIXME: LSI support 
			//system("iptables -I OUTPUT -p 17 ! -d 127.0.0.1 -j QUEUE"); // XX FIXME: LSI support 
		}
		if(!accept_hip_esp_traffic){
			system("iptables -I FORWARD -p 139 -j QUEUE");
			system("iptables -I FORWARD -p 50 -j QUEUE");
			system("iptables -I FORWARD -p 17 --dport 50500 -j QUEUE");
			system("iptables -I FORWARD -p 17 --sport 50500 -j QUEUE");
			
			system("iptables -I INPUT -p 139 -j QUEUE");
			system("iptables -I INPUT -p 50 -j QUEUE");
			
			
			system("iptables -I OUTPUT -p 139  -j QUEUE");
			system("iptables -I OUTPUT -p 50 -j QUEUE");
			system("iptables -I OUTPUT -p 17 --dport 50500 -j QUEUE");
			system("iptables -I OUTPUT -p 17 --sport 50500 -j QUEUE");
		}
		if(!accept_normal_traffic){
			system("iptables -I FORWARD -j DROP");
			system("iptables -I INPUT -j DROP");
			system("iptables -I OUTPUT -j DROP");
		}
	}

	//ipv6 traffic
	if(use_ipv6){
		if (hip_opptcp) {
			system("ip6tables -I FORWARD -p 6 -j QUEUE");
			system("ip6tables -I INPUT -p 6 -j QUEUE");
			system("ip6tables -I OUTPUT -p 6 -j QUEUE");
		}
		if (hip_userspace_ipsec) {
			system("ip6tables -I INPUT -p 50 -j QUEUE"); /* ESP over IPv6 */

			//system("ip6tables -I FORWARD -p 6 ! -d ::1 -j QUEUE"); /* TCP: do we need this?? */
			system("ip6tables -I OUTPUT -p 6 ! -d ::1 -j QUEUE"); /* TCP over IPv6: possibly HIT based connection */

			//system("ip6tables -I FORWARD -p 17 -j QUEUE"); /* UDP: do we need this ??? */ 
			system("ip6tables -I OUTPUT -p 17 ! -d ::1 -j QUEUE"); /* UDP over IPv6: possibly HIT based connection */
                }

		if(!accept_hip_esp_traffic){
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
		if(!accept_normal_traffic){
			system("ip6tables -I FORWARD -j DROP");
			system("ip6tables -I INPUT -j DROP");
			system("ip6tables -I OUTPUT -j DROP");
		}
	}
out_err:
	return 0;
}

void firewall_close(int signal){
	HIP_DEBUG("Closing firewall...\n");
	firewall_exit();
	exit(signal);
}

void firewall_exit(){
	HIP_DEBUG("Firewall exit\n");

	if (flush_iptables) {
		HIP_DEBUG("Flushing all rules\n");
		system("iptables -F INPUT");
		system("iptables -F OUTPUT");
		system("iptables -F FORWARD");
		system("ip6tables -F INPUT");
		system("ip6tables -F OUTPUT");
		system("ip6tables -F FORWARD");
	} else {
		HIP_DEBUG("Some dagling iptables rules may be present!\n");
	}

	hip_remove_lock_file(HIP_FIREWALL_LOCK_FILE);
}

/*-------------PACKET FILTERING FUNCTIONS------------------*/
int match_hit(struct in6_addr match_hit, 
			struct in6_addr packet_hit, 
			int boolean){
   	int i = IN6_ARE_ADDR_EQUAL(&match_hit, &packet_hit);
  	HIP_DEBUG("match_hit: hit1: %s hit2: %s bool: %d match: %d\n", 
	    addr_to_numeric(&match_hit), addr_to_numeric(&packet_hit), boolean, i);
  	if(boolean)
    	return i;
  	else 
    	return !i;
}

/**
 *inspects host identity by verifying sender signature
 * returns 1 if verified succesfully otherwise 0
 */
int match_hi(struct hip_host_id * hi, 
	     	struct hip_common * packet){
	int value = 0;  
	if(packet->type_hdr == HIP_I1)
    {
      	_HIP_DEBUG("match_hi: I1\n");
    	return 1;
    }
  	value = verify_packet_signature(hi, packet);
  	if(value == 0)
    	_HIP_DEBUG("match_hi: verify ok\n");
  	else
    	_HIP_DEBUG("match_hi: verify failed\n");
  	if(value == 0)
    	return 1;
  	return 0;
}

int match_int(int match, int packet, int boolean){
  	if(boolean)
    	return match == packet;
  	else
    	return !(match == packet);
}

int match_string(const char * match, const char * packet, int boolean){
  	if(boolean)
    	return !strcmp(match, packet);
  	else
    	return strcmp(match, packet);
}

/*------------------------------------------------*/

static void die(struct ipq_handle *h){
  	HIP_DEBUG("dying\n");
  	ipq_perror("passer");
  	ipq_destroy_handle(h);
  	firewall_close(1);
}

/**
 * Tests whether a packet is a HIP packet.
 *
 * @param  hdr        a pointer to a HIP packet.
 * @param trafficType ?
 * @return            One if @c hdr is a HIP packet, zero otherwise.
 */ 
int is_hip_packet(void * hdr, int trafficType){
	struct udphdr *udphdr;
	int hdr_size;

	HIP_DEBUG("\n");

	if(trafficType == 4){
		struct ip * iphdr = (struct ip *)hdr;
		if(iphdr->ip_p == IPPROTO_HIP) 
			return 1;
		if(iphdr->ip_p != IPPROTO_UDP)
			return 0;

		//the udp src and dest ports are analysed
		hdr_size = (iphdr->ip_hl * 4);
		udphdr = ((struct udphdr *) (((char *) iphdr) + hdr_size));
	}
	if(trafficType == 6){
		struct ip6_hdr * ip6_hdr = (struct ip6_hdr *)hdr;
		if(ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_HIP)
			return 1;
		if(ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt != IPPROTO_UDP)
			return 0;

		//the udp src and dest ports are analysed		
		hdr_size = (ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_plen * 4);
		udphdr = ((struct udphdr *) (((char *) ip6_hdr) + hdr_size));
	}

	if((udphdr->source == ntohs(HIP_NAT_UDP_PORT)) || 
	   (udphdr->dest   == ntohs(HIP_NAT_UDP_PORT)))
		return 1;
	else
		return 0;
}


/**
 * Not allow a packet to pass
 * 
 * @param handle	the handle for the packets.
 * @param packetId	the packet ID.
 * @return		nothing
 */
void allow_packet(struct ipq_handle *handle, unsigned long packetId){
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
void drop_packet(struct ipq_handle *handle, unsigned long packetId){
	ipq_set_verdict(handle, packetId, NF_DROP, 0, NULL);
	HIP_DEBUG("Packet dropped \n\n");
}


/**
 * Returns whether a packet is incoming
 * 
 * @param theHook	the packet hook.
 * @return		1 if incoming packet, 0 otherwise.
 */
int is_incoming_packet(unsigned int theHook){
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
int is_outgoing_packet(unsigned int theHook){
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
				 int		    trafficType){
	int i, optLen, hdr_size, optionsLen;
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
		hdr_size = (iphdr->ip_hl * 4);
		tcphdr = ((struct tcphdr *) (((char *) iphdr) + hdr_size));
		hdrBytes = ((char *) iphdr) + hdr_size;

		HIP_DEBUG_INADDR("the destination", &iphdr->ip_src);
		
		//peer and local ip needed for sending the i1 through hipd
		IPV4_TO_IPV6_MAP(&iphdr->ip_src, peer_ip);//TO  BE FIXED obtain the pseudo hit instead
	}
	else if(trafficType == 6){
		ip6_hdr = (struct ip6_hdr *)hdr;
		//get the tcp header		
		hdr_size = (ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_plen * 4);
		tcphdr = ((struct tcphdr *) (((char *) ip6_hdr) + hdr_size));
		hdrBytes = ((char *) ip6_hdr) + hdr_size;

		//peer and local ip needed for sending the i1 through hipd
		peer_ip = &ip6_hdr->ip6_src;//TO  BE FIXED obtain the pseudo hit instead
	}

/*	//no checking for SYN 0 here
	//because there is a following case
	//of checking TCP RST_ACK packets,
	//where SYN is 0

	//check if SYN field is 0
	if(tcphdr->syn == 0){
		allow_packet(handle, packetId);
		return;
	}
*/
	//check that there are no options
	if(tcphdr->doff == 5){
		allow_packet(handle, packetId);
		return;
	}

	if((tcphdr->syn == 1) && (tcphdr->ack == 0)){	//incoming, syn=1 and ack=0
		if(tcp_packet_has_i1_option(hdrBytes, 4*tcphdr->doff)){
			//swap the ports
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

			/* send packet out after adding HIT
			 * the option is already there but
			 * it has to be added again since
			 * if only the HIT is added, it will
			 * overwrite the i1 option that is
			 * in the options of TCP
			 */
			hip_request_send_tcp_packet(hdr, hdr_size + 4*tcphdr->doff, trafficType, 1, 1);

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

		if(tcp_packet_has_i1_option(hdrBytes, 4*tcphdr->doff)){
			//tcp header pointer + 20(minimum header length) + 4(i1 option length in the TCP options)
			memcpy(peer_hit, &hdrBytes[20 + 4], 16);

			hip_request_send_i1_to_hip_peer_from_hipd(
					peer_hit,
					peer_ip);

			//the packet is no more needed
			drop_packet(handle, packetId);
			return;
		}
		else{
			//save in db that peer does not support hip
			hip_request_oppipdb_add_entry(peer_ip);

			//signal for the normal TCP packets not to be blocked for this peer
			hip_request_unblock_app_from_hipd(peer_ip);

			//normal traffic connections should be allowed to be created
			allow_packet(handle, packetId);
			return;
		}
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
int tcp_packet_has_i1_option(void * tcphdrBytes, int hdrLen){
	int   i = 20;//the initial obligatory part of the TCP header
	int   len = 0;
	unsigned char *bytes =(char*)tcphdrBytes;

	HIP_DEBUG("\n");

	while(i < hdrLen){
		switch (bytes[i]) {
		case HIP_OPTION_KIND:	//hip option
			return 1;
		break;
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
		}
	}
	return 0;
}


/**
 * Sends a message to hipd so that hipd initiates the basic exchange, sending the i1. In this message, the ports are 0, so that at the hip_send_i1 function we know we don't need to send the TCP SYN_i1 again.
 * 
 * @param peer_hit	the peer hit that has been obtained from the TCP SYN_ACK_i1 packet.
 * @param peer_ip	the peer ip to send the i1 packet to.
 * @return		nothing.
 */
void hip_request_send_i1_to_hip_peer_from_hipd(struct in6_addr *peer_hit,
					       struct in6_addr *peer_ip){
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
	return;
}


/**
 * Send the ip of a peer to hipd, so that it can unblock the packets that are sent to a particular peer. This is done when we receive a TCP SYN_ACK/RST_ACK without the i1 option.
 * 
 * @param peer_ip	peer ip.
 * @return		nothing
 */
void hip_request_unblock_app_from_hipd(const struct in6_addr *peer_ip){
	struct hip_common *msg = NULL;
	int err = 0;

	HIP_DEBUG("\n");	

	HIP_IFE(!(msg = hip_msg_alloc()), -1);

	HIP_IFEL(hip_build_param_contents(msg, (void *)(peer_ip),
					  HIP_PARAM_IPV6_ADDR,
					  sizeof(struct in6_addr)),
		-1, "build param HIP_PARAM_IPV6_ADDR failed\n");
	
	/* build the message header */
	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_OPPTCP_UNBLOCK_APP, 0),
		 -1, "build hdr failed\n");
	HIP_DUMP_MSG(msg);
	/* send and receive msg to/from hipd */
	HIP_IFEL(hip_send_recv_daemon_info(msg), -1, "send_recv msg failed\n");
	_HIP_DEBUG("send_recv msg succeed\n");
	/* check error value */
	HIP_IFEL(hip_get_msg_err(msg), -1, "Got erroneous message!\n");

 out_err:
	return;
}


/**
 * Send the ip of a peer to hipd, so that it can add it to the blacklist database.
 * 
 * @param peer_ip	peer ip.
 * @return		nothing
 */
void hip_request_oppipdb_add_entry(struct in6_addr *peer_ip){
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
	return;
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
void hip_request_send_tcp_packet(void *hdr,
				 int   packet_size,
				 int   trafficType,
				 int   addHit,
				 int   addOption){
	struct hip_common *msg = NULL;
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
	HIP_IFEL(hip_send_recv_daemon_info(msg), -1, "send_recv msg failed\n");
	_HIP_DEBUG("send_recv msg succeed\n");
	/* check error value */
	HIP_IFEL(hip_get_msg_err(msg), -1, "Got erroneous message!\n");

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
				 unsigned long	    packetId,
				 void		   *hdr,
				 int		    trafficType){
	int i, optLen, hdr_size, optionsLen;
	char          *hdrBytes = NULL;
	struct tcphdr *tcphdr;

	HIP_DEBUG("\n");

	if(trafficType == 4){
		struct ip * iphdr = (struct ip *)hdr;
		//get the tcp header
		hdr_size = (iphdr->ip_hl * 4);
		tcphdr = ((struct tcphdr *) (((char *) iphdr) + hdr_size));
		hdrBytes = ((char *) iphdr) + hdr_size;
	}
	if(trafficType == 6){
		struct ip6_hdr * ip6_hdr = (struct ip6_hdr *)hdr;
		//get the tcp header		
		hdr_size = (ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_plen * 4);
		tcphdr = ((struct tcphdr *) (((char *) ip6_hdr) + hdr_size));
		hdrBytes = ((char *) ip6_hdr) + hdr_size;
	}

	//check if SYN field is 0
	if(tcphdr->syn == 0){
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

/* filter hip packet according to rules.
 * return verdict
 */
int filter_esp(const struct in6_addr * dst_addr,
	       struct hip_esp_packet * esp,
	       unsigned int hook, 
	       const char * in_if, 
	       const char * out_if)
{
	struct _GList * list = (struct _GList *) read_rules(hook);
	struct rule * rule = NULL;
	int match = 1; // is the packet still a potential match to current rule
	int ret_val = 0;
	uint32_t spi = esp->esp_data->esp_spi;	

	_HIP_DEBUG("filter_esp:\n");
	while (list != NULL){
      		match = 1;
      		rule = (struct rule *) list->data;
      		_HIP_DEBUG("   filter_esp: checking for:\n");     
      		//print_rule(rule);
       		HIP_DEBUG_HIT("dst addr: ", dst_addr);
       		HIP_DEBUG("SPI: %d\n", ntohl(spi)); 
        
      		//type not valid with ESP packets
      		if(rule->type)
	  	{
	    		//not valid with ESP packet
	    		_HIP_DEBUG("filter_esp: type option not valid for esp\n");
	      		match = 0;	
	  	}      
      		//src and dst hits are matched with state option
      		if((rule->src_hit || rule->dst_hit) && !rule->state)
	  	{
	    		//not valid with ESP packet
	    		_HIP_DEBUG("filter_esp: hit options without state option not valid for esp\n");
	     		match = 0;	
	  	}      
      		if(match && rule->in_if)
	  	{
	    		if(!match_string(rule->in_if->value, in_if, rule->in_if->boolean))
	      			match = 0;
	    		_HIP_DEBUG("filter_esp: in_if rule: %s, packet: %s, boolean: %d, match: %d \n",
		      			rule->in_if->value, 
		      			in_if, rule->in_if->boolean, match);
	  	}
		if(match && rule->out_if)
	  	{
	    		if(!match_string(rule->out_if->value, 
			     		out_if, 
			     		rule->out_if->boolean))
	      			match = 0;
	    		_HIP_DEBUG("filter_esp: out_if rule: %s, packet: %s, boolean: %d, match: %d \n",
		      			rule->out_if->value, out_if, rule->out_if->boolean, match);
	  	}	
		//must be last, so match and verdict known here
		if(match && rule->state)
	 	{
	    		//the entire rule os passed as argument as hits can only be 
	    		//filtered whit the state information
	    		if(!filter_esp_state(dst_addr, esp, rule)) {//rule->state, rule->accept))
	      			match = 0;
	    			_HIP_DEBUG("filter_esp: state, rule %d, boolean %d match %d\n", 
		      				rule->state->int_opt.value,
		      				rule->state->int_opt.boolean, 
		      				match);
				break;
			}
	  	}
		// if a match, no need to check further rules
		if(match){
	  		_HIP_DEBUG("filter_esp: match found\n");
	  		break;
 		}
      		list = list->next;
    	}
  	//was there a rule matching the packet
  	if(rule && match)
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
	    	//if HIT has matched and HI defined, verify signature 
	    	if(match && rule->src_hi)
	      	{
			_HIP_DEBUG("filter_hip: src_hi \n");
			if(!match_hi(rule->src_hi, buf))
		  		match = 0;	
	      	}
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



/* added by Tao Wan, This is the function for hip userspace ipsec output
 * Todo: How to do hip_sadb_lookup_addr() or  hip_sadb_lookup_spi(spi)
 *   hip_sadb_lookup_addr(struct sockaddr *addr)
 **/

void hip_firewall_userspace_ipsec_output(struct ipq_handle *handle,
					 unsigned long	    packetId,
					 void		   *hdr,
					 int		    trafficType,
					 ipq_packet_msg_t *ip_packet_in_the_queue)
{
	
// parse the peer HIT from arguments

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
	struct in6_addr peer_ip;
	struct in6_addr peer_hit;
	// in_port_t        src_tcp_port;
	// in_port_t        dst_tcp_port;

	struct sockaddr_storage ipv6_addr_to_sockaddr_hit;
	struct sockaddr_storage sockaddr_local_default_hit;
	struct hip_tlv_common *current_param = NULL;
	struct in6_addr *defhit;
	
	struct hip_common *msg = NULL;
	
	int err = 0;

	HIP_DEBUG("Try to get peer_hit\n");

	// XX FIXME: TAO ALLOCATE STATICALLY TO AVOID SILLY MEM LEAKS
	//peer_ip  = HIP_MALLOC(sizeof(struct in6_xaddr), 0);
	//peer_hit = HIP_MALLOC(16, 0);

	if(trafficType == 4){
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
	else if(trafficType == 6){
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

	hip_addr_to_sockaddr(&peer_hit, &ipv6_addr_to_sockaddr_hit);     


	HIP_DEBUG_SOCKADDR("ipv6_addr_to_sockaddr_hit value is :", &ipv6_addr_to_sockaddr_hit);

	
	HIP_DEBUG("Can hip_sadb_lookup_addr() find hip_sadb_entry? : %s\n",
		hip_sadb_lookup_addr(&ipv6_addr_to_sockaddr_hit) ? "YES" : "NO");
	

	if (hip_sadb_lookup_addr(&ipv6_addr_to_sockaddr_hit) == NULL) {
		
		HIP_DEBUG("pfkey send acquire........\n");
		pfkey_send_acquire(&ipv6_addr_to_sockaddr_hit);
		
	} else {
		// TAO XX FIXME: READ LOCAL HIT AND PASS IT AS SOCKADDR STRUCTURE
		// TO hip_esp_output
	
		//hip_esp_traffic_userspace_handler(&hip_esp_output_id, 
		//				     hip_esp_output, 
		//				  NULL);
	
	
		HIP_DEBUG("Sending esp output......");
	
		HIP_IFE(!(msg = hip_msg_alloc()), -1);
		HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_DEFAULT_HIT,0),-1,
			 "Fail to get hits");
		HIP_IFEL(hip_send_recv_daemon_info(msg), -1,
			 "send/recv daemon info\n");
		
		
		defhit = hip_get_param_contents(msg, HIP_PARAM_HIT);
		HIP_INFO_HIT("default hi is ",defhit);
		
		hip_addr_to_sockaddr(defhit, &sockaddr_local_default_hit);
		
		hip_esp_output(&sockaddr_local_default_hit, 
			       ip6_hdr, length_of_packet); /* XX FIXME: LSI */
	}
	
	HIP_DEBUG("Can hip_sadb_lookup_addr() find hip_sadb_entry? : %s\n",
		  hip_sadb_lookup_addr(&ipv6_addr_to_sockaddr_hit) ? "YES" : "NO");
	
	
 out_err:
	return;
	

}



/* added by Tao Wan, This is the function for hip userspace ipsec input 
 *
 **/


void hip_firewall_userspace_ipsec_input()
{
	
	//hip_esp_traffic_userspace_handler(&hip_esp_input_id, 
	//				  hip_esp_input, 
	//				  NULL);
	hip_esp_input(NULL);
	
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
static void *handle_ip_traffic(void *ptr){
	int status;
	unsigned char buf[BUFSIZE];
	struct hip_esp * esp_data = NULL;
	struct hip_esp_packet * esp = NULL;
	struct hip_common * hip_common = NULL;
	struct in6_addr * src_addr = NULL;
	struct in6_addr * dst_addr = NULL;
	struct ipq_handle *hndl;
	int ipv4Traffic = 0, ipv6Traffic = 0;
	int type = *((int *) ptr);
	unsigned int packetHook;

	HIP_DEBUG("thread for type=IPv%d traffic started\n", type);

	if(type == 4){
		ipv4Traffic = 1;
		hndl = h4;
	}
	else if(type == 6){
		ipv6Traffic = 1;
		hndl = h6;
	}

	src_addr = HIP_MALLOC(sizeof(struct in6_addr), 0);
	dst_addr = HIP_MALLOC(sizeof(struct in6_addr), 0);
	if (!src_addr || !dst_addr)
		goto out_err;

	do{
		status = ipq_read(hndl, buf, BUFSIZE, 0);
		if (status < 0)
			die(hndl);
    
		switch (ipq_message_type(buf)) {
		case NLMSG_ERROR:
		  fprintf(stderr, "Received error message (%d): %s\n", ipq_get_msgerr(buf), ipq_errstr());
		break;
      
		case IPQM_PACKET: {
			struct ip6_hdr * ip6_hdr = NULL;
			struct ip * iphdr = NULL;
			void * packet_hdr = NULL;
			int hdr_size = 0;
      
			ipq_packet_msg_t *m = ipq_get_packet(buf);
			packetHook = m->hook;

			if(ipv4Traffic){
                		_HIP_DEBUG("ipv4\n");
                		iphdr = (struct ip *) m->payload; 
                		packet_hdr = (void *)iphdr;
                		hdr_size = (iphdr->ip_hl * 4);

				if (iphdr->ip_p == IPPROTO_UDP){
					hdr_size += sizeof(struct udphdr);
				}
                		_HIP_DEBUG("header size: %d\n", hdr_size);
               		 	IPV4_TO_IPV6_MAP(&iphdr->ip_src, src_addr);
                		IPV4_TO_IPV6_MAP(&iphdr->ip_dst, dst_addr);
        		

				HIP_DEBUG_IN6ADDR("IPv4 source address is ", src_addr);
				HIP_DEBUG_IN6ADDR("IPv4 source address is ", dst_addr);
				
			}
        		else if(ipv6Traffic){
                		_HIP_DEBUG("ipv6\n");
                		ip6_hdr = (struct ip6_hdr *) m->payload;   
                		packet_hdr = (void *)ip6_hdr;
               		 	hdr_size = sizeof(struct ip6_hdr);
               		 	_HIP_DEBUG("header size: %d\n", hdr_size);
                		ipv6_addr_copy(src_addr, &ip6_hdr->ip6_src);
                		ipv6_addr_copy(dst_addr, &ip6_hdr->ip6_dst);
								
				HIP_DEBUG_IN6ADDR("IPv6 source address is ", src_addr);
				HIP_DEBUG_IN6ADDR("IPv6 source address is ", dst_addr);
        		}

			HIP_DEBUG("Is this a HIP packet: %s\n",
				  is_hip_packet(packet_hdr, type) ? "YES" : "NO");
			
      			if(is_hip_packet(packet_hdr, type)){
      				HIP_DEBUG("****** Received HIP packet ******\n");
				int packet_length = 0;
				struct hip_sig * sig = NULL;

				if (m->data_len <= (BUFSIZE - hdr_size)){
	  				packet_length = m->data_len - hdr_size; 	
	  				_HIP_DEBUG("HIP packet size smaller than buffer size\n");
	  			}
	  			else { 
	  				packet_length = BUFSIZE - hdr_size;
	  				_HIP_DEBUG("HIP packet size greater than buffer size\n");
	  			}
				hip_common = (struct hip_common *)HIP_MALLOC(packet_length, 0);

				//hip_common = (struct hip_common*) (m->payload + sizeof (struct ip6_hdr));

				memcpy(hip_common, m->payload + hdr_size, packet_length);		
			

				sig = (struct hip_sig *) hip_get_param(hip_common, HIP_PARAM_HIP_SIGNATURE);
				if(sig == NULL)
	  				_HIP_DEBUG("no signature\n");
				else
	  				_HIP_DEBUG("signature exists\n");


				if(filter_hip(src_addr, 
					      dst_addr, 
					      hip_common, 
					      m->hook,
					      m->indev_name,
					      m->outdev_name))
	  			{
					allow_packet(hndl, m->packet_id);
				}
				else
	  			{
					drop_packet(hndl, m->packet_id);
	  			}
			} else {
                                /* OPPORTUNISTIC MODE HACKS */
				if((ipv4Traffic && iphdr->ip_p != IPPROTO_TCP) ||
				   (ipv6Traffic && ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt != IPPROTO_TCP))
				   /* ip6_un1_nxt ---> next header */
					
				{
					if(accept_normal_traffic)
						allow_packet(hndl, m->packet_id);
					else
						drop_packet(hndl, m->packet_id);
				}  else if(is_incoming_packet(packetHook)) {
					if (hip_userspace_ipsec)
					{
						HIP_DEBUG("debug message: HIP firewall userspace ipsec input: \n ");
						// hip_firewall_userspace_ipsec_output(hndl, m->packet_id, packet_hdr, type); /*added by Tao Wan */
						hip_firewall_userspace_ipsec_input(); /* added by Tao Wan */
					
					}
					else
						examine_incoming_tcp_packet(hndl, m->packet_id, packet_hdr, type);

				} else if(is_outgoing_packet(packetHook)) {
					/*examine_outgoing_tcp_packet(hndl, m->packet_id, packet_hdr, type);*/
					
					HIP_DEBUG("Is this a IPv6 packet: %s\n",
						  ipv6Traffic ? "YES" : "NO");

					HIP_DEBUG("Is src_addr a HIT: %s\n",
						  ipv6_addr_is_hit(src_addr) ? "YES" : "NO");

					HIP_DEBUG("Is dst_addr a HIT: %s\n",
						  ipv6_addr_is_hit(dst_addr) ? "YES" : "NO");

					HIP_DEBUG_IN6ADDR("src addr :\n", src_addr);
					HIP_DEBUG_IN6ADDR("dst addr  :\n", dst_addr);
					


					
					if (hip_userspace_ipsec  &&  ipv6Traffic == 1 
					    && ipv6_addr_is_hit(src_addr) && ipv6_addr_is_hit(dst_addr)) /* && if (packet == IPv6 && hip_is_hit(dst && src)*/ 
						{
							HIP_DEBUG("debug message: HIP firewall userspace ipsec output: \n ");
							// hip_firewall_userspace_ipsec_input(); /* added by Tao Wan */
							// XX FIXME: 
							hip_firewall_userspace_ipsec_output(hndl, m->packet_id, packet_hdr, type, m); /*added by Tao Wan */
							
						}
					else
						allow_packet(hndl, m->packet_id);
					
				} else {
					if(accept_normal_traffic)
						allow_packet(hndl, m->packet_id);
					else
						drop_packet(hndl, m->packet_id);
				}
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
	}while (1);

out_err:  
	//if (hip_common)
	free(hip_common);
	free(src_addr);
        free(dst_addr);
        if (esp) {
		if (esp_data) {
	    	esp->esp_data = NULL;
	    	free(esp_data);
	    }
	    free(esp);
	}
  	ipq_destroy_handle(hndl);

	if(src_addr)
 		HIP_FREE(src_addr);
	if(dst_addr)
 		HIP_FREE(dst_addr);
	return;
}

void check_and_write_default_config(){
	struct stat status;
	FILE *fp = NULL;
	ssize_t items;
	char *file = HIP_FW_DEFAULT_RULE_FILE;

	_HIP_DEBUG("\n");

	if (stat(file, &status) && errno == ENOENT) {
		errno = 0;
		fp = fopen(file, "w" /* mode */);
		if(!fp)
			HIP_PERROR("Failed to write config file.\n");
		HIP_ASSERT(fp);
		items = fwrite(HIP_FW_CONFIG_FILE_EX,
			       strlen(HIP_FW_CONFIG_FILE_EX), 1, fp);
		HIP_ASSERT(items > 0);
		fclose(fp);
	}
}

int main(int argc, char **argv)
{
	int err = 0;
	int status;
	long int timeout = 1;
	//unsigned char buf[BUFSIZE];
	struct rule * rule = NULL;
	struct _GList * temp_list = NULL;
	//struct hip_common * hip_common = NULL;
	//struct hip_esp * esp_data = NULL;
	//struct hip_esp_packet * esp = NULL;
	int escrow_active = 0;
	const int family4 = 4, family6 = 6;
	int ch, tmp;
	char *default_rule_file = HIP_FW_DEFAULT_RULE_FILE;
	char *rule_file = default_rule_file;
	char *traffic;
	extern char *optarg;
	extern int optind, optopt;
	int errflg = 0, killold = 0;

	check_and_write_default_config();

	hip_set_logdebug(LOGDEBUG_NONE);

	while ((ch = getopt(argc, argv, "f:t:vdFHAbk")) != -1) {
		switch(ch) {
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
			timeout = atol(argv[optind]);
		break;
		case 'F':
			flush_iptables = 0;
		break;
		case ':':   /* -f or -p without operand */
			printf("Option -%c requires an operand\n", optopt);
			errflg++;
		break;
		case 'b':
			foreground = 0;
		break;
		case 'k':
			killold = 1;
		break;
		case '?':
			printf("Unrecognized option: -%c\n", optopt);
			errflg++;
		}
	}

	if (errflg) {
		print_usage();
		printf("Invalid argument. Closing. \n\n");                
		exit(2);
	}    

	if (!foreground) {
		hip_set_logtype(LOGTYPE_SYSLOG);
		if (fork() > 0)
			return 0;
	}

	HIP_IFEL(hip_create_lock_file(HIP_FIREWALL_LOCK_FILE, killold), -1,
		 "Failed to obtain firewall lock.\n");

	HIP_INFO("firewall pid=%d starting\n", getpid());

	//use by default both ipv4 and ipv6
	HIP_DEBUG("Using ipv4 and ipv6\n");
	use_ipv4 = 1;
	use_ipv6 = 1;


	read_file(rule_file);
	HIP_DEBUG("Firewall rule table: \n");
	print_rule_tables();
	//running test functions for rule handling
	//  test_parse_copy();
	//  test_rule_management();

	HIP_DEBUG("starting up with rule_file: %s and connection timeout: %d\n", 
                rule_file, timeout);

	firewall_probe_kernel_modules();

	if (use_ipv4) {
		h4 = ipq_create_handle(0, PF_INET);
		if (!h4)
  			die(h4);
		status = ipq_set_mode(h4, IPQ_COPY_PACKET, BUFSIZE);
		if (status < 0)
			die(h4);
	}

	if (use_ipv6) {
		h6 = ipq_create_handle(0, PF_INET6);
		if (!h6)
			die(h6);
		status = ipq_set_mode(h6, IPQ_COPY_PACKET, BUFSIZE);
		if (status < 0)
			die(h6);
	}

	firewall_init();

#ifdef G_THREADS_IMPL_POSIX
      	HIP_DEBUG("init_timeout_checking: posix thread implementation\n");
#endif //G_THREADS_IMPL_POSIX
#ifdef G_THREADS_IMPL_SOLARIS
      	HIP_DEBUG("init_timeout_checking: solaris thread implementation\n");
#endif //G_THREADS_IMPL_SOLARIS
#ifdef G_THREADS_IMPL_NONE
      	HIP_DEBUG("init_timeout_checking: no thread implementation\n");
#endif //G_THREADS_IMPL_NONE
		//HIP_DEBUG("Timeout val = %d", timeout_val);
      	g_thread_init(NULL);
  
  	init_timeout_checking(timeout);
  	control_thread_init();


	if (use_ipv4) {
                pthread_create(&ipv4Thread, NULL, &handle_ip_traffic,
			       (void*) &family4);
        }
	if (use_ipv6) {
                pthread_create(&ipv6Thread, NULL, &handle_ip_traffic,
			       (void*) &family6);
        }

	if (use_ipv4)
		pthread_join(ipv4Thread, NULL);
	if (use_ipv6)
		pthread_join(ipv6Thread, NULL);	

out_err:

  	firewall_exit();
  	return 0;
}


/**
 * Loads several modules that are needed by the firewall.
 * 
 * @return	nothing.
 */
void firewall_probe_kernel_modules()
{
	int count, err, status;
	char cmd[40];
	int mod_total;
	char *mod_name[] =
	{
		"ip_queue", "ip6_queue",
		"iptable_filter", "ip6table_filter"
	};

	mod_total = sizeof(mod_name) / sizeof(char *);

	HIP_DEBUG("Probing for %d modules. When the modules are built-in, the errors can be ignored\n", mod_total);	

	for (count = 0; count < mod_total; count++)
	{
		snprintf(cmd, sizeof(cmd), "%s %s", "/sbin/modprobe", mod_name[count]);
		HIP_DEBUG("%s\n", cmd);
		err = fork();
		if (err < 0) HIP_ERROR("Failed to fork() for modprobe!\n");
		else if (err == 0)
		{
			/* Redirect stderr, so few non fatal errors wont show up. */
			stderr = freopen("/dev/null", "w", stderr);
			execlp("/sbin/modprobe", "/sbin/modprobe", mod_name[count], (char *)NULL);
		}
		else waitpid(err, &status, 0);
	}
	HIP_DEBUG("Probing completed\n");
}


int hip_esp_traffic_userspace_handler(pthread_t *hip_esp_userspace_id_param, 
				      void (*hip_esp_userspace_traffic)(void *), 
				      void *thread_param)
  {
  pthread_attr_t  attr;
  int rc = 0;
  unsigned int stacksize;
 
  if (rc = pthread_attr_init(&attr))
    return EXIT_FAILURE;
  
  
  if (rc = pthread_attr_setstacksize(&attr, stacksize))
    return EXIT_FAILURE;   
  
  if (rc = pthread_create(hip_esp_userspace_id_param, &attr, (void*(*)(void*)) &hip_esp_userspace_traffic, 
			  thread_param))
    return EXIT_FAILURE;     
  
  /* wait for thread termination */
  pthread_join(hip_esp_userspace_id_param, NULL);
  return EXIT_SUCCESS;

}



