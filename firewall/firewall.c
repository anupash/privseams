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

//#define HIP_HEADER_START 128 //bytes
/* NOTE: if buffer size is changed, make sure to check
 * 		 the HIP packet size in hip_fw_init_context() */
#define BUFSIZE HIP_MAX_PACKET
//#define BUFSIZE 2048

int statefulFiltering = 1;
int escrow_active = 0;
int accept_normal_traffic_by_default = 1;
int accept_hip_esp_traffic_by_default = 0;
int flush_iptables = 1;

int counter = 0;
int hip_proxy_status = 0;
int foreground = 1;
#ifdef CONFIG_HIP_OPPTCP
int hip_opptcp = 1;
#else
int hip_opptcp = 0;
#endif
int hip_userspace_ipsec = 0;

/* Default HIT - do not access this directly, call hip_fw_get_default_hit() */
struct in6_addr default_hit;

/*
 * The firewall handlers do not accept rules directly. They should return
 * zero when they transformed packet and the original should be dropped.
 * Non-zero means that there was an error or the packet handler did not
 * know what to do with the packet.
 */
int (*hip_fw_handler[NF_IP_NUMHOOKS][FW_PROTO_NUM])(hip_fw_context_t *) = { NULL };

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

/*
 * Rules:
 *
 * Output:
 *
 * - HIP:
 *   1. default rule checks for hip
 *   1. filter_hip
 *
 * - ESP:
 *   1. default rule checks for esp
 *   2. filter_esp
 *
 * - TCP:
 *   1. default rule checks for non-hip
 *   2.
 *   - destination is hit (userspace ipsec output)
 *   - destination is lsi (lsi output)
 *   - destination not hit or lsi
 *     1. opp tcp filtering (TBD)
 *
 * - Other
 *   - Same as with TCP except no opp tcp filtering
 *
 * Input:
 * 
 * - HIP:
 *   1. default rule checks for hip
 *   2. filter_hip
 *
 * - ESP:
 *   1. default rule checks for hip
 *   2. filter_esp
 *   3. userspace_ipsec input
 *   4. lsi input
 *
 * - Other:
 *   - Same as with TCP except no opp tcp input
 *
 * - TCP:
 *   1. default rule checks for non-hip
 *   2. opp tcp input
 *   3. proxy input
  *
 * Forward:
 *
 * - HIP:
 *   1. None
 * 
 * - ESP:
 *   1. None
 *
 * - TCP: 
 *   1. Proxy input
 * 
 * - Other:
 *   2. Proxy input
 *   
 */
int firewall_init_rules()
{
	HIP_DEBUG("Initializing firewall\n");

	// funtion pointers for the respective packet handlers
	hip_fw_handler[NF_IP_LOCAL_IN][OTHER_PACKET] = hip_fw_handle_other_input;
	hip_fw_handler[NF_IP_LOCAL_IN][HIP_PACKET] = hip_fw_handle_hip_input;
	hip_fw_handler[NF_IP_LOCAL_IN][ESP_PACKET] = hip_fw_handle_esp_input;
	hip_fw_handler[NF_IP_LOCAL_IN][TCP_PACKET] = hip_fw_handle_tcp_input;

	hip_fw_handler[NF_IP_LOCAL_OUT][OTHER_PACKET] = hip_fw_handle_other_output;
	hip_fw_handler[NF_IP_LOCAL_OUT][HIP_PACKET] = hip_fw_handle_hip_output;
	hip_fw_handler[NF_IP_LOCAL_OUT][ESP_PACKET] = hip_fw_handle_esp_output;
	hip_fw_handler[NF_IP_LOCAL_OUT][TCP_PACKET] = hip_fw_handle_tcp_output;

	hip_fw_handler[NF_IP_FORWARD][OTHER_PACKET] = hip_fw_handle_other_forward;
	hip_fw_handler[NF_IP_FORWARD][HIP_PACKET] = NULL;
	hip_fw_handler[NF_IP_FORWARD][ESP_PACKET] = NULL;
	hip_fw_handler[NF_IP_FORWARD][TCP_PACKET] = hip_fw_handle_tcp_forward;

	HIP_DEBUG("Enabling forwarding for IPv4 and IPv6\n");
	system("echo 1 >/proc/sys/net/ipv4/conf/all/forwarding");
	system("echo 1 >/proc/sys/net/ipv6/conf/all/forwarding");

	if (flush_iptables)
	{
		hip_fw_flush_iptables();
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
		// this has to be set up first in order to be the default behavior
		if (!accept_normal_traffic_by_default)
		{
			// make DROP the default behavior of all chains
			// TODO don't drop LSIs -> else IPv4 apps won't work
			// -> also messaging between HIPd and firewall is blocked here
			system("iptables -I FORWARD -j DROP");
			system("iptables -I INPUT -j DROP");
			system("iptables -I OUTPUT -j DROP");
			
			// but still allow packets with HITs as destination
			// FIXME what about checking the src for HITs?
			system("ip6tables -I FORWARD ! -d 2001:0010::/28 -j DROP");
			system("ip6tables -I INPUT ! -d 2001:0010::/28 -j DROP");
			system("ip6tables -I OUTPUT ! -d 2001:0010::/28 -j DROP");
		}
		
		// this will allow the firewall to handle HIP traffic
		// HIP port
		system("iptables -I FORWARD -p 139 -j QUEUE");
		// ESP port
		system("iptables -I FORWARD -p 50 -j QUEUE");
		// UDP encapsulation for HIP
		system("iptables -I FORWARD -p 17 --dport 50500 -j QUEUE");
		system("iptables -I FORWARD -p 17 --sport 50500 -j QUEUE");

		system("iptables -I INPUT -p 139 -j QUEUE");
		system("iptables -I INPUT -p 50 -j QUEUE");
		system("iptables -I INPUT -p 17 --dport 50500 -j QUEUE");
		system("iptables -I INPUT -p 17 --sport 50500 -j QUEUE");

		system("iptables -I OUTPUT -p 139 -j QUEUE");
		system("iptables -I OUTPUT -p 50 -j QUEUE");
		system("iptables -I OUTPUT -p 17 --dport 50500 -j QUEUE");
		system("iptables -I OUTPUT -p 17 --sport 50500 -j QUEUE");
		
		
		system("ip6tables -I FORWARD -p 139 -j QUEUE");
		system("ip6tables -I FORWARD -p 50 -j QUEUE");
		system("ip6tables -I FORWARD -p 17 --dport 50500 -j QUEUE");
		system("ip6tables -I FORWARD -p 17 --sport 50500 -j QUEUE");

		system("ip6tables -I INPUT -p 139 -j QUEUE");
		system("ip6tables -I INPUT -p 50 -j QUEUE");
		system("ip6tables -I INPUT -p 17 --dport 50500 -j QUEUE");
		system("ip6tables -I INPUT -p 17 --sport 50500 -j QUEUE");

		system("ip6tables -I OUTPUT -p 139 -j QUEUE");
		system("ip6tables -I OUTPUT -p 50 -j QUEUE");
		system("ip6tables -I OUTPUT -p 17 --dport 50500 -j QUEUE");
		system("ip6tables -I OUTPUT -p 17 --sport 50500 -j QUEUE");

	}

#ifdef CONFIG_HIP_OPPTCP//tcp over ipv4
	//system("iptables -I FORWARD -p 6 -j QUEUE"); // is this needed? -miika
	system("iptables -I INPUT -p 6 -j QUEUE");
	system("iptables -I OUTPUT -p 6 -j QUEUE");
	
	//system("ip6tables -I FORWARD -p 6 -j QUEUE");  // is this needed? -miika
	system("ip6tables -I INPUT -p 6 -j QUEUE");
	system("ip6tables -I OUTPUT -p 6 -j QUEUE");
#endif

	if (hip_userspace_ipsec) {
		system("iptables -I INPUT -p 50 -j QUEUE"); /* ESP over IPv4 */
		system("iptables -I INPUT -p 17 --dport 50500 -j QUEUE");
		system("iptables -I INPUT -p 17 --sport 50500 -j QUEUE");

		system("ip6tables -I INPUT -p 50 -j QUEUE"); /* ESP over IPv6 */
		
		//system("ip6tables -I OUTPUT -p 6 ! -d ::1 -j QUEUE"); /* TCP over IPv6: possibly HIT based connection */
		system("ip6tables -I OUTPUT -p 6 -d 2001:0010::/28 -j QUEUE"); /* TCP over IPv6: possibly HIT based connection */
		
		//system("ip6tables -I OUTPUT -p 17 ! -d ::1 -j QUEUE"); /* UDP over IPv6: possibly HIT based connection */
		system("ip6tables -I OUTPUT -p 17 -d 2001:0010::/28 -j QUEUE"); /* UDP over IPv6: possibly HIT based connection */
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

void hip_fw_flush_iptables(void) {
	HIP_DEBUG("Flushing all rules\n");
	
	// -F flushes the chains
	system("iptables -F INPUT");
	system("iptables -F OUTPUT");
	system("iptables -F FORWARD");
	system("ip6tables -F INPUT");
	system("ip6tables -F OUTPUT");
	system("ip6tables -F FORWARD");
}

void firewall_exit()
{
	HIP_DEBUG("Firewall exit\n");

	if (flush_iptables)
	{
		hip_fw_flush_iptables();
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
	// FIXME first check mapping: HI <-> HIT (cheaper operation)
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
int hip_fw_init_context(hip_fw_context_t *ctx, char *buf, int ip_version){
	int ip_hdr_len, err = 0;
	// length of packet starting at udp header
	uint16_t udp_len = 0;
	struct udphdr *udphdr = NULL;
	int udp_encap_zero_bytes = 0;
	
	// default assumption
	ctx->packet_type = OTHER_PACKET;
	
	// same context memory as for packets before -> re-init
	memset(ctx, 0, sizeof(hip_fw_context_t));
	
	// add whole packet to context and ip version
	ctx->ipq_packet = ipq_get_packet(buf);
	// TODO might there be an error we have to catch?
	
	// check if packet is to big for the buffer
	if (ctx->ipq_packet->data_len > BUFSIZE)
	{
		_HIP_DEBUG("packet size greater than buffer size\n");
		
		err = 1;
		goto end_init;
	}
	
	ctx->ip_version = ip_version;

	if (ctx->ip_version == 4)
	{
		_HIP_DEBUG("IPv4 packet\n");
		
		struct ip *iphdr = (struct ip *) ctx->ipq_packet->payload;
		// add pointer to IPv4 header to context
		ctx->ip_hdr.ipv4 = iphdr;
		
		/* ip_hl is given in multiple of 4 bytes
		 * 
		 * NOTE: not sizeof(struct ip) as we might have options */
		ip_hdr_len = (iphdr->ip_hl * 4);
		// needed for opportunistic TCP
		ctx->ip_hdr_len = ip_hdr_len;
		_HIP_DEBUG("ip_hdr_len is %d\n", hdr_size);
		
		// add IPv4 addresses
		IPV4_TO_IPV6_MAP(&ctx->ip_hdr.ipv4->ip_src, &ctx->src);
		IPV4_TO_IPV6_MAP(&ctx->ip_hdr.ipv4->ip_dst, &ctx->dst);
		
		HIP_DEBUG_HIT("packet src", &ctx->src);
		HIP_DEBUG_HIT("packet dst", &ctx->dst);
		
		HIP_DEBUG("IPv4 next header protocol number is %d\n", iphdr->ip_p);
		
		// find out which transport layer protocol is used
		if(iphdr->ip_p == IPPROTO_HIP)
		{
			// we have found a plain HIP control packet
			HIP_DEBUG("plain HIP packet\n");
			
			ctx->packet_type = HIP_PACKET;
			ctx->transport_hdr.hip = (struct hip_common *) (((char *)iphdr) + sizeof(struct ip));
			
			goto end_init;
			
		} else if (iphdr->ip_p == IPPROTO_ESP)
		{
			// this is an ESP packet
			HIP_DEBUG("plain ESP packet\n");
			
			ctx->packet_type = ESP_PACKET;
			ctx->transport_hdr.esp = (struct hip_esp *) (((char *)iphdr) + sizeof(struct ip));
			
			goto end_init;
			
#ifdef CONFIG_HIP_OPPTCP
		} else if(iphdr->ip_p == IPPROTO_TCP)
		{
			// this might be a TCP packet for opportunistic mode
			HIP_DEBUG("plain TCP packet\n");
			
			ctx->packet_type = TCP_PACKET;
			ctx->transport_hdr.tcp = (struct tcphdr *) (((char *)iphdr) + sizeof(struct ip));
			
			goto end_init;
			
#endif
			
		} else if (iphdr->ip_p != IPPROTO_UDP)
		{
			// if it's not UDP either, it's unsupported
			HIP_DEBUG("some other packet\n");

			goto end_init;
		}
		
		// need UDP header to look for encapsulated ESP or STUN
		udp_len = iphdr->ip_len;
		udphdr = ((struct udphdr *) (((char *) iphdr) + ip_hdr_len));
		
		// add UDP header to context
		ctx->udp_encap_hdr = udphdr;
		
	} else if (ctx->ip_version == 6)
	{
		_HIP_DEBUG("IPv6 packet\n");
		
		struct ip6_hdr *ip6_hdr = (struct ip6_hdr *)ctx->ipq_packet->payload;
		// add pointer to IPv4 header to context
		ctx->ip_hdr.ipv6 = ip6_hdr;
		
		// Ipv6 has fixed header length of 40 bytes
		ip_hdr_len = 40;
		// needed for opportunistic TCP
		ctx->ip_hdr_len = ip_hdr_len;
		_HIP_DEBUG("ip_hdr_len is %d\n", ip_hdr_len);
		
		// add IPv6 addresses
		ipv6_addr_copy(&ctx->src, &ip6_hdr->ip6_src);
		ipv6_addr_copy(&ctx->dst, &ip6_hdr->ip6_dst);
		
		HIP_DEBUG_HIT("packet src", &ctx->src);
		HIP_DEBUG_HIT("packet dst", &ctx->dst);
		
		HIP_DEBUG("IPv6 next header protocol number is %d\n",
			  ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt);
		
		// find out which transport layer protocol is used
		if(ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_HIP)
		{
			// we have found a plain HIP control packet
			HIP_DEBUG("plain HIP packet\n");
			
			ctx->packet_type = HIP_PACKET;
			ctx->transport_hdr.hip = (struct hip_common *) (((char *)ip6_hdr) + sizeof(struct ip6_hdr));
			
			goto end_init;
			
		} else if (ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_ESP)
		{
			// we have found a plain ESP packet
			HIP_DEBUG("plain ESP packet\n");
			
			ctx->packet_type = ESP_PACKET;
			ctx->transport_hdr.esp = (struct hip_esp *) (((char *)ip6_hdr) + sizeof(struct ip6_hdr));
			
			goto end_init;
			
#ifdef CONFIG_HIP_OPPTCP
		} else if(ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_TCP)
		{
			// this might be a TCP packet for opportunistic mode
			HIP_DEBUG("plain TCP packet\n");
			
			ctx->packet_type = TCP_PACKET;
			ctx->transport_hdr.tcp = (struct tcphdr *) (((char *)ip6_hdr) + sizeof(struct ip6_hdr));
			
			goto end_init;
#endif
			
		} else if (ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt != IPPROTO_UDP)
		{
			// if it's not UDP either, it's unsupported
			HIP_DEBUG("some other packet\n");
			
			goto end_init;
		}
	
		/* for now these calculations are not necessary as UDP encapsulation
		 * is only used for IPv4 at the moment
		 * 
		 * we keep them anyway in order to ease UDP encapsulation handling
		 * with IPv6
		 * 
		 * NOTE: the length will include optional extension headers 
		 * -> handle this */
		udp_len = ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_plen;
		udphdr = ((struct udphdr *) (((char *) ip6_hdr) + ip_hdr_len));
		
		// add udp header to context
		ctx->udp_encap_hdr = udphdr;
	}

	HIP_DEBUG("UDP header size  is %d\n", sizeof(struct udphdr));
	
	/* only handle IPv4 right now
	 * -> however this is the place to handle UDP encapsulated IPv6 */
	if (ctx->ip_version == 4)
	{
		// we might have only received a UDP packet with headers only 
		if (udp_len >= sizeof(struct ip) + sizeof(struct udphdr) + HIP_UDP_ZERO_BYTES_LEN)
		{
			__u32 *zero_bytes = NULL;
			
			// we can distinguish UDP encapsulated control and data traffic with 32 zero bits
			// behind UDP header
			zero_bytes = (__u32 *) (((char *)udphdr) + sizeof(struct udphdr));
			
			HIP_HEXDUMP("zero_bytes: ", zero_bytes, 4);
			
			/* check whether next 32 bits are zero or not */
			if (*zero_bytes == 0)
			{
				udp_encap_zero_bytes = 1;
				
				HIP_DEBUG("Zero SPI found\n");
			}
			
			zero_bytes = NULL;
		} else
		{
			// only UDP header + payload < 32 bit -> neither HIP nor ESP
			HIP_DEBUG("UDP packet with <32 bit payload\n");
			
			goto end_init;
		}
	}
	    
	// HIP packets have zero bytes (IPv4 only right now)
	if(ctx->ip_version == 4 && udphdr
			&& ((udphdr->source == ntohs(HIP_NAT_UDP_PORT)) || 
		        (udphdr->dest == ntohs(HIP_NAT_UDP_PORT)))
		    && udp_encap_zero_bytes)
		
	{	
		/* check for HIP control message */
		if (!hip_check_network_msg((struct hip_common *) (((char *)udphdr) 
								     + 
								  sizeof(struct udphdr) 
								  + 
								  HIP_UDP_ZERO_BYTES_LEN)))
		{
			// we found an UDP encapsulated HIP control packet
			HIP_DEBUG("UDP encapsulated HIP control packet\n");
			
			// add to context
			ctx->packet_type = HIP_PACKET;
			ctx->transport_hdr.hip = (struct hip_common *) (((char *)udphdr) 
									+ sizeof(struct udphdr) 
									+ HIP_UDP_ZERO_BYTES_LEN);
			
			goto end_init;
		}
		HIP_DEBUG("FIXME zero bytes recognition obviously not working\n");
	}
	
	// ESP does not have zero bytes (IPv4 only right now)
	else if (ctx->ip_version == 4 && udphdr
		   && ((udphdr->source == ntohs(HIP_NAT_UDP_PORT)) || 
		       (udphdr->dest == ntohs(HIP_NAT_UDP_PORT)))
		   && !udp_encap_zero_bytes)
	{
		/* from the ports and the non zero SPI we can tell that this
		 * is an ESP packet */
		HIP_DEBUG("UDP encapsulated ESP packet or STUN PACKET\n");
		HIP_DEBUG("Assuming ESP. Todo: verify SPI from database\n");
		
		// add to context
		ctx->packet_type = ESP_PACKET;
		ctx->transport_hdr.esp = (struct hip_esp *) (((char *)udphdr) 
							     + sizeof(struct udphdr));
		
		goto end_init;
	}
	
	// normal UDP packet or UDP encapsulated IPv6
	else {
		HIP_DEBUG("normal UDP packet\n");	
	}

end_init:	
	return err;
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
	// TODO error to be handled?
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
	// TODO error to be handled?
	HIP_DEBUG("Packet dropped \n\n");
}


/* filter esp packet according to rules.
 * return verdict
 */
int filter_esp(const struct in6_addr * dst_addr, struct hip_esp * esp,
	       unsigned int hook, const char * in_if, const char * out_if)
{
	// list with all rules for hook (= IN / OUT / FORWARD)
	struct _GList * list = (struct _GList *) read_rules(hook);
	struct rule * rule= NULL;
	// assume matching rule
	int match = 1;
	// block traffic by default
	int verdict = 0;
	
	uint32_t spi = esp->esp_spi;
	
	_HIP_DEBUG("filter_esp:\n");
	while (list != NULL)
	{
		match = 1;
		rule = (struct rule *) list->data;
		
		//print_rule(rule);
		HIP_DEBUG_HIT("dst addr: ", dst_addr);
		HIP_DEBUG("SPI: %d\n", ntohl(spi));
		
		//type not valid with ESP packets -> should not be set in rules
		if (rule->type)
		{
			_HIP_DEBUG("filter_esp: type option not valid for esp\n");
			match = 0;
		}
		
		//src and dst hits are matched with state option
		// TODO HITs are invisible, aren't they!?
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
			{
				match = 0;
			}
			
			_HIP_DEBUG("filter_esp: in_if rule: %s, packet: %s, boolean: %d, match: %d \n",
				   rule->in_if->value, in_if, rule->in_if->boolean, match);
		}
		
		if (match && rule->out_if)
		{
			if (!match_string(rule->out_if->value, out_if,
					  rule->out_if->boolean))
			{
				match = 0;
			}
			
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
				_HIP_DEBUG("filter_esp: state: rule %d, boolean %d, match %d\n",
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
		
		// else try to match next rule
		list = list->next;
	}
		
	//was there a rule matching the packet
	if (rule && match)
	{
		_HIP_DEBUG("filter_esp: packet matched rule, target %d\n", rule->accept);
		verdict = rule->accept;
	}
	else
		verdict = accept_hip_esp_traffic_by_default;
	
	//release rule list
	read_rules_exit(0);
	
	return verdict;
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
	// complete rule list for hook (== IN / OUT / FORWARD)
  	struct _GList * list = (struct _GList *) read_rules(hook);
  	struct rule * rule = NULL;
  	// assume match for current rule
  	int match = 1;
  	// assume packet has not yet passed connection tracking
  	int conntracked = 0;
  	// block traffic by default
  	int verdict = 0;

	HIP_DEBUG("\n");

  	//if dynamically changing rules possible 
  	//int hip_packet = is_hip_packet(), ..if(hip_packet && rule->src_hit)
  	//+ filter_state käsittelemään myös esp paketit
  	while (list != NULL)
	{
  		match = 1;
  		rule = (struct rule *) list->data;    
  		
  		HIP_DEBUG("HIP type number is %d\n", buf->type_hdr);
  		
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
    	else if (buf->type_hdr == HIP_NOTIFY)
    		HIP_DEBUG("packet type: NOTIFY\n");
    	else
    		HIP_DEBUG("packet type: UNKNOWN\n");
    	
		HIP_DEBUG_HIT("src hit: ", &(buf->hits));
        HIP_DEBUG_HIT("dst hit: ", &(buf->hitr));

        // check src_hit if defined in rule
      	if(match && rule->src_hit)
	  	{
    		HIP_DEBUG("filter_hip: src_hit\n");
    		
    		if(!match_hit(rule->src_hit->value, 
		  		buf->hits, 
		  		rule->src_hit->boolean))
    		{
      			match = 0;
    		}
		}
      	
    	// check dst_hit if defined in rule
    	if(match && rule->dst_hit)
		{
    		HIP_DEBUG("filter_hip: dst_hit\n");
    		
    		if(!match_hit(rule->dst_hit->value, 
		  		buf->hitr, 
		  		rule->dst_hit->boolean))
    		{
    			match = 0;
    		}
	  	}
    	
    	// check the HIP packet type (I1, UPDATE, etc.)
      	if(match && rule->type)
	  	{
    		HIP_DEBUG("filter_hip: type\n");
    		if(!match_int(rule->type->value, 
		  		buf->type_hdr, 
		  		rule->type->boolean))
    		{
     			match = 0;
    		}
    		
	    	HIP_DEBUG("filter_hip: type rule: %d, packet: %d, boolean: %d, match: %d\n",
		    		rule->type->value, 
		    		buf->type_hdr,
		    		rule->type->boolean,
		    		match);
	  	}
      	
      	// TODO comment
      	if(match && rule->in_if)
	  	{
    		if(!match_string(rule->in_if->value, in_if, rule->in_if->boolean))
    		{
      			match = 0;
    		}
    		
    		HIP_DEBUG("filter_hip: in_if rule: %s, packet: %s, boolean: %d, match: %d \n",
	      			rule->in_if->value, 
	      			in_if, rule->in_if->boolean, match);
	  	}
      	
      	// TODO comment
      	if(match && rule->out_if)
	  	{
    		if(!match_string(rule->out_if->value, 
		     		out_if, 
		     		rule->out_if->boolean))
    		{
      			match = 0;
    		}
    		
    		HIP_DEBUG("filter_hip: out_if rule: %s, packet: %s, boolean: %d, match: %d \n",
	      			rule->out_if->value, out_if, rule->out_if->boolean, match);
	  	}
      	
      	// if HI defined in rule, verify signature now 
      	// - late as it's an expensive operation
      	// - checks that the message src is the src defined in the _rule_
    	if(match && rule->src_hi)
      	{
			_HIP_DEBUG("filter_hip: src_hi\n");
			
			if(!match_hi(rule->src_hi, buf))
			{
		  		match = 0;
			}
	    }
	
      	/* check if packet matches state from connection tracking
      	 * 
		 * must be last, so not called if packet is going to be dropped */
      	if(match && rule->state)
	  	{
      		/* we at least had some packet before -> check this packet
      		 * 
      		 * this will also check the signature of the packet, if we already
      		 * have a src_HI stored for the _connection_ */
    		if(!filter_state(ip6_src, ip6_dst, buf, rule->state, rule->accept))
    		{
    			match = 0;
    		} else
    		{
    			// if it is a valid packet, this also tracked the packet
    			conntracked = 1;
    		}
    		
    		HIP_DEBUG("filter_hip: state, rule %d, boolean %d, match %d\n", 
	      			rule->state->int_opt.value,
	      			rule->state->int_opt.boolean, 
	      			match);
		}
      	
		// if a match, no need to check further rules
		if(match)
		{
			HIP_DEBUG("filter_hip: match found\n");
			break;
 		}
    	
		// else proceed with next rule
		list = list->next;
    }
  	
  	// if we found a matching rule, use its verdict
  	if(rule && match)
	{
		HIP_DEBUG("filter_hip: packet matched rule, target %d\n", rule->accept);
		verdict = rule->accept; 
	}
 	else
    	verdict = accept_hip_esp_traffic_by_default;

  	//release rule list
  	read_rules_exit(0);
  	
  	// if packet will be accepted and connection tracking is used
  	// but there is no state for the packet in the conntrack module
  	// yet -> show the packet to conntracking
  	if(statefulFiltering && verdict && !conntracked)
  	{
    	conntrack(ip6_src, ip6_dst, buf);
  	}
  	
  	return verdict; 
}

int hip_fw_handle_other_output(hip_fw_context_t *ctx) {
	int err = 0;

	HIP_DEBUG("\n");

	if (hip_userspace_ipsec)
		HIP_IFE(hip_fw_userspace_ipsec_output(ctx->ip_version,
						      ctx->ip_hdr.ipv4,
						      ctx->ipq_packet), -1);
						   
	/* XX FIXME: LSI HOOKS */

	/* No need to check default rules as it is handled by the
	   iptables rules */
 out_err:

	return err;
}

int hip_fw_handle_hip_output(hip_fw_context_t *ctx) {
	int verdict = 0;
	int packet_length = 0;
	struct hip_sig * sig = NULL;
	
	HIP_DEBUG("****** Received HIP packet ******\n");
	
	verdict = filter_hip(&ctx->src, 
			 &ctx->dst, 
			 ctx->transport_hdr.hip, 
			 ctx->ipq_packet->hook,
			 ctx->ipq_packet->indev_name,
			 ctx->ipq_packet->outdev_name);

 out_err:
	/* zero return value means that the packet should be dropped */
	return verdict;
}

int hip_fw_handle_esp_output(hip_fw_context_t *ctx) {
	int verdict = 0;

	HIP_DEBUG("\n");

	HIP_DEBUG("XX FIXME: Skipping ESP checks. SPI detection for IPv4, IPv6 and UDPv4 not working\n");
	verdict = 1;

	/*
	err = filter_esp(&ctx->dst, 
			 ctx->transport_hdr.esp,
			 ctx->ipq_packet->hook,
			 ctx->ipq_packet->indev_name,
			 ctx->ipq_packet->outdev_name);
			 */

	return verdict;
}

int hip_fw_handle_tcp_output(hip_fw_context_t *ctx) {

	HIP_DEBUG("\n");

	/* XX FIXME: opp tcp filtering */

	return hip_fw_handle_other_output(ctx);
}

int hip_fw_handle_other_input(hip_fw_context_t *ctx) {
	int verdict = 1;

	HIP_DEBUG("\n");

	if (ipv6_addr_is_hit(&ctx->src) && ipv6_addr_is_hit(&ctx->dst))
		verdict = handle_proxy_inbound_traffic(ctx->ipq_packet,
						       &ctx->src);

	/* No need to check default rules as it is handled by the iptables rules */
 out_err:

	return verdict;
}

int hip_fw_handle_hip_input(hip_fw_context_t *ctx) {
	int verdict = 0;

	HIP_DEBUG("\n");

	// for now input and output are handled symmetrically
	// err = 0 means drop
	verdict = hip_fw_handle_hip_output(ctx);

 out_err:
	return verdict;
}

int hip_fw_handle_esp_input(hip_fw_context_t *ctx) {
	int verdict = 1;

	HIP_DEBUG("\n");

	/* XX FIXME: ADD LSI INPUT AFTER USERSPACE IPSEC */

	if (hip_userspace_ipsec) {
		HIP_DEBUG("debug message: HIP firewall userspace ipsec input: \n ");
		// added by Tao Wan
		verdict = hip_fw_userspace_ipsec_input(ctx->ip_version,
						       ctx->ip_hdr.ipv4,
						       ctx->ipq_packet);
	} else {
		verdict = 1;
		HIP_DEBUG("XX FIXME: Skipping ESP checks. SPI detection for IPv4, IPv6 and UDPv4 not working\n");
	}

 out_err:
	return verdict;
}

int hip_fw_handle_tcp_input(hip_fw_context_t *ctx) {
	int verdict = 0;

	HIP_DEBUG("\n");

	/* if tcp handling consumes the packet, other input is skipped */

	if(!ipv6_addr_is_hit(&ctx->dst))
		verdict = hip_fw_examine_incoming_tcp_packet(ctx->ip_hdr.ipv4,
							     ctx->ip_version,
							     ctx->ip_hdr_len);
	else
		verdict = hip_fw_handle_other_input(ctx);

 out_err:

	return verdict;
}

int hip_fw_handle_other_forward(hip_fw_context_t *ctx) {
	int verdict = 1;

	HIP_DEBUG("\n");

	if (hip_proxy_status && !ipv6_addr_is_hit(&ctx->dst))
		verdict = handle_proxy_outbound_traffic(&ctx->ipq_packet,
							&ctx->src,
							&ctx->dst,
							ctx->ip_hdr_len,
							ctx->ip_version);

	/* No need to check default rules as it is handled by the iptables rules */

 out_err:

	return verdict;
}

int hip_fw_handle_tcp_forward(hip_fw_context_t *ctx) {
	HIP_DEBUG("\n");

	return hip_fw_handle_other_forward(ctx);
}


/**
 * Analyzes packets.

 * @param *ptr	pointer to an integer that indicates
 * 		the type of traffic: 4 - ipv4; 6 - ipv6.
 * @return	nothing, this function loops forever,
 * 		until the firewall is stopped.
 */
int hip_fw_handle_packet(char *buf, struct ipq_handle *hndl, int ip_version, hip_fw_context_t *ctx)
{
	// assume DROP
	int verdict = 0;
	
	// same buffer memory as for packets before -> re-init
	memset(buf, 0, BUFSIZE);
	
	/* waits for queue messages to arrive from ip_queue and
	 * copies them into a supplied buffer */
	if (ipq_read(hndl, buf, BUFSIZE, 0) < 0)
	{
		HIP_PERROR("ipq_read failed: ");
		// TODO this error needs to be handled seperately -> die(hndl)?
		goto out_err;
	}
		
	/* queued messages may be a packet messages or an error messages */
	switch (ipq_message_type(buf))
	{
		case NLMSG_ERROR:
			HIP_ERROR("Received error message (%d): %s\n", ipq_get_msgerr(buf), ipq_errstr());
			goto out_err;
			break;
		case IPQM_PACKET:
			HIP_DEBUG("Received ipqm packet\n");
			// no goto -> go on with processing the message below
			break;
		default:
			HIP_DEBUG("Unsupported libipq packet\n");
			goto out_err;
			break;
	}
	
	// set up firewall context
	if (hip_fw_init_context(ctx, buf, ip_version))
		goto out_err;
	
	// match context with rules
	if (hip_fw_handler[ctx->ipq_packet->hook][ctx->packet_type]) {
		verdict = (hip_fw_handler[ctx->ipq_packet->hook][ctx->packet_type])(ctx);
	} else {
		HIP_DEBUG("Ignoring, no handler for hook (%d) with type (%d)\n");
	}
	
 out_err:
	if (verdict) {
		HIP_DEBUG("=== Verdict: allow packet ===\n");
		allow_packet(hndl, ctx->ipq_packet->packet_id);
	} else {
		HIP_DEBUG("=== Verdict: drop packet ===\n");
		drop_packet(hndl, ctx->ipq_packet->packet_id);
	}
	
	return 0;
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
	struct ipq_handle *h4 = NULL, *h6 = NULL;
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
	unsigned char buf[BUFSIZE];
	hip_fw_context_t ctx;

	if (geteuid() != 0) {
		HIP_ERROR("firewall must be run as root\n");
		exit(-1);
	}

	memset(&default_hit, 0, sizeof(default_hit));

	hip_query_default_local_hit_from_hipd();

	_HIP_DEBUG_HIT("Default hit is ", hip_fw_get_default_hit());

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
			accept_normal_traffic_by_default = 0;
			break;
		case 'A':
			accept_hip_esp_traffic_by_default = 1;
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
		HIP_DEBUG("Forking into background\n");
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

	// create firewall queue handles for IPv4 traffic
	// FIXME died handle will still be used below
	h4 = ipq_create_handle(0, PF_INET);
	if (!h4)
		die(h4);
	status = ipq_set_mode(h4, IPQ_COPY_PACKET, BUFSIZE);
	if (status < 0)
		die(h4);

	// create firewall queue handles for IPv6 traffic
	// FIXME died handle will still be used below
	h6 = ipq_create_handle(0, PF_INET6);
	if (!h6)
		die(h6);
	status = ipq_set_mode(h6, IPQ_COPY_PACKET, BUFSIZE);
	if (status < 0)
		die(h6);

	// set up ip(6)tables rules
	firewall_init_rules();
	//get default HIT
	//hip_get_local_hit_wrapper(&proxy_hit);

	/* Allocate message. */
	msg = hip_msg_alloc();
	if (!msg) {
		err = -1;
		return err;
	}

	/*New UDP socket for communication with HIPD*/
	hip_fw_sock = socket(AF_INET6, SOCK_DGRAM, 0);
	HIP_IFEL((hip_fw_sock < 0), 1, "Could not create socket for firewall.\n");
	memset(&sock_addr, 0, sizeof(sock_addr));
	sock_addr.sin6_family = AF_INET6;
	sock_addr.sin6_port = htons(HIP_FIREWALL_PORT);
	sock_addr.sin6_addr = in6addr_loopback;
	HIP_IFEL(bind(hip_fw_sock, (struct sockaddr *)& sock_addr,
		      sizeof(sock_addr)), -1, "Bind on firewall socket addr failed\n");


	//init_timeout_checking(timeout);
	
#ifdef CONFIG_HIP_HIPPROXY	
	request_hipproxy_status(); //send hipproxy status request before the control thread running.
#endif /* CONFIG_HIP_HIPPROXY */

	highest_descriptor = maxof(3, hip_fw_sock, h4->fd, h6->fd);

	// do all the work here
	while (1) {
		// set up file descriptors for select
		FD_ZERO(&read_fdset);
		FD_SET(hip_fw_sock, &read_fdset);
		FD_SET(h4->fd, &read_fdset);
		FD_SET(h6->fd, &read_fdset);

		timeout.tv_sec = HIP_SELECT_TIMEOUT;
		timeout.tv_usec = 0;

		_HIP_DEBUG("HIP fw select\n");

		// get handle with queued packet and process
		if ((err = HIPD_SELECT((highest_descriptor + 1), &read_fdset, 
				       NULL, NULL, &timeout)) < 0) {
			HIP_PERROR("select error, ignoring\n");
			continue;
		}

		if (FD_ISSET(h4->fd, &read_fdset)) {
			err = hip_fw_handle_packet(buf, h4, 4, &ctx);
		}

		if (FD_ISSET(h6->fd, &read_fdset)) {
			err = hip_fw_handle_packet(buf, h6, 6, &ctx);
		}

		if (FD_ISSET(hip_fw_sock, &read_fdset)) {
			HIP_DEBUG("****** Received HIPD message ******\n");
			bzero(&sock_addr, sizeof(sock_addr));
			alen = sizeof(sock_addr);
			n = recvfrom(hip_fw_sock, msg, sizeof(struct hip_common), MSG_PEEK,
		             (struct sockaddr *)&sock_addr, &alen);
			if (n < 0)
			{
				HIP_ERROR("Error receiving message header from daemon.\n");
				err = -1;
				continue;
			}


			_HIP_DEBUG("Header received successfully\n");
			alen = sizeof(sock_addr);
			len = hip_get_msg_total_len(msg);

			_HIP_DEBUG("Receiving message (%d bytes)\n", len);
			n = recvfrom(hip_fw_sock, msg, len, 0,
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
	if (hip_fw_sock)
		close(hip_fw_sock);
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

