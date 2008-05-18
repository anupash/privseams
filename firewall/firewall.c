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
#define BUFSIZE 2048

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
int hip_userspace_ipsec = 1;

/* Default HIT - do not access this directly, call hip_fw_get_default_hit */
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

		if (!accept_normal_traffic_by_default)
		{
			system("iptables -P FORWARD DROP");
			system("iptables -P INPUT DROP");
			system("iptables -P OUTPUT DROP");
			
			system("ip6tables -P FORWARD DROP");
			system("ip6tables -P INPUT DROP");
			system("ip6tables -P OUTPUT DROP");
		}

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
	
	system("iptables -F INPUT");
	system("iptables -F OUTPUT");
	system("iptables -F FORWARD");
	system("ip6tables -F INPUT");
	system("ip6tables -F OUTPUT");
	system("ip6tables -F FORWARD");
	
	system("iptables -P INPUT ACCEPT");
	system("iptables -P OUTPUT ACCEPT");
	system("iptables -P FORWARD ACCEPT");
	system("ip6tables -P INPUT ACCEPT");
	system("ip6tables -P OUTPUT ACCEPT");
	system("ip6tables -P FORWARD ACCEPT");
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
	int hdr_size, err = 0;
	uint16_t plen;
	struct udphdr *udphdr = NULL;
	int udp_encap_zero_bytes = 0;
	
	HIP_DEBUG("\n");

	memset(ctx, 0, sizeof(hip_fw_context_t));
	ctx->ipq_packet = ipq_get_packet(buf);
	ctx->ip_version = ip_version;
	ctx->packet_type = OTHER_PACKET; /* default assumption */

	if (ctx->ip_version == 4)
	{
		struct ip *iphdr = (struct ip *) ctx->ipq_packet->payload;

		_HIP_DEBUG("IPv4 packet\n");

		// add pointer to IPv4 header to context
		ctx->ip_hdr.ipv4 = iphdr;
		// add IPv4 addresses
		IPV4_TO_IPV6_MAP(&ctx->ip_hdr.ipv4->ip_src, &ctx->src);
		IPV4_TO_IPV6_MAP(&ctx->ip_hdr.ipv4->ip_dst, &ctx->dst);
		
		_HIP_DEBUG("IPv4 next header protocol number is %d\n", iphdr->ip_p);
		
		
		// find out which transport layer protocol is used
		if(iphdr->ip_p == IPPROTO_HIP)
		{
			// we have found a plain HIP control packet
			HIP_DEBUG("plain HIP packet\n");
			
			ctx->packet_type = HIP_PACKET;
			ctx->transport_hdr.hip = (struct hip_common *) (((char *)iphdr) + sizeof(struct ip));
			
		} else if (iphdr->ip_p == IPPROTO_ESP)
		{
			// this is an ESP packet
			HIP_DEBUG("plain ESP packet\n");
			
			ctx->packet_type = ESP_PACKET;
			ctx->transport_hdr.esp = (struct hip_esp *) (((char *)iphdr) + sizeof(struct ip));
			
			
#ifdef CONFIG_HIP_OPPTCP
		} else if(iphdr->ip_p == IPPROTO_TCP)
		{
			// this might be a TCP packet for opportunistic mode
			HIP_DEBUG("plain TCP packet\n");
			
			ctx->packet_type = TCP_PACKET;
			ctx->transport_hdr.tcp = (struct tcphdr *) (((char *)iphdr) + sizeof(struct ip));
			
#endif
			
		} else if (iphdr->ip_p != IPPROTO_UDP)
		{
			// if it's not UDP either, it's unsupported
			HIP_DEBUG("some other packet\n");
			
			ctx->packet_type = OTHER_PACKET;
			
		}
		
		// need UDP header to look for encapsulated ESP or STUN
		hdr_size = (iphdr->ip_hl * 4);
		HIP_DEBUG("hdr_size is %d\n", hdr_size);
		plen = iphdr->ip_len;
		udphdr = ((struct udphdr *) (((char *) iphdr) + hdr_size));
		ctx->ip_hdr_len = hdr_size;
		// add udp header to context
		ctx->udp_encap_hdr = udphdr;
	} else if (ctx->ip_version == 6)
	{
		struct ip6_hdr *ip6_hdr = (struct ip6_hdr *)ctx->ipq_packet->payload;
		
		// add pointer to IPv4 header to context
		ctx->ip_hdr.ipv6 = ip6_hdr;
		// add IPv6 addresses
		ipv6_addr_copy(&ctx->src, &ip6_hdr->ip6_src);
		ipv6_addr_copy(&ctx->dst, &ip6_hdr->ip6_dst);
		
		HIP_DEBUG("IPv6 next header protocol number is %d\n",
			  ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt);
		
		// find out which transport layer protocol is used
		if(ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_HIP)
		{
			// we have found a plain HIP control packet
			HIP_DEBUG("plain HIP packet\n");
			
			ctx->packet_type = HIP_PACKET;
			ctx->transport_hdr.hip = (struct hip_common *) (((char *)ip6_hdr) + sizeof(struct ip6_hdr));
			
		} else if (ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_ESP)
		{
			// we have found a plain ESP packet
			HIP_DEBUG("plain ESP packet\n");
			
			ctx->packet_type = ESP_PACKET;
			ctx->transport_hdr.esp = (struct hip_esp *) (((char *)ip6_hdr) + sizeof(struct ip6_hdr));
			
#ifdef CONFIG_HIP_OPPTCP
		} else if(ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_TCP)
		{
			// this might be a TCP packet for opportunistic mode
			HIP_DEBUG("plain TCP packet\n");
			
			ctx->packet_type = TCP_PACKET;
			ctx->transport_hdr.tcp = (struct tcphdr *) (((char *)ip6_hdr) + sizeof(struct ip6_hdr));
			
#endif
			
		} else if (ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt != IPPROTO_UDP)
		{
			// if it's not UDP either, it's unsupported
			HIP_DEBUG("some other packet\n");
			
			ctx->packet_type = OTHER_PACKET;
		}
	
		// TODO René: Miika, we don't need to check for UDP encap here!?
		// if we care, add UDP to context
		// else clean up
		hdr_size = (ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_plen * 4);
		plen = ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_plen;
		ctx->ip_hdr_len = plen;
		udphdr = ((struct udphdr *) (((char *) ip6_hdr) + hdr_size));
	}

	HIP_DEBUG("UDP header size  is %d\n", sizeof(struct udphdr));
	
	// TODO what does that "if" check exactly?
	if (ctx->ip_version == 4 &&
	    (plen >= sizeof(struct ip) + sizeof(struct udphdr) + HIP_UDP_ZERO_BYTES_LEN))
	{
		__u32 *zero_bytes = NULL;
		
		// we can distinguish UDP encapsulated control and data traffic with 32 zero bits
		zero_bytes = (__u32 *) (((char *)udphdr) + sizeof(struct udphdr));
		
		HIP_HEXDUMP("zero_bytes: ", zero_bytes, 4);
		
		/*Check whether SPI number is zero or not */
		if (*zero_bytes == 0) {
			udp_encap_zero_bytes = 1;
			HIP_DEBUG("Zero SPI found\n");
		}
	}

	if(udphdr && ((udphdr->source == ntohs(HIP_NAT_UDP_PORT)) || 
		      (udphdr->dest == ntohs(HIP_NAT_UDP_PORT))) &&
	   udp_encap_zero_bytes)
		
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
			
		}
		HIP_DEBUG("FIXME zero bytes recognition obviously not working\n");
	} else if (udphdr
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
		
	} else {
		HIP_DEBUG("Other packet\n");
	}

out_err:	
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


/* filter hip packet according to rules.
 * return verdict
 */
int filter_esp(const struct in6_addr * dst_addr, struct hip_esp * esp,
	       unsigned int hook, const char * in_if, const char * out_if)
{
	struct _GList * list = (struct _GList *) read_rules(hook);
	struct rule * rule= NULL;
	int match = 1; // is the packet still a potential match to current rule
	int ret_val = 0;
	uint32_t spi = esp->esp_spi;

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
		ret_val = accept_hip_esp_traffic_by_default;
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
      		HIP_DEBUG("   filter_hip: checking for \n");     
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
    		ret_val = accept_hip_esp_traffic_by_default;

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

int hip_fw_handle_other_output(hip_fw_context_t *ctx) {
	int err = 0;

	HIP_DEBUG("\n");

	if (hip_userspace_ipsec)
		HIP_IFE(hip_fw_userspace_ipsec_output(ctx->ip_version,
							    ctx->ip_hdr.ipv4,
							    ctx->ipq_packet), -1);
						   
	/* XX FIXME: LSI HOOKS */

	/* No need to check default rules as it is handled by the iptables rules */
 out_err:

	return err;
}

int hip_fw_handle_hip_output(hip_fw_context_t *ctx) {
	int err = 0;
	int packet_length = 0;
	struct hip_sig * sig = NULL;
	
	HIP_DEBUG("****** Received HIP packet ******\n");
	if (ctx->ipq_packet->data_len <= (BUFSIZE - ctx->ip_hdr_len)) {
		packet_length = ctx->ipq_packet->data_len -
			ctx->ip_hdr_len; 	
		_HIP_DEBUG("HIP packet size smaller than buffer size\n");
	} else {
		/* packet is too long -> drop as max_size is well defined in RFC */
		//packet_length = BUFSIZE - hdr_size;
		_HIP_DEBUG("HIP packet size greater than buffer size\n");
		err = -1;
		goto out_err;
	}
	
	// TODO check if signature is verified somewhere
	sig = (struct hip_sig *) hip_get_param(ctx->transport_hdr.hip,
					       HIP_PARAM_HIP_SIGNATURE);
	if(sig == NULL)
		_HIP_DEBUG("no signature\n");
	else
		_HIP_DEBUG("signature exists\n");
	
	err = filter_hip(&ctx->src, 
			 &ctx->dst, 
			 (hip_common_t *) (ctx->ipq_packet->payload + ctx->ip_hdr_len), 
			 ctx->ipq_packet->hook,
			 ctx->ipq_packet->indev_name,
			 ctx->ipq_packet->outdev_name);

 out_err:
	/* zero return value means that the packet should be dropped */
	return err;
}

int hip_fw_handle_esp_output(hip_fw_context_t *ctx) {
	int err = 0;

	HIP_DEBUG("\n");

	HIP_ERROR("XX FIXME: Skipping ESP checks. SPI detection for IPv4, IPv6 and UDPv4 not working\n");
	return -1;

	err = filter_esp(&ctx->dst, 
			 ctx->transport_hdr.esp,
			 ctx->ipq_packet->hook,
			 ctx->ipq_packet->indev_name,
			 ctx->ipq_packet->outdev_name);

	return err;
}

int hip_fw_handle_tcp_output(hip_fw_context_t *ctx) {

	HIP_DEBUG("\n");

	/* XX FIXME: opp tcp filtering */

	return hip_fw_handle_other_output(ctx);
}

int hip_fw_handle_other_input(hip_fw_context_t *ctx) {
	int err = 0;

	HIP_DEBUG("\n");

	if(ipv6_addr_is_hit(&ctx->src) && ipv6_addr_is_hit(&ctx->dst))
		HIP_IFE(handle_proxy_inbound_traffic(ctx->ipq_packet, &ctx->src), -1);

	/* No need to check default rules as it is handled by the iptables rules */
 out_err:

	return err;
}

int hip_fw_handle_hip_input(hip_fw_context_t *ctx) {
	int err = 0;

	HIP_DEBUG("\n");

	HIP_IFE(hip_fw_handle_hip_output(ctx), -1);

 out_err:
	return err;
}

int hip_fw_handle_esp_input(hip_fw_context_t *ctx) {
	int err = 0;

	HIP_DEBUG("\n");

	if (hip_userspace_ipsec) {
		HIP_DEBUG("debug message: HIP firewall userspace ipsec input: \n ");
		/* added by Tao Wan */
		HIP_IFE(hip_fw_userspace_ipsec_input(ctx->ip_version,
						     ctx->ip_hdr.ipv4,
						     ctx->ipq_packet), -1);
	}

	/* XX FIXME: ADD LSI INPUT HERE */

	HIP_ERROR("XX FIXME: Skipping ESP checks. SPI detection for IPv4, IPv6 and UDPv4 not working\n");
	return -1;

 out_err:
	return err;
}

int hip_fw_handle_tcp_input(hip_fw_context_t *ctx) {
	int err = 0;

	HIP_DEBUG("\n");

	/* if tcp handling consumes the packet, other input is skipped */

	HIP_IFE(!hip_fw_examine_incoming_tcp_packet(ctx->ip_hdr.ipv4,
						    ctx->ip_version,
						    ctx->ip_hdr_len), 0);
	HIP_IFE(hip_fw_handle_other_input(ctx), 0);

 out_err:

	return err;
}

int hip_fw_handle_other_forward(hip_fw_context_t *ctx) {
	int err = 0;

	HIP_DEBUG("\n");

	if (hip_proxy_status)
		HIP_IFE(handle_proxy_outbound_traffic(&ctx->ipq_packet,
						      &ctx->src,
						      &ctx->dst,
						      ctx->ip_hdr_len,
						      ctx->ip_version), -1);

	/* No need to check default rules as it is handled by the iptables rules */

 out_err:

	return err;
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
	int err = 0;
	
	HIP_DEBUG("thread for IPv%d traffic started\n", ip_version);
	
	memset(buf, 0, BUFSIZE);
	
	/* waits for queue messages to arrive from ip_queue and
	 * copies them into a supplied buffer */
	if (ipq_read(hndl, buf, BUFSIZE, 0) < 0) {
		HIP_PERROR("ipq_read failed: ");
		err = -1;
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
			HIP_DEBUG("default case\n");
			goto out_err;
			break;
	}
	
	// further process the packet
	// TODO find a fancy function name
	err = hip_fw_init_context(ctx, buf, ip_version);
	if (err)
		goto out_err;

	HIP_DEBUG_HIT("packet src", &ctx->src);
	HIP_DEBUG_HIT("packet dst", &ctx->dst);

	// TODO check if correct below here
	
	if (hip_fw_handler[ctx->ipq_packet->hook][ctx->packet_type]) {
		err = !(hip_fw_handler[ctx->ipq_packet->hook][ctx->packet_type])(ctx);
	} else {
		HIP_DEBUG("Ignoring, no handler for hook (%d) with type (%d)\n");
	}
	
 out_err:
	if (err) {
		HIP_DEBUG("=== Verdict: drop packet ===\n");
		drop_packet(hndl, ctx->ipq_packet->packet_id);
	} else {
		HIP_DEBUG("=== Verdict: allow packet ===\n");
		allow_packet(hndl, ctx->ipq_packet->packet_id);
	}
	
#if 0
	if (hip_common)
		free(hip_common);
	if (esp)
	{
		if (esp_data)
		{
			 free(esp_data);
			 esp->esp_data = NULL;
		}
		free(esp);
	}
	ipq_destroy_handle(hndl);
#endif
	
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

	if (hip_userspace_ipsec) {
		hip_query_default_local_hit_from_hipd();
	}

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

	while (1) {
		FD_ZERO(&read_fdset);
		FD_SET(hip_fw_sock, &read_fdset);
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

