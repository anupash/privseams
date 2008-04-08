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
#include "netdev.h"
#include <sys/types.h>
/* #include <libiptc/libiptc.h> */

#include <errno.h>
extern int errno;

//#define HIP_HEADER_START 128 //bytes
#define BUFSIZE 2048

HIP_HASHTABLE *firewall_lsi_hit_db;

struct ipq_handle *h4 = NULL, *h6 = NULL;
int statefulFiltering = 1; 
int escrow_active = 0;
int bex_done = 0;
int use_ipv4 = 0;
int use_ipv6 = 0;
int accept_normal_traffic = 1;
int flush_iptables = 1;
pthread_t ipv4Thread, ipv6Thread;

int counter = 0;
int firewall_raw_sock_v6 = 0;

void print_usage()
{
	printf("HIP Firewall\n");
	printf("Usage: firewall [-f file_name] [-t timeout] [-d|-v] [-F|-H]\n");
	printf("      - H allow only HIP related traffic\n");
	printf("      - f file_name is a path to a file containing firewall filtering rules (default %s)\n", HIP_FW_DEFAULT_RULE_FILE);
	printf("      - timeout is connection timeout value in seconds\n");
	printf("      - d = debugging output\n");
	printf("      - v = verbose output\n");
	printf("      - t = timeout for packet capture (default %d secs)\n",
	       HIP_FW_DEFAULT_TIMEOUT);
	printf("      - F = do not flush iptables rules\n\n");
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

void set_bex_done(int done){
	bex_done = done;
}

int is_bex_done(){
	return bex_done;
}

/*----------------INIT/EXIT FUNCTIONS----------------------*/

int firewall_init(char *rule_file){

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

	read_file(rule_file);
	HIP_DEBUG("Firewall rule table: \n");
	print_rule_tables();
	//running test functions for rule handling
	//  test_parse_copy();
	//  test_rule_management();

	//HIP_DEBUG("starting up with rule_file: %s and connection timeout: %d\n", 
          //      rule_file, timeout);
	if (use_ipv4) {
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
		system("iptables -I OUTPUT -d 192.0.0.0/8 -j QUEUE");

#ifdef CONFIG_HIP_OPPTCP
		system("iptables -I FORWARD -p 6 -j QUEUE");
		system("iptables -I INPUT -p 6 -j QUEUE");
		system("iptables -I OUTPUT -p 6 -j QUEUE");
#endif

		if (!accept_normal_traffic) {
			system("iptables -I FORWARD -j DROP");
			system("iptables -I INPUT -j DROP");
			system("iptables -I OUTPUT -j DROP");
		}
	}
	if (use_ipv6) {
		system("ip6tables -I FORWARD -p 139 -j QUEUE");
		system("ip6tables -I FORWARD -p 50 -j QUEUE");
		
		system("ip6tables -I INPUT -p 139 -j QUEUE");
		system("ip6tables -I INPUT -p 50 -j QUEUE");
		
		system("ip6tables -I OUTPUT -p 139  -j QUEUE");
		system("ip6tables -I OUTPUT -p 50 -j QUEUE");

#ifdef CONFIG_HIP_OPPTCP
		system("ip6tables -I FORWARD -p 6 -j QUEUE");
		system("ip6tables -I INPUT -p 6 -j QUEUE");
		system("ip6tables -I OUTPUT -p 6 -j QUEUE");
#endif

		if (!accept_normal_traffic) {
			system("ip6tables -I FORWARD -j DROP");
			system("ip6tables -I INPUT -j DROP");
			system("ip6tables -I OUTPUT -j DROP");
		}
	}
	return 0;
}

void firewall_close(int signal){
	HIP_DEBUG("Closing firewall...\n");
	firewall_exit();
	exit(signal);
}

void hip_firewall_delete_hldb(void){
	int i;
	firewall_hl_t *this;
	hip_list_t *item, *tmp;
	
	HIP_DEBUG("Start hldb delete\n");
	HIP_LOCK_HT(&firewall_lsi_hit_db);

	list_for_each_safe(item, tmp, firewall_lsi_hit_db, i)
	{
		this = list_entry(item);
		hip_ht_delete(firewall_lsi_hit_db, this);
	}
	HIP_UNLOCK_HT(&firewall_lsi_hit_db);
	HIP_DEBUG("End hldbdb delete\n");
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
	hip_firewall_delete_hldb();
	if (firewall_raw_sock_v6)
		close(firewall_raw_sock_v6);
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
	if(packet->type_hdr == HIP_I1){
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

int is_hip_packet(void * hdr, int trafficType){
	struct udphdr *udphdr;
	int hdr_size;

	if(trafficType == 4){
		struct ip * iphdr = (struct ip *)hdr;
		HIP_DEBUG("Packet header type: %d\n",iphdr->ip_p);
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
*
*/
void allow_packet(struct ipq_handle *handle, unsigned long packetId){
	ipq_set_verdict(handle, packetId, NF_ACCEPT, 0, NULL);
	HIP_DEBUG("Packet accepted \n\n");
}


/**
*
*/
void drop_packet(struct ipq_handle *handle, unsigned long packetId){
	ipq_set_verdict(handle, packetId, NF_DROP, 0, NULL);
	HIP_DEBUG("Packet dropped \n\n");
}




/**
* Returns true if the packet direction is input
*/
int is_incoming_packet(unsigned int theHook){
	if(theHook == NF_IP_LOCAL_IN)
		return 1;
	return 0;
}


/**
* Returns true if the packet direction is output
*/
int is_outgoing_packet(unsigned int theHook){
	if(theHook == NF_IP_LOCAL_OUT)
		return 1;
	return 0;
}

#ifdef CONFIG_HIP_OPPTCP

/**
* checks for the i1 option in a packet
*/
int tcp_packet_has_i1_option(void * tcphdrBytes, int hdrLen){
	int i = 20, foundHipOpp = 0, len = 0;
	char *bytes =(char*)tcphdrBytes;
	//HIP_OPTION_KIND

	while((i < hdrLen) && (foundHipOpp == 0)){
		switch (bytes[i]) {
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
		case HIP_OPTION_KIND:	//hip option
			return 1;
		break;
		}
		//i++;
	}
	return foundHipOpp;
}


/**
*
*/
void examine_incoming_packet(struct ipq_handle *handle,
			     			 unsigned long      packetId,
			     			 void              *hdr,
			     			 int 				trafficType){
    int   i, optLen;
	int   hdr_size;
	int   optionsLen;
	char *hdrBytes = NULL;
	struct tcphdr *tcphdr;
	struct ip      *iphdr;
	struct ip6_hdr *ip6_hdr;
	//fields for temporary values
	u_int16_t portTemp;
	struct in_addr  addrTemp;
	struct in6_addr addr6Temp;

	if(trafficType == 4){
		iphdr = (struct ip *)hdr;
		//get the tcp header
		hdr_size = (iphdr->ip_hl * 4);
		tcphdr = ((struct tcphdr *) (((char *) iphdr) + hdr_size));
		hdrBytes = ((char *) iphdr) + hdr_size;
	}
	else if(trafficType == 6){
		ip6_hdr = (struct ip6_hdr *)hdr;
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

	//check that there are options
	if(tcphdr->doff == 5){	//no options
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

			//send packet out after adding HIT
			//no need to add i1 option, since
			//it is already in the received packet
			send_tcp_packet(hdr, hdr_size + 4*tcphdr->doff, trafficType, 0, 1);
			//drop original packet
			drop_packet(handle, packetId);
			return;
		}
		else{
			allow_packet(handle, packetId);
			return;
		}
	}
	else if((tcphdr->syn == 1) && (tcphdr->ack == 1)){	//incoming, syn=1 and ack=1
		allow_packet(handle, packetId);
		return;
	}
	//allow all the rest
	allow_packet(handle, packetId);
}


//###########################################################
void examine_outgoing_packet(struct ipq_handle *handle,
			     			 unsigned long      packetId,
			     			 void              *hdr,
			     			 int 				trafficType){
    int   i, optLen;
	int   hdr_size;
	int   optionsLen;
	char *hdrBytes = NULL;
	struct tcphdr *tcphdr;

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
	if(((tcphdr->syn == 1) && (tcphdr->ack == 0))){
		if(tcp_packet_has_i1_option(hdrBytes, 4*tcphdr->doff)){
			allow_packet(handle, packetId);
			return;
		}
		//add the option to the packet
		send_tcp_packet(hdr, hdr_size + 4*tcphdr->doff, trafficType, 1, 0);
		//drop original packet
		drop_packet(handle, packetId);
		return;
	}

	//allow all the rest
	allow_packet(handle, packetId);
}
#endif /* CONFIG_HIP_OPPTCP */


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
  	while (list != NULL)
    {
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

                          
        HIP_DEBUG_HIT("src hit: ", &buf->hits);
        HIP_DEBUG_HIT("dst hit: ", &buf->hitr);

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


/**
* function called by a thread that loops
* through either ipv4 or ipv6 packets
*/
static void *handle_ip_traffic(void *ptr) {
	int status, err;
	unsigned char buf[BUFSIZE];
	struct hip_esp *esp_data = NULL;
	struct hip_esp_packet *esp = NULL;
	struct hip_common *hip_common = NULL;
	struct in6_addr *src_addr = NULL;
	struct in6_addr *dst_addr = NULL;
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
      			HIP_DEBUG("IPQM PACKET Detected!!\n");
			ipq_packet_msg_t *m = ipq_get_packet(buf);
			packetHook = m->hook;

			if(ipv4Traffic){
                		iphdr = (struct ip *) m->payload; 
                		packet_hdr = (void *)iphdr;
                		hdr_size = (iphdr->ip_hl * 4);
				if (iphdr->ip_p == IPPROTO_UDP)
					hdr_size += sizeof(struct udphdr);
                		HIP_DEBUG("ipv4 and header size: %d\n", hdr_size);

				if(IS_LSI((iphdr->ip_dst).s_addr)){
					if(is_outgoing_packet(packetHook)){
		                		HIP_DEBUG("It's LSI and outgoing packet\n");
						firewall_trigger_outgoing_lsi(m, &iphdr->ip_src, &iphdr->ip_dst);
						drop_packet(hndl, m->packet_id);
						break;
					}else if(is_incoming_packet(packetHook)){
						HIP_DEBUG("It's LSI and incoming packet\n");
						firewall_trigger_incoming_lsi(m, &iphdr->ip_src, &iphdr->ip_dst);
					}
					//drop_packet(hndl, m->packet_id);
				}
				//break;
 	      		}
        		else if(ipv6Traffic){
                		_HIP_DEBUG("ipv6\n");
                		ip6_hdr = (struct ip6_hdr *) m->payload;   
                		packet_hdr = (void *)ip6_hdr;
               		 	hdr_size = sizeof(struct ip6_hdr);
               		 	_HIP_DEBUG("header size: %d\n", hdr_size);
                		ipv6_addr_copy(src_addr, &ip6_hdr->ip6_src);
                		ipv6_addr_copy(dst_addr, &ip6_hdr->ip6_dst);
        		}
      	
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

				//HIP_DUMP_MSG(hip_common);
				allow_packet(hndl, m->packet_id);//test

				/*if(filter_hip(src_addr, 
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
					}*/
      			} else {
				if((ipv4Traffic && iphdr->ip_p != IPPROTO_TCP) ||
				   (ipv6Traffic && ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt != IPPROTO_TCP)) {
					if(accept_normal_traffic)
						allow_packet(hndl, m->packet_id);
					else
						drop_packet(hndl, m->packet_id);
				} /* OPPORTUNISTIC MODE HACKS */ 
#ifdef CONFIG_HIP_OPPTCP
				else if(is_incoming_packet(packetHook))
					examine_incoming_packet(hndl, m->packet_id, packet_hdr, type);
				else if(is_outgoing_packet(packetHook))
					examine_outgoing_packet(hndl, m->packet_id, packet_hdr, type);
				else{
					if(accept_normal_traffic)
						allow_packet(hndl, m->packet_id);
					else
						drop_packet(hndl, m->packet_id);
				}
#endif /* CONFIG_HIP_OPPTCP */
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
	HIP_DEBUG("We are going out, this is finishing....\n");
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

	return;
}

int firewall_trigger_incoming_lsi(ipq_packet_msg_t *m, struct in_addr *ip_src, struct in_addr *ip_dst){
	int err = 0;
	return err;
}


int firewall_trigger_outgoing_lsi(ipq_packet_msg_t *m, struct in_addr *ip_src, struct in_addr *ip_dst){
	int err, msg_type;
	struct in6_addr dst_addr;
	struct in6_addr *src_hit = NULL, *dst_hit = NULL;
	firewall_hl_t *entry_peer = NULL;

	HIP_DEBUG("1. FIREWALL_TRIGGERING OUTGOING LSI %s\n",inet_ntoa(*ip_dst));
	IPV4_TO_IPV6_MAP(ip_dst, &dst_addr);


	//HIP_DEBUG("Before searching in the database firewall, how is the table???\n\n");
	//hip_firewall_hldb_dump();
	entry_peer = firewall_hit_lsi_db_match(ip_dst);

	if (entry_peer)
	        reinject_packet(entry_peer->hit_our, entry_peer->hit_peer, m);
	else{
	  	// Run bex to initialize SP and SA
		HIP_IFEL(hip_trigger_bex(&src_hit, &dst_hit, NULL, &dst_addr), -1, 
			 "Base Exchange Trigger failed");
		firewall_add_hit_lsi(src_hit, dst_hit, ip_dst);
		if (is_bex_done()){
			reinject_packet(*src_hit, *dst_hit, m);
			set_bex_done(0);
		}
	}
out_err: 
	return err;
}


unsigned char *create_ipv6_header(struct ip *old_ip4, struct sockaddr_in6 *src, struct sockaddr_in6 *dst)
{
	struct ip6_hdr *ip6_hdr = NULL;
	int err;
	
	HIP_DEBUG("Creating ip header\n");
	HIP_IFEL(!(ip6_hdr = (struct iphdr *) HIP_MALLOC(sizeof(struct iphdr),0)),
		 -ENOMEM, "No memory available for create ipv6 header\n");
	HIP_DEBUG("-----------Creating ip header\n");
	ip6_hdr->ip6_flow = 0; // zero the version (4), TC (8), flow-ID (20) 
	ip6_hdr->ip6_vfc = 0x60;
	//ip6_hdr->ip6_plen = htons(len);
	ip6_hdr->ip6_hlim = 255;

	ip6_hdr->ip6_src = src->sin6_addr;
	ip6_hdr->ip6_dst = dst->sin6_addr;
	HIP_DEBUG("---------***************--Creating ip header\n");
	if (old_ip4){
		ip6_hdr->ip6_flow |=  old_ip4->ip_tos << 24; 
		ip6_hdr->ip6_hlim = old_ip4->ip_ttl;		
		//ip6_hdr->ip6_nxt =  protocol;
	}
out_err: 
	return ((unsigned char *)ip6_hdr);
}


int reinject_packet(struct in6_addr src_hit, struct in6_addr dst_hit, ipq_packet_msg_t *m){
	int err = 0;
	int sa_size = sizeof(struct sockaddr_in6);	
	struct ip *iphdr = (struct ip *) m->payload;
	int hdr_size = (iphdr->ip_hl * 4);
	struct tcphdr *tcphdr = ((struct tcphdr *) (((char *) iphdr) + hdr_size));
	struct sockaddr_in6 sock6_src, sock6_dest;
	struct in6_addr any = IN6ADDR_ANY_INIT;
	//unsigned char *ip6_header;


	HIP_DEBUG_HIT("............................reinject_packet src_hit ",&src_hit);
	HIP_DEBUG_HIT("............................reinject_packet dst_hit ",&dst_hit);
	
	sock6_src.sin6_family = AF_INET6;
	sock6_src.sin6_port = htons(tcphdr->source);
	ipv6_addr_copy(&sock6_src.sin6_addr, &src_hit);

	sock6_dest.sin6_family = AF_INET6;
	sock6_dest.sin6_port = htons(tcphdr->dest);
	ipv6_addr_copy(&sock6_dest.sin6_addr, &dst_hit);
	
	//ip6_header = create_ipv6_header(iphdr, &sock6_src, &sock6_dest);
	//HIP_DEBUG("After creating ip header\n");
   
	////////////
	/*unsigned char *packet;
	int pkt_len = sizeof(struct ip6_hdr)+(sizeof(m)-sizeof(iphdr));
	packet = (unsigned char *)malloc(pkt_len);
	memcpy(packet, ip6_header, sizeof(struct ip6_hdr));
	memcpy(packet+sizeof(struct ip6_hdr), tcphdr, sizeof(m)-sizeof(struct ip6_hdr));*/
	///////////

	HIP_IFEL(bind(firewall_raw_sock_v6, (struct sockaddr *) &sock6_src, sa_size),
		 -1, "Binding to raw sock failed\n");
	
	HIP_IFEL(sendto(firewall_raw_sock_v6, &tcphdr, sizeof(tcphdr), 0,
			(struct sockaddr *) &sock6_dest, sa_size), 
			-1, "Sent with raw sock failed\n");
	
out_err:
	HIP_DEBUG("Sent with raw sock failed %s\n",strerror(errno));
	/* Reset the interface to wildcard*/	
	ipv6_addr_copy(&sock6_src.sin6_addr, &any);
	bind(firewall_raw_sock_v6, (struct sockaddr *) &sock6_src, sa_size);
	HIP_DEBUG("..............Packet reinjected..............\n");
	return err;
}


//----------------------------------FIREWALL DATABASE---------------------------------

/**
 * firewall_hit_lsi_db_match:
 * Search in the database the given lsi
 *
 * @param lsi_peer: entrance that we are searching in the db
 * @return NULL if not found and otherwise the firewall_hl_t structure
 */
firewall_hl_t *firewall_hit_lsi_db_match(hip_lsi_t *lsi_peer){
  //hip_firewall_hldb_dump();
  return (firewall_hl_t *)hip_ht_find(firewall_lsi_hit_db, (void *)lsi_peer);
  
}


firewall_hl_t *hip_create_hl_entry(void){
	firewall_hl_t *entry = NULL;
	int err = 0;
	HIP_IFEL(!(entry = (firewall_hl_t *) HIP_MALLOC(sizeof(firewall_hl_t),0)),
		 -ENOMEM, "No memory available for firewall database entry\n");
  	memset(entry, 0, sizeof(entry));
out_err:
	return entry;
}


void hip_firewall_hldb_dump(void)
{
	int i;
	firewall_hl_t *this;
	hip_list_t *item, *tmp;
	HIP_DEBUG("/////////////////////////////\n");
	HIP_DEBUG("//////  Firewall db  ///////\n");
	HIP_DEBUG("/////////////////////////////\n")
	HIP_LOCK_HT(&firewall_lsi_hit_db);

	list_for_each_safe(item, tmp, firewall_lsi_hit_db, i)
	{
		this = list_entry(item);
		HIP_DEBUG_HIT("Dump >>> hit_our", &this->hit_our);
		HIP_DEBUG_HIT("Dump >>> hit_peer", &this->hit_peer);
		HIP_DEBUG_LSI("Dump >>> lsi", &this->lsi);
		HIP_DEBUG("Dump >>> bex_state %d \n", this->bex_state);
	}
	HIP_UNLOCK_HT(&firewall_lsi_hit_db);
	HIP_DEBUG("end hldbdb dump\n");
}

int firewall_add_hit_lsi(struct in6_addr *hit_our, struct in6_addr *hit_peer, hip_lsi_t *lsi){
	int err = 0;
	firewall_hl_t *new_entry = NULL;

	HIP_ASSERT(hit_our != NULL && hit_peer != NULL && lsi != NULL);
	HIP_DEBUG("Start firewall_add_hit_lsi\n");
	
	new_entry = hip_create_hl_entry();
	ipv6_addr_copy(&new_entry->hit_our, hit_our);
	ipv6_addr_copy(&new_entry->hit_peer, hit_peer);
	ipv4_addr_copy(&new_entry->lsi, lsi);
	new_entry->bex_state = 0;
	HIP_DEBUG_HIT("1. entry to add to firewall_db hit_our ", &new_entry->hit_our);
	HIP_DEBUG_HIT("1. entry to add to firewall_db hit_peer ", &new_entry->hit_peer);
	HIP_DEBUG_LSI("1. entry to add to firewall_db lsi ", &new_entry->lsi);
	hip_ht_add(firewall_lsi_hit_db, new_entry);

out_err:
	//	hip_firewall_hldb_dump();
	HIP_DEBUG("End firewall_add_hit_lsi\n");
	return err;
}


/**
 * hip_firewall_hash_lsi:
 * Generates the hash information that is used to index the table
 *
 * @param ptr: pointer to the lsi used to make the hash
 *
 * @return hash information
 */
unsigned long hip_firewall_hash_lsi(const void *ptr){
        hip_lsi_t *lsi = &((firewall_hl_t *)ptr)->lsi;
	uint8_t hash[HIP_AH_SHA_LEN];     
	     
	hip_build_digest(HIP_DIGEST_SHA1, lsi, sizeof(*lsi), hash);     
	return *((unsigned long *)hash);
}

/**
 * hip_firewall_match_lsi:
 * Compares two LSIs
 *
 * @param ptr1: pointer to lsi
 * @param ptr2: pointer to lsi
 *
 * @return 0 if hashes identical, otherwise 1
 */
int hip_firewall_match_lsi(const void *ptr1, const void *ptr2){
	return (hip_firewall_hash_lsi(ptr1) != hip_firewall_hash_lsi(ptr2));
}

void firewall_init_hldb(void){
	firewall_lsi_hit_db = hip_ht_init(hip_firewall_hash_lsi, hip_firewall_match_lsi);
}

//----------------------------------END FIREWALL DATABASE SUPPORT---------------------------------


void check_and_write_default_config() {
	struct stat status;
	FILE *fp = NULL;
	ssize_t items;
	char *file = HIP_FW_DEFAULT_RULE_FILE;

	if (stat(file, &status) && errno == ENOENT) {
		errno = 0;
		fp = fopen(file, "w" /* mode */);
		HIP_ASSERT(fp);
		items = fwrite(HIP_FW_CONFIG_FILE_EX,
			       strlen(HIP_FW_CONFIG_FILE_EX), 1, fp);
		HIP_ASSERT(items > 0);
		fclose(fp);
	}
}

int firewall_init_raw_sock_v6()
{
	int on = 1, off = 0, err = 0;

	firewall_raw_sock_v6 = socket(AF_INET6, SOCK_RAW, IPPROTO_TCP);
	HIP_IFEL(firewall_raw_sock_v6 <= 0, 1, "Raw socket creation failed. Not root?\n");

	/* see bug id 212 why RECV_ERR is off */
	err = setsockopt(firewall_raw_sock_v6, IPPROTO_IPV6, IPV6_RECVERR, &off, sizeof(on));
	HIP_IFEL(err, -1, "setsockopt recverr failed\n");
	err = setsockopt(firewall_raw_sock_v6, IPPROTO_IPV6, IPV6_2292PKTINFO, &on, sizeof(on));
	HIP_IFEL(err, -1, "setsockopt pktinfo failed\n");
	err = setsockopt(firewall_raw_sock_v6, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	HIP_IFEL(err, -1, "setsockopt v6 reuseaddr failed\n");

 out_err:
	return err;
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
	char *traffic;
	extern char *optarg;
	extern int optind, optopt;
	int errflg = 0;
	const char *default_rule_file = HIP_FW_DEFAULT_RULE_FILE;
	char *rule_file = default_rule_file;
	

	check_and_write_default_config();

	hip_set_logdebug(LOGDEBUG_NONE);

	while ((ch = getopt(argc, argv, "f:t:vdFH")) != -1) {
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


	//use by default both ipv4 and ipv6
	HIP_DEBUG("Using ipv4 and ipv6\n");
	use_ipv4 = 1;
	use_ipv6 = 1;

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

	firewall_init(rule_file);
	firewall_init_hldb();

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
	firewall_init_raw_sock_v6();

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

  	firewall_exit();
  	return 0;
}

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
