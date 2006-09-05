/*
 * This code is GPL.
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

struct ipq_handle *h = NULL;
int statefulFiltering = 1; 


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

/*-------------PACKET FILTERING FUNCTIONS------------------*/
int match_hit(struct in6_addr match_hit, 
	      struct in6_addr packet_hit, 
	      int boolean){
  int i = IN6_ARE_ADDR_EQUAL(&match_hit, &packet_hit);
  HIP_DEBUG("match_hit: hit: %s bool: %d match: %d\n", 
	    addr_to_numeric(&match_hit), boolean, i);
  if (!i)
  	HIP_DEBUG("No match\n");	    
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
      HIP_DEBUG("match_hi: I1\n");
    return 1;
    }
  value = verify_packet_signature(hi, packet);
  if(value == 0)
    HIP_DEBUG("match_hi: verify ok\n");
  else
    HIP_DEBUG("match_hi: verify failed\n");
  if(value == 0)
    return 1;
  return 0;
}

int match_int(int match, int packet, int boolean)
{
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


static void die(struct ipq_handle *h)
{
  HIP_DEBUG("dying\n");
  ipq_perror("passer");
  ipq_destroy_handle(h);
  exit(1);
}

int is_hip_packet(const struct ip6_hdr * ip6_hdr)
{
  if(ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_HIP)
    return 1;
  else
    return 0;
}

int is_esp_packet(const struct ip6_hdr * ip6_hdr)
{

 if(ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt == 50)
    return 1;
  else
    return 0;
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

  HIP_DEBUG("filter_esp:\n");
  while (list != NULL)
    {
      match = 1;
      rule = (struct rule *) list->data;
      _HIP_DEBUG("   filter_esp: checking for:\n");     
      print_rule(rule);

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
	    if(!filter_esp_state(dst_addr, esp, rule))//rule->state, rule->accept))
	      match = 0;
	    _HIP_DEBUG("filter_esp: state, rule %d, boolean %d match %d\n", 
		      rule->state->int_opt.value,
		      rule->state->int_opt.boolean, 
		      match);
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
      HIP_DEBUG("filter_esp: packet matched rule, target %d\n", rule->accept);
      ret_val = rule->accept; 
    }
  else
    ret_val = 1; 
  //release rule list
  read_rules_exit(0);
  //return the target of the the matched rule or true if no rule matched
  return ret_val; 
}



/* filter hip packet according to rules.
 * return verdict
 */
int filter_hip(const struct ip6_hdr * ip6_hdr, 
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
  HIP_DEBUG("filter_hip: \n");
  while (list != NULL)
    {
      match = 1;
      rule = (struct rule *) list->data;
      _HIP_DEBUG("   filter_hip: checking for \n");     
      print_rule(rule);

      if(match && rule->src_hit)
	  {
	    _HIP_DEBUG("filter_hip: src_hit ");
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
	    _HIP_DEBUG("filter_hip: dst_hit \n");
	    if(!match_hit(rule->dst_hit->value, 
			  buf->hitr, 
			  rule->dst_hit->boolean))
	      match = 0;	
	  }
      if(match && rule->type)
	  {
	    _HIP_DEBUG("filter_hip: type ");
	    if(!match_int(rule->type->value, 
			  buf->type_hdr, 
			  rule->type->boolean))
	      match = 0;	
	    _HIP_DEBUG("filter_hip: type rule: %d, packet: %d, boolean: %d, match: %d\n",
		      rule->type->value, 
		      buf->type_hdr,
		      rule->type->boolean,
		      match);
	    
	  }      
      if(match && rule->in_if)
	  {
	    if(!match_string(rule->in_if->value, in_if, rule->in_if->boolean))
	      match = 0;
	    _HIP_DEBUG("filter_hip: in_if rule: %s, packet: %s, boolean: %d, match: %d \n",
		      rule->in_if->value, 
		      in_if, rule->in_if->boolean, match);
	  }
      if(match && rule->out_if)
	  {
	    if(!match_string(rule->out_if->value, 
			     out_if, 
			     rule->out_if->boolean))
	      match = 0;
	    _HIP_DEBUG("filter_hip: out_if rule: %s, packet: %s, boolean: %d, match: %d \n",
		      rule->out_if->value, out_if, rule->out_if->boolean, match);
	  }
	
	//must be last, so not called if packet is going to be dropped
      if(match && rule->state)
	  {
	    if(!filter_state(ip6_hdr, buf, rule->state, rule->accept))
	      match = 0;
	    else
	      conntracked = 1;
	    _HIP_DEBUG("filter_hip: state, rule %d, boolean %d match %d\n", 
		      rule->state->int_opt.value,
		      rule->state->int_opt.boolean, 
		      match);
	  }
	// if a match, no need to check further rules
	if(match){
	  _HIP_DEBUG("filter_hip: match found\n");
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
    ret_val = 1; 
  //release rule list
  read_rules_exit(0);
  // if packet will be accepted and connection tracking is used
  // but the packet has not been analysed by the conntrack module
  // show the packet to conntracking
  if(statefulFiltering && ret_val && !conntracked){
    conntrack(ip6_hdr, buf);
  }
  //return the target of the the matched rule
  return ret_val; 
}



int main(int argc, char **argv)
{
  int status;
  long int timeout;
  unsigned char buf[BUFSIZE];
  struct rule * rule = NULL;
  struct _GList * temp_list = NULL;
  struct hip_common hc;
  struct hip_common * hc_ptr;
  if(argc != 3)
    {
      printf("Firewall usage: firewall <file_name> <timeout>, where file_name is a path to a file containing firewall filtering rules and timeout is connection timeout value in seconds. Invalid argument count. Closing. \n");
      return 1;
    }
  
  read_file(argv[1]);
  HIP_DEBUG("Firewall rule table: \n");
  print_rule_tables();
  //running test functions for rule handling
  //  test_parse_copy();
  //  test_rule_management();

  timeout = atol(argv[2]);
  HIP_DEBUG("starting up with rule_file: %s and connection timeout: %d\n", 
	    argv[1], timeout);
  
  h = ipq_create_handle(0, PF_INET6);
  if (!h)
    die(h);
  
  status = ipq_set_mode(h, IPQ_COPY_PACKET, BUFSIZE);
  if (status < 0)
    die(h);


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

  do{
    status = ipq_read(h, buf, BUFSIZE, 0);
    if (status < 0)
      die(h);
    
    switch (ipq_message_type(buf)) {
    case NLMSG_ERROR:
      fprintf(stderr, "Received error message %d\n", ipq_get_msgerr(buf));
      break;
      
    case IPQM_PACKET: {
      
      struct ip6_hdr * ip6_hdr = NULL;
      ipq_packet_msg_t *m = ipq_get_packet(buf);
      ip6_hdr = (struct ip6_hdr *) m->payload; 
      
      if(is_hip_packet(ip6_hdr)){
      HIP_DEBUG("****** Received HIP packet ******\n");
	struct hip_common * hip_common = (struct hip_common*) (m->payload + 
       							      sizeof (struct ip6_hdr));
			
	struct hip_sig * sig = NULL;
	sig = (struct hip_sig *) hip_get_param(hip_common, HIP_PARAM_HIP_SIGNATURE);
	if(sig == NULL)
	  _HIP_DEBUG("no signature\n");
	else
	  _HIP_DEBUG("signature exists\n");

	if(filter_hip(ip6_hdr, 
		      hip_common, 
		      m->hook,
		      m->indev_name,
		      m->outdev_name))
	  {
	    status = ipq_set_verdict(h, m->packet_id,
				     NF_ACCEPT, 0, NULL);
	    HIP_DEBUG("packet accepted\n");
	  }
	else
	  {
	    status = ipq_set_verdict(h, m->packet_id,
				     NF_DROP, 0, NULL);
	    HIP_DEBUG("packet dropped\n");
	  }
      } 
      else if (is_esp_packet(ip6_hdr))
	{
	  HIP_DEBUG("****** Received ESP packet ******\n");
	  uint32_t spi_temp;
	  uint32_t spi_val;
	  struct hip_esp * esp_data;
	  
	  struct hip_esp_packet * esp = 
	  	(struct hip_esp_packet *)malloc(sizeof(struct hip_esp_packet));
	  esp->packet_length = 0;
	  esp->esp_data = NULL;
	  if (m->data_len <= (BUFSIZE - sizeof(struct ip6_hdr))){
	  	esp->packet_length = m->data_len - sizeof (struct ip6_hdr); 	
	  	HIP_DEBUG("Packet size smaller than buffer size\n");
	  }
	  else { 
	  	esp->packet_length = BUFSIZE - sizeof(struct ip6_hdr);	
	 
	  	HIP_DEBUG("Packet size greater than buffer size\n");
	  }
	  //esp_data = (struct hip_esp *)malloc(esp->packet_length);
	  //memcpy(esp_data, m->payload + sizeof (struct ip6_hdr), esp->packet_length);
	  //esp->esp_data = esp_data;
	  esp->esp_data = m->payload + sizeof (struct ip6_hdr);
	  //esp->esp_tail = NULL;
	  memcpy(&spi_temp, 
		 (m->payload + sizeof (struct ip6_hdr)), 
		 sizeof(__u32));
	  spi_val = ntohl(spi_temp);	 
	  
	  spi_temp = esp->esp_data->esp_spi;
	   
	  _HIP_DEBUG("spi_temp %d, spi_val %d, spi_val2 %d\n", spi_temp, spi_val, ntohl(spi_temp));
	 _HIP_HEXDUMP("ESP packet data: \n", esp->esp_data, esp->packet_length);
	  if(filter_esp(&ip6_hdr->ip6_dst, 
			esp,
			m->hook,
			m->indev_name,
			m->outdev_name))
	    {
	      status = ipq_set_verdict(h, m->packet_id,
				       NF_ACCEPT, 0, NULL);
	      HIP_DEBUG("esp packet accepted \n"); 
	    }
	  else
	    {
	      status = ipq_set_verdict(h, m->packet_id,
				       NF_DROP, 0, NULL);
	      HIP_DEBUG("esp packet dropped \n"); 
	    }
	    if (esp) {
	    	/*if (esp_data) {
	    		esp->esp_data = NULL;
	    		free(esp_data);
	    	}*/
	    	free(esp);
	    }
	}
      else{
	HIP_DEBUG("****** Received Unknown packet ******\n");
      	status = ipq_set_verdict(h, m->packet_id,
				 NF_DROP, 0, NULL);
	HIP_DEBUG("packet dropped \n");	
      }
      if (status < 0)
	die(h);
      break;
    }
    default:
      HIP_DEBUG("unknown msg\n");
      fprintf(stderr, "Unknown message type!\n");
      break;
    }
  } while (1);
  
  ipq_destroy_handle(h);
  return 0;
}
