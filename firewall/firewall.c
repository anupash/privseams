/*
 * This code is GPL.
 * Compile: gcc `pkg-config --cflags --libs glib-2.0` -D CONFIG_HIP_DEBUG  debug.c builder.c misc.c helpers.c file_reader.c conntrack.c firewall.c -o firewall /usr/lib/libipq.a
 * modprobe ip6_queue
 * ip6tables -A FORWARD -m hip -j QUEUE
 * (ip6tables -A INPUT -p 99 -j QUEUE)
 * 
 */

#include <linux/netfilter.h>
#include <libipq/libipq.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <stdio.h>
#include <glib.h>
#include <glib/glist.h>
#include <string.h>
#include <net/hip.h>

#include "firewall.h"
#include "rule_management.h"
#include "debug.h"
#include "helpers.h"
#include "conntrack.h"


//#define HIP_HEADER_START 128 //bytes
#define BUFSIZE 2048

struct ipq_handle *h;
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
int match_hit(struct in6_addr match_hit, struct in6_addr packet_hit, int boolean){
  int i = IN6_ARE_ADDR_EQUAL(&match_hit, &packet_hit);
  HIP_DEBUG("match_hit: hit: %s bool: %d match: %d\n", 
	    addr_to_numeric(&match_hit), boolean, i);
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


static void die(struct ipq_handle *h)
{
  HIP_DEBUG("dying\n");
  ipq_perror("passer");
  ipq_destroy_handle(h);
  exit(1);
}

int is_hip_packet(const struct ip6_hdr * ip6_hdr)
{
  if(ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt == 99)
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
  HIP_DEBUG("filter_hip: \n");
  while (list != NULL)
    {
      match = 1;
      rule = (struct rule *) list->data;
      HIP_DEBUG("   filter_hip: checking for \n");     
      print_rule(rule);
      /////      if(rule->hook == hook){
	if(match && rule->src_hit != NULL)
	  {
	    HIP_DEBUG("filter_hip: src_hit ");
	    if(!match_hit(rule->src_hit->value, 
			  buf->hits, 
			  rule->src_hit->boolean))
	      match = 0;	
	    //if HIT has matched and HI defined, verify signature 
	    if(match && rule->src_hi != NULL)
	      {
		HIP_DEBUG("filter_hip: src_hi \n");
		if(!match_hi(rule->src_hi, buf))
		  match = 0;	
	      }
	  }
	if(match && rule->dst_hit != NULL)
	  {
	    HIP_DEBUG("filter_hip: dst_hit \n");
	    if(!match_hit(rule->dst_hit->value, 
			  buf->hitr, 
			  rule->dst_hit->boolean))
	      match = 0;	
	  }
	if(match && rule->type != NULL)
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
	if(match && rule->in_if != NULL)
	  {
	    if(!match_string(rule->in_if->value, in_if, rule->in_if->boolean))
	      match = 0;
	    HIP_DEBUG("filter_hip: in_if rule: %s, packet: %s, boolean: %d, match: %d \n",
		      rule->in_if->value, 
		      in_if, rule->in_if->boolean, match);
	  }
	if(match && rule->out_if != NULL)
	  {
	    if(!match_string(rule->out_if->value, 
			     out_if, 
			     rule->out_if->boolean))
	      match = 0;
	    HIP_DEBUG("filter_hip: out_if rule: %s, packet: %s, boolean: %d, match: %d \n",
		      rule->out_if->value, out_if, rule->out_if->boolean, match);
	  }
	
	//must be last, so not called if packet is going to be dropped
	if(match && rule->state != NULL)
	  {
	    conntracked = 1;
	    if(!filter_state(ip6_hdr, buf, rule->state, rule->accept))
	       match = 0;
	    HIP_DEBUG("filter_hip: state, rule %d, boolean %d match %d\n", 
		      rule->state->int_opt.value,
		      rule->state->int_opt.boolean, 
		      match);
	  }
	// if a match, no need to check further rules
	if(match){
	  _HIP_DEBUG("filter_hip: match found\n");
	  break;
 	}
	/////}
      list = list->next;
    }
  //release rule list
  if(rule && match)
    {
      HIP_DEBUG("filter_hip: packet matched rule, target %d\n", rule->accept);
      ret_val = rule->accept; 
    }
  else
    ret_val = 1; 
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
      //TODO print usage
      printf("Firewall usage: firewall <file_name> <timeout>, where file_name is a path to a file containing firewall filtering rules and timeout is connection timeout value in seconds. Invalid argument count. Closing. \n");
      return 1;
    }
  
  read_file(argv[1]);
  HIP_DEBUG("Firewall rule table: \n");
  print_rule_tables();
  //test functions for rule handling
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

  init_timeout_checking(timeout);

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
      HIP_DEBUG("****** Received packet ******\n");
      ipq_packet_msg_t *m = ipq_get_packet(buf);
      ip6_hdr = (struct ip6_hdr *) m->payload; 
      
      if(is_hip_packet(ip6_hdr)){
	struct hip_common * hip_common = (struct hip_common*) (m->payload + 
       							      sizeof (struct ip6_hdr));
		
	struct hip_sig * sig = NULL;
	sig = hip_get_param(hip_common, HIP_PARAM_HIP_SIGNATURE);
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
	  uint32_t spi_val;
	  memcpy(&spi_val, 
		 (m->payload + sizeof (struct ip6_hdr)), 
		 sizeof(__u32));
	  if(filter_esp_packet(&ip6_hdr->ip6_dst, spi_val))
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
	}
      else{
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
