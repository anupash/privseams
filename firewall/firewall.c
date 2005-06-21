/*
 * This code is GPL.
 * Compile: gcc `pkg-config --cflags --libs glib-2.0` -D CONFIG_HIP_DEBUG  debug.c builder.c misc.c helpers.c file_reader.c conntrack.c firewall.c -o firewall /usr/lib/libipq.a
 * modprobe ip6_queue
 * ip6tables -A FORWARD -m hip -j QUEUE
 * (ip6tables -A INPUT -p 99 -j QUEUE)
 * 
 */

/*
  2 threads for receiving packets from ipq (4 and 6)
  serialized packet handling with locking

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
#define BUFSIZE 2048 //TODO mistä

struct ipq_handle *h;
int statefulFiltering = 1; 

//currently done at all times, rule_management 
//delete rule needs checking for state options in 
//all chains
void set_stateful_filtering(int v)
{
  statefulFiltering = 1;
  /////TODO  statefulFiltering = v;
}
int get_stateful_filtering()
{
  return statefulFiltering;
}

/*-------------PACKET FILTERING FUNCTIONS------------------*/
int match_hit(struct in6_addr match_hit, struct in6_addr packet_hit, int boolean){
  int i = IN6_ARE_ADDR_EQUAL(&match_hit, &packet_hit);
  HIP_DEBUG("match_hit: rule: %s packet: %s, bool: %d comparison %d\n ", 
	    addr_to_numeric(&match_hit), 
	    addr_to_numeric(&packet_hit),
	    boolean,
	    i);
  if(boolean)
    return i;
  else 
    return !i;
}

//inspects host identity by verifying sender signature
int match_hi(struct hip_host_id * hi, 
	     struct hip_common * packet){
  int value = 0;
  
  if(packet->type_hdr == HIP_I1)
    {
      HIP_DEBUG("match_hi: I1\n");
    return 1;
    }
  value = verify_packet_signature(hi, packet);
  HIP_DEBUG("match_hi: verify returned %d", value);
  return value;
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

int is_hip_packet(struct ip6_hdr * ip6_hdr)
{
  if(ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt == 99)
    return 1;
  else
    return 0;
}

int is_esp_packet(struct ip6_hdr * ip6_hdr)
{
  if(ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt == 50)
    return 1;
  else
    return 0;
}

/* filter hip packet according to rues.
 * return verdict
 */
int filter_hip(struct ip6_hdr * ip6_hdr, 
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
  while (list != NULL)
    {
      match = 1;
      rule = (struct rule *) list->data;
      /////      if(rule->hook == hook){
	if(match && rule->src_hit != NULL)
	  {
	    HIP_DEBUG("filter_hip: src_hit ");
	    if(!match_hit(rule->src_hit->value, 
			  buf->hits, 
			  rule->src_hit->boolean))
	      match = 0;	
	    /*	    HIP_DEBUG("rule src: %s, packet src: %s, %d, packet dst %s, %d, boolean: %d, match: %d\n",
		      addr_to_numeric(&rule->src_hit->value), 
		      addr_to_numeric(&buf->hits), &buf->hits, 
		      addr_to_numeric(&buf->hitr), &buf->hitr,
		      rule->src_hit->boolean,
		      match);
	    */
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
	    /*
	    HIP_DEBUG("rule dst: %s, packet dst: %s, %d, packet src %s, %d, boolean: %d, match: %d\n",
		      addr_to_numeric(&rule->dst_hit->value), 
		      addr_to_numeric(&buf->hitr), &buf->hitr,
		      addr_to_numeric(&buf->hits), &buf->hits,
		      rule->dst_hit->boolean,
		      match);
	    */
	  }
	if(match &&rule->type != NULL)
	  {
	    HIP_DEBUG("filter_hip: type ");
	    if(!match_int(rule->type->value, 
			  buf->type_hdr, 
			  rule->type->boolean))
	      match = 0;	
	    HIP_DEBUG("rule type: %d, packet type: %d, boolean: %d, match: %d\n",
		      rule->type->value, 
		      buf->type_hdr,
		      rule->type->boolean,
		 match);
	    
	  }      
	if(match && rule->in_if != NULL)
	  {
	    if(!match_string(rule->in_if->value, in_if, rule->in_if->boolean))
	      match = 0;
	    HIP_DEBUG("filter_hip: match in_if rule: %s, packet: %s, match: %d \n",
		      rule->in_if->value, in_if, match);
	  }
	if(match && rule->out_if != NULL)
	  {
	    if(!match_string(rule->out_if->value, 
			     out_if, 
			     rule->out_if->boolean))
	      match = 0;
	    HIP_DEBUG("filter_hip: match out_if rule: %s, packet: %s, match: %d \n",
		      rule->out_if->value, out_if, match);
	  }
	
	//must be last, so not called if packet is going to be dropped
	if(match && rule->state != NULL)
	  {
	    conntracked = 1;
	    HIP_DEBUG("filter_hip: state ");
	    filter_state(ip6_hdr, buf, rule->state, rule->accept);
	  }
	// if a match, no need to check further rules
	if(match){
	  HIP_DEBUG("filter_hip: match found\n");
	  break;
 	}
	/////}
      list = list->next;
    }
  //release rule list
  if(rule && match)
    {
      HIP_DEBUG("filter_hip:packet matched rule, target %d\n", rule->accept);
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
  unsigned char buf[BUFSIZE];
  struct rule * rule = NULL;
  struct _GList * temp_list = NULL;
  struct hip_common hc;
  struct hip_common * hc_ptr;
  if(argc != 2)
    {
      printf("Invalid argument count. Closing. \n");
      return 1;
    }
  read_file(argv[1]);
  HIP_DEBUG("rules read, statefulFiltering %d printing rule table: \n", 
	    statefulFiltering);
  print_rule_tables();
  test_parse_copy();
  test_rule_management();
   
  HIP_DEBUG("starting up \n");
  
  h = ipq_create_handle(0, PF_INET6);
  if (!h)
    die(h);
  
  status = ipq_set_mode(h, IPQ_COPY_PACKET, BUFSIZE);
  if (status < 0)
    die(h);

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
      HIP_DEBUG("*****Received packet******\n");
      ipq_packet_msg_t *m = ipq_get_packet(buf);
      ip6_hdr = (struct ip6_hdr *) m->payload; 
      
      if(is_hip_packet(ip6_hdr)){
	struct hip_common * hip_common = (struct hip_common*) (m->payload + 
       							      sizeof (struct ip6_hdr));
	//	struct hip_common * hip_common2 = hip_common;
	//	struct hip_common * hip_common3 = hip_common2;
	
	//	HIP_DEBUG("main: src addr: %s, dst_addr %s\n", 
	//     addr_to_numeric(&ip6_hdr->ip6_src), 
	//     addr_to_numeric(&ip6_hdr->ip6_dst));
	if(filter_hip(ip6_hdr, 
		      hip_common, //(struct hip_common *) (buf + HIP_HEADER_START),
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
	  //TODO prettier way to get spi
	  uint32_t spi_val;
	  memcpy(&spi_val, 
		 (m->payload + sizeof (struct ip6_hdr)), 
		 sizeof(__u32));
	  if(filter_esp_packet(&ip6_hdr->ip6_dst, spi_val))
	    {
	      status = ipq_set_verdict(h, m->packet_id,
				       NF_ACCEPT, 0, NULL);

	      HIP_DEBUG("esppacket accepted, spi %d\n", spi_val); 
	    }
	  else
	    {
	      status = ipq_set_verdict(h, m->packet_id,
				       NF_DROP, 0, NULL);

	      HIP_DEBUG("esp packet dropped, spi %d\n", spi_val); 
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
