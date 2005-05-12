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
//#include <linux/in6.h>
//#include <arpa/inet.h>
//#include <linux/ip.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
//#include <linux/ipv6.h>
#include <stdio.h>
#include <glib.h>
#include <glib/glist.h>
#include <string.h>
#include <net/hip.h>

#include "firewall.h"
#include "file_reader.h"
//#include "misc.h"
#include "debug.h"
#include "helpers.h"
#include "conntrack.h"


#define HIP_HEADER_START 128 //bytes

#define BUFSIZE 2048

struct GList * rules;
struct ipq_handle *h;

static void die(struct ipq_handle *h)
{
  HIP_DEBUG("dying\n");
  ipq_perror("passer");
  ipq_destroy_handle(h);
  exit(1);
}


/*
int is_hip_packet(char *buf)
{
  HIP_DEBUG("is hip packet\n");
  if(*buf == 0x3b)
    return 1;
  else
    return 0;
}
*/

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




int match_hit(struct in6_addr match_hit, struct in6_addr packet_hit, int boolean){
  int i = IN6_ARE_ADDR_EQUAL(&match_hit, &packet_hit);
  HIP_DEBUG("comparison %d\n ", i);
  if(boolean)
    return i;
  else 
    return !i;
  //  return boolean && IN6_ARE_ADDR_EQUAL(&match_hit, &packet_hit); 
}

int match_dst_hit(){
  return 0;
}

int match_packet_type(int match_type, int packet_type, int boolean){
  if(boolean)
    return match_type == packet_type;
  else
    return !(match_type == packet_type);
}

int filter_hi(/* packet */){
  //get hit from packet
  //find matching HI
  //verify signature

}


/*---- rules ----*/


//TODO print_rule


/* filter hip packet according to rues.
 * return verdict
 */
int filter_hip(const struct ip6_hdr * ip6_hdr, const struct hip_common *buf)
{
  struct _GList * list = (struct _GList *)rules;
  struct rule * rule = NULL;
  int match = 1; // is the packet still a potential match to current rule
  int temp = 0;
  while (list != NULL)
    {
      temp++;
      match = 1;
      rule = (struct rule *) list->data;
      if(rule->src_hit != NULL)
	{
	  //if match and no inverting
	  // return verdict false immediately 
	  if(!match_hit(rule->src_hit->value, 
			buf->hits, 
			rule->src_hit->boolean))
	    match = 0;	
	  HIP_DEBUG("rule src: %s, packet src: %s, %d, packet dst %s, %d, boolean: %d, match: %d\n",
		 addr_to_numeric(&rule->src_hit->value), 
		 addr_to_numeric(&buf->hits), &buf->hits, 
		 addr_to_numeric(&buf->hitr), &buf->hitr,
		 rule->src_hit->boolean,
		 match);
	}
      if(match && rule->dst_hit != NULL)
	{
	  //if match and no inverting
	  // return verdict false immediately 
	  //	  struct in6_addr * dst_hit = (struct in6_addr *)(buf->hits + 16);
	  if(!match_hit(rule->dst_hit->value, 
			buf->hitr, 
			rule->dst_hit->boolean))
	    /*	   
		  if(!match_hit(rule->dst_hit->value, 
		  *dst_hit, 
		  rule->dst_hit->boolean))
	    */
	    match = 0;	
	  HIP_DEBUG("rule dst: %s, packet dst: %s, %d, packet src %s, %d, boolean: %d, match: %d\n",
		 addr_to_numeric(&rule->dst_hit->value), 
		 addr_to_numeric(&buf->hitr), &buf->hitr,
		 addr_to_numeric(&buf->hits), &buf->hits,
		 rule->dst_hit->boolean,
		 match);
	  /*
	  HIP_DEBUG("rule dst: %s, packet dst: %s, packet src %s, boolean: %d, match: %d\n",
		 addr_to_numeric(&rule->dst_hit->value), 
		 addr_to_numeric(dst_hit), 
		 addr_to_numeric(&buf->hits), 
		 rule->dst_hit->boolean,
		 match);
		  */
	}
      if(match &&rule->type != NULL)
	{
	  if(!match_packet_type(rule->type->value, 
			buf->type_hdr, 
			rule->type->boolean))
	    /*	   
		  if(!match_hit(rule->dst_hit->value, 
		  *dst_hit, 
		  rule->dst_hit->boolean))
	    */
	    match = 0;	
	  HIP_DEBUG("rule type: %d, packet type: %d, boolean: %d, match: %d\n",
		 rule->type->value, 
		 buf->type_hdr,
		 rule->type->boolean,
		 match);
	  
	}
      //must be last, so accept argument is valid
      if(match && rule->state != NULL)
	{
	  filter_state(ip6_hdr, buf, rule->state, rule->accept);
	}
      // if a match, no need to cheack further rules
      if(match)
	return rule->accept;
      
      //while(rules)
      //  filter according to rule
      //  if drop, return verdict drop
      //return verdict accept
      list = list->next;
    }
  //  HIP_DEBUG("filtering hip packet: %d", hip_get_msg_total_len(buf));
  //TODO jos tila match
  /*    filter_state(buf);
  struct hip_data * data = get_hip_tuple(buf);
  struct connection * connection = get_connection_by_hip(data);
  if(!connection)
    {
      insert_new_connection(data);      
    }
  else
    {
      //  connection->state = CONN_ESTABLISHED;      
    }
  */
  //  filter_state(buf);
  return 1;
}



/*-------------*/

void print_rule_table(){
  struct _GList * list = (struct _GList *) rules;
  while(list != NULL)
    {
      struct rule * rule = (struct rule *)list->data;
      print_rule(rule);
      list = list->next;
    }
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
  get_rules(argv[1], &rules);
  temp_list = (struct _GList *)rules;
  HIP_DEBUG("printing rule table: \n");
  print_rule_table();
   
  //  hipList = NULL; 
  // espList = NULL; 
  //  GHashTable * hip_table = g_hash_table_new((*g_int_hash),
  //				    (*g_int_equal));

  HIP_DEBUG("starting up \n");
  
  h = ipq_create_handle(0, PF_INET6);
  if (!h)
    die(h);
  
  status = ipq_set_mode(h, IPQ_COPY_PACKET, BUFSIZE);
  if (status < 0)
    die(h);

  //TODO read rules from file
  //store into CHAIN structure(s)  
  

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
      HIP_DEBUG("Received packet\n");
      ipq_packet_msg_t *m = ipq_get_packet(buf);
      ip6_hdr = (struct ip6_hdr *) m->payload; 
      
      //  HIP_HEXDUMP("packet", buf+HIP_HEADER_START, 100);

      //      HIP_DEBUG("Setting verdict to packet\n");
      if(is_hip_packet(ip6_hdr)){
	//	struct iphdr *ip = (struct iphdr*) m->payload;
	struct hip_common *hip_common = (struct hip_common*) (ip6_hdr + 
							      sizeof (struct ip6_hdr)); 
	  //(m->payload + (4 * ip->ihl));

	hc_ptr = memcpy(&hc, (buf+HIP_HEADER_START), sizeof(struct hip_common));
	memcpy(&hc.hits, (buf+HIP_HEADER_START+8), sizeof(struct in6_addr));
	memcpy(&hc.hitr, (buf+HIP_HEADER_START+8+16), sizeof(struct in6_addr));
	// HIP_HEXDUMP("packet ", (struct hip_common *)m, 150); //TODO ruma
	HIP_DEBUG("hip_common src %s, %d, dst %s, %d \n", 
	       addr_to_numeric(&hc.hits), &hc.hits,
	       addr_to_numeric(&hc.hitr), &hc.hitr);
	
	//	struct sk_buff * skb = (struct sk_buff *)m->payload;
	//	struct hip_common * hip_common = (struct hip_common*) skb->h.raw;
	HIP_DEBUG("main: src addr: %s, dst_addr %s\n", 
	       addr_to_numeric(&ip6_hdr->ip6_src), 
	       addr_to_numeric(&ip6_hdr->ip6_dst));
	if(filter_hip(ip6_hdr, (struct hip_common *) (buf + HIP_HEADER_START)))
	  status = ipq_set_verdict(h, m->packet_id,
				   NF_ACCEPT, 0, NULL);
	HIP_DEBUG("packet accepted\n");
	
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

	      HIP_DEBUG("packet accepted, spi %d\n", spi_val); 
	    }
	}
      else{
	status = ipq_set_verdict(h, m->packet_id,
				 NF_ACCEPT, 0, NULL);
	HIP_DEBUG("packet \"dropped\"\n");	
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
