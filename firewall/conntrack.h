#ifndef CONNTRACK_H
#define CONNTRACK_H

#include <netinet/in.h>
//#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/hip.h>
#include "firewall.h"
#include "rule_management.h"
//#include "hip.h"
/*-------------- CONNECTION TRACKING ------------*/

enum{
  ORIGINAL_DIR,
  REPLY_DIR,
    };

enum{
  STATE_NEW,
  STATE_ESTABLISHED,
  STATE_ESTABLISHING_FROM_UPDATE
};

/*state table structures*/
struct match {
  struct in6_addr src_hit;
  struct in6_addr dst_hit;
  int type;
  int state;
};

struct esp_tuple{
  uint32_t spi;
  //TODO make a set of addresses
  struct in6_addr dst_addr;
  struct tuple * tuple;
  //TODO int verified;
};

struct hip_data{
  struct in6_addr src_hit;
  struct in6_addr dst_hit;
  struct hip_host_id * src_hi;
  int (*verify)(struct hip_host_id *, struct hip_common *);
};

struct hip_tuple {
  struct hip_data * data;
  struct tuple * tuple;
};


struct tuple {
  struct hip_tuple * hip_tuple;
  struct GSList * esp_tuples;
  int direction;
  struct connection * connection;
  int state; //state the in which the sender party of this tuple is
};

struct connection {
  struct tuple original;
  struct tuple reply;  
  int state; //state for filtering
  int hip_state; //hip protocol state
};
/*--------------  CONNECTION TRACKING ------------*/

//TODO some init module function necessary?
void print_data(struct hip_data * data);
//struct hip_data * get_hip_tuple(const struct hip_common * buf);
//struct tuple * get_tuple_by_hip(struct hip_data * data);
//void insert_new_connection(struct hip_data * data);
int filter_esp_packet(const struct in6_addr * dst_addr, uint32_t spi);
int filter_state(struct ip6_hdr * ip6_hdr, 
		 struct hip_common * buf, 
		 struct state_option * rule, 
		 int);
void conntrack(struct ip6_hdr * ip6_hdr, 
	       struct hip_common * buf);
int verify_packet_signature(struct hip_host_id * hi, 
			    struct hip_common * common);
#endif
