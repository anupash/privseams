#ifndef CONNTRACK_H
#define CONNTRACK_H

#include <netinet/in.h>
//#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/hip.h>
#include "firewall.h"
//#include "hip.h"
/*-------------- CONNECTION TRACKING ------------*/

enum{
  ORIGINAL_DIR,
  REPLY_DIR,
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
};

struct hip_data{
  struct in6_addr src_hit;
  struct in6_addr dst_hit;
  struct hip_host_id * src_hi;
  struct hip_host_id * dst_hi;
};

struct hip_tuple {
  struct hip_data * data;
  struct tuple * tuple;
};


struct tuple {
  struct hip_tuple * hip_tuple;
  struct esp_tuple * esp_tuple;
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
int filter_state(const struct ip6_hdr * ip6_hdr, 
		 const struct hip_common * buf, 
		 const struct int_option * rule, 
		 int);
#endif
