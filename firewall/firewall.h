#ifndef HIP_FIREWALL_H
#define HIP_FIREWALL_H

#include <netinet/in.h>
#include <linux/netfilter.h>
#include <libipq/libipq.h>

//made public for filter_esp_state function
int match_hit(struct in6_addr match_hit, 
	      struct in6_addr packet_hit, 
	      int boolean);
void set_stateful_filtering(int v);
int get_stateful_filtering();

#endif

