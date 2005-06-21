#ifndef HIP_FIREWALL_H
#define HIP_FIREWALL_H

#include <netinet/in.h>
#include <linux/netfilter.h>
#include <libipq.h>
//#include "builder.h"
//#include <linux/ipv6.h>
//#include "debug.h"

void set_stateful_filtering(int v);
int get_stateful_filtering();

#endif

