#ifndef FIREWALL_CONTROL_H_
#define FIREWALL_CONTROL_H_

#include <stdio.h>
#include <glib/gthread.h>
#include <sys/un.h>

#include <errno.h>
#include <stddef.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <linux/icmpv6.h>

#include "builder.h"
#include "protodefs.h"
#include "firewalldb.h"

typedef struct pseudo_v6 {
       struct  in6_addr src;
        struct in6_addr dst;
        u16 length;
        u16 zero1;
        u8 zero2;
        u8 next;
} pseudo_v6;

gpointer run_control_thread(gpointer data);
int control_thread_init(void);
int sendto_hipd(void *msg, size_t len);
int handle_msg(struct hip_common * msg, struct sockaddr_in6 * sock_addr);
int firewall_init_raw_sock_v6();

#endif /*FIREWALL_CONTROL_H_*/
