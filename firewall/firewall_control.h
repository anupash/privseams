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

gpointer run_control_thread(gpointer data);
int control_thread_init(void);
int sendto_hipd(void *msg, size_t len);
int handle_msg(struct hip_common * msg, struct sockaddr_in6 * sock_addr);
int firewall_init_raw_sock_v6();

#endif /*FIREWALL_CONTROL_H_*/
