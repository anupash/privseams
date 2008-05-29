#ifndef FIREWALL_CONTROL_H_
#define FIREWALL_CONTROL_H_

#include <stdio.h>
#include <glib/gthread.h>
#include <sys/un.h>
#include <errno.h>
#include <stddef.h>
#include <sys/socket.h>

#include "builder.h"
#include "protodefs.h"
#include "firewalldb.h"
#include "ipsec_userspace_api.h"

typedef struct pseudo_v6 {
       struct  in6_addr src;
        struct in6_addr dst;
        u16 length;
        u16 zero1;
        u8 zero2;
        u8 next;
} pseudo_v6;

struct prseuheader
{
	unsigned long s_addr;
	unsigned long d_addr;
	unsigned char zero;
	unsigned char prototp;
	unsigned short len;
};

gpointer run_control_thread(gpointer data);
int control_thread_init(void);
int sendto_hipd(void *msg, size_t len);
int handle_msg(struct hip_common * msg, struct sockaddr_in6 * sock_addr);
int firewall_init_raw_sock_v6();
int request_hipproxy_status(void);
extern int hip_proxy_status;
extern int hip_fw_sock;

#endif /*FIREWALL_CONTROL_H_*/
