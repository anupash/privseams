#ifndef FIREWALL_CONTROL_H_
#define FIREWALL_CONTROL_H_

#include <stdio.h>
#include <glib/gthread.h>
#include <sys/un.h>

#include "builder.h"
#include "protodefs.h"
#include "ipsec_userspace_api.h"

gpointer run_control_thread(gpointer data);
int control_thread_init(void);
int sendto_hipd(void *msg, size_t len);
int handle_msg(struct hip_common * msg, struct sockaddr_in6 * sock_addr);
int request_hipproxy_status(void);
extern int hip_proxy_status;
extern int hip_fw_sock;

#endif /*FIREWALL_CONTROL_H_*/
