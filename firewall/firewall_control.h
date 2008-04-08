#ifndef FIREWALL_CONTROL_H_
#define FIREWALL_CONTROL_H_

#include <stdio.h>
#include <glib/gthread.h>
#include <sys/un.h>

#include "builder.h"
#include "protodefs.h"

gpointer run_control_thread(gpointer data);
int control_thread_init(void);
int sendto_hipd(void *msg, size_t len);
int handle_msg(struct hip_common * msg, struct sockaddr_in6 * sock_addr);
int firewall_init_raw_sock_v6();

#endif /*FIREWALL_CONTROL_H_*/
