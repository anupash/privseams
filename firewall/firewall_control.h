#ifndef FIREWALL_CONTROL_H_
#define FIREWALL_CONTROL_H_

#include <stdio.h>
#include <glib/gthread.h>
#include <sys/un.h>

//#include "state.h"
//#include "user.h"
#include "builder.h"
#include "protodefs.h"
//#include "rule_management.h"
//#include "debug.h"


gpointer run_control_thread(gpointer data);
int control_thread_init(void);
int sendto_hipd(void *msg, size_t len);
int handle_msg(struct hip_common * msg, struct sockaddr_un * sock_addr);

#endif /*FIREWALL_CONTROL_H_*/
