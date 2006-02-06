#ifndef HIPD_H
#define HIPD_H

#include <signal.h>     /* signal() */
#include <stdio.h>      /* stderr and others */
#include <errno.h>      /* errno */
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <time.h>

#include "hip.h"
#include "crypto.h"
#include "cookie.h"
#include "workqueue.h"
#include "debug.h"
#include "netdev.h"
#include "hipconf.h"

#include <linux/netlink.h>      /* get_my_addresses() support   */
#include <linux/rtnetlink.h>    /* get_my_addresses() support   */
#include <sys/un.h>

#ifdef CONFIG_HIP_HI3
#include "i3_client_api.h"
#endif

#define HIP_HIT_DEV "dummy0"

#ifdef CONFIG_HIP_HI3
#define HIPD_SELECT(a,b,c,d,e) cl_select(a,b,c,d,e)
#else
#define HIPD_SELECT(a,b,c,d,e) select(a,b,c,d,e)
#endif



extern struct rtnl_handle hip_nl_route;
extern struct rtnl_handle hip_nl_ipsec;
extern time_t load_time;

int hip_agent_is_alive();
int hip_agent_filter(struct hip_common *msg);

#define IPV4_HDR_SIZE 20

#define HIT_SIZE 16

#endif /* HIPD_H */
