#ifndef HIPD_H
#define HIPD_H

#include <signal.h>     /* signal() */
#include <stdio.h>      /* stderr and others */
#include <errno.h>      /* errno */
#include <unistd.h>
#include <fcntl.h>

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

extern struct rtnl_handle nl_ifaddr;
extern struct rtnl_handle nl_route_only;
extern time_t load_time;

#endif /* HIPD_H */
