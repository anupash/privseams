#ifndef HIPD_H
#define HIPD_H

#include <signal.h>     /* signal() */
#include <stdio.h>      /* stderr and others */
#include <errno.h>      /* errno */
#include <unistd.h>
#include <fcntl.h>
#include <linux/netlink.h>      /* get_my_addresses() support   */
#include <linux/rtnetlink.h>    /* get_my_addresses() support   */

#include "hip.h"
#include "crypto.h"
#include "cookie.h"
#include "workqueue.h"
//#include "debug.h"
#include "netdev.h"
#ifdef CONFIG_HIP_HI3
#include "i3_client_api.h"
#endif

extern struct hip_nl_handle nl_khipd;
extern time_t load_time;

#endif /* HIPD_H */
