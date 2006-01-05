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

#define IPV4_TO_IPV6_MAP(in_addr_from, in6_addr_to)                    \
         {(in6_addr_to)->s6_addr32[0] = 0;                               \
          (in6_addr_to)->s6_addr32[1] = 0;                                \
          (in6_addr_to)->s6_addr32[2] = htonl(0xffff);                    \
         (in6_addr_to)->s6_addr32[3] = (uint32_t) (in_addr_from);}

#define IPV6_TO_IPV4_MAP(in6_addr_from,in_addr_to)    \
       { ((uint32_t *) in_addr_to)[0] =                        \
         (uint32_t *) (in6_addr_from)->s6_addr32[3]; }

#define IPV6_EQ_IPV4(in6_addr_a,in_addr_b)   \
       ( IN6_IS_ADDR_V4MAPPED(in6_addr_a) && \
	((in6_addr_a)->s6_addr32[3] == (in_addr_b).s_addr)) 
//#define REMOVE_IPV4_HEADER(hip_msg)		\
//	(uint8_t *)hip_msg+=20;
#define IPV4_HDR_SIZE 20

#define HIT_SIZE 16
#define HIT2LSI(a) ( 0x01000000L | \
                     (((a)[HIT_SIZE-3]<<16)+((a)[HIT_SIZE-2]<<8)+((a)[HIT_SIZE-1])))

#define IS_LSI32(a) ((a & 0xFF) == 0x01)

#define HIT_IS_LSI(a) \
        ((((__const uint32_t *) (a))[0] == 0)                                 \
         && (((__const uint32_t *) (a))[1] == 0)                              \
         && (((__const uint32_t *) (a))[2] == 0)                              \
         && (((__const uint32_t *) (a))[3] != 0))                              

#endif /* HIPD_H */
