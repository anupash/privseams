#ifndef HIPD_H
#define HIPD_H

#include <signal.h>     /* signal() */
#include <stdio.h>      /* stderr and others */
#include <errno.h>      /* errno */
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <time.h>
#include <stdint.h>
#include <sys/un.h>
#include <netinet/udp.h>
#include <sys/socket.h>

#include "crypto.h"
#include "cookie.h"
#include "user.h"
#include "debug.h"
#include "netdev.h"
#include "hipconf.h"
#include "nat.h"
#include "init.h"
#include "hidb.h"
#include "maintenance.h"
#include "accessor.h"

#ifdef CONFIG_HIP_HI3
#include "i3_client_api.h"
#endif

#ifdef CONFIG_HIP_BLIND
#include "blind.h"
#endif

#define HIPL_VERSION 1.0

#define HIP_HIT_DEV "dummy0"

#ifdef CONFIG_HIP_HI3
#  define HIPD_SELECT(a,b,c,d,e) cl_select(a,b,c,d,e)
#else
#  define HIPD_SELECT(a,b,c,d,e) select(a,b,c,d,e)
#endif

#define HIP_SELECT_TIMEOUT        1
#define HIP_RETRANSMIT_MAX        5
#define HIP_RETRANSMIT_INTERVAL   1 /* seconds */
#define HIP_OPP_WAIT              5 /* seconds */
#define HIP_OPP_FALLBACK_INTERVAL 1 /* seconds */
#define HIP_OPP_FALLBACK_INIT \
           (HIP_OPP_FALLBACK_INTERVAL / HIP_SELECT_TIMEOUT)
/* the interval with which the hadb entries are checked for retransmissions */
#define HIP_RETRANSMIT_INIT \
           (HIP_RETRANSMIT_INTERVAL / HIP_SELECT_TIMEOUT)
/* wait about n seconds before retransmitting.
   the actual time is between n and n + RETRANSMIT_INIT seconds */
#define HIP_RETRANSMIT_WAIT 10
 
#define HIP_R1_PRECREATE_INTERVAL 60*60 /* seconds */
#define HIP_R1_PRECREATE_INIT \
           (HIP_R1_PRECREATE_INTERVAL / HIP_SELECT_TIMEOUT)
#define OPENDHT_REFRESH_INTERVAL 60 /* seconds Original 60 using 1 with sockaddrs */
#define OPENDHT_REFRESH_INIT \
           (OPENDHT_REFRESH_INTERVAL / HIP_SELECT_TIMEOUT)

/* How many duplicates to send simultaneously: 1 means no duplicates */
#define HIP_PACKET_DUPLICATES                1
/* Set to 1 if you want to simulate lost output packet */
#define HIP_SIMULATE_PACKET_LOSS             1
 /* Packet loss probability in percents */
#define HIP_SIMULATE_PACKET_LOSS_PROBABILITY 0
#define HIP_SIMULATE_PACKET_IS_LOST() (random() < ((uint64_t) HIP_SIMULATE_PACKET_LOSS_PROBABILITY * RAND_MAX) / 100)

#define HIP_NETLINK_TALK_ACK 0 /* see netlink_talk */

extern struct rtnl_handle hip_nl_route;
extern struct rtnl_handle hip_nl_ipsec;
extern time_t load_time;

extern int hip_raw_sock_v6;
extern int hip_raw_sock_v4;
extern int hip_nat_sock_udp;
extern int hip_nat_sock_udp_data;

extern int hip_user_sock;
extern int hip_agent_sock, hip_agent_status;
extern struct sockaddr_un hip_agent_addr;

extern int hip_firewall_sock, hip_firewall_status;
extern struct sockaddr_in6 hip_firewall_addr;


extern int is_active_handover;

int hip_agent_is_alive();

int hip_firewall_is_alive();
int hip_firewall_add_escrow_data(hip_ha_t *entry, struct in6_addr * hit_s, 
        struct in6_addr * hit_r, struct hip_keys *keys);
int hip_firewall_remove_escrow_data(struct in6_addr *addr, uint32_t spi);

/* Functions for handling incoming packets. */
int hip_sock_recv_agent(void);
int hip_sock_recv_firewall(void);


#define IPV4_HDR_SIZE 20


#define HIT_SIZE 16

#endif /* HIPD_H */
