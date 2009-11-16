#ifndef HIPD_H
#define HIPD_H

#include <signal.h>		/* signal() */
#include <stdio.h>		/* stderr and others */
#include <errno.h>		/* errno */
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <time.h>
#include <stdint.h>
#ifndef ANDROID_CHANGES
#include <sys/un.h>
#endif
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
#include "message.h"
#include "esp_prot_common.h"

#define HIPL_VERSION 1.0
#define HIP_HIT_DEV "dummy0"
#define HIPD_SELECT(a,b,c,d,e) select(a,b,c,d,e)

#define HIP_SELECT_TIMEOUT        1
#define HIP_RETRANSMIT_MAX        5
#define HIP_RETRANSMIT_INTERVAL   1 /* seconds */
#define HIP_OPP_WAIT              5 /* seconds */
#define HIP_OPP_FALLBACK_INTERVAL 1 /* seconds */
#define HIP_OPP_FALLBACK_INIT	(HIP_OPP_FALLBACK_INTERVAL / HIP_SELECT_TIMEOUT)
/* the interval with which the hadb entries are checked for retransmissions */
#define HIP_RETRANSMIT_INIT		(HIP_RETRANSMIT_INTERVAL / HIP_SELECT_TIMEOUT)
/* wait about n seconds before retransmitting.
   the actual time is between n and n + RETRANSMIT_INIT seconds */
#define HIP_RETRANSMIT_WAIT 10
 
#define HIP_R1_PRECREATE_INTERVAL 60*60 /* seconds */
#define HIP_R1_PRECREATE_INIT	(HIP_R1_PRECREATE_INTERVAL / HIP_SELECT_TIMEOUT)

#define QUEUE_CHECK_INTERVAL 15 /* seconds */
#define QUEUE_CHECK_INIT		(QUEUE_CHECK_INTERVAL / HIP_SELECT_TIMEOUT)

#define CERTIFICATE_PUBLISH_INTERVAL 120 /* seconds */
#define HIP_HA_PURGE_TIMEOUT 5

/* How many duplicates to send simultaneously: 1 means no duplicates */
#define HIP_PACKET_DUPLICATES		1
/* Set to 1 if you want to simulate lost output packet */
#define HIP_SIMULATE_PACKET_LOSS	1
 /* Packet loss probability in percents */
#define HIP_SIMULATE_PACKET_LOSS_PROBABILITY 0
#define HIP_SIMULATE_PACKET_IS_LOST() \
(random() < ((uint64_t) HIP_SIMULATE_PACKET_LOSS_PROBABILITY * RAND_MAX) / 100)

#define HIP_NETLINK_TALK_ACK 0 /* see netlink_talk */

#define HIPD_NL_GROUP 32

extern struct rtnl_handle hip_nl_route;
extern struct rtnl_handle hip_nl_ipsec;
extern struct rtnl_handle hip_nl_generic;
extern time_t load_time;

extern int hip_raw_sock_input_v6;
extern int hip_raw_sock_input_v4;
extern int hip_nat_sock_input_udp;

extern int hip_raw_sock_output_v6;
extern int hip_raw_sock_output_v4;
extern int hip_nat_sock_output_udp;

extern int hip_nat_sock_output_udp_v6;
extern int hip_nat_sock_input_udp_v6;

extern int hip_user_sock;

extern int hip_firewall_sock, hip_firewall_status;
extern struct sockaddr_in6 hip_firewall_addr;

extern int hit_db_lock ;
extern int is_active_mhaddr;
extern int is_hard_handover;

int hip_firewall_is_alive();

/* Functions for handling incoming packets. */
int hip_sock_recv_firewall(void);
//Merge-may int hip_sendto_firewall(const struct hip_common *msg, size_t len);

//int hip_sendto(const struct hip_common *msg, const struct sockaddr_in6 *dst);

/* Functions for handling outgoing packets. */
int hip_sendto_firewall(const struct hip_common *msg);

#define IPV4_HDR_SIZE 20

#define HIT_SIZE 16

#endif /* HIPD_H */
