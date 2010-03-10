#ifndef HIP_HIPD_HIPD_H
#define HIP_HIPD_HIPD_H

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

#include "config.h"
#include "lib/core/crypto.h"
#include "cookie.h"
#include "user.h"
#include "lib/core/debug.h"
#include "netdev.h"
#include "lib/conf/hipconf.h"
#include "nat.h"
#include "init.h"
#include "hidb.h"
#include "maintenance.h"
#include "accessor.h" /* @todo: header recursion: accessor.h calls hipd.h */
#include "lib/core/message.h"
#include "lib/core/esp_prot_common.h"

#define HIP_HIT_DEV "dummy0"

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
 * the actual time is between n and n + RETRANSMIT_INIT seconds */
#define HIP_RETRANSMIT_WAIT 10

#define HIP_R1_PRECREATE_INTERVAL 60 * 60 /* seconds */
#define HIP_R1_PRECREATE_INIT (HIP_R1_PRECREATE_INTERVAL / HIP_SELECT_TIMEOUT)
#define OPENDHT_REFRESH_INTERVAL 30 /* seconds Original 60 using 1 with sockaddrs */
#define OPENDHT_REFRESH_INIT (OPENDHT_REFRESH_INTERVAL / HIP_SELECT_TIMEOUT)

#define QUEUE_CHECK_INTERVAL 15 /* seconds */
#define QUEUE_CHECK_INIT (QUEUE_CHECK_INTERVAL / HIP_SELECT_TIMEOUT)

#define CERTIFICATE_PUBLISH_INTERVAL 120 /* seconds */
#define HIP_HA_PURGE_TIMEOUT 5

/* How many duplicates to send simultaneously: 1 means no duplicates */
#define HIP_PACKET_DUPLICATES                1
/* Set to 1 if you want to simulate lost output packet */
#define HIP_SIMULATE_PACKET_LOSS             1
/* Packet loss probability in percents */
#define HIP_SIMULATE_PACKET_LOSS_PROBABILITY 0
#define HIP_SIMULATE_PACKET_IS_LOST() (random() < ((uint64_t) HIP_SIMULATE_PACKET_LOSS_PROBABILITY * RAND_MAX) / 100)

#define HIP_NETLINK_TALK_ACK 0 /* see netlink_talk */

#define HIP_ADDRESS_CHANGE_WAIT_INTERVAL 6 /* seconds */
#define HIP_ADDRESS_CHANGE_HB_COUNT_TRIGGER 2

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

extern int address_change_time_counter;

extern int hip_wait_addr_changes_to_stabilize;

extern int hip_user_sock;

extern int hip_firewall_sock, hip_firewall_status;
extern struct sockaddr_in6 hip_firewall_addr;

extern int hit_db_lock;
extern int is_active_mhaddr;
extern int is_hard_handover;

extern int hip_shotgun_status;

extern int hip_encrypt_i2_hi;

extern struct addrinfo *opendht_serving_gateway;

extern hip_transform_suite_t hip_nat_status;

extern int hip_use_userspace_data_packet_mode;

extern int hip_buddies_inuse;

extern int esp_prot_active;
extern int esp_prot_num_transforms;
extern long esp_prot_num_parallel_hchains;

extern int hip_trigger_update_on_heart_beat_failure;

extern int hip_locator_status;
extern int hip_transform_order;

extern int suppress_af_family;
extern int address_count;
extern HIP_HASHTABLE *addresses;

extern uint8_t esp_prot_transforms[MAX_NUM_TRANSFORMS];

int hip_firewall_is_alive(void);

/* Functions for handling incoming packets. */
int hip_sock_recv_firewall(void);
//Merge-may int hip_sendto_firewall(const struct hip_common *msg, size_t len);

//int hip_sendto(const struct hip_common *msg, const struct sockaddr_in6 *dst);

void hip_set_opportunistic_tcp_status(struct hip_common *msg);
int hip_get_opportunistic_tcp_status(void);

/* Functions for handling outgoing packets. */
int hip_sendto_firewall(const struct hip_common *msg);

#define IPV4_HDR_SIZE 20

#endif /* HIP_HIPD_HIPD_H */
