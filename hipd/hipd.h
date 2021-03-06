/*
 * Copyright (c) 2010 Aalto University and RWTH Aachen University.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef HIP_HIPD_HIPD_H
#define HIP_HIPD_HIPD_H

#include <netdb.h>
#include <stdint.h>
#include <netinet/in.h>
#include <sys/types.h>

#include "lib/core/hashtable.h"
#include "lib/core/protodefs.h"
#include "lib/tool/nlink.h"


#define HIP_HIT_DEV "dummy0"

#define HIP_DEFAULT_HI_ALGO       HIP_HI_ECDSA
#define HIP_MODULE_SIGNALING      1

#define HIP_SELECT_TIMEOUT        1
#define HIP_RETRANSMIT_MAX        5
#define HIP_RETRANSMIT_INTERVAL   1 /* seconds */
/* the interval with which the hadb entries are checked for retransmissions */
#define HIP_RETRANSMIT_INIT \
    (HIP_RETRANSMIT_INTERVAL / HIP_SELECT_TIMEOUT)
/* wait about n seconds before retransmitting.
 * the actual time is between n and n + RETRANSMIT_INIT seconds */
#define HIP_RETRANSMIT_WAIT 10

#define HIP_R1_PRECREATE_INTERVAL 60 * 60 /* seconds */
#define HIP_R1_PRECREATE_INIT (HIP_R1_PRECREATE_INTERVAL / HIP_SELECT_TIMEOUT)

#define QUEUE_CHECK_INTERVAL 15 /* seconds */
#define QUEUE_CHECK_INIT (QUEUE_CHECK_INTERVAL / HIP_SELECT_TIMEOUT)

#define CERTIFICATE_PUBLISH_INTERVAL 120 /* seconds */
#define HIP_HA_PURGE_TIMEOUT 5

#define HIP_ADDRESS_CHANGE_WAIT_INTERVAL 3 /* seconds */

extern struct rtnl_handle hip_nl_route;
extern struct rtnl_handle hip_nl_ipsec;
extern struct rtnl_handle hip_nl_generic;

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

extern struct sockaddr_in6 hip_firewall_addr;

extern int hit_db_lock;

extern int hip_shotgun_status;

extern int hip_broadcast_status;

extern int hip_encrypt_i2_hi;

extern hip_transform_suite hip_nat_status;

extern int  esp_prot_active;
extern int  esp_prot_num_transforms;
extern long esp_prot_num_parallel_hchains;

extern int hip_locator_status;
extern int hip_transform_order;

extern int            suppress_af_family;
extern int            address_count;
extern HIP_HASHTABLE *addresses;

/* For switch userspace / kernel IPsec */
extern int hip_use_userspace_ipsec;

/* Functions for handling incoming packets. */
int hip_sock_recv_firewall(void);

/* Functions for handling outgoing packets. */
int hip_sendto_firewall(const struct hip_common *msg);

int hipd_parse_cmdline_opts(int argc, char *argv[], uint64_t * flags);
int hipd_main(uint64_t flags);

#endif /* HIP_HIPD_HIPD_H */
