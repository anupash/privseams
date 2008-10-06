#ifndef HIP_LSI_H
#define HIP_LSI_H

#include <libipq.h>
#include "firewalldb.h"
#include "debug.h"
#include "ife.h"

int is_packet_reinjection(struct in_addr *ip_src);

int hip_fw_handle_incoming_hit(ipq_packet_msg_t *m, struct in6_addr *ip_src, struct in6_addr *ip_dst);

int hip_fw_handle_outgoing_lsi(ipq_packet_msg_t *m, struct in_addr *ip_src, struct in_addr *ip_dst);

int reinject_packet(struct in6_addr src_hit, struct in6_addr dst_hit, ipq_packet_msg_t *m, int ipOrigTraffic, int incoming);

#endif



/*
#define HIP_STATE_NONE                   0
#define HIP_STATE_UNASSOCIATED           1
#define HIP_STATE_I1_SENT                2
#define HIP_STATE_I2_SENT                3
#define HIP_STATE_R2_SENT                4
#define HIP_STATE_ESTABLISHED            5
#define HIP_STATE_FAILED                 7
#define HIP_STATE_CLOSING                8
#define HIP_STATE_CLOSED                 9
*/
