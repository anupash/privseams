#ifndef __NAT_H__
#define __NAT_H__
#define HIP_MAX_LENGTH_UDP_PACKET 2000
#include "hip.h"
#include "workqueue.h"
#include "debug.h"
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <netdb.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>

extern int hip_raw_sock_udp;

int hip_read_control_msg_udp(int socket, struct hip_common *hip_msg,
                         int read_addr, struct in6_addr *saddr,
                         struct in6_addr *daddr);

int hip_send_udp(struct in6_addr *local_addr,
                  struct in6_addr *peer_addr,
		  uint32_t src_port, uint32_t dst_port,
                  struct hip_common* msg,
                  hip_ha_t *entry,
                  int retransmit);

int hip_receive_control_packet_udp(struct hip_common *msg,
                               struct in6_addr *src_addr,
                               struct in6_addr *dst_addr,
                                struct hip_stateless_info *info);


#endif //__NAT_H__

