#ifndef __NAT_H__
#define __NAT_H__

#define HIP_MAX_LENGTH_UDP_PACKET 2000
#define HIP_NAT_KEEP_ALIVE_TIME 5


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

extern int hip_nat_sock_udp;
extern int hip_nat_status;

int hip_nat_on(struct hip_common *msg);
int hip_nat_off(struct hip_common *msg);
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

int hip_nat_keep_alive();
int hip_handle_keep_alive(hip_ha_t *entry, void *not_used);
int hip_set_nat_off_sa(hip_ha_t *entry, void *not_used);
int hip_set_nat_on_sa(hip_ha_t *entry, void *not_used);
#endif //__NAT_H__

