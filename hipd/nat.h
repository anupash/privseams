#ifndef __NAT_H__
#define __NAT_H__
#define HIP_MAX_LENGTH_UDP_PACKET 2000
#include "workqueue.h"
#include "netlink.h"
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <netdb.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>


//int hip_receive_udp(struct hip_nl_handle *nl, hip_filter_t handler, void *arg);
//int hip_send_udp(struct in6_addr *src_addr, struct in6_addr *peer_addr, struct hip_common* buf, int buf_len);

#endif //__NAT_H__

