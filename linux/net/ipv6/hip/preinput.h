#ifndef HIP_PREINPUT_H
#define HIP_PREINPUT_H

#ifdef __KERNEL__
#include <linux/ipv6.h> /* struct ipv6hdr */
#include <linux/skbuff.h> /* struct sk_buff */
#include <linux/types.h>
#endif

#include <net/hip.h>
#include "debug.h"
#include "workqueue.h"
#if defined CONFIG_HIP_HI3 && !defined __KERNEL__
#include "i3.h"
#include "i3_client_api.h"
#include "i3_client_id.h"

struct hi3_ipv4_addr {
	u8 sin_family;
	struct in_addr sin_addr;
};

struct hi3_ipv6_addr {
	u8 sin6_family;
	struct in6_addr sin6_addr;
};
#endif

#ifndef __KERNEL__
struct pseudo_header6
{
        unsigned char src_addr[16];
        unsigned char dst_addr[16];
        u32 packet_length;
        char zero[3];
        u8 next_hdr;
};

struct pseudo_header
{
        unsigned char src_addr[4];
        unsigned char dst_addr[4];
        u8 zero;
        u8 protocol;
        u16 packet_length;
};
#endif

#ifdef __KERNEL__  
void hip_handle_esp(uint32_t spi, struct ipv6hdr *hdr);
int hip_inbound(struct sk_buff **skb, unsigned int *nhoff);
#else
#ifdef CONFIG_HIP_HI3
void hip_inbound(cl_trigger *t, void *data, void *ctx);
#endif
u16 checksum_packet(char *data, struct sockaddr *src, struct sockaddr *dst);
#endif

#endif /* HIP_PREINPUT_H */
