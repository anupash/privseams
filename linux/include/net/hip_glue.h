#ifndef _NET_HIP_GLUE_H
#define _NET_HIP_GLUE_H

#ifdef __KERNEL__

#include <linux/skbuff.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/sock.h>
#include <net/flow.h>

#define HIP_CALLPROC(X) if(hip_functions.X) hip_functions.X
#define HIP_CALLFUNC(X,Y) (!hip_functions.X)?(Y):hip_functions.X
#define HIP_SETCALL(X) if(hip_functions.X) printk("hip: Warning, function assigned twice!\n"); \
                           hip_functions.X = X
#define HIP_INVALIDATE(X) hip_functions.X = NULL

struct hip_callable_functions {
	/* int (*hip_exchange) (struct sockaddr *uaddr, int addr_len); */
	void (*hip_handle_esp) (uint32_t spi, struct ipv6hdr *ipv6);
	int (*hip_handle_output) (struct ipv6hdr *hdr, struct sk_buff *skb);
	int (*hip_get_addr) (struct in6_addr *hit, struct in6_addr *addr);
	int (*hip_get_saddr) (struct flowi *fl, struct in6_addr *hit_storage);
	void (*hip_unknown_spi) (struct sk_buff *skb, uint32_t spi);
	void (*hip_handle_ipv6_dad_completed)(int ifindex);
	void (*hip_handle_inet6_addr_del)(int ifindex);
	uint32_t (*hip_get_default_spi_out) (struct in6_addr *hit, int *state_ok);
	int (*hip_hit_is_our) (struct in6_addr *hit);
};

extern struct hip_callable_functions hip_functions;

#endif /* __KERNEL__ */

#endif /* _NET_HIP_GLUE_H */
