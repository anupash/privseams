#ifndef _NET_HIP_GLUE_H
#define _NET_HIP_GLUE_H

#ifdef __KERNEL__

#include <linux/skbuff.h>

#include <net/ip.h>
#include <net/ipv6.h>
#include <net/sock.h>
#include <net/flow.h>
//#include <net/sadb.h>

#define HIP_CALLPROC(X) if(hip_functions.X) hip_functions.X
#define HIP_CALLFUNC(X,Y) (!hip_functions.X)?(Y):hip_functions.X
#define HIP_SETCALL(X) if(hip_functions.X) printk("hip: Warning, function assigned twice!\n"); \
                           hip_functions.X = X
#define HIP_INVALIDATE(X) hip_functions.X = NULL

struct hip_callable_functions {
	/* int (*hip_exchange) (struct sockaddr *uaddr, int addr_len); */

	void (*hip_handle_esp) (struct ipv6hdr *ipv6);
	int (*hip_handle_output) (struct ipv6hdr *hdr, struct sk_buff *skb);

	int (*hip_bypass_ipsec) (void);
	int (*hip_get_addr) (struct in6_addr *hit, struct in6_addr *addr);
	int (*hip_get_hits) (struct in6_addr *hitd, struct in6_addr *hits);

	int (*hip_get_saddr) (struct flowi *fl, struct in6_addr *hit_storage);

	int (*hip_inbound) (struct sk_buff **skb, unsigned int *nhoff);

	
	void (*hip_unknown_spi) (struct sk_buff *skb);
	void (*hip_handle_dst_unreachable) (struct sk_buff *skb);
	int (*hip_is_our_spi) (uint32_t spi, struct in6_addr *hit);
};

extern struct hip_callable_functions hip_functions;

#endif /* __KERNEL__ */

/* Returns true if addr is a HIT */
static inline int hip_is_hit(struct in6_addr *addr) 
{
	int bits;

	bits = addr->s6_addr[0] & 0xC0;

	if (bits == 0x80 || bits == 0x40)
		return 1;

	return 0;
}


#endif /* _NET_HIP_GLUE_H */
