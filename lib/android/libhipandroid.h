
#ifndef LIBHIPANDROID_H
#define LIBHIPANDROID_H

#ifdef ANDROID_CHANGES

typedef unsigned int  in_port_t;

#ifndef if_nameindex
struct if_nameindex
  {
    unsigned int if_index;      /* 1, 2, ... */
    char *if_name;              /* null terminated name: "eth0", ... */
  };
#endif

extern const struct in6_addr in6addr_loopback;   /* ::1 */

#define __THROW

#define INET_ADDRSTRLEN 16

#define IN6ADDR_ANY_INIT { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 } } }

/* From OpenBSD libc */
/* For lockf implementation */
#define F_ULOCK         0       /* unlock locked section */
#define F_LOCK          1       /* lock a section for exclusive use */
#define F_TLOCK         2       /* test and lock a section for exclusive use */
#define F_TEST          3       /* test a section for locks by other procs */

#include <sys/types.h>
#include <linux/in6.h>
#include <linux/coda.h>
#include <linux/icmp.h>
#include <netinet/in6.h>
#include <netinet/in.h>
#include "icmp6.h"
#include "ifaddrs.h"

#define ip6_vfc   ip6_ctlun.ip6_un2_vfc
#define ip6_flow  ip6_ctlun.ip6_un1.ip6_un1_flow
#define ip6_plen  ip6_ctlun.ip6_un1.ip6_un1_plen
#define ip6_nxt   ip6_ctlun.ip6_un1.ip6_un1_nxt
#define ip6_hlim  ip6_ctlun.ip6_un1.ip6_un1_hlim
#define ip6_hops  ip6_ctlun.ip6_un1.ip6_un1_hlim

#define icmp6hdr icmp6_hdr
#define icmp6_checksum icmp6_cksum
#define icmp6_identifier icmp6_id
#define icmp6_sequence icmp6_seq
#define ICMPV6_ECHO_REQUEST ICMP6_ECHO_REQUEST
#define ICMPV6_ECHO_REPLY ICMP6_ECHO_REPLY

#ifndef in6_pktinfo
/* IPv6 packet information.  */
struct in6_pktinfo
{
  struct in6_addr     ipi6_addr;    /* src/dst IPv6 address */
  unsigned int        ipi6_ifindex; /* send/recv interface index */
};
#endif

#endif /* ANDROID_CHANGES */
#endif /* LIBHIPANDROID_H */
