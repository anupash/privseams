#ifndef _HIP_NLINK_H
#define _HIP_NLINK_H

#include <stdio.h>
#include <stdint.h>
#include <net/if.h>
#include <netinet/in.h>

#include "builder.h"
#include "debug.h"
#include "xfrm.h"

/* Keep this one as the last to avoid some weird compilation problems */
#include <linux/netlink.h>

struct pseudo_hdr{
	u32 s_addr;
	u32 d_addr;
	u8  zer0;
	u8  protocol;
	u16 length;
};

struct pseudo6_hdr{
	struct in6_addr s_addr;
	struct in6_addr d_addr;
	u8  zer0;
	u8  protocol;
	u16 length;
};

/* New one to prevent netlink overrun */
#if 0
#define HIP_MAX_NETLINK_PACKET 3072
#endif
#define HIP_MAX_NETLINK_PACKET 65537

#ifndef  SOL_NETLINK
#  define  SOL_NETLINK 270
#endif

#ifndef  NETLINK_ADD_MEMBERSHIP
#  define  NETLINK_ADD_MEMBERSHIP 1
#endif

#ifndef  NETLINK_DROP_MEMBERSHIP
#  define  NETLINK_DROP_MEMBERSHIP 2
#endif

#define PREFIXLEN_SPECIFIED 1

#define NLMSG_TAIL(nmsg) \
	((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

#define HIP_OPTION_KIND 30

/* 1280 required for userspace ipsec, LSIs and
   bandwith-consuming apps (see bug id 451) */
#define HIP_DEFAULT_MTU 1280

struct netdev_address {
  //hip_list_t next;
	struct sockaddr_storage addr;
	int if_index;
        unsigned char secret[40];
        time_t timestamp;
	int flags;
};

struct idxmap
{
        struct idxmap * next;
        unsigned        index;
        int             type;
        int             alen;
        unsigned        flags;
        unsigned char   addr[8];
        char            name[16];
};

typedef struct
{
        __u8 family;
        __u8 bytelen;
        __s16 bitlen;
        __u32 flags;
        __u32 data[4];
} inet_prefix;

struct rtnl_handle
{
        int                     fd;
        struct sockaddr_nl      local;
        struct sockaddr_nl      peer;
        __u32                   seq;
        __u32                   dump;
};

/* Workaround: in6_pktinfo does not compile on Fedora and Ubuntu anymore.
   This works also with CentOS */
struct inet6_pktinfo {
	struct in6_addr ipi6_addr;
	unsigned int ipi6_ifindex;
};

typedef int (*hip_filter_t)(const struct nlmsghdr *n, int len, void *arg);
typedef int (*rtnl_filter_t)(const struct sockaddr_nl *,
			     const struct nlmsghdr *n, void **);

//int lsi_total;

int get_ctl_fd(void);
int do_chflags(const char *dev, __u32 flags, __u32 mask);
int set_up_device(char *dev, int up);
int addattr_l(struct nlmsghdr *n, int maxlen, int type, const void *data, 
	      int alen);

int hip_netlink_open(struct rtnl_handle *nl, unsigned subscriptions, int protocol);
int hip_netlink_receive(struct rtnl_handle *nl, hip_filter_t handler, void *arg);
int rtnl_open_byproto(struct rtnl_handle *rth, unsigned subscriptions,
			  int protocol);
void rtnl_close(struct rtnl_handle *rth);
int hip_netlink_receive_workorder(const struct nlmsghdr *n, int len, void *arg);
int netlink_talk(struct rtnl_handle *nl, struct nlmsghdr *n, pid_t peer,
			unsigned groups, struct nlmsghdr *answer,
			hip_filter_t junk, void *arg);

int hip_ipaddr_modify(struct rtnl_handle *rth, int cmd, int family, char *ip,
			char *dev, struct idxmap **idxma);
int hip_iproute_modify(struct rtnl_handle *rth,
			int cmd, int flags, int family, char *ip,
			char *dev);
int hip_iproute_get(struct rtnl_handle *rth, const struct in6_addr *src_addr,
			const struct in6_addr *dst_addr, char *idev, char *odev,
			int family, struct idxmap **idxmap);


void rtnl_tab_initialize(char *file, char **tab, int size);
int xfrm_init_lft(struct xfrm_lifetime_cfg *lft);
int xfrm_fill_selector(struct xfrm_selector *sel,
		       const struct in6_addr *id_our,
		       const struct in6_addr *id_peer,
		       __u8 proto, u8 id_prefix,
		       uint32_t src_port, uint32_t dst_port,
		       int preferred_family);
int xfrm_fill_encap(struct xfrm_encap_tmpl *encap, int sport, int dport, struct in6_addr *oa);

int xfrm_algo_parse(struct xfrm_algo *alg, enum xfrm_attr_type_t type,
		    char *name, unsigned char *key, int key_len, int max);

int xfrm_fill_encap(struct xfrm_encap_tmpl *encap, int sport, int dport, struct in6_addr *oa);
int xfrm_init_lft(struct xfrm_lifetime_cfg *lft);


#endif /* _HIP_NLINK_H */
