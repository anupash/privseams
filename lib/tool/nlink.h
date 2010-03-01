#ifndef HIP_LIB_TOOL_NLINK_H
#define HIP_LIB_TOOL_NLINK_H

#include <stdio.h>
#include <stdint.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/netlink.h>
/* CentOS 5.4 and some other legacy systems are broken. Including
   linux/rtnetlink.h complains that __u32 or __64 is undefine */
#ifndef __u32
#define __u32 uint32_t
#define __u64 uint64_t
#endif /* __u32 */
#include <linux/xfrm.h>
#include <linux/rtnetlink.h>

#include "lib/core/builder.h"
#include "lib/core/debug.h"


struct pseudo_hdr {
    u32 s_addr;
    u32 d_addr;
    u8  zer0;
    u8  protocol;
    u16 length;
};

struct pseudo6_hdr {
    struct in6_addr s_addr;
    struct in6_addr d_addr;
    u8              zer0;
    u8              protocol;
    u16             length;
};

#define HIP_OPTION_KIND 30

struct netdev_address {
    //hip_list_t next;
    struct sockaddr_storage addr;
    int                     if_index;
    unsigned char           secret[40];
    time_t                  timestamp;
    int                     flags;
};

struct idxmap {
    struct idxmap *next;
    unsigned       index;
    int            type;
    int            alen;
    unsigned       flags;
    unsigned char  addr[8];
    char           name[16];
};

struct rtnl_handle {
    int                fd;
    struct sockaddr_nl local;
    struct sockaddr_nl peer;
    uint32_t           seq;
    uint32_t           dump;
};

/* Workaround: in6_pktinfo does not compile on Fedora and Ubuntu anymore.
 * This works also with CentOS */
struct inet6_pktinfo {
    struct in6_addr ipi6_addr;
    unsigned int    ipi6_ifindex;
};

typedef int (*hip_filter_t)(const struct nlmsghdr *n, int len, void *arg);

int set_up_device(char *dev, int up);
int addattr_l(struct nlmsghdr *n, int maxlen, int type, const void *data,
              int alen);

int hip_netlink_open(struct rtnl_handle *nl,
                     unsigned subscriptions,
                     int protocol);
int hip_netlink_receive(struct rtnl_handle *nl,
                        hip_filter_t handler,
                        void *arg);
int rtnl_open_byproto(struct rtnl_handle *rth,
                      unsigned subscriptions,
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
int hip_iproute_get(struct rtnl_handle *rth, struct in6_addr *src_addr,
                    const struct in6_addr *dst_addr, char *idev, char *odev,
                    int family, struct idxmap **idxmap);

int xfrm_init_lft(struct xfrm_lifetime_cfg *lft);
int xfrm_fill_selector(struct xfrm_selector *sel,
                       const struct in6_addr *id_our,
                       const struct in6_addr *id_peer,
                       uint8_t proto, u8 id_prefix,
                       uint32_t src_port, uint32_t dst_port,
                       int preferred_family);
int xfrm_fill_encap(struct xfrm_encap_tmpl *encap,
                    int sport,
                    int dport,
                    const struct in6_addr *oa);

int xfrm_algo_parse(struct xfrm_algo *alg, enum xfrm_attr_type_t type,
                    char *name, const unsigned char *key,
                    int key_len, int max);

#endif /* HIP_LIB_TOOL_NLINK_H */
