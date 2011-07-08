#ifndef HIP_LIB_TOOL_NLINK_H
#define HIP_LIB_TOOL_NLINK_H

#include <stdint.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/xfrm.h>
#include <sys/socket.h>
#include <sys/types.h>


#define HIP_NETLINK_TALK_ACK 0 /* see netlink_talk */


struct pseudo_hdr {
    uint32_t s_addr;
    uint32_t d_addr;
    uint8_t  zer0;
    uint8_t  protocol;
    uint16_t length;
};

struct pseudo6_hdr {
    struct in6_addr s_addr;
    struct in6_addr d_addr;
    uint8_t         zer0;
    uint8_t         protocol;
    uint16_t        length;
};

struct netdev_address {
    struct sockaddr_storage addr;
    int                     if_index;
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

/* FIXME: in6_pktinfo is a GNU extension. Copy it into HIPL as inet6_pktinfo
 * because it is small and simple although it is preferable to avoid it. */
struct inet6_pktinfo {
    struct in6_addr ipi6_addr;
    unsigned int    ipi6_ifindex;
};

typedef int (*hip_filter)(struct nlmsghdr *n, int len, void *arg);

int set_up_device(const char *dev, int up);
int addattr_l(struct nlmsghdr *n, unsigned maxlen, int type, const void *data,
              int alen);

int hip_netlink_open(struct rtnl_handle *nl, unsigned subscriptions,
                     int protocol);
int hip_netlink_receive(struct rtnl_handle *nl, hip_filter handler, void *arg);

int rtnl_open_byproto(struct rtnl_handle *rth, unsigned subscriptions,
                      int protocol);
void rtnl_close(struct rtnl_handle *rth);
int hip_netlink_receive_workorder(const struct nlmsghdr *n, int len, void *arg);
int netlink_talk(struct rtnl_handle *nl, struct nlmsghdr *n, pid_t peer,
                 unsigned groups, struct nlmsghdr *answer,
                 hip_filter junk, void *arg);

int hip_ipaddr_modify(struct rtnl_handle *rth, int cmd, int family, char *ip,
                      const char *dev, struct idxmap **idxma);
int hip_iproute_modify(struct rtnl_handle *rth, int cmd, int flags, int family,
                       char *ip, const char *dev);
int hip_iproute_get(struct rtnl_handle *rth, struct in6_addr *src_addr,
                    const struct in6_addr *dst_addr, char *idev, char *odev,
                    int family, struct idxmap **idxmap);

#endif /* HIP_LIB_TOOL_NLINK_H */
