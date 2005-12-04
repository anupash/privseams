#ifndef _HIP_NLINK_H
#define _HIP_NLINK_H

#include <sys/socket.h>
#include <linux/types.h>
#include <linux/netlink.h>
#include <stdio.h>
#include <stdint.h>

#include "builder.h"
#include "debug.h"
#include "hip.h"
#include "hipd.h"

#define SA2IP(x) (((struct sockaddr*)x)->sa_family==AF_INET) ? \
        (void*)&((struct sockaddr_in*)x)->sin_addr : \
        (void*)&((struct sockaddr_in6*)x)->sin6_addr
#define SALEN(x) (((struct sockaddr*)x)->sa_family==AF_INET) ? \
        sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)
#define SAIPLEN(x) (((struct sockaddr*)x)->sa_family==AF_INET) ? 4 : 16

#define NLMSG_TAIL(nmsg) \
	((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

struct netdev_address {
	struct list_head next;
	struct sockaddr_storage addr;
	int if_index;
};

struct hip_nl_handle {
        int                     fd;
        struct sockaddr_nl      local;
        struct sockaddr_nl      peer;
        __u32                   seq;
        __u32                   dump;
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

typedef int (*hip_filter_t)(const struct nlmsghdr *n, int len, void *arg);
typedef int (*rtnl_filter_t)(const struct sockaddr_nl *,
			     const struct nlmsghdr *n, void **);

int get_ctl_fd(void);
int do_chflags(const char *dev, __u32 flags, __u32 mask);
int set_up_device(char *dev, int up);
int addattr_l(struct nlmsghdr *n, int maxlen, int type, const void *data, 
	      int alen);

int hip_netlink_open(struct hip_nl_handle *nl, unsigned subscriptions, int protocol);
int hip_netlink_receive(struct hip_nl_handle *nl, hip_filter_t handler, void *arg);
int hip_netlink_send_buf(struct hip_nl_handle *nl, const char *buf, int len);
int hip_netlink_receive_workorder(const struct nlmsghdr *n, int len, void *arg);
int netlink_talk(struct hip_nl_handle *nl, struct nlmsghdr *n, pid_t peer,
			unsigned groups, struct nlmsghdr *answer,
		 hip_filter_t junk, void *arg);
int hip_netlink_talk(struct hip_nl_handle *nl, struct hip_work_order *req, struct hip_work_order *resp);
int hip_netlink_send(struct hip_work_order *hwo);
void hip_netlink_close(struct hip_nl_handle *rth);

#endif /* _HIP_NLINK_H */
