#include <sys/socket.h>
#include <linux/netlink.h>

#include "debug.h" /* logging facilities */
#include "netlink.h"

static struct rtnl_handle *rtnl;

/* base exchange IPv6 addresses need to be put into ifindex2spi map,
 * so a function is needed which gets the ifindex of the network
 * device which has the address @addr */
int hip_ipv6_devaddr2ifindex(struct in6_addr *addr)
{
	HIP_ERROR("hip_ipv6_devaddr2ifindex, oh crap.\n");
	exit(1);
	return 1;
}

/* Processes a received netlink message */
static int accept_msg(const struct sockaddr_nl *who,
		      const struct nlmsghdr *n, void *arg)
{
	struct hip_work_order *hwo;
	int msg_len;
	
	hwo = (struct hip_work_order *)malloc(sizeof(struct hip_work_order));
	if (!hwo) {
		HIP_ERROR("Out of memory.\n");
		return -1;
	}

	memcpy(hwo, NLMSG_DATA(n), sizeof(struct hip_work_order_hdr));
	msg_len = hip_get_msg_total_len((const struct hip_common *)&((struct hip_work_order *)NLMSG_DATA(n))->msg);	
	hwo->msg = (struct hip_common *)malloc(msg_len);
	if (!hwo->msg) {
		HIP_ERROR("Out of memory.\n");
		free(hwo);
		return -1;
	}
	
	memcpy(hwo->msg, &((struct hip_work_order *)NLMSG_DATA(n))->msg, msg_len);

	return hip_do_work(hwo);
}

/* 
 * Unfortunately libnetlink does not provide a generic receive a
 * message function. This is a modified version of the rtnl_listen
 * function that processes only a finite amount of messages and then
 * returns. 
*/
int hip_netlink_receive() {
	struct hip_work_order *result = NULL;
	struct hip_work_order *hwo;
	struct nlmsghdr *h;
	struct sockaddr_nl nladdr;
	struct iovec iov;
        struct msghdr msg = {
                (void*)&nladdr, sizeof(nladdr),
                &iov,   1,
                NULL,   0,
                0
        };
	int msg_len, status;
	char buf[NLMSG_SPACE(HIP_MAX_NETLINK_PACKET)];

        memset(&nladdr, 0, sizeof(nladdr));
        nladdr.nl_family = AF_NETLINK;
        nladdr.nl_pid = 0;
        nladdr.nl_groups = 0;
	iov.iov_base = buf;
	
	while (1) {
                iov.iov_len = sizeof(buf);
                status = recvmsg(rtnl->fd, &msg, 0);

                if (status < 0) {
                        if (errno == EINTR)
                                continue;
			HIP_ERROR("Netlink overrun.\n");
                        continue;
                }
                if (status == 0) {
                        HIP_ERROR("EOF on netlink\n");
                        return -1;
                }
                if (msg.msg_namelen != sizeof(nladdr)) {
                        HIP_ERROR("Sender address length == %d\n", msg.msg_namelen);
                        exit(1);
                }
		for (h = (struct nlmsghdr*)buf; status >= sizeof(*h); ) {
                        int err;
                        int len = h->nlmsg_len;
                        int l = len - sizeof(*h);

                        if (l<0 || len>status) {
                                if (msg.msg_flags & MSG_TRUNC) {
                                        HIP_ERROR("Truncated netlink message\n");
                                        return -1;
                                }

                                HIP_ERROR("Malformed netlink message: len=%d\n", len);
                                exit(1);
                        }

                        err = accept_msg(&nladdr, h, NULL);
                        if (err < 0)
                                return err;

                        status -= NLMSG_ALIGN(len);
                        h = (struct nlmsghdr*)((char*)h + NLMSG_ALIGN(len));
                }
                if (msg.msg_flags & MSG_TRUNC) {
                        HIP_ERROR("Message truncated\n");
                        break;
                }

                if (status) {
                        HIP_ERROR("Remnant of size %d\n", status);
                        exit(1);
                }

		/* All messages processed */
		break;
	}
}

int hip_netlink_send(struct hip_work_order *hwo) 
{
	struct hip_work_order *h;
	struct nlmsghdr *nlh;
	int msg_len, ret;

	msg_len = hip_get_msg_total_len((const struct hip_common *)&hwo->msg);
	nlh = (struct nlmsghdr *)HIP_MALLOC(NLMSG_SPACE(msg_len + sizeof(struct hip_work_order_hdr)), 0);
	if (!nlh) {
		HIP_ERROR("Out of memory.\n");
		return -1;
	}

	/* Fill the netlink message header */
	nlh->nlmsg_len = NLMSG_LENGTH(msg_len + sizeof(struct hip_work_order_hdr));
	nlh->nlmsg_pid = getpid(); /* self pid */
	nlh->nlmsg_flags = 0;
	
	/* Fill in the netlink message payload */
	h = (struct hip_work_order *)NLMSG_DATA(nlh);
	memcpy(h, hwo, sizeof(struct hip_work_order_hdr));
	memcpy(&h->msg, hwo->msg, msg_len);

        ret = rtnl_send(rtnl, (char*)nlh, nlh->nlmsg_len) <= 0;
	HIP_FREE(nlh);
	return ret;
}
