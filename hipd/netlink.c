#include <sys/socket.h>
#include <linux/netlink.h>

#include "debug.h" /* logging facilities */
#include "netlink.h"

static int netlink_fd;

struct hip_work_order *hip_netlink_receive(void) {
	struct hip_work_order *result = NULL;
	struct hip_work_order *hwo;
	struct nlmsghdr *nlh = NULL;
	struct sockaddr_nl nladdr;
	struct msghdr msg;
	struct iovec iov;
	int msg_len;
     
	nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(HIP_MAX_NETLINK_PACKET));
	if (!nlh) {
		HIP_ERROR("Out of memory.\n");
		goto err;
	}

	memset(nlh, 0, NLMSG_SPACE(HIP_MAX_NETLINK_PACKET));
	iov.iov_base = (void *)nlh;
	iov.iov_len = 1;
	msg.msg_name = (void *)&(nladdr);
	msg.msg_namelen = sizeof(nladdr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	recvmsg(netlink_fd, &msg, 0);
	/** FIXME error handling */
	
	result = HIP_MALLOC(sizeof(struct hip_work_order), GFP_KERNEL);
	if (!result) {
		HIP_ERROR("Out of memory.\n");
		goto err;
	}
	
	hwo = (struct hip_work_order *)NLMSG_DATA(nlh);

	memcpy(result, hwo, sizeof(struct hip_work_order_hdr));

	msg_len = hip_get_msg_total_len(&(hwo->msg));	
	result->msg = HIP_MALLOC(msg_len, GFP_KERNEL);
	if (!result->msg) {
		HIP_ERROR("Out of memory.\n");
		HIP_FREE(result);
		result = NULL;
		goto err;
	}
	
	memcpy(result->msg, &(hwo->msg), msg_len);
	
 err:
	if (nlh)
		HIP_FREE(nlh);
	
	return result;
}

int hip_netlink_send(struct hip_work_order *hwo) 
{
	struct hip_work_order *h;
	struct sockaddr_nl dest_addr;
	struct msghdr msg;
	struct nlmsghdr *nlh = NULL;
	struct iovec iov;
	int msg_len;

	msg_len = hip_get_msg_total_len(&hwo->msg);
	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_pid = 0; /* For Linux Kernel */
	dest_addr.nl_groups = 0; /* unicast */
	nlh = (struct nlmsghdr *)HIP_MALLOC(NLMSG_SPACE(msg_len + sizeof(struct hip_work_order_hdr)), 0);
	if (!nlh) {
		HIP_ERROR("Out of memory.\n");
		return -1;
	}

	/* Fill the netlink message header */
	nlh->nlmsg_len = NLMSG_SPACE(msg_len + sizeof(struct hip_work_order_hdr));
	nlh->nlmsg_pid = getpid(); /* self pid */
	nlh->nlmsg_flags = 0;
	
	/* Fill in the netlink message payload */
	h = (struct hip_work_order *)NLMSG_DATA(nlh);
	memcpy(h, hwo, sizeof(struct hip_work_order_hdr));
	memcpy(&h->msg, hwo->msg, msg_len);

	/* Send */
	iov.iov_base = (void *)nlh;
	iov.iov_len = nlh->nlmsg_len;
	msg.msg_name = (void *)&dest_addr;
	msg.msg_namelen = sizeof(dest_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	sendmsg(netlink_fd, &msg, 0);
	/* FIXME: errors of sendmsg */

	HIP_FREE(nlh);
	return 0;
}

/*
 * function hip_netlink_open()
 *
 * Opens and binds a Netlink socket, setting *s_net.
 *
 * Returns 0 on success, -1 otherwise.
 */
int hip_netlink_open(int *fd)
{
	struct sockaddr_nl local;
        
	if (*fd)
		close(*fd);
	if ((*fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_HIP)) < 0)
		return(-1);
	
	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;
	/* subscribe to link, IPv4/IPv6 address notifications */
	local.nl_groups = 0; // FIXME: HIP -types
        
	if (bind(*fd, (struct sockaddr *)&local, sizeof(local)) < 0)
		return(-1);
        
	netlink_fd = *fd;
	return(0);
}

void hip_netlink_close() {
	close(netlink_fd);
}
