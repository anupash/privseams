#include "netlink.h"

static struct sock *nl_sk = NULL;
static u32 hipd_pid;

/* Signal handler to wakeup the blocking datagram receiver */
void nl_data_ready (struct sock *sk, int len)
{
	wake_up_interruptible(sk->sk_sleep);
}

int hip_netlink_open(int *fd) {
	nl_sk = netlink_kernel_create(NETLINK_HIP, 
				      nl_data_ready);
	/** FIXME: error processing */
	return 0;
}

void hip_netlink_close() {
	if (!nl_sk) 
		sock_release(nl_sk->sk_socket);
}

struct hip_work_order *hip_netlink_receive(void)
{
	struct hip_work_order *result;
	struct sk_buff *skb = NULL;
	struct nlmsghdr *nlh = NULL;
	struct hip_work_order *hwo = NULL;
	uint16_t msg_len;
	int err;

	/* wait for message coming down from user-space */
	skb = skb_recv_datagram(nl_sk, 0, 0, &err);     
	/** FIXME: error check */
	nlh = (struct nlmsghdr *)skb->data;
	hipd_pid = nlh->nlmsg_pid;
	
	result = HIP_MALLOC(sizeof(struct hip_work_order), GFP_KERNEL);
	if (!result) {
		HIP_ERROR("Out of memory.\n");
		kfree_skb(skb);
		result = NULL;
		goto err;
	}
	
	hwo = (struct hip_work_order *)NLMSG_DATA(nlh);
	memcpy(result, hwo, sizeof(struct hip_work_order_hdr));

	msg_len = hip_get_msg_total_len((const struct hip_common *)&hwo->msg);	
	result->msg = HIP_MALLOC(msg_len, GFP_KERNEL);
	if (!result->msg) {
		HIP_ERROR("Out of memory.\n");
		kfree_skb(skb);
		HIP_FREE(hwo);
		result = NULL;
		goto err;
	}
	
	memcpy(result->msg, &hwo->msg, msg_len);
	result = hwo;
	kfree_skb(skb);
	
 err:
	return result;
}

int hip_netlink_send(struct hip_work_order *hwo) 
{
	struct hip_work_order *h;
	struct sk_buff *skb = NULL;
	struct nlmsghdr *nlh;
	int msg_len;

	msg_len = hip_get_msg_total_len((const struct hip_common *)&hwo->msg);
	skb = alloc_skb(NLMSG_SPACE(msg_len + sizeof(struct hip_work_order_hdr)), GFP_KERNEL);	
	if (!skb) {
		HIP_ERROR("Out of memory.\n");
		return -1;
	}
     
	nlh = (struct nlmsghdr *)skb->data;
	nlh->nlmsg_len = NLMSG_SPACE(msg_len + sizeof(struct hip_work_order_hdr));
	nlh->nlmsg_pid = 0; /* from kernel */
	nlh->nlmsg_flags = 0;
	
	/* Copy the payload */
	h = NLMSG_DATA(nlh);
	memcpy(h, hwo, sizeof(struct hip_work_order_hdr));
	memcpy(&h->msg, hwo->msg, msg_len);
	
	NETLINK_CB(skb).groups = 0; /* not in mcast group */
	NETLINK_CB(skb).pid = 0; /* from kernel */
	NETLINK_CB(skb).dst_pid = hipd_pid;
	NETLINK_CB(skb).dst_groups = 0; /* unicast */
	netlink_unicast(nl_sk, skb, hipd_pid, MSG_DONTWAIT);
	/* FIXME: errors of unicast */

	kfree_skb(skb);
	return 1;
}


