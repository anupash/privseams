#include "netlink.h"

static struct sock *nl_sk = NULL;
static u32 hipd_pid;

/* Insert the received message to the queue */
static int hip_rcv_msg(struct sk_buff *skb, struct nlmsghdr *nlh, int *err)
{
	struct hip_work_order *hwo = NULL;
	struct hip_work_order *result = NULL;
	uint16_t msg_len;

	*err = -1;
	hipd_pid = nlh->nlmsg_pid;
	
	if (!(result = hip_init_job(GFP_KERNEL))) {
		return -1;
	}
	
	hwo = (struct hip_work_order *)NLMSG_DATA(nlh);
	memcpy(result, hwo, sizeof(struct hip_work_order_hdr));

	msg_len = hip_get_msg_total_len((struct hip_common *) &hwo->msg);
	result->seq = nlh->nlmsg_seq;
	result->msg = HIP_MALLOC(msg_len, GFP_KERNEL);
	if (!result->msg) {
		HIP_ERROR("Out of memory.\n");
		HIP_FREE(result);
		return -1;
	}
	
	memcpy(result->msg, &hwo->msg, msg_len);
	hip_insert_work_order_cpu(result, smp_processor_id());

	*err = 0;
	return 0;
}

static int hip_rcv_skb(struct sk_buff *skb)
{
	int err;
	struct nlmsghdr *nlh;

	while (skb->len >= NLMSG_SPACE(0)) {
		u32 rlen;

		nlh = (struct nlmsghdr *) skb->data;
		if (nlh->nlmsg_len < sizeof(*nlh) ||
		    skb->len < nlh->nlmsg_len)
			return 0;
		rlen = NLMSG_ALIGN(nlh->nlmsg_len);
		if (rlen > skb->len)
			rlen = skb->len;
		if (hip_rcv_msg(skb, nlh, &err) < 0) {
			if (err == 0)
				return -1;
			netlink_ack(skb, nlh, err);
		} else if (nlh->nlmsg_flags & NLM_F_ACK) {
			netlink_ack(skb, nlh, 0);
		}
		skb_pull(skb, rlen);
	}

	return 0;
}

static void hip_netlink_rcv(struct sock *sk, int len) {
	do {
		struct sk_buff *skb;

		while ((skb = skb_dequeue(&sk->sk_receive_queue)) != NULL) {
			if (hip_rcv_skb(skb)) {
				if (skb->len)
					skb_queue_head(&sk->sk_receive_queue,
						       skb);
				else
					kfree_skb(skb);
				break;
			}
			kfree_skb(skb);
		}
		
	} while (nl_sk && nl_sk->sk_receive_queue.qlen);
}

int hip_netlink_open(void) {
	nl_sk = netlink_kernel_create(NETLINK_HIP, hip_netlink_rcv);
	if (nl_sk == NULL)
		return -ENOMEM;

	HIP_DEBUG("HIP netlink socket created.");
	
	return 0;
}

void hip_netlink_close(void) {
	if (nl_sk)
		sock_release(nl_sk->sk_socket);
}

int hip_netlink_send(struct hip_work_order *hwo)
{
	struct hip_work_order_hdr *h;
	struct hip_common *msg;
	struct sk_buff *skb = NULL;
	struct nlmsghdr *nlh;
	struct hip_common *dummy = NULL;
	int msg_len;

	if (!nl_sk) {
		HIP_ERROR("Netlink socket not open.\n");
		return -1;
	}
	
	if (!hipd_pid) {
		HIP_ERROR("No hipd userspace daemon running.\n");
		return -1;
	}

	/* No message: allocate memory and create a dummy message */
	if (!hwo->msg) {
		/* assert: hip_insert_work_order frees this memory */
		dummy = hip_msg_alloc();
		if (!dummy) {
			return -1;
		}
		if (hip_build_netlink_dummy_header(dummy)) {
			return -1;
		}
		hwo->msg = dummy;
	}

	msg_len = hip_get_msg_total_len(hwo->msg);

	skb = alloc_skb(NLMSG_SPACE(msg_len +
				    sizeof(struct hip_work_order_hdr)),
			GFP_KERNEL);	
	if (!skb) {
		HIP_ERROR("Out of memory.\n");
		return -1;
	}
     
	nlh = (struct nlmsghdr *)skb_put(skb, NLMSG_SPACE(0));
	nlh->nlmsg_len = NLMSG_SPACE(msg_len +
				     sizeof(struct hip_work_order_hdr));
	nlh->nlmsg_pid = 0; /* from kernel */
	nlh->nlmsg_flags = 0;
	nlh->nlmsg_seq = hwo->seq;
	
	/* Copy the payload */
	h = (struct hip_work_order_hdr *)
		skb_put(skb, sizeof(struct hip_work_order_hdr));
	memcpy(h, hwo, sizeof(struct hip_work_order_hdr));
	msg = (struct hip_common *)skb_put(skb, msg_len);
	memcpy(msg, hwo->msg, msg_len);
	
	NETLINK_CB(skb).groups = 0; /* not in mcast group */
	NETLINK_CB(skb).pid = 0; /* from kernel */
	NETLINK_CB(skb).dst_pid = hipd_pid;
	NETLINK_CB(skb).dst_groups = 0; /* unicast */

	msg_len = netlink_unicast(nl_sk, skb, hipd_pid, MSG_DONTWAIT);
	/* FIXME: errors of unicast? */

	HIP_DEBUG("Sent %d bytes to PID %d\n", msg_len, hipd_pid);

	/* Kernel frees the skb */

	return 0;
}


