#include <sys/socket.h>
#include <linux/netlink.h>

#include "debug.h" /* logging facilities */
#include "netlink.h"
#include "hipd.h"

/*
 * Note that most of the functions are modified versions of
 * libnetlink functions (the originals were buggy...).
 */

/* base exchange IPv6 addresses need to be put into ifindex2spi map,
 * so a function is needed which gets the ifindex of the network
 * device which has the address @addr 
 */
int hip_ipv6_devaddr2ifindex(struct in6_addr *addr)
{
	HIP_ERROR("hip_ipv6_devaddr2ifindex, oh crap.\n");
	exit(1);
	return 1;
}

/* Processes a received netlink message(s) */
static int receive_work_order(const struct sockaddr_nl *who,
			      const struct nlmsghdr *n, int len)
{
	struct hip_work_order *hwo;
	struct nlmsghdr *tail = n + len;
	int msg_len, ret;
	
	while (n < tail) {
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
	
		/* Do not process the message here, but store it to the queue */
		if (ret = hip_insert_work_order_cpu(hwo, 0) != 1) {
			return ret;
		}

		n += NLMSG_SPACE(msg_len + sizeof(struct hip_work_order_hdr));
	}

	return ret;
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
                status = recvmsg(nl.fd, &msg, 0);

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

                        err = receive_work_order(&nladdr, h, len);
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

/**
 * This is a copy from the libnetlink's talk function. It has a fixed
 * handling of message source/destination validation and proper buffer
 * handling for junk messages.
 */
static int netlink_talk(struct hip_nl_handle *nl, struct nlmsghdr *n, pid_t peer,
			unsigned groups, struct nlmsghdr *answer,
			hip_filter_t junk)
{
        int status;
        unsigned seq;
        struct nlmsghdr *h;
        struct sockaddr_nl nladdr;
        struct iovec iov = { (void*)n, n->nlmsg_len };
        char   buf[16384];
        struct msghdr msg = {
                (void*)&nladdr, sizeof(nladdr),
                &iov,   1,
                NULL,   0,
                0
        };

        memset(&nladdr, 0, sizeof(nladdr));
        nladdr.nl_family = AF_NETLINK;
        nladdr.nl_pid = peer;
        nladdr.nl_groups = groups;

        n->nlmsg_seq = seq = ++nl->seq;

        if (answer == NULL)
                n->nlmsg_flags |= NLM_F_ACK;

        status = sendmsg(nl->fd, &msg, 0);

        if (status < 0) {
                perror("Cannot talk to rtnetlink");
                return -1;
        }

        memset(buf,0,sizeof(buf));

        iov.iov_base = buf;

        while (1) {
                iov.iov_len = sizeof(buf);
                status = recvmsg(nl->fd, &msg, 0);

                if (status < 0) {
                        if (errno == EINTR)
                                continue;
                        perror("OVERRUN");
                        continue;
                }
		if (status == 0) {
                        HIP_ERROR("EOF on netlink.\n");
                        return -1;
                }
                if (msg.msg_namelen != sizeof(nladdr)) {
                        HIP_ERROR("sender address length == %d\n", msg.msg_namelen);
                        exit(1);
                }
                for (h = (struct nlmsghdr*)buf; status >= sizeof(*h); ) {
                        int err;
                        int len = h->nlmsg_len;
                        int l = len - sizeof(*h);

                        if (l<0 || len>status) {
                                if (msg.msg_flags & MSG_TRUNC) {
                                        HIP_ERROR("Truncated message\n");
                                        return -1;
                                }
                                HIP_ERROR("Malformed message: len=%d\n", len);
                                exit(1);
                        }

                        if (nladdr.nl_pid != peer ||
                            h->nlmsg_seq != seq) {
                                if (junk) {
                                        err = junk(&nladdr, h, len);
                                        if (err < 0)
                                                return err;
                                }

				/* Original version lacked this: */
				status -= len;
                                continue;
                        }

                        if (h->nlmsg_type == NLMSG_ERROR) {
                                struct nlmsgerr *err = (struct nlmsgerr*)NLMSG_DATA(h);
                                if (l < sizeof(struct nlmsgerr)) {
                                        HIP_ERROR("Truncated\n");
                                } else {
                                        errno = -err->error;
                                        if (errno == 0) {
                                                if (answer)
                                                        memcpy(answer, h, h->nlmsg_len);
                                                return 0;
                                        }
                                        perror("RTNETLINK answers");
                                }
                                return -1;
                        }
                        if (answer) {
                                memcpy(answer, h, h->nlmsg_len);
                                return 0;
                        }

                        HIP_ERROR("Unexpected netlink reply!\n");

                        status -= NLMSG_ALIGN(len);
                        h = (struct nlmsghdr*)((char*)h + NLMSG_ALIGN(len));
                }
                if (msg.msg_flags & MSG_TRUNC) {
                        HIP_ERROR("Message truncated\n");
                        continue;
                }
                if (status) {
                        HIP_ERROR("Remnant of size %d\n", status);
                        exit(1);
                }
        }
}

/*
 * Sends and receives a work order.
 */
int hip_netlink_talk(struct hip_work_order *req, 
		     struct hip_work_order *resp) 
{
	struct {
                struct nlmsghdr n;
                struct hip_work_order_hdr hdr;
                char msg[HIP_MAX_NETLINK_PACKET];
        } tx, rx;
	int msg_len;

        /* Fill in the netlink message payload */
	msg_len = hip_get_msg_total_len((const struct hip_common *)&req->msg);
	memcpy(&tx.hdr, &req->hdr, sizeof(struct hip_work_order_hdr));
	memcpy(tx.msg, req->msg, msg_len);

	/* Fill the header */
	tx.n.nlmsg_len = NLMSG_LENGTH(msg_len + sizeof(struct hip_work_order_hdr));
        tx.n.nlmsg_pid = getpid(); /* self pid */
        tx.n.nlmsg_flags = 0;

	/* Let the talk insert any non-responses to our queue so that
           they will be processed later */
	if (netlink_talk(&nl, &tx.n, 0, 0, &rx.n, receive_work_order) < 0) {
		HIP_ERROR("Unable to talk over netlink.\n");
		return -1;
	}
	
	msg_len = hip_get_msg_total_len((const struct hip_common *)rx.msg);
	resp->msg = (struct hip_common *)malloc(msg_len);
	if (!resp->msg) {
		HIP_ERROR("Out of memory!\n");
		return -1;
	}

	/* Copy the response payload */
	memcpy(&resp->hdr, &rx.hdr, sizeof(struct hip_work_order_hdr));
	memcpy(resp->msg, rx.msg, msg_len);
	return 0;
}

static int nl_send(struct hip_nl_handle *rth, const char *buf, int len)
{
        struct sockaddr_nl nladdr;

        memset(&nladdr, 0, sizeof(nladdr));
        nladdr.nl_family = AF_NETLINK;

        return sendto(rth->fd, buf, len, 0, (struct sockaddr*)&nladdr, sizeof(nladdr));
}

/*
 * Sends a work order.
 */
int hip_netlink_send(struct hip_work_order *hwo) 
{
	struct hip_work_order *h;
	struct nlmsghdr *nlh;
	int msg_len, ret;

	msg_len = hip_get_msg_total_len((const struct hip_common *)&hwo->msg);
	nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(msg_len + sizeof(struct hip_work_order_hdr)));
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

        ret = nl_send(&nl, (char*)nlh, nlh->nlmsg_len) <= 0;
	HIP_FREE(nlh);
	return ret;
}

int hip_netlink_open(struct hip_nl_handle *rth, unsigned subscriptions, int protocol)
{
        int addr_len;
        int sndbuf = 32768;
        int rcvbuf = 32768;

        memset(rth, 0, sizeof(rth));

        rth->fd = socket(AF_NETLINK, SOCK_RAW, protocol);
        if (rth->fd < 0) {
                perror("Cannot open netlink socket");
                return -1;
        }

        if (setsockopt(rth->fd,SOL_SOCKET,SO_SNDBUF,&sndbuf,sizeof(sndbuf)) < 0) {
                perror("SO_SNDBUF");
                return -1;
        }

        if (setsockopt(rth->fd,SOL_SOCKET,SO_RCVBUF,&rcvbuf,sizeof(rcvbuf)) < 0) {
                perror("SO_RCVBUF");
                return -1;
        }

        memset(&rth->local, 0, sizeof(rth->local));
        rth->local.nl_family = AF_NETLINK;
        rth->local.nl_groups = subscriptions;

        if (bind(rth->fd, (struct sockaddr*)&rth->local, sizeof(rth->local)) < 0) {
                perror("Cannot bind netlink socket");
                return -1;
        }
        addr_len = sizeof(rth->local);
        if (getsockname(rth->fd, (struct sockaddr*)&rth->local, &addr_len) < 0) {
                perror("Cannot getsockname");
                return -1;
        }
        if (addr_len != sizeof(rth->local)) {
                HIP_ERROR("Wrong address length %d\n", addr_len);
                return -1;
        }
        if (rth->local.nl_family != AF_NETLINK) {
                HIP_ERROR("Wrong address family %d\n", rth->local.nl_family);
                return -1;
        }
        rth->seq = time(NULL);
        return 0;
}


