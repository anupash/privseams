#include "nlink.h"

/*
 * Note that most of the functions are modified versions of
 * libnetlink functions (the originals were buggy...).
 */

int addattr_l(struct nlmsghdr *n, int maxlen, int type, const void *data, 
	      int alen)
{
	int len = RTA_LENGTH(alen);
	struct rtattr *rta;

	if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen) {
		fprintf(stderr, "addattr_l ERROR: message exceeded bound of %d\n",maxlen);
		return -1;
	}
	rta = NLMSG_TAIL(n);
	rta->rta_type = type;
	rta->rta_len = len;
	memcpy(RTA_DATA(rta), data, alen);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
	return 0;
}

#if 0
/* Processes a received netlink message(s) */
int hip_netlink_receive_workorder(const struct nlmsghdr *n, int len, void *arg)
{
	struct hip_work_order *hwo;
	struct nlmsghdr *tail = (struct nlmsghdr *) (((char *) n) + len);
	int msg_len, ret;
	
	while (n < tail) {
		hwo = (struct hip_work_order *)hip_init_job(GFP_KERNEL);
		if (!hwo) {
			HIP_ERROR("Out of memory.\n");
			return -1;
		}

		memcpy(hwo, NLMSG_DATA(n), sizeof(struct hip_work_order_hdr));
		msg_len = hip_get_msg_total_len((const struct hip_common *)&((struct hip_work_order *)NLMSG_DATA(n))->msg);	
		hwo->msg = (struct hip_common *) HIP_MALLOC(msg_len, 0);
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
#endif

/* 
 * Unfortunately libnetlink does not provide a generic receive a
 * message function. This is a modified version of the rtnl_listen
 * function that processes only a finite amount of messages and then
 * returns. 
*/
int hip_netlink_receive(int hip_raw_sock, struct hip_nl_handle *nl, 
			hip_filter_t handler,
			void *arg) 
{
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

	HIP_DEBUG("Received a netlink message\n");

        memset(&nladdr, 0, sizeof(nladdr));
        nladdr.nl_family = AF_NETLINK;
        nladdr.nl_pid = 0;
        nladdr.nl_groups = 0;
	iov.iov_base = buf;
	
	while (1) {
                iov.iov_len = sizeof(buf);
                status = recvmsg(nl->fd, &msg, 0);

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

                        err = handler(hip_raw_sock, h, len, arg);
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
		return 0;
	}
}

/**
 * This is a copy from the libnetlink's talk function. It has a fixed
 * handling of message source/destination validation and proper buffer
 * handling for junk messages.
 */
int netlink_talk(struct hip_nl_handle *nl, struct nlmsghdr *n, pid_t peer,
			unsigned groups, struct nlmsghdr *answer,
			hip_filter_t junk, void *arg)
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
                HIP_PERROR("Cannot talk to rtnetlink");
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
                        HIP_PERROR("OVERRUN");
                        continue;
                }
		if (status == 0) {
                        HIP_ERROR("EOF on netlink.\n");
                        return -1;
                }
                if (msg.msg_namelen != sizeof(nladdr)) {
                        HIP_ERROR("sender address length == %d\n",
				  msg.msg_namelen);
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
                                        err = junk(0, h, len, arg);
                                        if (err < 0)
                                                return err;
                                }

				/* Original version lacked this: */
				status -= len;
                                continue;
                        }

                        if (h->nlmsg_type == NLMSG_ERROR) {
                                struct nlmsgerr *err = 
					(struct nlmsgerr*)NLMSG_DATA(h);
                                if (l < sizeof(struct nlmsgerr)) {
                                        HIP_ERROR("Truncated\n");
                                } else {
                                        errno = -err->error;
                                        if (errno == 0) {
                                                if (answer)
                                                        memcpy(answer, h, h->nlmsg_len);
                                                return 0;
                                        }
                                        HIP_PERROR("RTNETLINK answers");
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

#if 0
/*
 * Sends and receives a work order.
 */
int hip_netlink_talk(struct hip_nl_handle *nl,
		     struct hip_work_order *req, 
		     struct hip_work_order *resp) 
{
	struct {
                struct nlmsghdr n;
                struct hip_work_order_hdr hdr;
                char msg[HIP_MAX_NETLINK_PACKET];
        } tx, rx;
	int msg_len;

	_HIP_DEBUG("entered\n");
        /* Fill in the netlink message payload */
	msg_len = hip_get_msg_total_len((const struct hip_common *)&req->msg);
	memcpy(&tx.hdr, &req->hdr, sizeof(struct hip_work_order_hdr));
	memcpy(tx.msg, req->msg, msg_len);

	/* Fill the header */
	tx.n.nlmsg_len = NLMSG_LENGTH(msg_len +
				      sizeof(struct hip_work_order_hdr));
	tx.n.nlmsg_type = 0; // XX FIXME
        tx.n.nlmsg_flags = 0;
	tx.n.nlmsg_seq = 0; // XX FIXME
        tx.n.nlmsg_pid = getpid(); /* self pid */

	/* Let the talk insert any non-responses to our queue so that
           they will be processed later */
	HIP_DEBUG("Calling netlink_talk...\n");
	if (netlink_talk(nl, &tx.n, 0, 0, &rx.n,
			 hip_netlink_receive_workorder, NULL) < 0) {
		HIP_ERROR("Unable to talk over netlink.\n");
		return -1;
	}
	HIP_DEBUG("Called netlink_talk...\n");

	msg_len = hip_get_msg_total_len((const struct hip_common *)rx.msg);
	resp->msg = (struct hip_common *) HIP_MALLOC(msg_len, 0);
	if (!resp->msg) {
		HIP_ERROR("Out of memory!\n");
		return -1;
	}

	/* Copy the response payload */
	memcpy(&resp->hdr, &rx.hdr, sizeof(struct hip_work_order_hdr));
	memcpy(resp->msg, rx.msg, msg_len);

	return 0;
}
#endif

int hip_netlink_send_buf(struct hip_nl_handle *rth, const char *buf, int len)
{
        struct sockaddr_nl nladdr;

        memset(&nladdr, 0, sizeof(struct sockaddr_nl));
        nladdr.nl_family = AF_NETLINK;

        return sendto(rth->fd, buf, len, 0, (struct sockaddr*)&nladdr, sizeof(struct sockaddr_nl));
}

#if 0
/*
 * Sends a work order to kernel daemon.
 */
int hip_netlink_send(struct hip_work_order *hwo) 
{
	struct hip_work_order *h;
	struct nlmsghdr *nlh;
	struct hip_common *dummy = NULL;
	int msg_len, ret, nlh_len;

	HIP_DEBUG("Sending a netlink message\n");

	/* No message: allocate memory and create a dummy message */
	if (!hwo->msg) {
		/* assert: hip_insert_work_order frees this memory */
		dummy = hip_msg_alloc();
		if (!dummy) {
			return -1;
		}
		if (!hip_build_netlink_dummy_header(dummy)) {
			return -1;
		}
		hwo->msg = dummy;
	}

	msg_len = hip_get_msg_total_len((const struct hip_common *)hwo->msg);
	nlh_len = NLMSG_SPACE(msg_len + sizeof(struct hip_work_order_hdr));
	nlh = (struct nlmsghdr *) HIP_MALLOC(nlh_len, 0);
	if (!nlh) {
		HIP_ERROR("Out of memory\n");
		return -1;
	}
	memset(nlh, 0, nlh_len);

	/* Fill the netlink message header */
	nlh->nlmsg_len = NLMSG_LENGTH(msg_len + sizeof(struct hip_work_order_hdr));
	nlh->nlmsg_pid = getpid(); /* self pid */
	nlh->nlmsg_flags = 0;
	
	/* Fill in the netlink message payload */
	h = (struct hip_work_order *)NLMSG_DATA(nlh);
	memcpy(h, hwo, sizeof(struct hip_work_order_hdr));
	memcpy(&h->msg, hwo->msg, msg_len);

        ret = hip_netlink_send_buf(&nl_khipd, (char*)nlh, nlh->nlmsg_len) <= 0;
	HIP_FREE(nlh);
	return ret;
}
#endif

int hip_netlink_open(struct hip_nl_handle *rth, unsigned subscriptions, int protocol)
{
        socklen_t addr_len;
        int sndbuf = 32768;
        int rcvbuf = 32768;

        memset(rth, 0, sizeof(rth));

        rth->fd = socket(AF_NETLINK, SOCK_RAW, protocol);
        if (rth->fd < 0) {
                HIP_PERROR("Cannot open a netlink socket");
                return -1;
        }
	_HIP_DEBUG("setsockopt SO_SNDBUF\n");
        if (setsockopt(rth->fd,SOL_SOCKET,SO_SNDBUF,&sndbuf,sizeof(sndbuf)) < 0) {
                HIP_PERROR("SO_SNDBUF");
                return -1;
        }
	_HIP_DEBUG("setsockopt SO_RCVBUF\n");
        if (setsockopt(rth->fd,SOL_SOCKET,SO_RCVBUF,&rcvbuf,sizeof(rcvbuf)) < 0) {
                HIP_PERROR("SO_RCVBUF");
                return -1;
        }

        memset(&rth->local, 0, sizeof(rth->local));
        rth->local.nl_family = AF_NETLINK;
        rth->local.nl_groups = subscriptions;

        if (bind(rth->fd, (struct sockaddr*)&rth->local, sizeof(rth->local)) < 0) {
                HIP_PERROR("Cannot bind a netlink socket");
                return -1;
        }
        addr_len = sizeof(rth->local);
        if (getsockname(rth->fd, (struct sockaddr*)&rth->local, &addr_len) < 0) {
                HIP_PERROR("Cannot getsockname");
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

void hip_netlink_close(struct hip_nl_handle *rth)
{
	close(rth->fd);
}
