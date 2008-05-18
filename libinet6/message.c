/** @file
 * HIP userspace communication mechanism between userspace and kernelspace.
 * The mechanism is used by hipd, hipconf and unittest.
 * 
 * @author  Miika Komu <miika_iki.fi>
 * @author  Bing Zhou <bingzhou_cc.hut.fi>
 * @version 1.0
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl.txt">GNU/GPL</a>.
 * @see     message.h
 * @todo    Asynchronous term should be replaced with a better one.
 * @todo    Asynchronous messages should also have a counterpart that receives
 *          a response from kernel.
 */
#include "message.h"

/**
 * Does something?
 *
 * @param  socket         a file descriptor.
 * @param  encap_hdr_size ?
 * @return Number of bytes received on success or a negative error value on
 *         error.
 */ 
int hip_peek_recv_total_len(int socket, int encap_hdr_size)
{
	int bytes = 0, err = 0;
	int hdr_size = encap_hdr_size + sizeof(struct hip_common);
	char *msg = NULL;
	hip_common_t *hip_hdr = NULL;
	
        /* We're using system call here add thus reseting errno. */
	errno = 0;
	
	msg = (char *)malloc(hdr_size);
	
	if(msg == NULL) {
		HIP_ERROR("Error allocating memory.\n");
		err = -ENOMEM;
		goto out_err;
	}
	

	bytes = recvfrom(socket, msg, hdr_size, MSG_PEEK, NULL, NULL);
	
	if(bytes != hdr_size) {
		err = bytes;
		goto out_err;
	}

	hip_hdr = (struct hip_common *) (msg + encap_hdr_size);
	bytes = hip_get_msg_total_len(hip_hdr);
	
	if(bytes == 0) {
		err = -EBADMSG;
		errno = EBADMSG;
		HIP_ERROR("HIP message is of zero length.\n");
		goto out_err;
	} else if(bytes > HIP_MAX_PACKET) {
		err = -EMSGSIZE;
		errno = EMSGSIZE;
		HIP_ERROR("HIP message max length exceeded.\n");
		goto out_err;
	}

	bytes += encap_hdr_size;
	
 out_err:
	if (msg != NULL) {
		free(msg);
	}
	if (err != 0) {
		return err;
	}

	return bytes;
}

int hip_daemon_connect(int hip_user_sock) {
	int err = 0, n, len;
	int hip_agent_sock = 0;
	struct sockaddr_in6 daemon_addr;
	/* We're using system call here add thus reseting errno. */
	errno = 0;

	memset(&daemon_addr, 0, sizeof(daemon_addr));
        daemon_addr.sin6_family = AF_INET6;
        daemon_addr.sin6_port = htons(HIP_DAEMON_LOCAL_PORT);
        daemon_addr.sin6_addr = in6addr_loopback;

	HIP_IFEL(connect(hip_user_sock, (struct sockaddr *) &daemon_addr,
			 sizeof(daemon_addr)), -1,
		 "connection to daemon failed\n");

 out_err:

	return err;
}

int hip_daemon_bind_socket(int socket, struct sockaddr *sa) {
	int err = 0, port = 0, on = 1;
	struct sockaddr_in6 *addr = (struct sockaddr_in6 *) sa;

	HIP_ASSERT(addr->sin6_family == AF_INET6);

	errno = 0;

	setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	if (addr->sin6_port) {
		HIP_DEBUG("Bind to fixed port %d\n", addr->sin6_port);
		err = bind(socket,(struct sockaddr *)addr,
			   sizeof(struct sockaddr_in6));
		err = -errno;
		goto out_err;
	}

	for(port = 1023; port > 25; port--) {
                _HIP_DEBUG("trying bind() to port %d\n", port);
		addr->sin6_port = htons(port);
		err = bind(socket,(struct sockaddr *)addr,
			   hip_sockaddr_len(addr));
		if (err == -1) {
			if (errno == 13) {
				HIP_DEBUG("Use ephemeral port number in connect\n");
				err = 0;
				break;
			} else {
				HIP_ERROR("Error %d bind() wasn't succesful\n",
					  errno);
				err = -1;
				goto out_err;
			}
		}
		else {
			_HIP_DEBUG("Bind() to port %d successful\n", port);
			goto out_err;
		}
	}

	if (port == 26) {
		HIP_ERROR("All privileged ports were occupied\n");
		err = -1;
	}

 out_err:
	errno = 0;
	return err;
}

int hip_send_recv_daemon_info(struct hip_common *msg) {
	int hip_user_sock = 0, err = 0, n = 0, len = 0;
	struct sockaddr_in6 addr;

	/* We're using system call here add thus reseting errno. */
	errno = 0;

	/* Displays all debugging messages. */
	HIP_DEBUG("Handling DEBUG ALL user message.\n");
	HIP_IFEL(hip_set_logdebug(LOGDEBUG_ALL), -1,
			 "Error when setting daemon DEBUG status to ALL\n");

	HIP_IFE(((hip_user_sock = socket(AF_INET6, SOCK_DGRAM, 0)) < 0), EHIP);

	memset(&addr, 0, sizeof(addr));
        addr.sin6_family = AF_INET6;
        addr.sin6_addr = in6addr_loopback;
	HIP_IFEL(hip_daemon_bind_socket(hip_user_sock,
					(struct sockaddr *) &addr), -1,
		 "bind failed\n");

	HIP_IFEL(hip_daemon_connect(hip_user_sock), -1,
		 "connect failed\n");

	if ((len = hip_get_msg_total_len(msg)) < 0) {
		err = -EBADMSG;
		goto out_err;
	}
	
	n = send(hip_user_sock, msg, len, 0);
	if (n < len) {
		HIP_ERROR("Could not send message to daemon.\n");
		err = -ECOMM;
		goto out_err;
	}
	
	_HIP_DEBUG("Waiting to receive daemon info.\n");
	
	if((len = hip_peek_recv_total_len(hip_user_sock, 0)) < 0) {
		err = len;
		goto out_err;
	}

	n = recv(hip_user_sock, msg, len, 0);
	if (n == 0) {
		HIP_INFO("The HIP daemon has performed an "\
			 "orderly shutdown.\n");
		/* Note. This is not an error condition, thus we return zero. */
		goto out_err;
	} else if(n < sizeof(struct hip_common)) {
		HIP_ERROR("Could not receive message from daemon.\n");
		goto out_err;
	}
	
	if (hip_get_msg_err(msg)) {
		HIP_ERROR("HIP message contained an error.\n");
		err = -EHIP;
	}

 out_err:

	if (hip_user_sock)
		close(hip_user_sock);
	
	return err;
}


int hip_send_daemon_info_wrapper(struct hip_common *msg, int send_only) {
	int hip_user_sock = 0, err = 0, n, len;
	struct sockaddr_in6 addr;
	
	if (!send_only)
		return hip_send_recv_daemon_info(msg);

	HIP_IFE(((hip_user_sock = socket(AF_INET6, SOCK_DGRAM, 0)) < 0), -1);

	memset(&addr, 0, sizeof(addr));
        addr.sin6_family = AF_INET6;
        addr.sin6_addr = in6addr_loopback;

	HIP_IFEL(hip_daemon_bind_socket(hip_user_sock,
					(struct sockaddr *) &addr), -1,
		 "bind failed\n");

	HIP_IFEL(hip_daemon_connect(hip_user_sock), -1,
		 "connect failed\n");

	len = hip_get_msg_total_len(msg);
	n = send(hip_user_sock, msg, len, 0);
	if (n < len) {
		HIP_ERROR("Could not send message to daemon.\n");
		err = -1;
		goto out_err;
	}

 out_err:
	if (hip_user_sock)
		close(hip_user_sock);

	return err;
}

int hip_recv_daemon_info(struct hip_common *msg, uint16_t info_type) {
	/** @todo required by the native HIP API */
	/* Call first send_daemon_info with info_type and then recvfrom */
	return -1;
}

int hip_read_user_control_msg(int socket, struct hip_common *hip_msg,
			      struct sockaddr_in6 *saddr)
{
	int err = 0, bytes, hdr_size = sizeof(struct hip_common), total;
	socklen_t len;
	
	memset(saddr, 0, sizeof(*saddr));

	len = sizeof(*saddr);

	HIP_IFEL(((total = hip_peek_recv_total_len(socket, 0)) <= 0), -1,
		 "recv peek failed\n");
	
	_HIP_DEBUG("msg total length = %d\n", total);
	
	/** @todo Compiler warning;
	    warning: pointer targets in passing argument 6 of 'recvfrom'
	    differ in signedness. */
	HIP_IFEL(((bytes = recvfrom(socket, hip_msg, total, 0,
				    (struct sockaddr *) saddr,
				    &len)) != total), -1, "recv\n");

	HIP_DEBUG("received user message from local port %d\n", ntohs(saddr->sin6_port));
	_HIP_DEBUG("read_user_control_msg recv len=%d\n", len);
	_HIP_HEXDUMP("recv saddr ", saddr, sizeof(struct sockaddr_un));
	_HIP_DEBUG("read %d bytes succesfully\n", bytes);
 out_err:
	if (bytes < 0 || err)
		HIP_PERROR("perror: ");

	return err;
}

/* Moved function doxy descriptor to the header file. Lauri 11.03.2008 */
int hip_read_control_msg_all(int socket, struct hip_common *hip_msg,
                             struct in6_addr *saddr,
                             struct in6_addr *daddr,
                             hip_portpair_t *msg_info,
                             int encap_hdr_size, int is_ipv4)
{
	struct sockaddr_storage addr_from, addr_to;
	struct sockaddr_in *addr_from4 = ((struct sockaddr_in *) &addr_from);
	struct sockaddr_in6 *addr_from6 =
		((struct sockaddr_in6 *) &addr_from);
        struct cmsghdr *cmsg;
        struct msghdr msg;
	union {
		struct in_pktinfo *pktinfo_in4;
		struct in6_pktinfo *pktinfo_in6;
	} pktinfo;
        struct iovec iov;
        char cbuff[CMSG_SPACE(256)];
        int err = 0, len;
	int cmsg_level, cmsg_type;

	HIP_ASSERT(saddr);
	HIP_ASSERT(daddr);

	HIP_DEBUG("hip_read_control_msg_all() invoked.\n");

	HIP_IFEL(((len = hip_peek_recv_total_len(socket, encap_hdr_size))<= 0),
		 -1, "Bad packet length (%d)\n", len);

	memset(msg_info, 0, sizeof(hip_portpair_t));
	memset(&addr_to, 0, sizeof(addr_to));

        /* setup message header with control and receive buffers */
        msg.msg_name = &addr_from;
        msg.msg_namelen = sizeof(struct sockaddr_storage);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        memset(cbuff, 0, sizeof(cbuff));
        msg.msg_control = cbuff;
        msg.msg_controllen = sizeof(cbuff);
        msg.msg_flags = 0;

        iov.iov_len = len;
        iov.iov_base = hip_msg;

	pktinfo.pktinfo_in4 = NULL;

	len = recvmsg(socket, &msg, 0);

	HIP_IFEL((len < 0), -1, "ICMP%s error: errno=%d, %s\n",
		 (is_ipv4 ? "v4" : "v6"), errno, strerror(errno));

	cmsg_level = (is_ipv4) ? IPPROTO_IP : IPPROTO_IPV6;
	cmsg_type = (is_ipv4) ? IP_PKTINFO : IPV6_2292PKTINFO;

	/* destination address comes from ancillary data passed
	 * with msg due to IPV6_PKTINFO socket option */
	for (cmsg=CMSG_FIRSTHDR(&msg); cmsg; cmsg=CMSG_NXTHDR(&msg,cmsg)){
		if ((cmsg->cmsg_level == cmsg_level) && 
		    (cmsg->cmsg_type == cmsg_type)) {
			/* The structure is a union, so this fills also the
			   pktinfo_in6 pointer */
			pktinfo.pktinfo_in4 =
				(struct in_pktinfo*)CMSG_DATA(cmsg);
			break;
		}
	}
        
	/* If this fails, change IPV6_2292PKTINFO to IPV6_PKTINFO in
	   hip_init_raw_sock_v6 */
	HIP_IFEL(!pktinfo.pktinfo_in4, -1,
		 "Could not determine dst addr, dropping\n");

	/* UDP port numbers */
	if (is_ipv4 && encap_hdr_size == HIP_UDP_ZERO_BYTES_LEN) {
		/* Destination port is known from the bound socket. */
		HIP_DEBUG("hip_read_control_msg_all() source port = %d\n",
			  ntohs(addr_from4->sin_port));
		msg_info->src_port = ntohs(addr_from4->sin_port);
		/* The NAT socket is bound on port 50500, thus packets
		   received from NAT socket must have had 50500 as
		   destination port. */
		msg_info->dst_port = HIP_NAT_UDP_PORT; 
	}

	/* IPv4 addresses */
	if (is_ipv4) {
		struct sockaddr_in *addr_to4 = (struct sockaddr_in *) &addr_to;
		IPV4_TO_IPV6_MAP(&addr_from4->sin_addr, saddr);
		IPV4_TO_IPV6_MAP(&pktinfo.pktinfo_in4->ipi_addr,
				 daddr);
		addr_to4->sin_family = AF_INET;
		addr_to4->sin_addr = pktinfo.pktinfo_in4->ipi_addr;
		addr_to4->sin_port = msg_info->dst_port;
	} else /* IPv6 addresses */ {
		struct sockaddr_in6 *addr_to6 =
			(struct sockaddr_in6 *) &addr_to;
		memcpy(saddr, &addr_from6->sin6_addr,
		       sizeof(struct in6_addr));
		memcpy(daddr, &pktinfo.pktinfo_in6->ipi6_addr,
		       sizeof(struct in6_addr));
		addr_to6->sin6_family = AF_INET6;
		ipv6_addr_copy(&addr_to6->sin6_addr, daddr);
	}

	if (is_ipv4 && (encap_hdr_size == IPV4_HDR_SIZE)) {/* raw IPv4, !UDP */
		/* For some reason, the IPv4 header is always included.
		   Let's remove it here. */
		memmove(hip_msg, ((char *)hip_msg) + IPV4_HDR_SIZE,
			HIP_MAX_PACKET - IPV4_HDR_SIZE);
	} else if (is_ipv4 && encap_hdr_size == HIP_UDP_ZERO_BYTES_LEN) {
		/* remove 32-bits of zeroes between UDP and HIP headers */
		memmove(hip_msg, ((char *)hip_msg) + HIP_UDP_ZERO_BYTES_LEN,
			HIP_MAX_PACKET - HIP_UDP_ZERO_BYTES_LEN);
	}

	HIP_IFEL(hip_verify_network_header(hip_msg,
					   (struct sockaddr *) &addr_from,
					   (struct sockaddr *) &addr_to,
					   len - encap_hdr_size), -1,
		 "verifying network header failed\n");

	if (saddr)
		HIP_DEBUG_IN6ADDR("src", saddr);
	if (daddr)
		HIP_DEBUG_IN6ADDR("dst", daddr);

 out_err:
	return err;
}

int hip_read_control_msg_v6(int socket, struct hip_common *hip_msg,
			    struct in6_addr *saddr,
			    struct in6_addr *daddr,
                            hip_portpair_t *msg_info,
                            int encap_hdr_size)
{
	return hip_read_control_msg_all(socket, hip_msg, saddr,
					daddr, msg_info, encap_hdr_size, 0);
}

int hip_read_control_msg_v4(int socket, struct hip_common *hip_msg,
			    struct in6_addr *saddr,
			    struct in6_addr *daddr,
			    hip_portpair_t *msg_info,
			    int encap_hdr_size)
{
	return hip_read_control_msg_all(socket, hip_msg, saddr,
					daddr, msg_info, encap_hdr_size, 1);
}
