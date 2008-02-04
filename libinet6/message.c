/*
 * HIP userspace communication mechanism between userspace and kernelspace.
 * The mechanism is used by hipd, hipconf and unittest.
 * 
 * Authors:
 * - Miika Komu <miika@iki.fi>
 * - Bing Zhou <bingzhou@cc.hut.fi>
 *
 * TODO
 * - asynchronous term should be replaced with a better one
 * - async messages should also have a counterpart that receives
 *   a response from kernel
 */

#include "message.h"

int hip_peek_recv_total_len(int socket, int encap_hdr_size)
{
	int bytes = 0, err = 0;
	int hdr_size = encap_hdr_size + sizeof(struct hip_common);
	char *msg = NULL;
	struct hip_common *hip_hdr = NULL;
	
	HIP_IFEL(!(msg = malloc(hdr_size)), -1, "malloc (%d)failed\n",
		 hdr_size);
	
	HIP_IFEL(((bytes = recvfrom(socket, msg, hdr_size, MSG_PEEK,
				    NULL, NULL)) != hdr_size), -1,
		 "recv peek\n");
	
	hip_hdr = (struct hip_common *) (msg + encap_hdr_size);
	bytes = hip_get_msg_total_len(hip_hdr);
	HIP_IFEL((bytes > HIP_MAX_PACKET), -1, "packet too long\n");
	HIP_IFEL((bytes == 0), -1, "packet length is zero\n");
	bytes += encap_hdr_size;
	
 out_err:
	_HIP_DEBUG("bytes= %d  hdr_size = %d\n", bytes, hdr_size);
	if (err)
		bytes = -1;
	if (msg)
		free(msg);
	return bytes;
}

int hip_daemon_connect(int hip_user_sock, struct hip_common *msg) {
	int err = 0, n, len; // app_fd = 0;
	int hip_agent_sock = 0;
	//socklen_t alen = 0;
	//struct sockaddr_un app_addr, daemon_addr;
	struct sockaddr_in6 daemon_addr;

        bzero(&daemon_addr, sizeof(daemon_addr));
        daemon_addr.sin6_family = AF_INET6;
        daemon_addr.sin6_port = HIP_DAEMON_LOCAL_PORT;
        daemon_addr.sin6_addr = in6addr_loopback;

	HIP_IFEL(connect(hip_user_sock, (struct sockaddr *) &daemon_addr,
			 sizeof(daemon_addr)), -1,
		 "connection to daemon failed\n");

 out_err:

	return err;
}

int hip_send_recv_daemon_info(struct hip_common *msg) {
	int hip_user_sock = 0, err = 0, n, len;

	HIP_IFE(((hip_user_sock = socket(AF_INET6, SOCK_DGRAM, 0)) < 0), -1);

	HIP_IFEL(err = hip_daemon_connect(hip_user_sock, msg), -1,
		 "Sending of msg failed (no rcv)\n");

	len = hip_get_msg_total_len(msg);
	n = send(hip_user_sock, msg, len, 0);
	if (n < len) {
		HIP_ERROR("Could not send message to daemon.\n");
		err = -1;
		goto out_err;
	}

	_HIP_DEBUG("waiting to receive daemon info\n");

	n = recv(hip_user_sock, msg,
		 hip_peek_recv_total_len(hip_user_sock, 0), 0);
	if (n < sizeof(struct hip_common)) {
		HIP_ERROR("Could not receive message from daemon.\n");
		err = -1;
		goto out_err;
	} else {
		_HIP_DEBUG("%d bytes received\n", n); 
		
	}

	if (hip_get_msg_err(msg)) {
		HIP_ERROR("msg contained error\n");
	}

 out_err:

	if (hip_user_sock)
		close(hip_user_sock);
	return err;
}


int hip_send_daemon_info_wrapper(struct hip_common *msg, int send_only) {
	int hip_user_sock = 0, err = 0, n, len;

	if (!send_only)
		return hip_send_recv_daemon_info(msg);
	
	HIP_IFE(((hip_user_sock = socket(AF_INET6, SOCK_DGRAM, 0)) < 0), -1);

	HIP_IFEL(err = hip_daemon_connect(hip_user_sock, msg), -1,
		 "Sending of msg failed (no rcv)\n");

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
  	//hip_send_daemon_info(msg);
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
	
	/* TODO: Compiler warning;
	   warning: pointer targets in passing argument 6 of 'recvfrom'
	   differ in signedness. */
	HIP_IFEL(((bytes = recvfrom(socket, hip_msg, total, 0,
				    (struct sockaddr *) saddr,
				    &len)) != total), -1, "recv\n");

	HIP_DEBUG("received user message from local port %d\n", saddr->sin6_port);
	_HIP_DEBUG("read_user_control_msg recv len=%d\n", len);
	_HIP_HEXDUMP("recv saddr ", saddr, sizeof(struct sockaddr_un));
	_HIP_DEBUG("read %d bytes succesfully\n", bytes);
 out_err:
	if (bytes < 0 || err)
		HIP_PERROR("perror: ");

	return err;
}

/**
 * Prepares a @c hip_common struct based on information received from a socket.
 * 
 * Prepares a @c hip_common struct, allocates memory for buffers and nested
 * structs. Receives a message from socket and fills the @c hip_common struct
 * with the values from this message.
 *
 * @param socket         a socket to read from.
 * @param hip_msg        a pointer to a buffer where to put the received HIP
 *                       common header. This is returned as filled struct.
 * @param read_addr      a flag whether the adresses should be read from the
 *                       received packet. <b>1</b>:read addresses,
 *                       <b>0</b>:don't read addresses.
 * @param saddr          a pointer to a buffer where to put the source IP
 *                       address of the received message (if @c read_addr is set
 *                       to 1).
 * @param daddr          a pointer to a buffer where to put the destination IP
 *                       address of the received message (if @c read_addr is set
 *                       to 1).
 * @param msg_info       a pointer to a buffer where to put the source and 
 *                       destination ports of the received message.
 * @param encap_hdr_size size of encapsulated header in bytes.
 * @param is_ipv4        a boolean value to indicate whether message is received
 *                       on IPv4.
 * @return               -1 in case of an error, 0 otherwise.
 */
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
	if (is_ipv4 && encap_hdr_size == 0) {
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
