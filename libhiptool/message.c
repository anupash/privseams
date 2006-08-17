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
	
	HIP_IFEL(!(msg = malloc(hdr_size)), -1, "malloc failed\n");
	
	HIP_IFEL(((bytes = recvfrom(socket, msg, hdr_size, MSG_PEEK,
				    NULL, NULL)) != hdr_size), -1,
		 "recv peek\n");
	
	hip_hdr = (struct hip_common *) (msg + encap_hdr_size);
	bytes = hip_get_msg_total_len(hip_hdr);
	HIP_IFEL((bytes > HIP_MAX_PACKET), -1, "packet too long\n");
	HIP_IFEL((bytes == 0), -1, "packet length is zero\n");
	bytes += encap_hdr_size;
	
 out_err:
	if (err)
		bytes = -1;
	if (msg)
		free(msg);
	return bytes;
}

int hip_send_recv_daemon_info(struct hip_common *msg) {
	int err = 0, n, len, hip_user_sock = 0;
	int hip_agent_sock = 0;
	socklen_t alen = 0;
	struct sockaddr_un app_addr, daemon_addr;
	char *app_name;
	
	/* Create and bind daemon socket. */
	hip_user_sock = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (hip_user_sock < 0)
	{
		HIP_ERROR("Failed to create socket.\n");
		err = -1;
		goto out_err;
	}

	HIP_IFEL(!(app_name = tmpnam(NULL)), -1, "app_name\n");
	_HIP_DEBUG("app_name: %s\n", app_name);
	//HIP_IFEL((creat(app_name, S_IRWXO) < 0), -1, "creat\n");

	bzero(&app_addr, sizeof(app_addr));
	app_addr.sun_family = AF_UNIX;
	strcpy(app_addr.sun_path, app_name);

	_HIP_HEXDUMP("app_addr", &app_addr,  sizeof(app_addr));

	bzero(&daemon_addr, sizeof(daemon_addr));
	daemon_addr.sun_family = AF_UNIX;
	strcpy(daemon_addr.sun_path, HIP_DAEMONADDR_PATH);
	_HIP_HEXDUMP("daemon_addr", &daemon_addr,  sizeof(daemon_addr));

	HIP_IFEL(bind(hip_user_sock,(struct sockaddr *)&app_addr, 
		      strlen(app_addr.sun_path) + sizeof(app_addr.sun_family)),
		 -1, "app_addr bind failed");

	n = connect(hip_user_sock,(struct sockaddr *)&daemon_addr, sizeof(daemon_addr));

	n = sendto(hip_user_sock, msg, hip_get_msg_total_len(msg), 
		   0,(struct sockaddr *)&daemon_addr, sizeof(daemon_addr));

	if (n < 0) {
		HIP_ERROR("Could not send message to daemon.\n");
		err = -1;
		goto out_err;
	}

	HIP_DEBUG("waiting to receive deamon info\n");
	//recv(hip_user_sock, msg, hip_get_msg_total_len(msg), 0);
	n = recvfrom(hip_user_sock, msg, hip_get_msg_total_len(msg), 
	     0,(struct sockaddr *)&daemon_addr, &alen);
	
	if (n < 0) {
		HIP_ERROR("Could not receive message from daemon.\n");
		err = -1;
		goto out_err;
	}
	else {
	  HIP_DEBUG("%d bytes received\n", n); 
	}

 out_err:
	if (hip_user_sock)
		close(hip_user_sock);
	return err;
}

int hip_send_daemon_info(const struct hip_common *msg) {
  	// return hip_send_recv_daemon_info(msg);
  
  	// do not call send_recv function here,
  	// since this function is called at several other places
	// TODO: copy send_recv function's recvfrom to hip_recv_daemon_info()

  	int err = 0, n, len, hip_user_sock = 0;
	struct sockaddr_un user_addr;
	socklen_t alen;
	
	// Create and bind daemon socket.
	hip_user_sock = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (hip_user_sock < 0)
	{
		HIP_ERROR("Failed to create socket.\n");
		err = -1;
		goto out_err;
	}

	bzero(&user_addr, sizeof(user_addr));
	user_addr.sun_family = AF_UNIX;
	strcpy(user_addr.sun_path, HIP_DAEMONADDR_PATH);
	alen = sizeof(user_addr);
	//HIP_HEXDUMP("packet", msg,  hip_get_msg_total_len(msg));
	n = sendto(hip_user_sock, msg, hip_get_msg_total_len(msg), 
			0,(struct sockaddr *)&user_addr, alen);
	if (n < 0) {
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
	/*! \todo required by the native HIP API */
	/* Call first send_daemon_info with info_type and then recvfrom */
	return -1;
  	//hip_send_daemon_info(msg);
	

}

int hip_read_user_control_msg(int socket, struct hip_common *hip_msg,
			      struct sockaddr_un *saddr)
{
	int err = 0, bytes, hdr_size = sizeof(struct hip_common), total, len;
	
	len = sizeof(*saddr);
	_HIP_HEXDUMP("original saddr ", saddr, sizeof(struct sockaddr_un));

	HIP_IFEL(((total = hip_peek_recv_total_len(socket, 0)) <= 0), -1,
		 "recv peek failed\n");
	
#if 0
	HIP_IFEL(((bytes = recvfrom(socket, hip_msg, hdr_size, MSG_PEEK,
				    (struct sockaddr *)saddr,
				    &len)) != hdr_size), -1,
		 "recv peek\n");
	
	_HIP_DEBUG("read_user_control_msg recv peek len=%d\n", len);
	_HIP_HEXDUMP("peek saddr ",  saddr, sizeof(struct sockaddr_un));

	total = hip_get_msg_total_len(hip_msg);
#endif

	_HIP_DEBUG("msg total length = %d\n", total);

	HIP_IFEL(((bytes = recvfrom(socket, hip_msg, total, 0, (struct sockaddr *)saddr,
				    &len)) != total), -1, "recv\n");

	_HIP_DEBUG("read_user_control_msg recv len=%d\n", len);
	_HIP_HEXDUMP("recv saddr ", saddr, sizeof(struct sockaddr_un));
	_HIP_DEBUG("read %d bytes succesfully\n", bytes);
 out_err:
	if (bytes < 0 || err)
		HIP_PERROR("perror: ");

	return err;
}

/**
 * hip_read_control_msg - prepares the hip_common struct,
 * allocates memory for buffers and nested structs. Receives
 * a message from socket and fills the hip_common struct with the
 * values from this message.
 * @param socket socket to read from
 * @param hip_common is returned as filled struct
 * @read addr:  flag whether the adresses should be read from the received packet
 *              1:read addresses, 0:don't read addresses
 * @param saddr is used as return value for the sender address of the received message
 *              (if read_addr is set to 1)
 * @param daddr is used as return value for the destination address of the received message
 *              (if read_addr is set to 1)
 *
 * Returns -1 in case of an error, >0 otherwise.
 */
int hip_read_control_msg_all(int socket, struct hip_common *hip_msg,
			    int read_addr, struct in6_addr *saddr,
			    struct in6_addr *daddr,
                            struct hip_stateless_info *msg_info,
                            int encap_hdr_size, int is_ipv4)
{
        struct sockaddr_storage addr_from;
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

	HIP_DEBUG("db1\n");
	HIP_IFEL(((len = hip_peek_recv_total_len(socket, encap_hdr_size)) <= 0), -1,
		 "Bad packet length (%d)\n", len);

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

	HIP_DEBUG("db2\n");
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
        
        HIP_DEBUG("db3\n");

	/* If this fails, change IPV6_2292PKTINFO to IPV6_PKTINFO in
	   hip_init_raw_sock_v6 */
	HIP_IFEL(!pktinfo.pktinfo_in4 && read_addr, -1,
		 "Could not determine dst addr, dropping\n");

	/* UDP port numbers */
	if (is_ipv4) {
		HIP_DEBUG("port number ntohs = %d\n",
			  ntohs(addr_from4->sin_port));
		msg_info->src_port = ntohs(addr_from4->sin_port);
	}

	/* IPv4 addresses */
	if (read_addr && is_ipv4) {
		if (saddr)
			IPV4_TO_IPV6_MAP(&addr_from4->sin_addr, saddr);
		if (daddr)
			IPV4_TO_IPV6_MAP(&pktinfo.pktinfo_in4->ipi_addr,
					 daddr);
	}

	/* IPv6 addresses */
	if (read_addr && !is_ipv4) {
		if (saddr)
			memcpy(saddr, &addr_from6->sin6_addr,
			       sizeof(struct in6_addr));
		if (daddr)
			memcpy(daddr, &pktinfo.pktinfo_in6->ipi6_addr,
			       sizeof(struct in6_addr));
	}

	if (saddr)
		HIP_DEBUG_IN6ADDR("src\n", saddr);
	if (daddr)
		HIP_DEBUG_IN6ADDR("dst\n", daddr);

 out_err:
	return err;
}


int hip_read_control_msg_v6(int socket, struct hip_common *hip_msg,
			    int read_addr, struct in6_addr *saddr,
			    struct in6_addr *daddr,
                            struct hip_stateless_info *msg_info,
                            int encap_hdr_size)
{
	return hip_read_control_msg_all(socket, hip_msg, read_addr, saddr,
					daddr, msg_info, encap_hdr_size, 0);

}

int hip_read_control_msg_v4(int socket, struct hip_common *hip_msg,
			    int read_addr, struct in6_addr *saddr,
			    struct in6_addr *daddr,
			    struct hip_stateless_info *msg_info,
			    int encap_hdr_size)
{
	return hip_read_control_msg_all(socket, hip_msg, read_addr, saddr,
					daddr, msg_info, encap_hdr_size, 1);

}
