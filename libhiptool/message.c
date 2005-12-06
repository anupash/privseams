/*
 * HIP userspace communication mechanism between userspace and kernelspace.
 * The mechanism is used by hipd, hipconf and unittest.
 * 
 * Authors:
 * - Miika Komu <miika@iki.fi>
 *
 * TODO
 * - asynchronous term should be replaced with a better one
 * - async messages should also have a counterpart that receives
 *   a response from kernel
 */

#include "message.h"

int hip_send_daemon_info(const struct hip_common *msg) {
	int err = 0, n, len, hip_user_sock = 0;

	struct sockaddr_un user_addr;
	socklen_t alen;

	
	/* Create and bind daemon socket. */
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
	/* XX TODO: required by the native HIP API */
	/* Call first send_daemon_info with info_type and then recvfrom */
	return -1;
}

int hip_read_control_msg(int socket, struct hip_common *hip_msg,
			 int read_addr, struct in6_addr *saddr,
			 struct in6_addr *daddr)
{
        struct sockaddr_in6 addr_from;
        struct cmsghdr *cmsg;
        struct msghdr msg;
        struct in6_pktinfo *pktinfo = NULL;
        struct iovec iov;
        char cbuff[CMSG_SPACE(256)];
        int err = 0, len;

        /* setup message header with control and receive buffers */
        msg.msg_name = &addr_from;
        msg.msg_namelen = sizeof(struct sockaddr_in6);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;

        memset(cbuff, 0, sizeof(cbuff));
        msg.msg_control = cbuff;
        msg.msg_controllen = sizeof(cbuff);
        msg.msg_flags = 0;

        iov.iov_len = HIP_MAX_PACKET;
        iov.iov_base = hip_msg;

	len = recvmsg(socket, &msg, 0);

	/* ICMPv6 packet */
	HIP_IFEL(len < 0, -1, "ICMPv6 error: errno=%d, %s\n",
		 errno, strerror(errno));

	/* destination address comes from ancillary data passed
	 * with msg due to IPV6_PKTINFO socket option */
	for (cmsg=CMSG_FIRSTHDR(&msg); cmsg; cmsg=CMSG_NXTHDR(&msg,cmsg)){
		if ((cmsg->cmsg_level == IPPROTO_IPV6) && 
		    (cmsg->cmsg_type == IPV6_PKTINFO)) {
			pktinfo = (struct in6_pktinfo*)CMSG_DATA(cmsg);
			break;
		}
	}

#if 0
	HIP_IFEL(!pktinfo && read_addr, -1,
		 "Could not determine IPv6 dst, dropping\n");
#endif

	if (read_addr) {
		memcpy(daddr, &pktinfo->ipi6_addr, sizeof(struct in6_addr));
		memcpy(saddr, &addr_from.sin6_addr, sizeof(struct in6_addr));
		HIP_DEBUG_IN6ADDR("packet src addr\n", saddr);
		HIP_DEBUG_IN6ADDR("packet dst addr\n", daddr);
	}
	
 out_err:
	return err;
}
