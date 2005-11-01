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

int hip_user_sock = 0;

int hip_send_daemon_info(const struct hip_common *msg) {
	int err = 0, n, len;
	struct sockaddr_un user_addr;
	socklen_t alen;

	/* Allocate message. */
	//HIP_IFE(((msg = hip_msg_alloc()) == NULL), -1);
	HIP_DEBUG("msg length %d\n", hip_get_msg_total_len(msg));
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
	strcpy(user_addr.sun_path, HIP_DAEMONADDR_PATH);// tmpnam(NULL));
#if 0
	HIP_IFEL(bind(hip_user_sock, (struct sockaddr *)&user_addr,
		      /*sizeof(user_addr)*/
			strlen(user_addr.sun_path) + sizeof(user_addr.sun_family)),
		 -1, "Bind failed.\n");
#endif
	alen = sizeof(user_addr);
	n = sendto(hip_user_sock, msg, hip_get_msg_total_len(msg)/*sizeof(struct hip_common)*/, 
			0,(struct sockaddr *)&user_addr, alen);
	if (n < 0) {
		HIP_ERROR("Could not send message to daemon.\n");
		err = -1;
		goto out_err;
	}else {
		HIP_DEBUG("Sent %d bytes\n", n);
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

