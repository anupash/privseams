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

int hip_send_daemon_msg(const struct hip_common *msg) {
	int err = 0;
	struct hip_nl_handle hip_nl_msg;

	memset(&hip_nl_msg, 0, sizeof(struct hip_nl_handle));

	if (hip_netlink_open(&hip_nl_msg, 0, NETLINK_HIP) < 0) {
		HIP_ERROR("Failed to open HIP configuration channel\n");
		err = -1;
		goto out_err;
	}

	err = hip_netlink_send_buf(&hip_nl_msg, (const char *) msg,
				   hip_get_msg_total_len(msg));
	if (err) {
		HIP_ERROR("Sending of HIP msg failed (%d)\n", err);
		goto out_err;
	}

	_HIP_DUMP_MSG(msg);

out_err:
	if (hip_nl_msg.fd)
		hip_netlink_close(&hip_nl_msg);

	return err;
}

int hip_recv_daemon_msg(struct hip_common *msg) {
	/* XX TODO: required by the native HIP API */
	return -1;
}

