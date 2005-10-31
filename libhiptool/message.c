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
	int err = 0;
	
	/* XX TODO:
	   - create UNIX local domain socket (UDP)
	   - connect(HIP_DAEMON_PORT)
	   - send(msg) */
	err = -1;
	return err;
}

int hip_recv_daemon_info(struct hip_common *msg, uint16_t info_type) {
	/* XX TODO: required by the native HIP API */
	return -1;
}

