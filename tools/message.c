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

/**
 * open_hip - open the message channel for communicating with the HIP
 *            kernel module
 *
 * Returns: a file descriptor, or -1 if an error occurred. If an error
 * occurred, errno is also set.
 *
 */
int open_hip(void) {
  /* we're using the socket only for setting socket options, so the stream
     option could be anything */
  return socket(PF_HIP, SOCK_STREAM, 0);
}

/**
 * close_hip - open the channel for communicating with the HIP kernel module
 * @hipfd: the filehandle to be closed
 *
 * Returns: zero on success, or -1 if an error occurred.
 *
 */
int close_hip(int hipfd) {
  return close(hipfd);
}

int hip_set_global_option(const struct hip_common *msg) {
  int err = 0, hipfd = -1;

  hipfd = open_hip(); // sets also errno
  if (hipfd < 0) {
    HIP_ERROR("Failed to open HIP configuration channel\n");
    err = -errno;
    goto out;
  }

  err = setsockopt(hipfd, PF_HIP, SO_HIP_GLOBAL_OPT, msg,
		   hip_get_msg_total_len(msg));
  if (err) {
    HIP_ERROR("setsockopt failed (%d)\n", err);
    goto out_close;
  }

  _HIP_DUMP_MSG(msg);

 out_close:
  close(hipfd);
 out:
  return err;
}

int hip_get_global_option(struct hip_common *msg) {
  int err = 0, hipfd = -1;
  int msg_len = hip_get_msg_total_len(msg);

  hipfd = open_hip(); // sets also errno
  if (hipfd < 0) {
    HIP_ERROR("Failed to open HIP configuration channel\n");
    err = -errno;
    goto out;
  }

  /* The return value SHOULD fit into the msg */
  err = getsockopt(hipfd, PF_HIP, SO_HIP_GLOBAL_OPT, msg, &msg_len);
  if (err) {
    HIP_ERROR("getsockopt failed (%d)\n", err);
    goto out_close;
  }

  _HIP_DUMP_MSG(msg);

 out_close:
  close(hipfd);
 out:
  return err;
}

