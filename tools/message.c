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
  return open(HIP_DEV_NAME, 0); // sets also errno
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

/**
 * send_msg - send an asynchronous message to the kernel (without open/close!)
 * @msg: the message to be sent to the HIP kernel module (maximum size is
 *       HIP_MAX_PACKET)
 *
 * Returns: zero on successful operation, or negative on error
 */
int send_msg(const struct hip_common *msg) {
  int err = 0, hipfd = -1;

  hipfd = open_hip(); // sets also errno
  if (hipfd < 0) {
    HIP_PERROR("hip device " HIP_DEV_NAME ":");
    err = -errno;
    goto out;
  }

  err = ioctl(hipfd, HIP_IOCSHIPUSERMSG, msg);
  if (err) {
    HIP_ERROR("ioctl failed (%d)\n", err);
    goto out_close;
  }

  _HIP_DUMP_MSG(msg);

 out_close:
  close(hipfd);
 out:
  return err;
}

