#ifndef _LINUX_HIP_IOCTL
#define _LINUX_HIP_IOCTL

#include <net/hip.h>

#ifdef __KERNEL__
#  include <linux/ioctl.h>
#  include <linux/in6.h>
#  include <linux/time.h>
#else
#  include <sys/ioctl.h>
#endif /* __KERNEL__ */

/*
 * Authors:
 * - Janne Lundberg <jlu@tcs.hut.fi>
 * - Miika Komu <miika@iki.fi>
 * - Mika Kousa <mkousa@cc.hut.fi>
 *
 * TODO
 * - jlu:  we only give a HIT. Eventually hip_lhid will also give 
 *   a public key to the kernel
 */

#define HIP_CHAR_MAJOR 126
#define HIP_CHAR_NAME "hip"
#define HIP_DEV_NAME  "/dev/hip"

#define HIP_IOC_MAGIC 'k'
#define HIP_IOC_MAX   15

#define HIP_IOCSHIPDASYNCMSG _IOW(HIP_IOC_MAGIC, 1, struct hip_common)
#define HIP_IOCSTEST _IO(HIP_IOC_MAGIC, 15)

#endif /* _LINUX_HIP_IOCTL */
