#ifndef HIP_KERNEL_IOCTL
#define HIP_KERNEL_IOCTL

#include <linux/spinlock.h>
#include <net/hip.h>

/*
 * Async message is sent from userspace to kernel. The response is created
 * into the same message. The lock is here to save some
 * memory allocations so that this struct could be used by several
 * ioctl() calls same time and mutual exclusion could still be
 * guaranteed.
 */
struct hip_user_msg {
	spinlock_t lock;
	struct hip_common *msg;
};

int hip_init_ioctl(void);
void hip_uninit_ioctl(void);

extern int (*hip_user_msg_handler[])(const struct hip_common *,
				     struct hip_common *);
extern struct hip_user_msg hip_user_msg;

#endif /* HIP_KERNEL_IOCTL */
