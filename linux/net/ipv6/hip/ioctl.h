#ifndef HIP_KERNEL_IOCTL
#define HIP_KERNEL_IOCTL

#include <net/ip.h>
#include <net/ipv6.h>
#include <net/sock.h>
#include <net/addrconf.h>
#include <net/flow.h>
#include <net/hip.h>
#include <asm/string.h>
#include <asm/uaccess.h>
#include <asm/errno.h>
#include <linux/ioctl.h>
#include <linux/fs.h>
#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>   
#include <linux/slab.h>   
#include <linux/sched.h>
#include <linux/errno.h>    
#include <linux/types.h>    
#include <linux/skbuff.h>

#include "db.h"
#include "debug.h"
#include "daemon.h"
#include "builder.h"

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
