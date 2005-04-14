#ifndef HIP_HIP_H
#define HIP_HIP_H

#ifdef __KERNEL__
#  include <linux/time.h>
#  include <linux/spinlock.h>
#  include <linux/list.h>
#  include <linux/socket.h>
#  include <asm/scatterlist.h>
#  include <linux/proc_fs.h>
#  include <linux/notifier.h>
#  include <linux/spinlock.h>
#  include <linux/xfrm.h>
#  include <net/protocol.h>
#  include <net/checksum.h>
#  include <net/hip_glue.h>
#  include <net/addrconf.h>
#  include <net/xfrm.h>
#  include <linux/suspend.h>
#  include <linux/completion.h>
#  include <linux/cpumask.h>
#  include "sysctl.h"
#  include "proc.h"
#else

#define jiffies random()
#include "list.h"

#define atomic_inc(x) \
         (++(*x).counter)

#define atomic_read(x) \
         ((*x).counter)

#define atomic_dec_and_test(x) \
         (--((*x).counter) == 0)

#define atomic_set(x, v) \
         ((*x).counter = v)

/* XX FIX: implement the locking for userspace properly */
#define read_lock_irqsave(a,b) do {} while(0)
#define spin_unlock_irqrestore(a,b) do {} while(0)
#define write_lock_irqsave(a,b) do {} while(0)
#define write_unlock_irqrestore(a,b) do {} while(0)
#define read_unlock_irqrestore(a,b) do {} while(0)

#ifndef MIN
#  define MIN(a,b)	((a)<(b)?(a):(b))
#endif

#ifndef MAX
#  define MAX(a,b)	((a)>(b)?(a):(b))
#endif

/* XX FIXME: implement with a userspace semaphore etc? */
#define wmb() do {} while(0)
#define barrier() do {} while(0)

#endif /* __KERNEL__ */

#include <net/hip.h>
#include "input.h"
#include "builder.h"
#include "hidb.h"
#include "cookie.h"
#include "keymat.h"
#include "misc.h"
#include "output.h"
#include "workqueue.h"
#include "socket.h"
#include "update.h"
#ifdef CONFIG_HIP_RVS
#include "rvs.h"
#endif

/* used by hip worker to announce completion of work order */
#define KHIPD_OK                   0
#define KHIPD_QUIT                -1
#define KHIPD_ERROR               -2
#define KHIPD_UNRECOVERABLE_ERROR -3
#define HIP_MAX_SCATTERLISTS       5 // is this enough?

#ifdef __KERNEL__
int hip_map_virtual_to_pages(struct scatterlist *slist, int *slistcnt, 
			     const u8 *addr, const u32 size);
#endif /* __KERNEL__ */
int hip_ipv6_devaddr2ifindex(struct in6_addr *addr);
void hip_net_event(int ifindex, uint32_t event_src, uint32_t event);

extern struct socket *hip_output_socket;
extern time_t load_time;

#endif /* HIP_HIP_H */


