#ifndef HIP_HIP_H
#define HIP_HIP_H

#ifdef __KERNEL__
#  include <linux/time.h>
#  include <linux/spinlock.h>
#  include <linux/crypto.h>
#  include <linux/list.h>
#  include <linux/socket.h>
#  include <asm/scatterlist.h>
#  include <linux/proc_fs.h>
#  include <linux/notifier.h>
#  include <linux/spinlock.h>
#  include <linux/xfrm.h>
#  include <linux/crypto.h>
#  include <net/protocol.h>
#  include <net/checksum.h>
#  include <net/hip_glue.h>
#  include <net/addrconf.h>
#  include <net/xfrm.h>
#  include <linux/suspend.h>
#  include <linux/completion.h>
#  include <linux/cpumask.h>
#  include "sysctl.h"
#else

#include <stdlib.h>
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
#include "hadb.h"
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

#ifdef KRISUS_THESIS

#define KMM_GLOBAL 1
#define KMM_PARTIAL 2
#define KMM_SPINLOCK 3

#define KRISU_START_TIMER(mod) do {\
   if (mod == kmm) {\
      gtv_inuse = 1;\
      do_gettimeofday(&gtv_start);\
   }\
 } while(0)

#define KRISU_STOP_TIMER(mod,msg) do {\
   if (mod == kmm) {\
      do_gettimeofday(&gtv_stop);\
      gtv_inuse = 0;\
      hip_timeval_diff(&gtv_start,&gtv_stop,&gtv_result);\
      HIP_INFO("%s: %ld usec\n", msg, \
               gtv_result.tv_usec + gtv_result.tv_sec * 1000000);\
   }\
 } while(0)

#else

#define KRISU_START_TIMER(x)
#define KRISU_STOP_TIMER(x,y)

#endif /* KRISUS_THESIS */

extern int kmm; // hip.c
extern struct timeval gtv_start, gtv_stop, gtv_result;
extern int gtv_inuse;

extern spinlock_t dh_table_lock;

#ifdef __KERNEL__
int hip_build_digest_repeat(struct crypto_tfm *dgst, struct scatterlist *sg, 
			    int nsg, void *out);
int hip_map_virtual_to_pages(struct scatterlist *slist, int *slistcnt, 
			     const u8 *addr, const u32 size);
#endif /* __KERNEL__ */
int hip_build_digest(const int type, const void *in, int in_len, void *out);
int hip_write_hmac(int type, void *key, void *in, int in_len, void *out);
int hip_ipv6_devaddr2ifindex(struct in6_addr *addr);
int hip_crypto_encrypted(void *, const void *, int, int, void*, int);
void hip_net_event(int ifindex, uint32_t event_src, uint32_t event);

//extern DH *dh_table[HIP_MAX_DH_GROUP_ID];  // see crypto/dh.[ch]
extern struct crypto_tfm *impl_sha1;
//extern struct semaphore hip_work;
extern struct socket *hip_output_socket;
//extern spinlock_t hip_workqueue_lock;
extern time_t load_time;

#ifdef CONFIG_SYSCTL
struct hip_sys_config {
	int hip_cookie_max_k_r1;
};
extern struct hip_sys_config hip_sys_config;
#endif

#endif /* HIP_HIP_H */
