/*
 * Work queue functions for HIP
 *
 * Licence: GNU/GPL
 * Authors:
 * - Kristian Slavov <ksl@iki.fi>
 *
 * Common comments: __get_cpu_var() is used instead of the get_cpu_var() since
 * each workqueue "listener" is bound to a certain cpu. Workorder is always
 * inserted into the workqueue of the sender. This is actually the only place
 * where we would like the adder to be in the same cpu as the workqueue he is
 * adding to. This is ensured by local_irq_save().
 *
 */
#ifdef __KERNEL__
#include <asm/semaphore.h>
#include <asm/percpu.h>
#include <asm/system.h>
#include <linux/list.h>
#include <linux/interrupt.h>
#endif

#include "list.h"
#include "workqueue.h"
#include "netlink.h" /* hip_netlink_* functions */
#include "debug.h"
#include "builder.h"

#ifdef __KERNEL__
/* HIP Per Cpu WorkQueue */
struct hip_pc_wq {
	struct semaphore worklock;
	struct list_head workqueue;
};

static DEFINE_PER_CPU(struct hip_pc_wq, hip_workqueue);
#endif

/**
 * hip_get_work_order - Get one work order from workqueue
 * 
 * HIP daemons call this function when waiting for
 * work. They will sleep until a work order is received, which
 * is signalled by up()ing semaphore.
 * The received work order is removed from the workqueue and
 * returned to the kernel daemon for processing.
 * 
 * Returns work order or NULL, if an error occurs.
 */
#ifndef CONFIG_HIP_USERSPACE
static inline struct hip_work_order *hip_get_work_order_cpu(void)
{
	struct hip_work_order *result;
	unsigned long eflags;
	struct hip_pc_wq *wq;
	int locked;

	/* get_cpu_var / put_cpu_var ? */
	wq = &__get_cpu_var(hip_workqueue);

	/* Wait for job */
	locked = down_interruptible(&wq->worklock);
	if (locked) {
		if (locked == -EINTR)
			HIP_DEBUG("interrupted while trying to get lock\n");
		return NULL;
	}

	/* every processor has its own worker thread, so
	   spin lock is not needed. Only local irq disabling */
	local_irq_save(eflags);

	if (list_empty(&wq->workqueue)) {
		HIP_ERROR("Work queue empty?\n");
		result = NULL;
		goto err;
	}

	result = list_entry((&wq->workqueue)->next, struct hip_work_order, queue);
	if (!result) {
		HIP_ERROR("Couldn't extract the main structure from the list\n");
		result = NULL;
		goto err;
	}

	list_del((&wq->workqueue)->next);

 err:	
	local_irq_restore(eflags);
	return result;
}
#endif

/**
 * hip_get_work_order - Get one work order from workqueue
 * 
 * HIP daemons call this function when waiting for
 * work. They will sleep until a work order is received, which
 * is signalled by up()ing semaphore.
 * The received work order is removed from the workqueue and
 * returned to the kernel daemon for processing.
 * 
 * Returns work order or NULL, if an error occurs.
 */
struct hip_work_order *hip_get_work_order(void)
{
#ifndef CONFIG_HIP_USERSPACE
     return hip_get_work_order_cpu();
#else
     return hip_netlink_receive();
#endif
}

/**
 * hip_insert_work_order_cpu - Insert a work order on a particular CPU's workqueue
 * @hwo: Work order to be inserted
 * @cpu: Cpu number
 *
 * Adds the work order into @cpu CPU's HIP workqueue. Mainly useful to send messages
 * to another kernel daemons from one kernel daemon or user thread (ioctl etc)
 * This function is static in purpose. Normally this shouldn't be used. Instead use
 * the variant below.
 *
 * Returns 1, if ok. -1 if error
 */
#ifndef CONFIG_HIP_USERSPACE
static inline int hip_insert_work_order_cpu(struct hip_work_order *hwo, int cpu)
{
	unsigned long eflags;
	struct hip_pc_wq *wq;

	if (cpu >= NR_CPUS) {
		HIP_ERROR("Invalid CPU number: %d (max cpus: %d)\n", cpu, NR_CPUS);
		return -1;
	}

	if (!hwo) {
		HIP_ERROR("NULL hwo\n");
		return -1;
	}

	_HIP_DEBUG("hwo=0x%p cpu=%d\n", hwo, cpu);
	local_irq_save(eflags);

	/* get_cpu_var / put_cpu_var ? */
	wq = &per_cpu(hip_workqueue, cpu);
	if (wq) {
		list_add_tail(&hwo->queue, &wq->workqueue);
		/* what is the correct order of these two, l_i_r and up ? */
		up(&wq->worklock);
	} else
		HIP_ERROR("NULL wq, aieee!\n");

	local_irq_restore(eflags);
	return 1;
}
#endif

/**
 * hip_insert_work_order - Insert work order into the HIP working queue.
 * @hwo: Work order
 *
 * Returns 1 if ok, < 0 if error
 */
int hip_insert_work_order(struct hip_work_order *hwo)
{
	if (!hwo) {
		HIP_ERROR("NULL hwo\n");
		return -1;
	}

	if (hwo->hdr.type < 0 || hwo->hdr.type > HIP_MAX_WO_TYPES)
		return -1;

#ifndef CONFIG_HIP_USERSPACE
	return hip_insert_work_order_cpu(hwo, smp_processor_id());
#else
	return hip_netlink_send(hwo);
#endif
}

int hip_init_workqueue()
{
#ifndef CONFIG_HIP_USERSPACE
	struct hip_pc_wq *wq;
	unsigned long eflags;

	local_irq_save(eflags);

 	wq = &get_cpu_var(hip_workqueue);
 	INIT_LIST_HEAD(&wq->workqueue);
 	init_MUTEX_LOCKED(&wq->worklock);
 	put_cpu_var(hip_workqueue);
 	local_irq_restore(eflags);
#endif
	return 0;
}

void hip_uninit_workqueue()
{
#ifndef CONFIG_HIP_USERSPACE
	struct list_head *pos,*iter;
	struct hip_pc_wq *wq;
	struct hip_work_order *hwo;
	unsigned long eflags;

	local_irq_save(eflags);
 	//local_bh_disable();
 	/* get_cpu_var / put_cpu_var ? */
	//	wq = &__get_cpu_var(hip_workqueue);
	wq = &get_cpu_var(hip_workqueue);
	list_for_each_safe(pos, iter, &wq->workqueue) {
		hwo = list_entry(pos, struct hip_work_order, queue);
		hip_free_work_order(hwo);
		list_del(pos);
	}
 	put_cpu_var(hip_workqueue); // test
	local_irq_restore(eflags);
#endif
}

/**
 * hip_free_work_order - Free work order structure
 * @hwo: Work order to be freed
 *
 * Don't use @hwo after this function. The memory is freed.
 */
void hip_free_work_order(struct hip_work_order *hwo)
{
	if (hwo) {
		if (hwo->destructor)
			hwo->destructor(hwo);
		HIP_FREE(hwo);
	}
}

/**
 * hip_init_job - Allocate and initialize work order
 * @gfp_mask: Mask for memory allocation
 *
 * Returns work order struct, with all fields zeroed. Or %NULL in case
 * of error.
 */
struct hip_work_order *hip_init_job(int gfp_mask)
{
	struct hip_work_order *hwo;

	hwo = HIP_MALLOC(sizeof(struct hip_work_order), gfp_mask);
	if (hwo)
		memset(hwo, 0, sizeof(struct hip_work_order));		
	else
		HIP_ERROR("No memory for work order\n");

	return hwo;
}

#if 0
/* tkoponen: this kind of functionality duplication seems stupid, remove? */
/**
 * hip_create_job_with_hit - Create work order and add HIT as a first argument
 * @gfp_mask: Mask for memory allocation
 * @hit: HIT to be added
 *
 * Allocates and initializes work order with HIT as the first argument.
 * The memory for HIT is also allocated and the HIT is copied.
 */
struct hip_work_order *hip_create_job_with_hit(int gfp_mask, 
                                               const struct in6_addr *hit)
{
	struct hip_work_order *hwo;
	struct in6_addr *tmp;

	hwo = hip_init_job(gfp_mask);
	if (!hwo)
		return NULL;

	tmp = HIP_MALLOC(sizeof(struct in6_addr), gfp_mask);
	if (!tmp) {
		HIP_FREE(hwo);
		return NULL;
	}

	ipv6_addr_copy(tmp, hit);
	hwo->arg1 = tmp;
	hwo->arg2 = NULL;
	hwo->destructor = hwo_default_destructor;
	return hwo;
}

/**
 * hwo_default_destructor - Default destructor for work order
 *
 * Simple... if you don't understand, then you shouldn't be
 * dealing with the kernel.
 */
void hwo_default_destructor(struct hip_work_order *hwo)
{
	if (hwo && hwo->msg)
          HIP_FREE(hwo->msg);
}
#endif
