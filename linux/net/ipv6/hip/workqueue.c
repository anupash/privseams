/*
 * Work queue functions for HIP
 * Authors: Kristian Slavov <ksl@iki.fi>
 *
 * Common comments: __get_cpu_var() is used instead of the get_cpu_var() since
 * each workqueue "listener" is bound to a certain cpu. Workorder is always inserted
 * into the workqueue of the sender. This is actually the only place where we would
 * like the adder to be in the same cpu as the workqueue he is adding to.
 * This is ensured by local_irq_save().
 *
 */
#include "workqueue.h"
#include "debug.h"

#include <asm/semaphore.h>
#include <asm/percpu.h>
#include <asm/system.h>
#include <linux/list.h>
#include <linux/interrupt.h>

/* HIP Per Cpu WorkQueue */
struct hip_pc_wq {
	struct semaphore *worklock;
	struct list_head *workqueue;
};

static DEFINE_PER_CPU(struct hip_pc_wq, hip_workqueue);

/**
 * hip_get_work_order - Get one work order from workqueue
 * 
 * HIP kernel daemons call this function when waiting for
 * work. They will sleep until a work order is received, which
 * is signalled by up()ing semaphore.
 * The received work order is removed from the workqueue and
 * returned to the kernel daemon for processing.
 * 
 * Returns work order or NULL, if an error occurs.
 */
struct hip_work_order *hip_get_work_order(void)
{
	unsigned long eflags;
	struct hip_pc_wq *wq;
	struct hip_work_order *result;

	wq = &__get_cpu_var(hip_workqueue);

	/* Wait for job */
	down(wq->worklock);

	/* every processor has its own worker thread, so
	   spin lock is not needed. Only local irq disabling
	*/
	local_irq_save(eflags); 

	if (list_empty(wq->workqueue)) {
		HIP_ERROR("Work queue empty?\n");
		result = NULL;
		goto err;
	}

	result = list_entry(wq->workqueue->next, struct hip_work_order, queue);
	if (!result) {
		HIP_ERROR("Couldn't extract the main structure from the list\n");
		result = NULL;
		goto err;
	}

	list_del(wq->workqueue->next);

 err:	
	local_irq_restore(eflags);
	return result;

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
static int hip_insert_work_order_cpu(struct hip_work_order *hwo, int cpu)
{
	unsigned long eflags;
	struct hip_pc_wq *wq;

	if (cpu >= NR_CPUS) {
		HIP_ERROR("Invalid CPU number: %d (max cpus: %d)\n",cpu, NR_CPUS);
		return -1;
	}

	local_irq_save(eflags);

	wq = &per_cpu(hip_workqueue, cpu);
	list_add_tail(&hwo->queue, wq->workqueue);
	
	local_irq_restore(eflags);
	up(wq->worklock);
	/* what is the correct order of these two? */
	return 1;
}

/**
 * hip_insert_work_order - Insert work order into the HIP working queue of the current CPU.
 * @hwo: Work order
 *
 * Returns 1 if ok, < 0 if error
 */
int hip_insert_work_order(struct hip_work_order *hwo)
{
	/* sanity check? */

	if (hwo->type < 0 || hwo->type > HIP_MAX_WO_TYPES)
		return -1;

	return hip_insert_work_order_cpu(hwo, smp_processor_id());
}


int hip_init_workqueue()
{
	struct list_head *lh;
	struct semaphore *sem;
	struct hip_pc_wq *data;

	lh = kmalloc(sizeof(struct list_head),GFP_KERNEL);
	if (!lh)
		return -ENOBUFS;

	sem = kmalloc(sizeof(struct semaphore), GFP_KERNEL);
	if (!sem) {
		kfree(lh);
		return -ENOBUFS;
	}

	INIT_LIST_HEAD(lh);
	init_MUTEX_LOCKED(sem);

	data = &__get_cpu_var(hip_workqueue);
	data->worklock = sem;
	data->workqueue = lh;
	return 0;
}

void hip_uninit_workqueue()
{
	struct list_head *pos,*iter;
	struct hip_pc_wq *wq;
	struct hip_work_order *hwo;

	local_bh_disable();
	wq = &__get_cpu_var(hip_workqueue);

	list_for_each_safe(pos, iter, wq->workqueue) {
		hwo = list_entry(pos,struct hip_work_order,queue);
		hip_free_work_order(hwo);
		list_del(pos);
	}
	kfree(wq->workqueue);
	kfree(wq->worklock);
	local_bh_enable();
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
		kfree(hwo);
	}
}

/**
 * hip_stop_khipd - Kill all khipd threads.
 *
 * Sends a kill message to all khipd threads. They will process them as soon as they
 * have the time. Another option would be to store all pids of khids and send them
 * a signal.
 */
void hip_stop_khipd()
{
	struct hip_work_order *hwo;
	int i;
	
	for(i=0; i<NR_CPUS; i++) {
		hwo = hip_init_job(GFP_KERNEL);
		if (!hwo) {
			HIP_ERROR("Could not allocate memory to send kill message to kernel thread. Reboot\n");
			BUG();
			return;
		}

		hwo->type = HIP_WO_TYPE_MSG;
		hwo->subtype = HIP_WO_SUBTYPE_STOP;

		hip_insert_work_order_cpu(hwo,i);
	}
}

/**
 * hip_init_job - Allocate and initialize work order
 * @gfp_mask: Mask for memory allocation
 *
 * Returns work order struct, with all fields zeroed. Or NULL in case
 * of error.
 */
struct hip_work_order *hip_init_job(int gfp_mask)
{
	struct hip_work_order *hwo;

	hwo = kmalloc(sizeof(struct hip_work_order),gfp_mask);
	if (!hwo) {
		HIP_ERROR("No memory for work order\n");
	}

	memset(hwo,0,sizeof(struct hip_work_order));
	return hwo;
}

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

	tmp = kmalloc(sizeof(struct in6_addr),gfp_mask);
	if (!tmp) {
		kfree(hwo);
		return NULL;
	}

	ipv6_addr_copy(tmp,hit);
	hwo->arg1 = tmp;
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
	if (hwo) {
		if (hwo->arg1)
			kfree(hwo->arg1);
		if (hwo->arg2)
			kfree(hwo->arg2);
	}
}
