/*
 * Work queue functions for HIP
 * Authors: Kristian Slavov <ksl@iki.fi>
 *
 */

#include "workqueue.h"

struct hip_pc_wq {
	struct semaphore *worklock;
	struct list_head *workqueue;
};

static DEFINE_PER_CPU(struct hip_pc_wq, hip_workqueue);

/* SLEEPS! */
struct hip_work_order *hip_get_work_order(void)
{
	unsigned long eflags;
	struct hip_pc_wq *wq;
	struct hip_work_order *result;

	wq = &__get_cpu_var(hip_workqueue);

	HIP_ERROR("Debug data 1\n");
	HIP_ERROR("wq: %p\n",wq);
	HIP_ERROR("worklock: %p (cnt: %d, sleepz: %d)\n",wq->worklock, atomic_read(&wq->worklock->count), wq->worklock->sleepers);
	HIP_ERROR("workqueue: %p (%p <-> %p)\n",wq->workqueue, wq->workqueue->prev, wq->workqueue->next);

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

	HIP_ERROR("Some debug data 2\n");
	HIP_ERROR("wq: %p\n",wq);
	HIP_ERROR("worklock: %p (cnt: %d, sleepz: %d)\n",wq->worklock, atomic_read(&wq->worklock->count), wq->worklock->sleepers);
	HIP_ERROR("workqueue: %p (%p <-> %p)\n",wq->workqueue, wq->workqueue->prev, wq->workqueue->next);

	result = list_entry(wq->workqueue->next, struct hip_work_order, queue);
	if (!result) {
		HIP_ERROR("Couldn't extract the main structure from the list\n");
		result = NULL;
		goto err;
	}

	HIP_ERROR("Some debug data 3\n");
	HIP_ERROR("wq: %p\n",wq);
	HIP_ERROR("worklock: %p (cnt: %d, sleepz: %d)\n",wq->worklock, atomic_read(&wq->worklock->count), wq->worklock->sleepers);
	HIP_ERROR("workqueue: %p (%p <-> %p)\n",wq->workqueue, wq->workqueue->prev, wq->workqueue->next);

	list_del(wq->workqueue->next);

 err:	
	local_irq_restore(eflags);
	return result;

}

int hip_insert_work_order(struct hip_work_order *hwo)
{
	unsigned long eflags;
	struct hip_pc_wq *wq;

	/* sanity check? */

	if (hwo->type < 0 || hwo->type > HIP_MAX_WO_TYPES)
		return -1;

	HIP_ERROR("Inserting a nakki\n");

	wq = &__get_cpu_var(hip_workqueue);

	HIP_ERROR("Some debug data 4\n");
	HIP_ERROR("wq: %p\n",wq);
	HIP_ERROR("worklock: %p (cnt: %d, sleepz: %d)\n",wq->worklock, atomic_read(&wq->worklock->count), wq->worklock->sleepers);
	HIP_ERROR("workqueue: %p (%p <-> %p)\n",wq->workqueue, wq->workqueue->prev, wq->workqueue->next);

	local_irq_save(eflags);

	list_add_tail(&hwo->queue,wq->workqueue);

	HIP_ERROR("Some debug data 5\n");
	HIP_ERROR("wq: %p\n",wq);
	HIP_ERROR("worklock: %p (cnt: %d, sleepz: %d)\n",wq->worklock, atomic_read(&wq->worklock->count), wq->worklock->sleepers);
	HIP_ERROR("workqueue: %p (%p <-> %p)\n",wq->workqueue, wq->workqueue->prev, wq->workqueue->next);

	up(wq->worklock); // tell the worker, that there is work
	local_irq_restore(eflags);
	return 1;
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

	HIP_ERROR("HIP Semaphore initial: %d\n",atomic_read(&sem->count));

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

	wq = &__get_cpu_var(hip_workqueue);

	list_for_each_safe(pos, iter, wq->workqueue) {
		hwo = list_entry(pos,struct hip_work_order,queue);
		if (hwo) {
			if (hwo->arg1)
				kfree(hwo->arg1);
			if (hwo->arg2)
				kfree(hwo->arg2);
			kfree(hwo);
		}
		list_del(pos);
	}
	kfree(wq->workqueue);
	/* XXX: is there a possiblity that somebody would be using the semaphore? */
	kfree(wq->worklock);
}

/* XXX: Redesign this one, to enable killing all the threads. */
void hip_stop_khipd()
{
	struct hip_work_order *hwo;

	hwo = hip_init_job(GFP_KERNEL);
	if (!hwo)
		return;

	hwo->type = HIP_WO_TYPE_MSG;
	hwo->subtype = HIP_WO_SUBTYPE_STOP;

	hip_insert_work_order(hwo);
}

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

struct hip_work_order *hip_create_job_with_hit(int gfp_mask, 
					       struct in6_addr *hit)
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
	return hwo;
}

