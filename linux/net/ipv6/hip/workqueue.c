/*
 * Work queue functions for HIP
 * Authors: Kristian Slavov <ksl@iki.fi>
 *
 */

#include "workqueue.h"

static struct list_head *hip_workqueue;

struct hip_work_order *hip_get_work_order(void)
{
	int eflags;
	struct hip_work_order *result;

	/* every processor has its own worker thread, so
	   spin lock is not needed. Only local irq disabling
	*/
	local_irq_save(eflags); 

	if (list_empty(hip_workqueue)) {
		HIP_ERROR("Work queue empty?\n");
		result = NULL;
		goto err;
	}

	result = list_entry(hip_workqueue->next, struct hip_work_order, queue);
	if (!result) {
		HIP_ERROR("Couldn't extract the main structure from the list\n");
		result = NULL;
		goto err;
	}

	list_del(hip_workqueue->next);

 err:	
	local_irq_restore(eflags);
	return result;

}

int hip_insert_work_order(struct hip_work_order *hwo)
{
	int eflags;

	/* sanity check? */

	if (hwo->type < 0 || hwo->type > HIP_MAX_WO_TYPES)
		return -1;

	HIP_DEBUG("Inserting a nakki\n");
	local_irq_save(eflags);

	list_add_tail(&hwo->queue,hip_workqueue);

	up(&hip_work); // tell the worker, that there is work
	local_irq_restore(eflags);
	return 1;
}


void hip_init_workqueue()
{

	hip_workqueue = kmalloc(sizeof(struct list_head),GFP_KERNEL);

	INIT_LIST_HEAD(hip_workqueue);

	if (!list_empty(hip_workqueue)) {
		HIP_DEBUG("Hip_workqueue not empty!!!\n");
	}
}

void hip_uninit_workqueue()
{
	struct list_head *pos,*iter;
	struct hip_work_order *hwo;

	list_for_each_safe(pos,iter,hip_workqueue) {
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
	kfree(hip_workqueue);
}


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

