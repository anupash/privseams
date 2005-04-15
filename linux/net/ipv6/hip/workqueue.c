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
#include "workqueue.h"

/* HIP Per Cpu WorkQueue */
struct hip_pc_wq {
#ifdef __KERNEL__
	struct semaphore worklock;
#endif
	struct list_head workqueue;
};

#ifdef __KERNEL__
static DEFINE_PER_CPU(struct hip_pc_wq, hip_workqueue);
#else
static struct hip_pc_wq hip_workqueue;
#endif

/**
 * hwo_default_destructor - Default destructor for work order
 *
 * Simple... if you don't understand, then you shouldn't be
 * dealing with the kernel.
 */
static void hwo_default_destructor(struct hip_work_order *hwo)
{
	if (hwo && hwo->msg)
		HIP_FREE(hwo->msg);
}

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
	struct hip_work_order *result;
	struct hip_pc_wq *wq;
#ifdef __KERNEL__
	unsigned long eflags;
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
#else
	wq = &hip_workqueue;
#endif

	if (list_empty(&wq->workqueue)) {
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
#ifdef __KERNEL__
	local_irq_restore(eflags);
#endif
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
int hip_insert_work_order_cpu(struct hip_work_order *hwo, int cpu)
{
	unsigned long eflags;
	struct hip_pc_wq *wq;

	if (!hwo) {
		HIP_ERROR("NULL hwo\n");
		return -1;
	}

#ifdef __KERNEL__
	if (cpu >= NR_CPUS) {
		HIP_ERROR("Invalid CPU number: %d (max cpus: %d)\n", cpu, NR_CPUS);
		return -1;
	}

	_HIP_DEBUG("hwo=0x%p cpu=%d\n", hwo, cpu);
	local_irq_save(eflags);

	/* get_cpu_var / put_cpu_var ? */
	wq = &per_cpu(hip_workqueue, cpu);
#else
	wq = &hip_workqueue;
#endif
	if (wq) {
		list_add_tail(&hwo->queue, &wq->workqueue);
		/* what is the correct order of these two, l_i_r and up ? */
#ifdef __KERNEL__
		up(&wq->worklock);
#endif
	} else
		HIP_ERROR("NULL wq, aieee!\n");

#ifdef __KERNEL__
	local_irq_restore(eflags);
#endif
	return 1;
}

/**
 * hip_insert_work_order - Insert work order into the HIP working queue.
 * @hwo: Work order
 *
 * Returns 1 if ok, < 0 if error
 */
int hip_insert_work_order(struct hip_work_order *hwo)
{
#ifdef CONFIG_HIP_USERSPACE
	int ret;
#endif
	if (!hwo) {
		HIP_ERROR("NULL hwo\n");
		return -1;
	}

	if (hwo->hdr.type < 0 || hwo->hdr.type > HIP_MAX_WO_TYPES)
		return -1;

#ifdef CONFIG_HIP_USERSPACE
	ret = hip_netlink_send(hwo);
	hip_free_work_order(hwo);
	return ret;
#else
	return hip_insert_work_order_cpu(hwo, smp_processor_id());
#endif
}

int hip_init_workqueue()
{
	struct hip_pc_wq *wq;
#ifdef __KERNEL__
	unsigned long eflags;

	local_irq_save(eflags);

 	wq = &get_cpu_var(hip_workqueue);
#else
	wq = &hip_workqueue;
#endif
 	INIT_LIST_HEAD(&wq->workqueue);
#ifdef __KERNEL__
 	init_MUTEX_LOCKED(&wq->worklock);
 	put_cpu_var(hip_workqueue);
 	local_irq_restore(eflags);
#endif
	return 0;
}

void hip_uninit_workqueue()
{
	struct list_head *pos,*iter;
	struct hip_pc_wq *wq;
	struct hip_work_order *hwo;
#ifdef __KERNEL__
	unsigned long eflags;

	local_irq_save(eflags);
 	//local_bh_disable();
 	/* get_cpu_var / put_cpu_var ? */
	//	wq = &__get_cpu_var(hip_workqueue);
	wq = &get_cpu_var(hip_workqueue);
#else
	wq = &hip_workqueue;
#endif
	list_for_each_safe(pos, iter, &wq->workqueue) {
		hwo = list_entry(pos, struct hip_work_order, queue);
		hip_free_work_order(hwo);
		list_del(pos);
	}
#ifdef __KERNEL__
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

	hwo = (struct hip_work_order *)HIP_MALLOC(sizeof(struct hip_work_order), gfp_mask);
	if (hwo) {
		memset(hwo, 0, sizeof(struct hip_work_order));		
		hwo->destructor = hwo_default_destructor;
	} else {
		HIP_ERROR("No memory for work order\n");
	}

	return hwo;
}

int hip_do_work(struct hip_work_order *job)
{
	int res = 0;
	HIP_DEBUG("type=%d, subtype=%d\n", job->hdr.type, job->hdr.subtype);

	switch (job->hdr.type) {
	case HIP_WO_TYPE_INCOMING:
		HIP_START_TIMER(KMM_PARTIAL);
		switch(job->hdr.subtype) {
#if (defined __KERNEL__ && !defined CONFIG_HIP_USERSPACE) || !defined __KERNEL__
		case HIP_WO_SUBTYPE_RECV_I1:
			res = hip_receive_i1(job->msg, &job->hdr.src_addr,
					     &job->hdr.dst_addr);
			break;
		case HIP_WO_SUBTYPE_RECV_R1:
			res = hip_receive_r1(job->msg, &job->hdr.src_addr,
					     &job->hdr.dst_addr);
			break;
		case HIP_WO_SUBTYPE_RECV_I2:
			res = hip_receive_i2(job->msg, 
					     &job->hdr.src_addr,
					     &job->hdr.dst_addr);
			break;
		case HIP_WO_SUBTYPE_RECV_R2:
			res = hip_receive_r2(job->msg, &job->hdr.src_addr,
					     &job->hdr.dst_addr);
			HIP_STOP_TIMER(KMM_GLOBAL,"Base Exchange");
			break;
		case HIP_WO_SUBTYPE_RECV_UPDATE:
			res = hip_receive_update(job->msg, &job->hdr.src_addr,
						 &job->hdr.dst_addr);
			break;
		case HIP_WO_SUBTYPE_RECV_NOTIFY:
			res = hip_receive_notify(job->msg, &job->hdr.src_addr,
						 &job->hdr.dst_addr);
			break;
		case HIP_WO_SUBTYPE_RECV_BOS:
			res = hip_receive_bos(job->msg, &job->hdr.src_addr,
					      &job->hdr.dst_addr);
			break;
#endif /* (defined __KERNEL__ && !defined CONFIG_HIP_USERSPACE) || !defined __KERNEL__ */
		default:
			HIP_ERROR("Unknown subtype: %d (type=%d)\n",
				  job->hdr.subtype, job->hdr.type);
			break;
		}
		HIP_STOP_TIMER(KMM_PARTIAL, hip_msg_type_str(job->hdr.type));
		if (res < 0)
			res = KHIPD_ERROR;
		break;
	case HIP_WO_TYPE_OUTGOING:
	{			
		struct hip_work_order * resp = NULL;
		struct hip_keys *keys;

		switch(job->hdr.subtype) {
#if defined __KERNEL__ && defined CONFIG_HIP_USERSPACE
		case HIP_WO_SUBTYPE_SEND_PACKET:
			res = hip_csum_send(&job->hdr.src_addr, &job->hdr.dst_addr, 
					    job->msg);
			break;
			
		case HIP_WO_SUBTYPE_ACQSPI:
			resp = hip_init_job(GFP_KERNEL);
			if (!resp) 
				break;

			resp->seq = job->seq;
			res = resp->hdr.arg1 = hip_acquire_spi(&job->hdr.src_addr, &job->hdr.dst_addr);		       
			break;

		case HIP_WO_SUBTYPE_ADDSA:
			resp = hip_init_job(GFP_KERNEL);
			if (!resp) 
				break;
			keys = hip_get_param(job->msg, HIP_PARAM_KEYS); 
			if (!keys)
				break;

			resp->seq = job->seq;
			res = resp->hdr.arg1 = hip_add_sa(&job->hdr.src_addr, &job->hdr.dst_addr,
							  &keys->spi, keys->alg,
							  &keys->enc, &keys->auth,
							  keys->acquired, keys->direction);
			break;

		case HIP_WO_SUBTYPE_DELSA:
			resp = hip_init_job(GFP_KERNEL);
			if (!resp) 
				break;

			resp->seq = job->seq;
			res = resp->hdr.arg1 = hip_delete_sa(job->hdr.arg1, &job->hdr.dst_addr);
			break;

		case HIP_WO_SUBTYPE_FINSA:
			resp = hip_init_job(GFP_KERNEL);
			if (!resp) 
				break;

			resp->seq = job->seq;
			res = resp->hdr.arg1 = hip_finalize_sa(&job->hdr.dst_addr, job->hdr.arg1);
			break;

		case HIP_WO_SUBTYPE_XFRM_INIT:
			resp = hip_init_job(GFP_KERNEL);
			if (!resp) 
				break;

			resp->seq = job->seq;
			res = resp->hdr.arg1 =
				hip_xfrm_dst_init(&job->hdr.src_addr,
						  &job->hdr.dst_addr);
			break;

		case HIP_WO_SUBTYPE_XFRM_UPD:
			resp = hip_init_job(GFP_KERNEL);
			if (!resp) 
				break;

			resp->seq = job->seq;
			res = resp->hdr.arg1 = hip_xfrm_update(job->hdr.arg1, &job->hdr.dst_addr, 
							       *((int *)(&job->hdr.src_addr)),
							       job->hdr.arg2);
			break;

		case HIP_WO_SUBTYPE_XFRM_DEL:
			resp = hip_init_job(GFP_KERNEL);
			if (!resp) 
				break;

			resp->seq = job->seq;
			res = resp->hdr.arg1 = hip_xfrm_delete(job->hdr.arg1, &job->hdr.src_addr, job->hdr.arg2);
			break;

		case HIP_WO_SUBTYPE_PING:
			resp = hip_init_job(GFP_KERNEL);
			if (!resp) 
				break;

			resp->seq = job->seq;
			res = resp->hdr.arg1 = 0;
			break;
#endif /* defined __KERNEL__ && defined CONFIG_HIP_USERSPACE */

		default:
			HIP_ERROR("Unknown subtype: %d (type=%d)\n",
				  job->hdr.subtype, job->hdr.type);
			break;
		}

#if defined __KERNEL__ && defined CONFIG_HIP_USERSPACE
		if (resp) {
			hip_netlink_send(resp);
			hip_free_work_order(resp);
		}
#endif /* defined __KERNEL__ && defined CONFIG_HIP_USERSPACE */

		if (res < 0)
			res = KHIPD_ERROR;
		break;
	}

	case HIP_WO_TYPE_MSG:
		switch(job->hdr.subtype) {
#if defined __KERNEL__  && !defined CONFIG_HIP_USERSPACE
		case HIP_WO_SUBTYPE_IN6_EVENT:
			hip_net_event((int)job->hdr.arg1, 0, (uint32_t) job->hdr.arg2);
			res = KHIPD_OK;
			break;
		case HIP_WO_SUBTYPE_DEV_EVENT:
			hip_net_event((int)job->hdr.arg1, 1, (uint32_t) job->hdr.arg2);
			res = KHIPD_OK;
			break;
#endif
#if (defined __KERNEL__  && !defined CONFIG_HIP_USERSPACE) || !defined __KERNEL__
		case HIP_WO_SUBTYPE_ADDMAP:
			/* arg1 = d-hit, arg2=ipv6 */
			res = hip_hadb_add_peer_info(&job->hdr.dst_addr,
						     &job->hdr.src_addr);
			if (res < 0) {
				res = KHIPD_ERROR;
				break;
			}

			/* Synchronize the BEET database */
			res = hip_xfrm_dst_init(&job->hdr.dst_addr,
						&job->hdr.src_addr);
			if (res < 0)
				res = KHIPD_ERROR;
			break;
		case HIP_WO_SUBTYPE_DELMAP:
			/* arg1 = d-hit arg2=d-ipv6 */
			res = hip_del_peer_info(&job->hdr.dst_addr,
						&job->hdr.src_addr);
			if (res < 0)
				res = KHIPD_ERROR;
			break;
#ifdef CONFIG_HIP_RVS
		case HIP_WO_SUBTYPE_ADDRVS:
			/* arg1 = d-hit, arg2=ipv6 */
			res = hip_hadb_add_peer_info(&job->hdr.dst_addr, &job->hdr.src_addr);
			if (res < 0)
				res = KHIPD_ERROR;
			hip_rvs_set_request_flag(&job->hdr.dst_addr);
			{
				struct ipv6hdr hdr = {0};
				ipv6_addr_copy(&hdr.daddr, &job->hdr.dst_addr);
				hip_handle_output(&hdr, NULL);
			}
			res = 0;
			break;
#endif
		case HIP_WO_SUBTYPE_ADDHI:
			HIP_DEBUG("Adding \n");
			res = hip_handle_add_local_hi(job->msg);
			break;
		case HIP_WO_SUBTYPE_FLUSHMAPS:
		case HIP_WO_SUBTYPE_DELHI:
		case HIP_WO_SUBTYPE_FLUSHHIS:
		case HIP_WO_SUBTYPE_NEWDH:
			HIP_INFO("Not implemented subtype: %d (type=%d)\n",
				 job->hdr.subtype, job->hdr.type);
			res = KHIPD_ERROR;
			goto out_err;
#endif /* (defined __KERNEL__  && !defined CONFIG_HIP_USERSPACE) || !defined __KERNEL__ */
		default:
			HIP_ERROR("Unknown subtype: %d on type: %d\n",job->hdr.subtype,job->hdr.type);
			res = KHIPD_ERROR;
			goto out_err;
		}
	}

 out_err:
	if (job)
		hip_free_work_order(job);
	return res;
}


