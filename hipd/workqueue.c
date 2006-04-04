/*
 * Work queue functions for HIP
 *
 * Licence: GNU/GPL
 * Authors:
 * - Kristian Slavov <ksl@iki.fi>
 * - Miika Komu <miika@iki.fi>
 *
 * We don't currently have a workqueue. The functionality in this file mostly
 * covers catching userspace messages only.
 *
 */
#include "workqueue.h"

/* HIP Per Cpu WorkQueue */
struct hip_pc_wq {
	struct list_head workqueue;
};

static struct hip_pc_wq hip_workqueue;

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
	struct hip_work_order *err = NULL;
	struct hip_pc_wq *wq;

	wq = &hip_workqueue;

	HIP_IFE(list_empty(&wq->workqueue), NULL);
	HIP_IFEL(!(err = list_entry((&wq->workqueue)->next, struct hip_work_order, queue)),
		 NULL, "Couldn't extract the main structure from the list\n");

	list_del((&wq->workqueue)->next);

 out_err:	
	return err;
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
	int err = 1;
	struct hip_pc_wq *wq;

	wq = &hip_workqueue;

	if (wq) {
		list_add_tail(&hwo->queue, &wq->workqueue);
		/* what is the correct order of these two, l_i_r and up ? */
	}

	return err;
}

/**
 * hip_insert_work_order - Insert work order into the HIP working queue.
 * @hwo: Work order
 *
 * Returns 1 if ok, < 0 if error
 */
int hip_insert_work_order(struct hip_work_order *hwo)
{
	int ret;

#if 0
	if (hwo->hdr.type < 0 || hwo->hdr.type > HIP_MAX_WO_TYPES)
		return -1;

	ret = hip_netlink_send(hwo);
	hip_free_work_order(hwo);
#endif
	/* XX FIX: handle the packet directly, do not send to the kernel */
	ret = -1;
	return ret;
}

int hip_init_workqueue()
{
	struct hip_pc_wq *wq;

	wq = &hip_workqueue;

 	INIT_LIST_HEAD(&wq->workqueue);

	return 0;
}

void hip_uninit_workqueue()
{
	struct list_head *pos,*iter;
	struct hip_pc_wq *wq;
	struct hip_work_order *hwo;

	wq = &hip_workqueue;

	list_for_each_safe(pos, iter, &wq->workqueue) {
		hwo = list_entry(pos, struct hip_work_order, queue);
		hip_free_work_order(hwo);
		list_del(pos);
	}
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
		HIP_ERROR("Out of memory\n");
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
		case HIP_WO_SUBTYPE_RECV_CONTROL:
			res = hip_receive_control_packet(job->msg,
							 &job->hdr.id1,
							 &job->hdr.id2);
			break;
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
		switch(job->hdr.subtype) {
		case HIP_WO_SUBTYPE_SEND_I1:
		{
			hip_ha_t *entry;
			// FIXME: create HA here, on the fly if needed (Hi3)
 			entry = hip_hadb_try_to_find_by_peer_hit(&job->hdr.id2);
			if (!entry) {
				HIP_ERROR("Unknown HA\n");
				res = KHIPD_ERROR;
				goto send_i1_end;
			}
			HIP_DEBUG("*-*-*-*-*-*-*-*-*-*CALLING hip_send_i1 ***********\n");
			res = hip_send_i1(&entry->hit_peer, entry);
			if (res < 0) {
				HIP_ERROR("Sending of I1 failed (%d)\n", res);
				res = KHIPD_ERROR;
				barrier();
				entry->state = HIP_STATE_UNASSOCIATED;
				goto send_i1_end;
			}

		send_i1_end:
			if (entry)
				hip_db_put_ha(entry, hip_hadb_delete_state);
			break;
		}
		default:
			HIP_ERROR("Unknown subtype: %d (type=%d)\n",
				  job->hdr.subtype, job->hdr.type);
			break;
		}
		
		if (res < 0)
			res = KHIPD_ERROR;
		break;
	}
	
	case HIP_WO_TYPE_MSG:
		switch(job->hdr.subtype) {
#ifdef CONFIG_HIP_RVS
		case HIP_WO_SUBTYPE_ADDRVS:
#if 0
			/* arg1 = d-hit, arg2=ipv6 */
			res = hip_hadb_add_peer_info(&job->hdr.id2,
						     &job->hdr.id1);
			if (res < 0) {
				res = KHIPD_ERROR;
				break;
			}
			hip_rvs_set_request_flag(&job->hdr.id2);
			{
				struct ipv6hdr hdr = {0};
				ipv6_addr_copy(&hdr.daddr, &job->hdr.id2);
				hip_handle_output(&hdr, NULL);
			}
			break;
#endif
#endif /* CONFIG_HIP_RVS */
		case HIP_WO_SUBTYPE_ADDMAP:
			/* arg1 = d-hit, arg2=ipv6 */
			res = hip_hadb_add_peer_info(&job->hdr.id2,
						     &job->hdr.id1);
			if (res < 0) {
				res = KHIPD_ERROR;
				break;
			}

			break;
		case HIP_WO_SUBTYPE_DELMAP:
			/* arg1 = d-hit arg2=d-ipv6 */
			res = hip_del_peer_info(&job->hdr.id2,
						&job->hdr.id1);
			if (res < 0)
				res = KHIPD_ERROR;
			break;
		case HIP_WO_SUBTYPE_ADDHI:
			/* FIXME: Synchronize the BEET database */
			HIP_DEBUG("Adding \n");
			res = hip_handle_add_local_hi(job->msg);
			break;
		case HIP_WO_SUBTYPE_FLUSHMAPS:
		case HIP_WO_SUBTYPE_DELHI:
			HIP_DEBUG("Deleting a HI\n");
			res = hip_handle_del_local_hi(job->msg);
			break;
		case HIP_WO_SUBTYPE_FLUSHHIS:
		case HIP_WO_SUBTYPE_NEWDH:
			HIP_INFO("Not implemented subtype: %d (type=%d)\n",
				 job->hdr.subtype, job->hdr.type);
			res = KHIPD_ERROR;
			goto out_err;
		case HIP_WO_SUBTYPE_SEND_BOS:
			HIP_DEBUG("Sending BOS\n");
			res = hip_send_bos(job->msg);
			break;
		case HIP_WO_SUBTYPE_SEND_CLOSE:
			HIP_DEBUG("Sending CLOSE\n");
			res = hip_send_close(NULL);
			break;
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

int hip_handle_user_msg(struct hip_common *msg) {
	hip_hit_t *hit;
	int err = 0;
	int msg_type;

	err = hip_check_userspace_msg(msg);
	if (err) {
		HIP_ERROR("HIP socket option was invalid\n");
		goto out_err;
	}

	msg_type = hip_get_msg_type(msg);
	switch(msg_type) {
	case SO_HIP_ADD_LOCAL_HI:
		err = hip_handle_add_local_hi(msg);
		break;
	case SO_HIP_DEL_LOCAL_HI:
		err = hip_handle_del_local_hi(msg);
		break;
	case SO_HIP_ADD_PEER_MAP_HIT_IP:
		err = hip_add_peer_map(msg);
		break;
	case SO_HIP_DEL_PEER_MAP_HIT_IP:
		err = hip_del_peer_map(msg);
		break;
	case SO_HIP_RST:
		err = hip_send_close(msg);
		break;
	case SO_HIP_ADD_RVS:
#if 0 /* XX FIXME */
		err = hip_add_peer_map_hit_ip(msg);
		err = hip_rvs_set_request_flag();
		{
			struct ipv6hdr hdr = {0};
			ipv6_addr_copy(&hdr.daddr, &job->hdr.id2);
			hip_handle_output(&hdr, NULL);
		}
#endif
		break;
	case SO_HIP_BOS:
		err = hip_send_bos(msg);
		break;
	case SO_HIP_CONF_PUZZLE_NEW:
		err = hip_recreate_all_precreated_r1_packets();
		break;
	case SO_HIP_CONF_PUZZLE_GET:
		err = -ESOCKTNOSUPPORT; /* TBD */
		break;
	case SO_HIP_CONF_PUZZLE_SET:
		err = -ESOCKTNOSUPPORT; /* TBD */
		break;
	case SO_HIP_CONF_PUZZLE_INC:
		hit = hip_get_param_contents(msg, HIP_PARAM_HIT);
		hip_inc_cookie_difficulty(hit);
		break;
	case SO_HIP_CONF_PUZZLE_DEC:
		hit = hip_get_param_contents(msg, HIP_PARAM_HIT);
		hip_dec_cookie_difficulty(hit);
		break;
	case SO_HIP_SET_OPPORTUNISTIC_MODE: // Bing, added
	  	err = hip_set_opportunistic_mode(msg);
		break;
	default:
		HIP_ERROR("Unknown socket option (%d)\n", msg_type);
		err = -ESOCKTNOSUPPORT;
	}

 out_err:

	return err;
}
