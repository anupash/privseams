/*
 * HIP userspace message handling functions.
 *
 * Authors:
 * - Miika Komu <miika@iki.fi>
 * - Janne Lundberg <jlu@tcs.hut.fi>
 *
 * TODO:
 * - is the get function really atomic...
 * - optimize: only INPUT_READY is really needed (as Pekka told)
 * - hipd_finish should receive preparsed extentions instead of msg
 * - check that all finishers return int in hip.c
 * - What if there would be only one daemon (but many spool entries?),
 *   how would blocking be implemented? Current implementation more
 *   exposed to race conditions? Anyways, implement either
 *   - a queue of waiting messages for each spool entry
 *   - or a queue of waiting messages for all spool entries
 * - Exchange is allocated dynamically and what if i.e. daemon crashes,
 *   are exchanges still freed? The message queue is also stuck then.
 * - support for multithreaded daemon; is it really needed after Krisu's
 *   modifications?
 * - Support for shared context would make multiple daemon calls per
 *   packet easier? Or is this even needed? It would require just a
 *   simple, automatic counter in daemon exchange or context.
 * - add usage instructions
 * - is the sequentality (fifo) property really necessary in practise?
 * - hip.c should deny all hip connections until autosetup is finished!
 * - rename this file because it contains also some other functionality
 *   than just the daemon calling mechanism
 * - verify the mem deallocation procedure in hipd_send_response: what if
 *   kernel module is unloaded etc?
 */

#include "daemon.h"
#include "cookie.h"
#include "workqueue.h"

struct hipd_async_msg hipd_async_msg;

/* kernel module unit tests */
struct hip_unit_test_suite_list hip_unit_test_suite_list;

/*
 * Handlers for hipd asynchronous messages from userspace.  These
 * *must* be in same order as in <linux/hip_ioctl.h>. A null message
 * handler indicates that the message type cannot be handled as an
 * asynchronous message. For example, it is not sensible for the
 * userspace to command kernel to create a DSA key, since it the job
 * of the HIP daemon in the userspace.
 */
int (*hipd_async_msg_handlers[])(const struct hip_common *) = {
	NULL,                             /* HIP_USER_NULL_OPERATION */
	hipd_handle_async_add_hi,         /* HIP_USER_ADD_HI */
	hipd_handle_async_del_hi,         /* HIP_USER_DEL_HI */
	hipd_handle_async_add_map_hit_ip, /* HIP_USER_ADD_MAP_HIT_IP */
	hipd_handle_async_del_map_hit_ip, /* HIP_USER_DEL_MAP_HIT_IP */
	hipd_handle_async_unit_test,
	hipd_handle_async_rst
};

/**
 * hip_init_daemon - initialize the userspace communication message queues
 *
 * Returns: zero on error, or a negative error value on failure
 */
int hip_init_daemon(void)
{
	int err = 0;

	hipd_async_msg.msg = hip_msg_alloc();
	if (!hipd_async_msg.msg) {
		err = -ENOMEM;
		goto out;
	}

	spin_lock_init(&hipd_async_msg.lock);

 out:
	return err;

	
}

/**
 * hip_uninit_daemon - uninitialize the userspace communication message queues
 *
 */
void hip_uninit_daemon(void)
{
	HIP_INFO("kfree %p\n", hipd_async_msg.msg);
	kfree(hipd_async_msg.msg);

	/* XX TODO: free the linked list (it may be longer than initially) ! */

}

/**
 * hipd_handle_async_add_hi - handle adding of a localhost host identity
 * @msg: contains the hi parameter in fqdn format (includes private key)
 *       and the corresponding HIT calculated from the HI pubkey
 *
 * Returns: zero on success, or negative error value on failure
 */
int hipd_handle_async_add_hi(const struct hip_common *msg)
{
	int err = 0;
	struct hip_host_id *host_identity = NULL;
	struct hip_lhi *lhi = NULL;

	_HIP_DEBUG("\n");

	if ((err = hip_get_msg_err(msg)) != 0) {
		HIP_ERROR("daemon failed (%d)\n", err);
		goto out_err;
	}

	_HIP_DUMP_MSG(response);

	/* Note: lhi is not a real TLV structure, it is just wrapped into
	   TLV format. That is the reason to use get_param_contents() instead
	   of hip_get_param(). See also get_localhost_info() in hipd.c.*/
	lhi = hip_get_param_contents(msg, HIP_PARAM_HI);
        if (!lhi) {
		HIP_ERROR("no host lhi in response\n");
		err = -ENOENT;
		goto out_err;
	}

	host_identity = hip_get_param(msg, HIP_PARAM_HOST_ID);
        if (!host_identity) {
		HIP_ERROR("no host identity pubkey in response\n");
		err = -ENOENT;
		goto out_err;
	}

	err = hip_add_localhost_id(lhi, host_identity);
	if (err) {
		HIP_ERROR("adding of local host identity failed\n");
		goto out_err;
	}

	HIP_DEBUG("hip: Generating a new R1 now\n");

	if (!hip_precreate_r1(&lhi->hit)) {
		HIP_ERROR("Unable to precreate R1s... failing\n");
		err = -ENOENT;
		goto out_err;
	}

	HIP_INFO("hip auto setup ok\n");

 out_err:

	return err;
}

/**
 * hipd_handle_async_del_hi - handle deletion of a localhost host identity
 * @msg: the message containing the lhi to be deleted
 *
 * This function is currently unimplemented.
 *
 * Returns: zero on success, or negative error value on failure
 */
int hipd_handle_async_del_hi(const struct hip_common *msg)
{
	int err = 0;

	HIP_ERROR("Not implemented\n");
	err = -ENOSYS;

        return err;
}

/**
 * hipd_handle_async_add_map_hit_ip - handle adding of a HIT-to-IPv6 mapping
 * @msg: the message containing the mapping to be added to kernel databases
 *
 * Add a HIT-to-IPv6 mapping of peer to the mapping database in the kernel
 * module.
 *
 * Returns: zero on success, or negative error value on failure
 */
int hipd_handle_async_add_map_hit_ip(const struct hip_common *msg)
{
	struct in6_addr *hit, *ip, *ip_copy;
	struct hip_work_order *hwo;
	char buf[46];
	int err = 0;


	hit = (struct in6_addr *)
		hip_get_param_contents(msg, HIP_PARAM_HIT);
	if (!hit) {
		HIP_ERROR("handle async map: no hit\n");
		err = -ENODATA;
		goto out;
	}

	ip = (struct in6_addr *)
		hip_get_param_contents(msg, HIP_PARAM_IPV6_ADDR);
	if (!ip) {
		HIP_ERROR("handle async map: no ipv6 address\n");
		err = -ENODATA;
		goto out;
	}

	hip_in6_ntop(hit, buf);
	HIP_INFO("map HIT: %s\n", buf);
	hip_in6_ntop(ip, buf);
	HIP_INFO("map IP: %s\n", buf);
	
	hwo = hip_create_job_with_hit(GFP_KERNEL,hit); // i think KERNEL is ok here
	if (!hwo) {
		HIP_ERROR("No memory for hit <-> ip mapping\n");
		err = -ENOMEM;
		goto out;
	}

	ip_copy = kmalloc(sizeof(struct in6_addr),GFP_KERNEL);
	if (!ip_copy) {
		HIP_ERROR("No memory to copy IP to work order\n");
		err = -ENOMEM;
		goto out;
	}

	ipv6_addr_copy(ip_copy,ip);
	hwo->arg2 = ip_copy;
	hwo->type = HIP_WO_TYPE_MSG;
	hwo->subtype = HIP_WO_SUBTYPE_ADDMAP;

	hip_insert_work_order(hwo);
 out:
	return err;
}


int hipd_handle_async_rst(const struct hip_common *msg)
{
	struct in6_addr *hit;
	struct hip_work_order *hwo;
	int err = 0;

	hit = (struct in6_addr *)
		hip_get_param_contents(msg, HIP_PARAM_HIT);
	if (!hit) {
		HIP_ERROR("handle async map: no hit\n");
		err = -ENODATA;
		goto out;
	}

	hwo = hip_create_job_with_hit(GFP_KERNEL,hit);
	if (!hwo) {
		HIP_ERROR("No memory to complete RST\n");
		err = -ENOMEM;
		goto out;
	}

	hwo->type = HIP_WO_TYPE_MSG;
	hwo->subtype = HIP_WO_SUBTYPE_FLUSHMAPS;

	hip_insert_work_order(hwo);
 out:
	return err;
}

/**
 * hipd_handle_async_del_map_hit_ip - handle deletion of a mapping
 * @msg: the message containing the mapping to be deleted
 *
 * Currently this function is unimplemented.
 *
 * Returns: zero on success, or negative error value on failure
 */
int hipd_handle_async_del_map_hit_ip(const struct hip_common *msg)
{
	int err = 0;

	err = -ENOSYS; /* not implemented yet */

	return err;
}

/**
 * hipd_handle_async_unit_test - handle unit test message
 * @msg: message containing information about which unit tests to execute
 *
 * Execute unit tests in the kernelspace and return the number of unit tests
 * failed.
 *
 * Returns: the number of unit tests failed
 */

int hipd_handle_async_unit_test(const struct hip_common *msg)
{
	uint16_t err = 0;
#if 0 /* MIIKA CHECK */
	uint16_t suiteid, caseid;
	struct hip_unit_test *test = NULL;
	char err_log[HIP_UNIT_ERR_LOG_MSG_MAX_LEN] = "";

	test = (struct hip_unit_test *)
		hip_get_param(msg, HIP_PARAM_UNIT_TEST);
	if (!test) {
		HIP_ERROR("No unit test parameter found\n");
		err = -ENOMSG;
		goto out;
	}

	suiteid = hip_get_unit_test_suite_param_id(test);
	caseid = hip_get_unit_test_case_param_id(test);

	HIP_DEBUG("Executing suiteid=%d, caseid=%d\n", suiteid, caseid);

	err = hip_run_unit_test_case(&hip_unit_test_suite_list, suiteid,
				     caseid, err_log, sizeof(err_log));
	if (err)
		HIP_ERROR("\n===Unit Test Summary===\nTotal %d errors:\n%s\n",
			  err, err_log);
	else
		HIP_INFO("\n===Unit Test Summary===\nAll tests passed, no errors!\n");

 out:
#endif /* 0 MIIKA CHECK */

	return (int) err;
}
