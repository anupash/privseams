/*
 * HIP userspace message handling functions.
 *
 * Authors:
 * - Miika Komu <miika@iki.fi>
 * - Janne Lundberg <jlu@tcs.hut.fi>
 *
 * TODO:
 * - implement this stuff using PF_HIP???
 * - async messages should have a return message
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
 * - verify the mem deallocation procedure in hip_send_response: what if
 *   kernel module is unloaded etc?
 */

#include "daemon.h"
#include "builder.h"
#include "debug.h"
#include "ioctl.h"
#include "db.h"
#include "workqueue.h"
#include "misc.h"
#include "cookie.h"
#include "unit.h"

struct hip_user_msg hip_user_msg;

/* kernel module unit tests */
extern struct hip_unit_test_suite_list hip_unit_test_suite_list;

/*
 * Handlers for messages from userspace.  These *must* be in same order as
 * in <net/hip.c>. A null message handler indicates that the message
 * type cannot be handled. For example, it is not sensible for the
 * userspace to command kernel to create a DSA key, since it the job
 * of the HIP daemon in the userspace.
 */
int (*hip_user_msg_handler[])(const struct hip_common *,
			      struct hip_common *) = {
	NULL,
	hip_user_handle_add_local_hi,
	hip_user_handle_del_local_hi,
	hip_user_handle_add_peer_map_hit_ip,
	hip_user_handle_del_peer_map_hit_ip,
	hip_user_handle_unit_test,
	hip_user_handle_rst,
	hip_user_handle_set_my_eid,
	hip_user_handle_set_peer_eid,
	hip_user_handle_rvs,
};

/**
 * hip_init_user - initialize the userspace communication message queues
 *
 * Returns: zero on error, or a negative error value on failure
 */
int hip_init_user(void)
{
	int err = 0;

	hip_user_msg.msg = hip_msg_alloc();
	if (!hip_user_msg.msg) {
		err = -ENOMEM;
		goto out;
	}

	spin_lock_init(&hip_user_msg.lock);

 out:
	return err;

	
}

/**
 * hip_uninit_daemon - uninitialize the userspace communication message queues
 *
 */
void hip_uninit_user(void)
{
	HIP_INFO("kfree %p\n", hip_user_msg.msg);
	kfree(hip_user_msg.msg);

	/* XX TODO: free the linked list (it may be longer than initially) ! */

}

/*
 * note this function is called by two other functions below.
 */
int hip_user_add_local_hi(const struct hip_host_id *host_identity,
			  const struct hip_lhi *lhi)
{
	int err = 0;

	err = hip_add_localhost_id(lhi, host_identity);
	if (err) {
		HIP_ERROR("adding of local host identity failed\n");
		goto out_err;
	}

	/* If adding localhost id failed because there was a duplicate, we
	   won't precreate anything (and void causing dagling memory
	   pointers) */

	HIP_DEBUG("hip: Generating a new R1 now\n");

	if (!hip_precreate_r1(&lhi->hit)) {
		HIP_ERROR("Unable to precreate R1s... failing\n");
		err = -ENOENT;
		goto out_err;
	}

 out_err:
	return err;
}

/**
 * hip_user_handle_local_add_hi - handle adding of a localhost host identity
 * @msg: contains the hi parameter in fqdn format (includes private key)
 *       and the corresponding HIT calculated from the HI pubkey
 *
 * Returns: zero on success, or negative error value on failure
 */
int hip_user_handle_add_local_hi(const struct hip_common *input,
				 struct hip_common *output)
{
	int err = 0;
	struct hip_host_id *host_identity = NULL;
	struct hip_lhi lhi;

	HIP_DEBUG("\n");

	if ((err = hip_get_msg_err(input)) != 0) {
		HIP_ERROR("daemon failed (%d)\n", err);
		goto out_err;
	}

	_HIP_DUMP_MSG(response);

	host_identity = hip_get_param(input, HIP_PARAM_HOST_ID);
        if (!host_identity) {
		HIP_ERROR("no host identity pubkey in response\n");
		err = -ENOENT;
		goto out_err;
	}

	err = hip_private_host_id_to_hit(host_identity, &lhi.hit,
					 HIP_HIT_TYPE_HASH126);
	if (err) {
		HIP_ERROR("host id to hit conversion failed\n");
		goto out_err;
	}

	err = hip_user_add_local_hi(host_identity, &lhi);
	if (err) {
		HIP_ERROR("Failed to add HIP localhost identity\n");
		goto out_err;
	}

	HIP_DEBUG("Adding of HIP localhost identity was successful\n");

 out_err:

	hip_build_user_hdr(output, hip_get_msg_type(input), -err);

	return err;
}

/**
 * hip_user_handle_del_local_hi - handle deletion of a localhost host identity
 * @msg: the message containing the lhi to be deleted
 *
 * This function is currently unimplemented.
 *
 * Returns: zero on success, or negative error value on failure
 */
int hip_user_handle_del_local_hi(const struct hip_common *input,
				struct hip_common *output)
{
	int err = 0;

	HIP_ERROR("Not implemented\n");
	err = -ENOSYS;

	hip_build_user_hdr(output, hip_get_msg_type(input), -err);

        return err;
}

static int hip_insert_peer_map_work_order(const struct in6_addr *hit,
					  const struct in6_addr *ip,
					  int insert, int rvs)
{
	int err = 0;
	struct hip_work_order *hwo;
	struct in6_addr *ip_copy;

	hwo = hip_create_job_with_hit(GFP_ATOMIC, hit);
	if (!hwo) {
		HIP_ERROR("No memory for hit <-> ip mapping\n");
		err = -ENOMEM;
		goto out_err;
	}
	
	ip_copy = kmalloc(sizeof(struct in6_addr), GFP_ATOMIC);
	if (!ip_copy) {
		HIP_ERROR("No memory to copy IP to work order\n");
		err = -ENOMEM;
		goto out_err;
	}
	
	ipv6_addr_copy(ip_copy,ip);
	hwo->arg2 = ip_copy;
	hwo->type = HIP_WO_TYPE_MSG;
	if (rvs)
		hwo->subtype = HIP_WO_SUBTYPE_ADDRVS;
	else {
		if (insert)
			hwo->subtype = HIP_WO_SUBTYPE_ADDMAP;
		else
			hwo->subtype = HIP_WO_SUBTYPE_DELMAP;
	}

	hip_insert_work_order(hwo);

 out_err:

	return err;
}

static int hip_do_dummkopf_work(const struct hip_common *input,
				struct hip_common *output, int rvs)
{
	struct in6_addr *hit, *ip;
	char buf[46];
	int err = 0;


	hit = (struct in6_addr *)
		hip_get_param_contents(input, HIP_PARAM_HIT);
	if (!hit) {
		HIP_ERROR("handle async map: no hit\n");
		err = -ENODATA;
		goto out;
	}

	ip = (struct in6_addr *)
		hip_get_param_contents(input, HIP_PARAM_IPV6_ADDR);
	if (!ip) {
		HIP_ERROR("handle async map: no ipv6 address\n");
		err = -ENODATA;
		goto out;
	}

	hip_in6_ntop(hit, buf);
	HIP_INFO("map HIT: %s\n", buf);
	hip_in6_ntop(ip, buf);
	HIP_INFO("map IP: %s\n", buf);
	
 	err = hip_insert_peer_map_work_order(hit, ip, 1, rvs);
 	if (err) {
 		HIP_ERROR("Failed to insert peer map work order (%d)\n", err);
	}

 out:
 	hip_build_user_hdr(output, hip_get_msg_type(input), -err);
	return err;

}


/**
 * hip_user_handle_rvs - Handle a case where we want our host to register
 * with rendezvous server.
 * Use this instead off "add map" functionality since we set the special
 * flag... (rvs)
 */
int hip_user_handle_rvs(const struct hip_common *input,
			struct hip_common *output)
{
	return hip_do_dummkopf_work(input,output,1);
}


/**
 * hip_user_handle_add_peer_map_hit_ip - handle adding of a HIT-to-IPv6 mapping
 * @msg: the message containing the mapping to be added to kernel databases
 *
 * Add a HIT-to-IPv6 mapping of peer to the mapping database in the kernel
 * module.
 *
 * Returns: zero on success, or negative error value on failure
 */
int hip_user_handle_add_peer_map_hit_ip(const struct hip_common *input,
					  struct hip_common *output)
{
	return hip_do_dummkopf_work(input,output,0);
}

/**
 * hipd_handle_async_del_map_hit_ip - handle deletion of a mapping
 * @msg: the message containing the mapping to be deleted
 *
 * Currently this function is unimplemented.
 *
 * Returns: zero on success, or negative error value on failure
 */
int hip_user_handle_del_peer_map_hit_ip(const struct hip_common *input,
					struct hip_common *output)
{
	struct in6_addr *hit, *ip;
	char buf[46];
	int err = 0;


	hit = (struct in6_addr *)
		hip_get_param_contents(input, HIP_PARAM_HIT);
	if (!hit) {
		HIP_ERROR("handle async map: no hit\n");
		err = -ENODATA;
		goto out;
	}

	ip = (struct in6_addr *)
		hip_get_param_contents(input, HIP_PARAM_IPV6_ADDR);
	if (!ip) {
		HIP_ERROR("handle async map: no ipv6 address\n");
		err = -ENODATA;
		goto out;
	}

	hip_in6_ntop(hit, buf);
	HIP_INFO("map HIT: %s\n", buf);
	hip_in6_ntop(ip, buf);
	HIP_INFO("map IP: %s\n", buf);
	
 	err = hip_insert_peer_map_work_order(hit, ip, 0, 0);
 	if (err) {
 		HIP_ERROR("Failed to insert peer map work order (%d)\n", err);
	}

 out:
 	hip_build_user_hdr(output, hip_get_msg_type(input), -err);
	return err;
}


int hip_user_handle_rst(const struct hip_common *input,
			struct hip_common *output)
{
	hip_build_user_hdr(output, hip_get_msg_type(input), -ENOSYS);
	return -ENOSYS;
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
int hip_user_handle_unit_test(const struct hip_common *input,
				struct hip_common *output)
{
	int err = 0;
#if 0 /* XX TODO */
	uint16_t failed_test_cases;
	uint16_t suiteid, caseid;
	struct hip_unit_test *test = NULL;
	char err_log[HIP_UNIT_ERR_LOG_MSG_MAX_LEN] = "";

	test = (struct hip_unit_test *)
		hip_get_param(input, HIP_PARAM_UNIT_TEST);
	if (!test) {
		HIP_ERROR("No unit test parameter found\n");
		err = -ENOMSG;
		goto out;
	}

	suiteid = hip_get_unit_test_suite_param_id(test);
	caseid = hip_get_unit_test_case_param_id(test);

	HIP_DEBUG("Executing suiteid=%d, caseid=%d\n", suiteid, caseid);

	failed_test_cases = hip_run_unit_test_case(&hip_unit_test_suite_list,
						   suiteid, caseid,
						   err_log, sizeof(err_log));
	if (failed_test_cases)
		HIP_ERROR("\n===Unit Test Summary===\nTotal %d errors:\n%s\n",
			  failed_test_cases, err_log);
	else
		HIP_INFO("\n===Unit Test Summary===\nAll tests passed, no errors!\n");

 out:
	hip_build_user_hdr(output, hip_get_msg_type(input), failed_test_cases);
	hip_build_unit_test_log();
#endif

	return err;
}

/*
 * This function is similar to hip_user_handle_add_local_hi but there are three
 * major differences:
 * - this function is used by native HIP sockets (not hipconf)
 * - HIP sockets require EID handling which is done here
 * - this function DOES NOT call hip_precreate_r1, so you need launch
 */
int hip_user_handle_set_my_eid(const struct hip_common *input,
			       struct hip_common *output)
{
	int err = 0;
	struct sockaddr_eid eid;
	struct hip_tlv_common *param = NULL;
	struct hip_eid_iface *iface;
	struct hip_eid_endpoint *eid_endpoint;
	struct hip_lhi lhi;
	struct hip_eid_owner_info owner_info;
	struct hip_host_id *host_id;
	
	HIP_DEBUG("\n");
	
	/* Extra consistency test */
	if (hip_get_msg_type(input) != HIP_USER_SET_MY_EID) {
		err = -EINVAL;
		HIP_ERROR("Bad message type\n");
		goto out_err;
	}
	
	eid_endpoint = hip_get_param(input, HIP_PARAM_EID_ENDPOINT);
	if (!eid_endpoint) {
		err = -ENOENT;
		HIP_ERROR("Could not find eid endpoint\n");
		goto out_err;
	}

	if (eid_endpoint->endpoint.flags & HIP_ENDPOINT_FLAG_HIT) {
		err = -EAFNOSUPPORT;
		HIP_ERROR("setmyeid does not support HITs, only HIs\n");
		goto out_err;
	}
	
	HIP_DEBUG("hi len %d\n",
		  ntohs((eid_endpoint->endpoint.id.host_id.hi_length)));

	HIP_HEXDUMP("eid endpoint", eid_endpoint,
		    hip_get_param_total_len(eid_endpoint));

	host_id = &eid_endpoint->endpoint.id.host_id;

	owner_info.uid = current->uid;
	owner_info.gid = current->gid;
	
	if (hip_host_id_contains_private_key(host_id)) {
		err = hip_private_host_id_to_hit(host_id, &lhi.hit,
						 HIP_HIT_TYPE_HASH126);
		if (err) {
			HIP_ERROR("Failed to calculate HIT from HI.");
			goto out_err;
		}
	
		/* XX TODO: check UID/GID permissions before adding */
		err = hip_user_add_local_hi(host_id, &lhi);
		if (err == -EEXIST) {
			HIP_INFO("Host id exists already, ignoring\n");
			err = 0;
		} else if (err) {
			HIP_ERROR("Adding of localhost id failed");
			goto out_err;
		}
	} else {
		/* Only public key */
		err = hip_host_id_to_hit(host_id,
					 &lhi.hit, HIP_HIT_TYPE_HASH126);
	}
	
	HIP_DEBUG_HIT("calculated HIT", &lhi.hit);
	
	/* Iterate through the interfaces */
	while((param = hip_get_next_param(input, param)) != NULL) {
		/* Skip other parameters (only the endpoint should
		   really be there). */
		if (hip_get_param_type(param) != HIP_PARAM_EID_IFACE)
			continue;
		iface = (struct hip_eid_iface *) param;
		/* XX TODO: convert and store the iface somewhere?? */
		/* XX TODO: check also the UID permissions for storing
		   the ifaces before actually storing them */
	}
	
	/* The eid port information will be filled by the resolver. It is not
	   really meaningful in the eid db. */
	eid.eid_port = htons(0);
	
	lhi.anonymous =
	   (eid_endpoint->endpoint.flags & HIP_ENDPOINT_FLAG_ANON) ?
		1 : 0;
	
	/* XX TODO: check UID/GID permissions before adding ? */
	err = hip_db_set_my_eid(&eid, &lhi, &owner_info);
	if (err) {
		HIP_ERROR("Could not set my eid into the db\n");
		goto out_err;
	}

	HIP_DEBUG("EID value was set to %d\n", ntohs(eid.eid_val));

	/* Clear the output (in the case it is the same as the input) and
	   write a return message */
	
	hip_msg_init(output);
	hip_build_user_hdr(output, HIP_USER_SET_MY_EID, err);
	err = hip_build_param_eid_sockaddr(output,
					   (struct sockaddr *) &eid,
					   sizeof(struct sockaddr_eid));
	if (err) {
		HIP_ERROR("Could not build eid sockaddr\n");
		goto out_err;
	}
	
 out_err:
	return err;
}


int hip_user_handle_set_peer_eid(const struct hip_common *input,
				 struct hip_common *output)
{
	int err = 0;
	struct sockaddr_eid eid;
	struct hip_tlv_common *param = NULL;
	struct hip_eid_endpoint *eid_endpoint;
	struct hip_lhi lhi;
	struct hip_eid_owner_info owner_info;

	HIP_DEBUG("\n");
	
	/* Extra consistency test */
	if (hip_get_msg_type(input) != HIP_USER_SET_PEER_EID) {
		err = -EINVAL;
		HIP_ERROR("Bad message type\n");
		goto out_err;
	}
	
	eid_endpoint = hip_get_param(input, HIP_PARAM_EID_ENDPOINT);
	if (!eid_endpoint) {
		err = -ENOENT;
		HIP_ERROR("Could not find eid endpoint\n");
		goto out_err;
	}
	
	if (eid_endpoint->endpoint.flags & HIP_ENDPOINT_FLAG_HIT) {
		memcpy(&lhi.hit, &eid_endpoint->endpoint.id.hit,
		       sizeof(struct in6_addr));
		HIP_DEBUG_HIT("Peer HIT: ", &lhi.hit);
	} else {
		HIP_DEBUG("host_id len %d\n",
			 ntohs((eid_endpoint->endpoint.id.host_id.hi_length)));
		err = hip_host_id_to_hit(&eid_endpoint->endpoint.id.host_id,
					 &lhi.hit, HIP_HIT_TYPE_HASH126);
		if (err) {
			HIP_ERROR("Failed to calculate HIT from HI.");
			goto out_err;
		}
	}

	lhi.anonymous =
	       (eid_endpoint->endpoint.flags & HIP_ENDPOINT_FLAG_ANON) ? 1 : 0;

	/* Fill eid owner information in and assign a peer EID */

	owner_info.uid = current->uid;
	owner_info.gid = current->gid;
	
	/* The eid port information will be filled by the resolver. It is not
	   really meaningful in the eid db. */
	eid.eid_port = htons(0);

	err = hip_db_set_peer_eid(&eid, &lhi, &owner_info);
	if (err) {
		HIP_ERROR("Could not set my eid into the db\n");
		goto out_err;
	}
	
	/* Iterate through the addresses */

	while((param = hip_get_next_param(input, param)) != NULL) {
		struct sockaddr_in6 *sockaddr;

		HIP_DEBUG("Param type=%d\n", hip_get_param_type(param));

		/* Skip other parameters (only the endpoint should
		   really be there). */
		if (hip_get_param_type(param) != HIP_PARAM_EID_SOCKADDR)
			continue;

		HIP_DEBUG("EID sockaddr found in the msg\n");

		sockaddr =
		  (struct sockaddr_in6 *) hip_get_param_contents_direct(param);
		if (sockaddr->sin6_family != AF_INET6) {
			HIP_INFO("sa_family %d not supported, ignoring\n",
				 sockaddr->sin6_family);
			continue;
		}

		HIP_DEBUG_IN6ADDR("Peer IPv6 address", &sockaddr->sin6_addr);

		/* XX FIX: the mapping should be tagged with an uid */

		err = hip_insert_peer_map_work_order(&lhi.hit,
						     &sockaddr->sin6_addr,1,0);
		if (err) {
			HIP_ERROR("Failed to insert map work order (%d)\n",
				  err);
			goto out_err;
		}
	}
	
	/* Finished. Write a return message with the EID. */
	
	hip_build_user_hdr(output, hip_get_msg_type(input), -err);
	err = hip_build_param_eid_sockaddr(output,
					   (struct sockaddr *) &eid,
					   sizeof(eid));
	if (err) {
		HIP_ERROR("Could not build eid sockaddr\n");
		goto out_err;
	}

 out_err:
	/* XX FIXME: if there were errors, remove eid and hit-ip mappings
	   if necessary */

	return err;
}

