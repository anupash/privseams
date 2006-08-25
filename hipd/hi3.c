#include "hi3.h"

#ifdef CONFIG_HIP_HI3
static int hi3_hi_initializer(void **arg) {
  //	insert_trigger(&rsa_lhi.hit, (struct hip_host_id_entry *)
		       //	       hip_get_hostid_entry_by_lhi(&hip_local_hostid_db, &rsa_lhi.hit));
	//	insert_trigger(&dsa_lhi.hit, (struct hip_host_id_entry *)
	//	       hip_get_hostid_entry_by_lhi(&hip_local_hostid_db, &dsa_lhi.hit));
	return 0;
}

static int addr_parse(char *buf, struct sockaddr_in6 *in6, int len, int *res) {
	struct hi3_ipv4_addr *h4 = (struct hi3_ipv4_addr *)buf;
	if (len < (h4->sin_family == AF_INET ? sizeof(struct hi3_ipv4_addr) : 
		   sizeof(struct hi3_ipv6_addr))) {
		HIP_ERROR("Received packet too small. Dropping\n");
		*res = 0;
		return 0;
	}

	if (h4->sin_family == AF_INET) {
		((struct sockaddr_in *)in6)->sin_addr = h4->sin_addr;
		((struct sockaddr_in *)in6)->sin_family = AF_INET;
		*res = AF_INET;
		return sizeof(struct hi3_ipv4_addr);

	} else if (h4->sin_family == AF_INET6) {
		in6->sin6_addr = ((struct hi3_ipv6_addr *)buf)->sin6_addr;
		in6->sin6_family = AF_INET6;
		*res = AF_INET6;
		return sizeof(struct hi3_ipv4_addr);
	} 

	HIP_ERROR("Illegal family. Dropping\n");
	return 0;
}

/**
 * This is the i3 callback to process received data.
 */
static void hip_i3_inbound(cl_trigger *t, void* data, void *fun_ctx) 
{
	cl_buf* clb = (cl_buf *)data;
	struct hip_common *hip_common;
	struct hip_work_order *hwo;
	struct sockaddr_in6 src, dst;
	struct hi3_ipv4_addr *h4;
	struct hi3_ipv6_addr *h6;
	int family, l, type;
	char *buf = clb->data;
	int len = clb->data_len;

	/* First check the hi3 address header */

	/* Source and destination address */
	l = addr_parse(buf, &src, len, &family);
	if (family == 0) goto out_err;
	len -= l;
	buf += l;

	l = addr_parse(buf, &dst, len, &family);
	if (family == 0) goto out_err;
	len -= l;
	buf += l;

	/* See if there is at least the HIP header in the packet */
        if (len < sizeof(struct hip_common)) {
		HIP_ERROR("Received packet too small. Dropping\n");
		goto out_err;
	}
	
	hip_common = (struct hip_common*)buf;
	HIP_DEBUG("Received HIP packet type %d\n", hip_common->type_hdr);
	_HIP_HEXDUMP("HIP PACKET", hip_common,
		     hip_get_msg_total_len(hip_common));

        if (hip_verify_network_header(hip_common, 
				      (struct sockaddr *)&src, 
				      (struct sockaddr *)&dst,
				      len)) {
		HIP_ERROR("Verifying of the network header failed\n");
		goto out_err;
	}

	if (hip_check_network_msg(hip_common)) {
		HIP_ERROR("HIP packet is invalid\n");
		goto out_err;
	}

	if (hip_receive_control_packet(hip_common)) {
		HIP_ERROR("HIP packet processsing failed\n");
		goto out_err;
	}

 out_err:
	cl_free_buf(clb);
}

/* 
 * i3 callbacks for trigger management
 */
static void constraint_failed(cl_trigger *t, void *data, void *fun_ctx) {
	/* This should never occur if the infrastructure works */
	HIP_ERROR("Trigger constraint failed\n");
}

static void trigger_inserted(cl_trigger *t, void *data, void *fun_ctx) {	
	HIP_DEBUG("Trigger inserted\n");
}

static void trigger_failure(cl_trigger *t, void *data, void *fun_ctx) {
	/* FIXME: A small delay before trying again? */
	HIP_ERROR("Trigger failed, reinserting...\n");
	
	/* Reinsert trigger */
	cl_insert_trigger(t, 0);
}

static int insert_trigger(struct in6_addr *hit, 
			  struct hip_host_id_entry *entry) {
	ID id, ida;
	cl_trigger *t1, *t2;
	Key key;

	HIP_ASSERT(entry);

	/*
	 * Create and insert triggers (id, ida), and (ida, R), respectively.
	 * All triggers are r-constrained (right constrained)
	 */
	bzero(&id, ID_LEN);
	memcpy(&id, hit, sizeof(hit));
	get_random_bytes(id.x, ID_LEN);	
#if 0
 FIXME: should these be here or not...
	cl_set_private_id(&id);
	cl_set_private_id(&ida);
#endif 

	/* Note: ida will be updated as ida.key = h_r(id.key) */
	t1 = cl_create_trigger_id(&id, ID_LEN_BITS, &ida,
				  CL_TRIGGER_CFLAG_R_CONSTRAINT);
	t2  = cl_create_trigger(&ida, ID_LEN_BITS, &key,
				CL_TRIGGER_CFLAG_R_CONSTRAINT);

	/* associate callbacks with the inserted trigger */
	cl_register_trigger_callback(t2, CL_CBK_TRIGGER_CONSTRAINT_FAILED,
				     constraint_failed, NULL);
	cl_register_trigger_callback(t2, CL_CBK_RECEIVE_PAYLOAD,
				     hip_i3_inbound, NULL);
	cl_register_trigger_callback(t2, CL_CBK_TRIGGER_INSERTED,
				     trigger_inserted, NULL);
	cl_register_trigger_callback(t2, CL_CBK_TRIGGER_REFRESH_FAILED,
				     trigger_failure, NULL);

	/* Insert triggers */
	cl_insert_trigger(t2, 0);
	cl_insert_trigger(t1, 0);

	//entry->t1 = t1; FIXME: with handlers/a
	//entry->t2 = t2;
}

#endif /* HIP_CONFIG_HI3 */
 



