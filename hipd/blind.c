#include "blind.h"



int hip_set_blind_on_sa(hip_ha_t *entry, void *not_used)
{
  int err = 0;
  
  if(entry) {
    entry->blind = 1;
  }
 out_err:
  return err;
}

int hip_set_blind_off_sa(hip_ha_t *entry, void *not_used)
{
  int err = 0;
  
  if(entry) {
    entry->blind = 0;
  }
 out_err:
  return err;
}

int hip_set_blind_on(void)
{
  int err = 0;
  
  hip_blind_status = 1;
  HIP_IFEL(hip_for_each_ha(hip_set_blind_on_sa, NULL), 0,
	   "for_each_ha err.\n");
  
 out_err:
  return err;
}

int hip_set_blind_off(void)
{
  int err = 0;
  
  hip_blind_status = 0;
  HIP_IFEL(hip_for_each_ha(hip_set_blind_off_sa, NULL), 0,
	   "for_each_ha err.\n");
  
 out_err:
  return err;
}


int hip_blind_get_status(void)
{
  return hip_blind_status;
}

int hip_handle_i1_blind(struct hip_common *i1,
			struct in6_addr *i1_saddr,
			struct in6_addr *i1_daddr,
			hip_ha_t *entry,
			struct hip_stateless_info *i1_info) 
{
  struct hip_common *r1pkt = NULL;
  struct in6_addr hitr_plain;
  int hashalgo;//just to send it in the function to follow;
               //hashalgo should be SHA1();
  struct in6_addr *own_addr, *dst_addr;
  struct hip_tlv_common *puzzle = NULL;
  int err = 0;
#if 0

  HIP_DEBUG("\n");

  // if blind we have to get the puzzle from the precreated r1 s and 
  //construct a new r1 which has to be sent...
  

  
  //XX--TODO: SHA1 alone is enough.. so, change the corresponding functions of plain_to_blind and blind_to_plain
	

  own_addr = i1_daddr;
  dst_addr = ((!dstip || ipv6_addr_any(dstip)) ? i1_saddr : dstip);


  HIP_IFEL(hip_blind_to_plain_hit(i1->hitr, hitr_plain, nonce->nonce, hashalgo),-1,
	   "Unable to unblind the responder HIT");
	
	HIP_IFEL(!(r1pkt = hip_get_r1(dst_addr, own_addr, src_hit, dst_hit)), -ENOENT,
		 "No precreated R1\n");
	
	if (dst_hit)
		ipv6_addr_copy(&r1pkt->hitr, dst_hit);
	else
		memset(&r1pkt->hitr, 0, sizeof(struct in6_addr));
	_HIP_DEBUG_HIT("hip_xmit_r1:: ripkt->hitr", &r1pkt->hitr);
	
	//set cookie state to used (more or less temporary solution ?)
	_HIP_HEXDUMP("R1 pkt", r1pkt, hip_get_msg_total_len(r1pkt));
	
	
	// get puzzle: hip_get_param(r1, HIP_PARAM_PUZZLE)
	puzzle = (struct hip_tlv_common *)hip_get_param(i1, HIP_PARAM_PUZZLE);
	
	// create_r1: hip_create_r1()
	// modify create_r1:
	// * add int flags and set a bit for blinded mode
	// * if (flag & BLIND_MODE) then skip HOST_ID building
	//XX-- most of the work in this func hip_xmit_ has been done.. so.. wud just make hip_cum_send call
	// REMEMBER TO DEALLOCATE MEMORY IN THE END

#endif
 out_err:
	return err;
}


/**
 * hip_create_r1 - construct a new R1-payload
 * @src_hit: source HIT used in the packet
 *
 * Returns 0 on success, or negative on error
 */
struct hip_common *hip_create_blinded_r1(const struct in6_addr *src_hit, 
					 int (*sign)(struct hip_host_id *p, struct hip_common *m),
					 struct hip_host_id *host_id_priv,
					 const struct hip_host_id *host_id_pub,
					 int cookie_k)
{
#if 0
 	struct hip_common *msg;
 	int err = 0,dh_size,written, mask;
 	u8 *dh_data = NULL;
 	/* Supported HIP and ESP transforms. */
 	hip_transform_suite_t transform_hip_suite[] = {
		HIP_HIP_AES_SHA1,
		HIP_HIP_3DES_SHA1,
		HIP_HIP_NULL_SHA1
	};
 	hip_transform_suite_t transform_esp_suite[] = {
		HIP_ESP_AES_SHA1,
		HIP_ESP_3DES_SHA1,
		HIP_ESP_NULL_SHA1
	};
	//	struct hip_host_id  *host_id_pub = NULL;
	HIP_IFEL(!(msg = hip_msg_alloc()), -ENOMEM, "Out of memory\n");

 	/* Allocate memory for writing Diffie-Hellman shared secret */
	HIP_IFEL((dh_size = hip_get_dh_size(HIP_DEFAULT_DH_GROUP_ID)) == 0, 
		 -1, "Could not get dh size\n");
	HIP_IFEL(!(dh_data = HIP_MALLOC(dh_size, GFP_ATOMIC)), 
		 -1, "Failed to alloc memory for dh_data\n");
	memset(dh_data, 0, dh_size);

	_HIP_DEBUG("dh_size=%d\n", dh_size);
	//	HIP_IFEL(!(host_id_pub = hip_get_any_localhost_public_key(HIP_HI_DEFAULT_ALGO)),
	//	 -1, "Could not acquire localhost public key\n");
	//HIP_HEXDUMP("Our pub host id\n", host_id_pub,
	//	    hip_get_param_total_len(host_id_pub));
	
 	/* Ready to begin building of the R1 packet */
#ifdef CONFIG_HIP_RVS
	mask |= HIP_CONTROL_RVS_CAPABLE; //XX: FIXME
#endif


	mask |= HIP_CONTROL_BLIND;

	HIP_DEBUG("mask=0x%x\n", mask);
	/* TODO: TH: hip_build_network_hdr has to be replaced with an apprporiate function pointer */
 	hip_build_network_hdr(msg, HIP_R1, mask, src_hit, NULL);

	/********** R1_COUNTER (OPTIONAL) *********/

 	/********** PUZZLE ************/
	HIP_IFEL(hip_build_param_puzzle(msg, cookie_k,
					42 /* 2^(42-32) sec lifetime */, 
					0, 0),  -1, 
		 "Cookies were burned. Bummer!\n");

 	/********** Diffie-Hellman **********/
	HIP_IFEL((written = hip_insert_dh(dh_data, dh_size,
					  HIP_DEFAULT_DH_GROUP_ID)) < 0,
		 -1, "Could not extract DH public key\n");
	
	HIP_IFEL(hip_build_param_diffie_hellman_contents(msg,
							 HIP_DEFAULT_DH_GROUP_ID,
							 dh_data, written), -1,
		 "Building of DH failed.\n");

 	/********** HIP transform. **********/
 	HIP_IFEL(hip_build_param_transform(msg, HIP_PARAM_HIP_TRANSFORM,
					   transform_hip_suite,
					   sizeof(transform_hip_suite) /
					   sizeof(hip_transform_suite_t)), -1, 
		 "Building of HIP transform failed\n");

 	/********** ESP-ENC transform. **********/
 	HIP_IFEL(hip_build_param_transform(msg, HIP_PARAM_ESP_TRANSFORM,  
					   transform_esp_suite,
					   sizeof(transform_esp_suite) /
					   sizeof(hip_transform_suite_t)), -1, 
		 "Building of ESP transform failed\n");

	/********** ECHO_REQUEST_SIGN (OPTIONAL) *********/

	// XX TODO: do if there is time
	//HIP_HEXDUMP("Pubkey:", host_id_pub, hip_get_param_total_len(host_id_pub));

 	/********** Signature 2 **********/	
 	HIP_IFEL(sign(host_id_priv, msg), -1, "Signing of R1 failed.\n");
	_HIP_HEXDUMP("R1", msg, hip_get_msg_total_len(msg));

	/********** ECHO_REQUEST (OPTIONAL) *********/

	/* Fill puzzle parameters */
	{
		struct hip_puzzle *pz;
		uint64_t random_i;

		HIP_IFEL(!(pz = hip_get_param(msg, HIP_PARAM_PUZZLE)), -1, 
			 "Internal error\n");

		// FIX ME: this does not always work:
		//get_random_bytes(pz->opaque, HIP_PUZZLE_OPAQUE_LEN);

		/* hardcode kludge */
		pz->opaque[0] = 'H';
		pz->opaque[1] = 'I';
		//pz->opaque[2] = 'P';
		/* todo: remove random_i variable */
		get_random_bytes(&random_i,sizeof(random_i));
		pz->I = random_i;
	}

 	/************** Packet ready ***************/

// 	if (host_id_pub)
	//		HIP_FREE(host_id_pub);
 	if (dh_data)
 		HIP_FREE(dh_data);

	//HIP_HEXDUMP("r1", msg, hip_get_msg_total_len(msg));

	return msg;

  out_err:
	//	if (host_id_pub)
	//	HIP_FREE(host_id_pub);
 	if (msg)
 		HIP_FREE(msg);
 	if (dh_data)
 		HIP_FREE(dh_data);
#endif

  	return NULL;
}

int hip_precreate_blinded_r1(struct hip_r1entry *r1table_blinded, struct in6_addr *hit, 
			     int (*sign)(struct hip_host_id *p, struct hip_common *m),
			     struct hip_host_id *privkey, struct hip_host_id *pubkey)
{
	int i=0;
	for(i = 0; i < HIP_R1TABLESIZE; i++) {
		int cookie_k;

		cookie_k = hip_get_cookie_difficulty(NULL);

		r1table_blinded[i].r1 = hip_create_blinded_r1(hit, sign, privkey, pubkey,
							      cookie_k);
		if (!r1table_blinded[i].r1) {
			HIP_ERROR("Unable to precreate R1s\n");
			goto err_out;
		}

		HIP_DEBUG("Packet %d created\n", i);
	}

	return 1;

 err_out:
	return 0;
}

struct hip_common *hip_get_r1_blinded(struct in6_addr *ip_i, struct in6_addr *ip_r,
			      struct in6_addr *our_hit,
			      struct in6_addr *peer_hit)
{

#if 0
	struct hip_common *err = NULL, *r1 = NULL;
	struct hip_r1entry * r1table_blinded;
	struct hip_host_id_entry *hid;
	int idx, len;

	/* Find the proper R1 table and copy the R1 message from the table */
	HIP_READ_LOCK_DB(HIP_DB_LOCAL_HID);	
	HIP_IFEL(!(hid = hip_get_hostid_entry_by_lhi_and_algo(HIP_DB_LOCAL_HID, our_hit, HIP_ANY_ALGO)), 
		 NULL, "Requested source HIT no more available.\n");
	HIP_DEBUG("!!!!!!!!! Is Requested source HIT available?");
	r1table_blinded = hid->r1;

	idx = hip_calc_cookie_idx(ip_i, ip_r, peer_hit);
	HIP_DEBUG("Calculated index: %d\n", idx);

	/* the code under if 0 periodically changes the puzzle. It is not included
	   in compilation as there is currently no easy way of signing the R1 packet
	   after having changed its puzzle.
	*/

	/* Create a copy of the found entry */
	len = hip_get_msg_total_len(r1table_blinded[idx].r1);
	r1 = HIP_MALLOC(len, GFP_KERNEL);
	memcpy(r1, r1table_blinded[idx].r1, len);
	err = r1;

 out_err:	
	if (!err && r1)
		HIP_FREE(r1);

	HIP_READ_UNLOCK_DB(HIP_DB_LOCAL_HID);
	return err;
#endif
	return NULL;
}

