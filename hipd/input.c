
/** @file
 * This file defines handling functions for incoming packets for the Host
 * Identity Protocol (HIP).
 * 
 * @author  Janne Lundberg
 * @author  Miika Komu
 * @author  Mika Kousa
 * @author  Kristian Slavov
 * @author  Anthony D. Joseph
 * @author  Bing Zhou
 * @author  Tobias Heer
 * @author  Laura Takkinen //blind code
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl.txt">GNU/GPL</a>.
 * @note    Doxygen comments for functions are now in the header file.
 *          Lauri 19.09.2007 16:43
 */
#include "input.h"

#ifdef CONFIG_HIP_OPPORTUNISTIC
extern unsigned int opportunistic_mode;
#endif

/** A function set for NAT travelsal. */
extern hip_xmit_func_set_t nat_xmit_func_set;
extern int hip_build_param_esp_info(struct hip_common *msg,
				    uint16_t keymat_index, uint32_t old_spi,
				    uint32_t new_spi);

/* Fix the packet len before calling this function! */
static int hip_verify_hmac(struct hip_common *buffer, u8 *hmac,
			   void *hmac_key, int hmac_type)
{
	int err = 0;
	u8 *hmac_res = NULL;

	HIP_IFEL(!(hmac_res = HIP_MALLOC(HIP_AH_SHA_LEN, GFP_ATOMIC)), -ENOMEM,
		 "HIP_MALLOC failed\n");

	_HIP_HEXDUMP("HMAC data", buffer, hip_get_msg_total_len(buffer));

	HIP_IFEL(!hip_write_hmac(hmac_type, hmac_key, buffer,
				 hip_get_msg_total_len(buffer), hmac_res),
		 -EINVAL, "Could not build hmac\n");

	_HIP_HEXDUMP("HMAC", hmac_res, HIP_AH_SHA_LEN);
	HIP_IFE(memcmp(hmac_res, hmac, HIP_AH_SHA_LEN), -EINVAL);
	memcmp(hmac_res, hmac, HIP_AH_SHA_LEN);
 out_err:
	if (hmac_res)
		HIP_FREE(hmac_res);

	return err;
}

int hip_verify_packet_hmac(struct hip_common *msg,
			   struct hip_crypto_key *crypto_key)
{
	HIP_DEBUG("hip_verify_packet_hmac() invoked.\n");
	int err = 0, len, orig_len;
	u8 orig_checksum;
	struct hip_crypto_key tmpkey;
	struct hip_hmac *hmac;

	HIP_IFEL(!(hmac = hip_get_param(msg, HIP_PARAM_HMAC)),
		 -ENOMSG, "No HMAC parameter\n");

	/* hmac verification modifies the msg length temporarile, so we have
	   to restore the length */
	orig_len = hip_get_msg_total_len(msg);

	/* hmac verification assumes that checksum is zero */
	orig_checksum = hip_get_msg_checksum(msg);
	hip_zero_msg_checksum(msg);

	len = (u8 *) hmac - (u8*) msg;
	hip_set_msg_total_len(msg, len);

	HIP_HEXDUMP("HMAC key", crypto_key->key,
		    hip_hmac_key_length(HIP_ESP_AES_SHA1));

	HIP_HEXDUMP("HMACced data", msg, len);
	memcpy(&tmpkey, crypto_key, sizeof(tmpkey));

	HIP_IFEL(hip_verify_hmac(msg, hmac->hmac_data, tmpkey.key,
				 HIP_DIGEST_SHA1_HMAC), 
		 -1, "HMAC validation failed\n");

	/* revert the changes to the packet */
	hip_set_msg_total_len(msg, orig_len);
	hip_set_msg_checksum(msg, orig_checksum);

 out_err:
	return err;
}

int hip_verify_packet_rvs_hmac(struct hip_common *msg,
			   struct hip_crypto_key *crypto_key)
{
	int err = 0, len, orig_len;
	u8 orig_checksum;
	struct hip_crypto_key tmpkey;
	struct hip_hmac *hmac;

	_HIP_DEBUG("hip_verify_packet_rvs_hmac() invoked.\n");

	HIP_IFEL(!(hmac = hip_get_param(msg, HIP_PARAM_RVS_HMAC)),
		 -ENOMSG, "No HMAC parameter\n");

	/* hmac verification modifies the msg length temporarily, so we have
	   to restore the length */
	orig_len = hip_get_msg_total_len(msg);

	/* hmac verification assumes that checksum is zero */
	orig_checksum = hip_get_msg_checksum(msg);
	hip_zero_msg_checksum(msg);

	len = (u8 *) hmac - (u8*) msg;
	hip_set_msg_total_len(msg, len);

	HIP_HEXDUMP("HMAC key", crypto_key->key,
		    hip_hmac_key_length(HIP_ESP_AES_SHA1));

	HIP_HEXDUMP("HMACced data", msg, len);
	memcpy(&tmpkey, crypto_key, sizeof(tmpkey));

	HIP_IFEL(hip_verify_hmac(msg, hmac->hmac_data, tmpkey.key,
				 HIP_DIGEST_SHA1_HMAC), 
		 -1, "HMAC validation failed\n");

	/* revert the changes to the packet */
	hip_set_msg_total_len(msg, orig_len);
	hip_set_msg_checksum(msg, orig_checksum);

 out_err:
	return err;
}

int hip_verify_packet_hmac2(struct hip_common *msg,
			    struct hip_crypto_key *crypto_key,
			    struct hip_host_id *host_id)
{
	int err = 0;
	struct hip_crypto_key tmpkey;
	struct hip_hmac *hmac;
	struct hip_common *msg_copy = NULL;
	struct hip_esp_info *esp_info;

	_HIP_DEBUG("hip_verify_packet_hmac2() invoked.\n");
	HIP_IFE(!(msg_copy = hip_msg_alloc()), -ENOMEM);
	memcpy(msg_copy, msg, sizeof(struct hip_common));
	hip_set_msg_total_len(msg_copy, 0);
	hip_zero_msg_checksum(msg_copy);

	esp_info = hip_get_param(msg, HIP_PARAM_ESP_INFO);
	HIP_ASSERT(esp_info);
	HIP_IFE(hip_build_param(msg_copy, esp_info), -EFAULT);
	hip_build_param(msg_copy, host_id);

	HIP_IFEL(!(hmac = hip_get_param(msg, HIP_PARAM_HMAC2)), -ENOMSG, "Packet contained no HMAC parameter\n");
	HIP_HEXDUMP("HMAC data", msg_copy, hip_get_msg_total_len(msg_copy));
	memcpy(&tmpkey, crypto_key, sizeof(tmpkey));

	HIP_IFEL(hip_verify_hmac(msg_copy, hmac->hmac_data, tmpkey.key, HIP_DIGEST_SHA1_HMAC), 
		-1, "HMAC validation failed\n");

 out_err:
	if (msg_copy)
		HIP_FREE(msg_copy);

	return err;
}

int hip_produce_keying_material(struct hip_common *msg,
				struct hip_context *ctx,
				uint64_t I,
				uint64_t J,
				struct hip_dh_public_value **dhpv)
{
	char *dh_shared_key = NULL;
	int hip_transf_length, hmac_transf_length;
	int auth_transf_length, esp_transf_length, we_are_HITg = 0;
	int hip_tfm, esp_tfm, err = 0, dh_shared_len = 1024;
	struct hip_keymat_keymat km;
	struct hip_esp_info *esp_info;
	char *keymat = NULL;
	size_t keymat_len_min; /* how many bytes we need at least for the KEYMAT */
	size_t keymat_len; /* note SHA boundary */
	struct hip_tlv_common *param = NULL;
	uint16_t esp_keymat_index, esp_default_keymat_index;
	struct hip_diffie_hellman *dhf;
	hip_ha_t *blind_entry;
	int type = 0;
	uint16_t nonce;
	struct in6_addr *plain_local_hit = NULL;

	_HIP_DEBUG("hip_produce_keying_material() invoked.\n");
	/* Perform light operations first before allocating memory or
	 * using lots of CPU time */
	HIP_IFEL(!(param = hip_get_param(msg, HIP_PARAM_HIP_TRANSFORM)),
		 -EINVAL, 
		 "Could not find HIP transform\n");
	HIP_IFEL((hip_tfm = hip_select_hip_transform((struct hip_hip_transform *) param)) == 0, 
		 -EINVAL, "Could not select HIP transform\n");
	HIP_IFEL(!(param = hip_get_param(msg, HIP_PARAM_ESP_TRANSFORM)),
		 -EINVAL, 
		 "Could not find ESP transform\n");
	HIP_IFEL((esp_tfm = hip_select_esp_transform((struct hip_esp_transform *) param)) == 0, 
		 -EINVAL, "Could not select proper ESP transform\n");

	hip_transf_length = hip_transform_key_length(hip_tfm);
	hmac_transf_length = hip_hmac_key_length(esp_tfm);
	esp_transf_length = hip_enc_key_length(esp_tfm);
	auth_transf_length = hip_auth_key_length_esp(esp_tfm);

	HIP_DEBUG("transform lengths: hip=%d, hmac=%d, esp=%d, auth=%d\n",
		  hip_transf_length, hmac_transf_length, esp_transf_length,
		  auth_transf_length);

	HIP_DEBUG("I=0x%llx J=0x%llx\n", I, J);

	/* Create only minumum amount of KEYMAT for now. From draft
	 * chapter HIP KEYMAT we know how many bytes we need for all
	 * keys used in the base exchange. */
	keymat_len_min = hip_transf_length + hmac_transf_length +
		hip_transf_length + hmac_transf_length + esp_transf_length +
		auth_transf_length + esp_transf_length + auth_transf_length;

	/* assume esp keys are after authentication keys */
	esp_default_keymat_index = hip_transf_length + hmac_transf_length +
		hip_transf_length + hmac_transf_length;

	/* R1 contains no ESP_INFO */
	esp_info = hip_get_param(msg, HIP_PARAM_ESP_INFO);
	if (esp_info)
		esp_keymat_index = ntohs(esp_info->keymat_index);
	else
		esp_keymat_index = esp_default_keymat_index;

	if (esp_keymat_index != esp_default_keymat_index) {
		/* XX FIXME */
		HIP_ERROR("Varying keymat slices not supported yet\n");
		err = -1;
		goto out_err;
	}

	keymat_len = keymat_len_min;
	if (keymat_len % HIP_AH_SHA_LEN)
		keymat_len += HIP_AH_SHA_LEN - (keymat_len % HIP_AH_SHA_LEN);

	HIP_DEBUG("keymat_len_min=%u keymat_len=%u\n", keymat_len_min,
		  keymat_len);
	HIP_IFEL(!(keymat = HIP_MALLOC(keymat_len, GFP_KERNEL)), -ENOMEM,
		 "No memory for KEYMAT\n");

	/* 1024 should be enough for shared secret. The length of the
	 * shared secret actually depends on the DH Group. */
	/*! \todo 1024 -> hip_get_dh_size ? */
	HIP_IFEL(!(dh_shared_key = HIP_MALLOC(dh_shared_len, GFP_KERNEL)),
		 -ENOMEM,  "No memory for DH shared key\n");
	memset(dh_shared_key, 0, dh_shared_len);
	HIP_IFEL(!(dhf= (struct hip_diffie_hellman*)hip_get_param(msg, HIP_PARAM_DIFFIE_HELLMAN)),
		 -ENOENT,  "No Diffie-Hellman param found\n");

	/* If the message has two DH keys, select (the stronger, usually) one. */
	*dhpv = hip_dh_select_key(dhf);

	_HIP_DEBUG("dhpv->group_id= %d\n",(*dhpv)->group_id);
	_HIP_DEBUG("dhpv->pub_len= %d\n", ntohs((*dhpv)->pub_len));

	HIP_IFEL((dh_shared_len = hip_calculate_shared_secret(
	     (*dhpv)->public_value,(*dhpv)->group_id, ntohs((*dhpv)->pub_len), 
	     dh_shared_key, dh_shared_len)) < 0,
	     -EINVAL, "Calculation of shared secret failed\n");
	HIP_DEBUG("dh_shared_len=%u\n", dh_shared_len);
	HIP_HEXDUMP("DH SHARED PARAM", param, hip_get_param_total_len(param));
	HIP_HEXDUMP("DH SHARED KEY", dh_shared_key, dh_shared_len);

#ifdef CONFIG_HIP_BLIND
	HIP_DEBUG_HIT("key_material msg->hits (responder)", &msg->hits);
	HIP_DEBUG_HIT("key_material msg->hitr (local)", &msg->hitr);
	
	if (hip_blind_get_status()) {
	  type = hip_get_msg_type(msg);

	  /* Initiator produces keying material for I2: 
	   * uses own blinded hit and plain initiator hit
	   */
	  if (type == HIP_R1) {
	    HIP_IFEL((blind_entry = hip_hadb_find_by_blind_hits(&msg->hitr, &msg->hits)) == NULL, 
		     -1, "Could not found blinded hip_ha_t entry\n");
	    hip_make_keymat(dh_shared_key, dh_shared_len,
			    &km, keymat, keymat_len,
			    &blind_entry->hit_peer, &msg->hitr, &ctx->keymat_calc_index, I, J);
	  } 
	  /* Responder produces keying material for handling I2: 
	   * uses own plain hit and blinded initiator hit
	   */
	  else if (type == HIP_I2) {
	    HIP_IFEL((plain_local_hit = HIP_MALLOC(sizeof(struct in6_addr), 0)) == NULL,
		     -1, "Couldn't allocate memory\n");
	    HIP_IFEL(hip_blind_get_nonce(msg, &nonce), -1, "hip_blind_get_nonce failed\n");
	    HIP_IFEL(hip_plain_fingerprint(&nonce, &msg->hitr, plain_local_hit),
		     -1, "hip_plain_fingerprint failed\n");
	    HIP_DEBUG_HIT("plain_local_hit for handling I2", plain_local_hit);
	    hip_make_keymat(dh_shared_key, dh_shared_len,
			    &km, keymat, keymat_len,
			    &msg->hits, plain_local_hit, &ctx->keymat_calc_index, I, J);
	  }
	}
#endif
	if (!hip_blind_get_status()) {
	  hip_make_keymat(dh_shared_key, dh_shared_len,
			  &km, keymat, keymat_len,
			  &msg->hits, &msg->hitr, &ctx->keymat_calc_index, I, J);
	}
	/* draw from km to keymat, copy keymat to dst, length of
	 * keymat is len */

#if 0
	/* removed this because the cts is already set to 0 when it is
	   created */
	bzero(&ctx->hip_enc_in.key, sizeof(struct hip_crypto_key));
	bzero(&ctx->hip_enc_out.key, sizeof(struct hip_crypto_key));
	bzero(&ctx->hip_hmac_in.key, sizeof(struct hip_crypto_key));
	bzero(&ctx->hip_hmac_out.key, sizeof(struct hip_crypto_key));
	bzero(&ctx->esp_in.key, sizeof(struct hip_crypto_key));
	bzero(&ctx->esp_out.key, sizeof(struct hip_crypto_key));
	bzero(&ctx->auth_in.key, sizeof(struct hip_crypto_key));
	bzero(&ctx->auth_out.key, sizeof(struct hip_crypto_key));
#endif
	/* Draw keys: */
	we_are_HITg = hip_hit_is_bigger(&msg->hitr, &msg->hits);
	HIP_DEBUG("we are HIT%c\n", we_are_HITg ? 'g' : 'l');
	if (we_are_HITg) {
		hip_keymat_draw_and_copy(ctx->hip_enc_out.key, &km,	hip_transf_length);
		hip_keymat_draw_and_copy(ctx->hip_hmac_out.key,&km,	hmac_transf_length);
		hip_keymat_draw_and_copy(ctx->hip_enc_in.key, 	&km,	hip_transf_length);
 		hip_keymat_draw_and_copy(ctx->hip_hmac_in.key, &km,	hmac_transf_length);
		hip_keymat_draw_and_copy(ctx->esp_out.key, 	&km,	esp_transf_length);
 		hip_keymat_draw_and_copy(ctx->auth_out.key, 	&km,	auth_transf_length);
 		hip_keymat_draw_and_copy(ctx->esp_in.key, 	&km,	esp_transf_length);
 		hip_keymat_draw_and_copy(ctx->auth_in.key, 	&km,	auth_transf_length);
 	} else {
 	 	hip_keymat_draw_and_copy(ctx->hip_enc_in.key, 	&km,	hip_transf_length);
 		hip_keymat_draw_and_copy(ctx->hip_hmac_in.key,	&km,	hmac_transf_length);
 		hip_keymat_draw_and_copy(ctx->hip_enc_out.key,	&km,	hip_transf_length);
 		hip_keymat_draw_and_copy(ctx->hip_hmac_out.key,&km,	hmac_transf_length);
 		hip_keymat_draw_and_copy(ctx->esp_in.key, 	&km,	esp_transf_length);
 		hip_keymat_draw_and_copy(ctx->auth_in.key, 	&km,	auth_transf_length);
 		hip_keymat_draw_and_copy(ctx->esp_out.key, 	&km,	esp_transf_length);
 		hip_keymat_draw_and_copy(ctx->auth_out.key, 	&km,	auth_transf_length);
 	}
 	HIP_HEXDUMP("HIP-gl encryption:", &ctx->hip_enc_out.key, hip_transf_length);
 	HIP_HEXDUMP("HIP-gl integrity (HMAC) key:", &ctx->hip_hmac_out.key,
 		    hmac_transf_length);
 	_HIP_DEBUG("skipping HIP-lg encryption key, %u bytes\n", hip_transf_length);
	HIP_HEXDUMP("HIP-lg encryption:", &ctx->hip_enc_in.key, hip_transf_length);
 	HIP_HEXDUMP("HIP-lg integrity (HMAC) key:", &ctx->hip_hmac_in.key, hmac_transf_length);
 	HIP_HEXDUMP("SA-gl ESP encryption key:", &ctx->esp_out.key, esp_transf_length);
 	HIP_HEXDUMP("SA-gl ESP authentication key:", &ctx->auth_out.key, auth_transf_length);
 	HIP_HEXDUMP("SA-lg ESP encryption key:", &ctx->esp_in.key, esp_transf_length);
 	HIP_HEXDUMP("SA-lg ESP authentication key:", &ctx->auth_in.key, auth_transf_length);

#undef KEYMAT_DRAW_AND_COPY

	/* the next byte when creating new keymat */
	ctx->current_keymat_index = keymat_len_min; /* offset value, so no +1 ? */
	ctx->keymat_calc_index = (ctx->current_keymat_index / HIP_AH_SHA_LEN) + 1;
	ctx->esp_keymat_index = esp_keymat_index;

	memcpy(ctx->current_keymat_K, keymat+(ctx->keymat_calc_index-1)*HIP_AH_SHA_LEN, HIP_AH_SHA_LEN);

	_HIP_DEBUG("ctx: keymat_calc_index=%u current_keymat_index=%u\n",
		   ctx->keymat_calc_index, ctx->current_keymat_index);
	_HIP_HEXDUMP("CTX CURRENT KEYMAT", ctx->current_keymat_K, HIP_AH_SHA_LEN);

	/* store DH shared key */
	ctx->dh_shared_key = dh_shared_key;
	ctx->dh_shared_key_len = dh_shared_len;

	/* on success HIP_FREE for dh_shared_key is called by caller */
 out_err:
	if (err && dh_shared_key)
		HIP_FREE(dh_shared_key);
	if (keymat)
		HIP_FREE(keymat);
	if (plain_local_hit)
	  HIP_FREE(plain_local_hit);
	return err;
}

int hip_receive_control_packet(struct hip_common *msg,
			       struct in6_addr *src_addr,
			       struct in6_addr *dst_addr,
	                       hip_portpair_t *msg_info,
                               int filter)
{
	hip_ha_t tmp, *entry = NULL;
	int err = 0, type, skip_sync = 0;

	/* Debug printing of received packet information. All received HIP
	   control packets are first passed to this function. Therefore
	   printing packet data here works for all packets. To avoid excessive
	   debug printing do not print this information inside the individual
	   receive or handle functions. */
	_HIP_DEBUG("hip_receive_control_packet() invoked.\n");
	HIP_DEBUG_IN6ADDR("Source IP", src_addr);
	HIP_DEBUG_IN6ADDR("Destination IP", dst_addr);
	HIP_DEBUG_HIT("HIT Sender", &msg->hits);
	HIP_DEBUG_HIT("HIT Receiver", &msg->hitr);
	HIP_DEBUG("source port: %u, destination port: %u\n",
		  msg_info->src_port, msg_info->dst_port);
	HIP_DUMP_MSG(msg);

	HIP_IFEL(hip_check_network_msg(msg), -1,
		 "checking control message failed\n", -1);

	type = hip_get_msg_type(msg);

	/** @todo Check packet csum.*/

	entry = hip_hadb_find_byhits(&msg->hits, &msg->hitr);
#ifdef CONFIG_HIP_OPPORTUNISTIC
	if (!entry && opportunistic_mode &&
	    (type == HIP_I1 || type == HIP_R1)) {
		entry = hip_oppdb_get_hadb_entry_i1_r1(msg, src_addr,
						       dst_addr,
						       msg_info);
		/* If agent is prompting user, let's make sure that
		   the death counter in maintenance does not expire */
		if (hip_agent_is_alive())
		    entry->hip_opp_fallback_disable = filter;
	} else {
		/* Ugly bug fix for "conntest-client hostname tcp 12345"
		   where hostname maps to HIT and IP in hosts files.
		   Why the heck the receive function points here to
		   receive_opp_r1 even though we have a regular entry? */

	     /* What is the point of having receive function pointer anyways?
		Not to mention a SET of them... */
		if (entry)
			entry->hadb_rcv_func->hip_receive_r1 = hip_receive_r1;
	}
#endif
	
#ifdef CONFIG_HIP_AGENT
	/** Filter packet trough agent here. */
	if ((type == HIP_I1 || type == HIP_R1) && filter)
	{
		HIP_DEBUG("Filtering packet trough agent now (packet is %s).\n",
		          type == HIP_I1 ? "I1" : "R1");
		err = hip_agent_filter(msg, src_addr, dst_addr, msg_info);
		/* If packet filtering OK, return and wait for agent reply. */
		if (err == 0) goto out_err;
	}
#endif

#ifdef CONFIG_HIP_BLIND
	HIP_DEBUG("Blind block\n");
	// Packet that was received is blinded
	if (ntohs(msg->control) & HIP_PACKET_CTRL_BLIND) {
	  HIP_DEBUG("Message is blinded\n");
	  if(type == HIP_I1) { //Responder receives
	    HIP_DEBUG("set_blind_on\n");
	    // Activate blind mode
	    hip_set_blind_on();
	  } else if (type == HIP_R1 || // Initiator receives
		     type == HIP_I2 || // Responder receives
		     type == HIP_R2) { // Initiator receives
	    if (hip_blind_get_status()) 
	      entry = hip_hadb_find_by_blind_hits(&msg->hitr, &msg->hits);
	    else {
	      HIP_ERROR("Blinded packet %d received, but blind is not activated, drop packet\n", type);
	      err = -ENOSYS;
	      goto out_err;
	    }
	  } else {
	    //BLIND TODO: UPDATE, NOTIFY... 
	  }  
	} else {
	     if(hip_blind_get_status()) {
               HIP_ERROR("Blind mode is on, but we received plain packet %d, drop packet\n", type);
               err = -ENOSYS;
               goto out_err;
             }
        }	  
	/* fetch the state from the hadb database to be able to choose the
	   appropriate message handling functions */
	if (!(ntohs(msg->control) & HIP_PACKET_CTRL_BLIND)) { // Normal packet received
	    entry = hip_hadb_find_byhits(&msg->hits, &msg->hitr);
	}
#endif

	switch(type) {
	case HIP_I1:
		/* No state. */
	  HIP_DEBUG("Received HIP_I1 message\n");
	  err = (hip_get_rcv_default_func_set())->hip_receive_i1(msg, src_addr,
								 dst_addr,
								 entry,
								 msg_info);
	  break;
		
	case HIP_I2:
		/* Possibly state. */
		if(entry){
		     err = entry->hadb_rcv_func->
			  hip_receive_i2(msg, src_addr, dst_addr, entry,
					 msg_info);
		} else {
			err = ((hip_rcv_func_set_t *)
			       hip_get_rcv_default_func_set())->
				hip_receive_i2(msg, src_addr, dst_addr, entry,
					       msg_info);
		}
		break;
		
	case HIP_R1:
	  	/* State. */
	        HIP_IFEL(!entry, -1, "No entry when receiving R1\n");
		HIP_IFCS(entry, err = entry->hadb_rcv_func->
			 hip_receive_r1(msg, src_addr, dst_addr, entry,
					msg_info));
		break;
		
	case HIP_R2:
		HIP_IFCS(entry, err = entry->hadb_rcv_func->
			 hip_receive_r2(msg, src_addr, dst_addr, entry,
					msg_info));
		//HIP_STOP_TIMER(KMM_GLOBAL,"Base Exchange");
		break;
		
	case HIP_UPDATE:
		HIP_IFCS(entry, err = entry->hadb_rcv_func->
			 hip_receive_update(msg, src_addr, dst_addr, entry,
					    msg_info));
		break;
		
	case HIP_NOTIFY:
		HIP_IFCS(entry, err = entry->hadb_rcv_func->
			 hip_receive_notify(msg, src_addr, dst_addr, entry));
		break;
		
	case HIP_BOS:
	     HIP_IFCS(entry, err = entry->hadb_rcv_func->
		      hip_receive_bos(msg, src_addr, dst_addr, entry,
				      msg_info));
	     
	     /*In case of BOS the msg->hitr is null, therefore it is replaced
	       with our own HIT, so that the beet state can also be
	       synchronized. */

	     ipv6_addr_copy(&tmp.hit_peer, &msg->hits);
	     hip_init_us(&tmp, NULL);
	     ipv6_addr_copy(&msg->hitr, &tmp.hit_our);
	     skip_sync = 0;
	     break;
	case HIP_CLOSE:
		HIP_IFCS(entry, err = entry->hadb_rcv_func->
			 hip_receive_close(msg, entry));
		break;
		
	case HIP_CLOSE_ACK:
		HIP_IFCS(entry, err = entry->hadb_rcv_func->
			 hip_receive_close_ack(msg, entry));
		break;
		
	default:
		HIP_ERROR("Unknown packet %d\n", type);
		err = -ENOSYS;
	}
	
	HIP_DEBUG("Done with control packet, err is %d.\n", err);
	
	if (err)
		goto out_err;
	
out_err:
	
	return err;
}

int hip_receive_udp_control_packet(struct hip_common *msg,
				   struct in6_addr *saddr,
				   struct in6_addr *daddr,
				   hip_portpair_t *info)
{
        hip_ha_t *entry;
        int err = 0, type, skip_sync = 0;
	struct in6_addr *saddr_public = saddr;

	_HIP_DEBUG("hip_nat_receive_udp_control_packet() invoked.\n");

        type = hip_get_msg_type(msg);
        entry = hip_hadb_find_byhits(&msg->hits, &msg->hitr);
		
#ifndef CONFIG_HIP_RVS
	/* The ip of RVS is taken to be ip of the peer while using RVS server
	   to relay R1. Hence have removed this part for RVS --Abi */
	if (entry && (type == HIP_R1 || type == HIP_R2)) {
		/* When the responder equals to the NAT host, it can reply from
		   the private address instead of the public address. In this
		   case, the saddr will point to the private address, and using
		   it for I2 will fail the puzzle indexing (I1 was sent to the
		   public address). So, we make sure here that we're using the
		   same dst address for the I2 as for I1. Also, this address is
		   used for setting up the SAs: handle_r1 creates one-way SA and
		   handle_i2 the other way; let's make sure that they are the
		   same. */
		saddr_public = &entry->preferred_address;
	}
#endif

	HIP_IFEL(hip_receive_control_packet(msg, saddr_public, daddr,info,1), -1,
		 "receiving of control packet failed\n");
 out_err:
	return err;
}

int hip_create_i2(struct hip_context *ctx, uint64_t solved_puzzle, 
		  struct in6_addr *r1_saddr,
		  struct in6_addr *r1_daddr,
		  hip_ha_t *entry,
	          hip_portpair_t *r1_info,
		  struct hip_dh_public_value *dhpv)
{
	int err = 0, host_id_in_enc_len, written;
	uint32_t spi_in = 0;
	hip_transform_suite_t transform_hip_suite, transform_esp_suite; 
	char *enc_in_msg = NULL, *host_id_in_enc = NULL;
	unsigned char *iv = NULL;
	struct in6_addr daddr;
	struct hip_esp_info *esp_info;
	struct hip_common *i2 = NULL;
	struct hip_param *param;
	struct hip_diffie_hellman *dh_req;
	struct hip_spi_in_item spi_in_data;
	uint16_t mask = 0;
	int type_count = 0, request_rvs = 0, request_escrow = 0;
        int *reg_type = NULL;

	_HIP_DEBUG("hip_create_i2() invoked.\n");

	HIP_ASSERT(entry);

	/* allocate space for new I2 */
	HIP_IFEL(!(i2 = hip_msg_alloc()), -ENOMEM, "Allocation of I2 failed\n")


	/* TLV sanity checks are are already done by the caller of this
	   function. Now, begin to build I2 piece by piece. */

	/* Delete old SPDs and SAs, if present */
	hip_hadb_delete_inbound_spi(entry, 0);
	hip_hadb_delete_outbound_spi(entry, 0);

#ifdef CONFIG_HIP_BLIND
	if (hip_blind_get_status()) {
	  HIP_DEBUG("Build blinded I2\n");
	  mask |= HIP_PACKET_CTRL_BLIND;
	  // Build network header by using blinded HITs
	  entry->hadb_misc_func->
	       hip_build_network_hdr(i2, HIP_I2, mask, &entry->hit_our_blind,
				     &entry->hit_peer_blind);
	}
#endif

	if (!hip_blind_get_status()) {
	  HIP_DEBUG("Build normal I2\n");
	  /* create I2 */
	  entry->hadb_misc_func->
	       hip_build_network_hdr(i2, HIP_I2, mask, &(ctx->input->hitr),
				     &(ctx->input->hits));
	}

	/********** ESP_INFO **********/
	/* SPI is set below */
	HIP_IFEL(hip_build_param_esp_info(i2, ctx->esp_keymat_index, 0, 0),
		 -1, "building of ESP_INFO failed.\n");
	
	/********** R1 COUNTER (OPTIONAL) ********/
	/* we build this, if we have recorded some value (from previous R1s) */
	{
		uint64_t rtmp;

		HIP_LOCK_HA(entry);
		rtmp = entry->birthday;
		HIP_UNLOCK_HA(entry);

		HIP_IFEL(rtmp && hip_build_param_r1_counter(i2, rtmp), -1, 
			 "Could not build R1 GENERATION parameter\n");
	}

	/********* LOCATOR PARAMETER ************/
        /** Type 193 **/ 
        if (hip_locator_status == SO_HIP_SET_LOCATOR_ON) {
            HIP_DEBUG("Building LOCATOR parameter\n");
            if ((err = hip_build_locators(i2)) < 0) 
                HIP_DEBUG("LOCATOR parameter building failed\n");
        }
	/********** SOLUTION **********/
	{
		struct hip_puzzle *pz;
		
		HIP_IFEL(!(pz = hip_get_param(ctx->input, HIP_PARAM_PUZZLE)), -ENOENT, 
			 "Internal error: PUZZLE parameter mysteriously gone\n");
		HIP_IFEL(hip_build_param_solution(i2, pz, ntoh64(solved_puzzle)), -1, 
			 "Building of solution failed\n");
	}

	/********** Diffie-Hellman *********/
	HIP_IFEL(!(dh_req = hip_get_param(ctx->input, HIP_PARAM_DIFFIE_HELLMAN)),
		 -ENOENT, "Internal error\n");
	HIP_IFEL((written = hip_insert_dh(dhpv->public_value, 
		 ntohs(dhpv->pub_len), dhpv->group_id)) < 0,
		 -1, "Could not extract the DH public key\n");
	
	HIP_IFEL(hip_build_param_diffie_hellman_contents(i2,
		 dhpv->group_id, dhpv->public_value, written, 
		 HIP_MAX_DH_GROUP_ID, NULL, 0), -1,
		 "Building of DH failed.\n");

        /********** HIP transform. **********/
	HIP_IFE(!(param = hip_get_param(ctx->input, HIP_PARAM_HIP_TRANSFORM)), -ENOENT);
	HIP_IFEL((transform_hip_suite =
		  hip_select_hip_transform((struct hip_hip_transform *) param)) == 0, 
		 -EINVAL, "Could not find acceptable hip transform suite\n");
	
	/* Select only one transform */
	HIP_IFEL(hip_build_param_transform(i2, HIP_PARAM_HIP_TRANSFORM,
					   &transform_hip_suite, 1), -1, 
		 "Building of HIP transform failed\n");
	
	HIP_DEBUG("HIP transform: %d\n", transform_hip_suite);
	
	/********** ESP-ENC transform. **********/
	HIP_IFE(!(param = hip_get_param(ctx->input, HIP_PARAM_ESP_TRANSFORM)), -ENOENT);

	/* Select only one transform */
	HIP_IFEL((transform_esp_suite =
		  hip_select_esp_transform((struct hip_esp_transform *) param)) == 0,
		 -1, "Could not find acceptable hip transform suite\n");
	HIP_IFEL(hip_build_param_transform(i2, HIP_PARAM_ESP_TRANSFORM,
					   &transform_esp_suite, 1), -1,
		 "Building of ESP transform failed\n");

	/************ Encrypted ***********/
	switch (transform_hip_suite) {
	case HIP_HIP_AES_SHA1:
		HIP_IFEL(hip_build_param_encrypted_aes_sha1(i2, (struct hip_tlv_common *)entry->our_pub), 
			 -1, "Building of param encrypted failed.\n");
		enc_in_msg = hip_get_param(i2, HIP_PARAM_ENCRYPTED);
		HIP_ASSERT(enc_in_msg); /* Builder internal error. */
 		iv = ((struct hip_encrypted_aes_sha1 *) enc_in_msg)->iv;
		get_random_bytes(iv, 16);
 		host_id_in_enc = enc_in_msg +
			sizeof(struct hip_encrypted_aes_sha1);
		break;
	case HIP_HIP_3DES_SHA1:
		HIP_IFEL(hip_build_param_encrypted_3des_sha1(i2, (struct hip_tlv_common *)entry->our_pub), 
			 -1, "Building of param encrypted failed.\n");
		enc_in_msg = hip_get_param(i2, HIP_PARAM_ENCRYPTED);
		HIP_ASSERT(enc_in_msg); /* Builder internal error. */
 		iv = ((struct hip_encrypted_3des_sha1 *) enc_in_msg)->iv;
		get_random_bytes(iv, 8);
 		host_id_in_enc = enc_in_msg +
 			sizeof(struct hip_encrypted_3des_sha1);
		break;
	case HIP_HIP_NULL_SHA1:
		HIP_IFEL(hip_build_param_encrypted_null_sha1(i2, (struct hip_tlv_common *)entry->our_pub), 
			 -1, "Building of param encrypted failed.\n");
		enc_in_msg = hip_get_param(i2, HIP_PARAM_ENCRYPTED);
		HIP_ASSERT(enc_in_msg); /* Builder internal error. */
 		iv = NULL;
 		host_id_in_enc = enc_in_msg +
 			sizeof(struct hip_encrypted_null_sha1);
		break;
	default:
 		HIP_IFEL(1, -ENOSYS, "HIP transform not supported (%d)\n",
			 transform_hip_suite);
	}

	HIP_HEXDUMP("enc(host_id)", host_id_in_enc,
		    hip_get_param_total_len(host_id_in_enc));

	/* Calculate the length of the host id inside the encrypted param */
	host_id_in_enc_len = hip_get_param_total_len(host_id_in_enc);

	/* Adjust the host id length for AES (block size 16).
	   build_param_encrypted_aes has already taken care that there is
	   enough padding */
	if (transform_hip_suite == HIP_HIP_AES_SHA1) {
		int remainder = host_id_in_enc_len % 16;
		if (remainder) {
			HIP_DEBUG("Remainder %d (for AES)\n", remainder);
			host_id_in_enc_len += remainder;
		}
	}

	_HIP_HEXDUMP("hostidinmsg", host_id_in_enc,
		    hip_get_param_total_len(host_id_in_enc));
	_HIP_HEXDUMP("encinmsg", enc_in_msg,
		    hip_get_param_total_len(enc_in_msg));
	HIP_HEXDUMP("enc key", &ctx->hip_enc_out.key, HIP_MAX_KEY_LEN);
	_HIP_HEXDUMP("IV", iv, 16); // or 8
	HIP_DEBUG("host id type: %d\n",
		  hip_get_host_id_algo((struct hip_host_id *)host_id_in_enc));
	_HIP_HEXDUMP("hostidinmsg 2", host_id_in_enc, x);


	  HIP_IFEL(hip_crypto_encrypted(host_id_in_enc, iv,
					transform_hip_suite,
					host_id_in_enc_len,
					&ctx->hip_enc_out.key,
					HIP_DIRECTION_ENCRYPT), -1, 
		 "Building of param encrypted failed\n");

	_HIP_HEXDUMP("encinmsg 2", enc_in_msg,
		     hip_get_param_total_len(enc_in_msg));
	_HIP_HEXDUMP("hostidinmsg 2", host_id_in_enc, x);

        /* Now that almost everything is set up except the signature, we can
	 * try to set up inbound IPsec SA, similarly as in hip_create_r2 */

	HIP_DEBUG("src %d, dst %d\n", r1_info->src_port, r1_info->dst_port);

	entry->hip_transform = transform_hip_suite;

#ifdef CONFIG_HIP_BLIND
	if (hip_blind_get_status()) {
		/* let the setup routine give us a SPI. */
		HIP_DEBUG("Blind is ON\n");
		HIP_IFEL(hip_add_sa(r1_saddr, r1_daddr,
			      &entry->hit_peer, &entry->hit_our,
			      entry, &spi_in, transform_esp_suite, 
			      &ctx->esp_in, &ctx->auth_in, 0,
			      HIP_SPI_DIRECTION_IN, 0,
			      r1_info->src_port, r1_info->dst_port), -1, 
		         "Failed to setup IPsec SPD/SA entries, peer:src\n");
	}
#endif

	if (!hip_blind_get_status()) {
	  HIP_DEBUG("Blind is OFF\n");
	  /*Find lsi identifiers for the pair of hits given by the context */
	  hip_ha_t *entry_aux = hip_hadb_find_byhits(&ctx->input->hits, &ctx->input->hitr);
	  /* let the setup routine give us a SPI. */
	  HIP_IFEL(hip_add_sa(r1_saddr, r1_daddr,
			      &ctx->input->hits, &ctx->input->hitr,
			      &spi_in, transform_esp_suite, 
			      &ctx->esp_in, &ctx->auth_in, 0,
			      HIP_SPI_DIRECTION_IN, 0,
			      r1_info->src_port, r1_info->dst_port), -1, 
		   "Failed to setup IPsec SPD/SA entries, peer:src\n");

	}
	/* XXX: -EAGAIN */
	HIP_DEBUG("set up inbound IPsec SA, SPI=0x%x (host)\n", spi_in);
	
#ifdef CONFIG_HIP_BLIND
	if (hip_blind_get_status()) {
	  HIP_IFEL(hip_setup_hit_sp_pair(&entry->hit_peer,
					 &entry->hit_our,
					 r1_saddr, r1_daddr, IPPROTO_ESP, 1, 1), -1,
		   "Setting up SP pair failed\n");
	}
#endif
	if (!hip_blind_get_status()) {
	  HIP_IFEL(hip_setup_hit_sp_pair(&ctx->input->hits,
					 &ctx->input->hitr,
					 r1_saddr, r1_daddr, IPPROTO_ESP, 1, 1), -1,
		   "Setting up SP pair failed\n");
	}

 	esp_info = hip_get_param(i2, HIP_PARAM_ESP_INFO);
 	HIP_ASSERT(esp_info); /* Builder internal error */
	esp_info->new_spi = htonl(spi_in);
	/* LSI not created, as it is local, and we do not support IPv4 */

#ifdef CONFIG_HIP_ESCROW
    if (hip_deliver_escrow_data(r1_saddr, r1_daddr, &ctx->input->hits, 
        &ctx->input->hitr, &spi_in, transform_esp_suite, &ctx->esp_in, 
        HIP_ESCROW_OPERATION_ADD) != 0)
    {  
        HIP_DEBUG("Could not deliver escrow data to server\n");
    }             
#endif //CONFIG_HIP_ESCROW
    
    /* Check if the incoming R1 has a REG_REQUEST parameter. */

    /* Add service types to which the current machine wishes to
       register into the outgoing I2 packet. Each service type
       should check here if the current machines hadb is in correct
       state regarding to registering. This state is set before
       sending the I1 packet to peer (registrar). */

    // TODO: check also unregistrations
    uint8_t services[HIP_NUMBER_OF_EXISTING_SERVICES];
    
    type_count = hip_get_incomplete_registrations(&reg_type, entry, 1, services); 
    
    if (type_count > 0) {
	 HIP_DEBUG("Adding REG_REQUEST parameter with %d reg types.\n", type_count);
	 /** @todo Service lifetime value usage. Now requesting maximum lifetime
	     (255 ~= 178 days) always */
	 HIP_IFEL(hip_build_param_reg_request(i2, 255, services, type_count, 1),
		  -1, "Could not build REG_REQUEST parameter\n");
    }
    
    /******** NONCE *************************/
#ifdef CONFIG_HIP_BLIND
	if (hip_blind_get_status()) {
	  HIP_DEBUG("add nonce to the message\n");
	  HIP_IFEL(hip_build_param_blind_nonce(i2, entry->blind_nonce_i), 
		   -1, "Unable to attach nonce to the message.\n");
	}
#endif

	/********** ECHO_RESPONSE_SIGN (OPTIONAL) **************/
	/* must reply... */
	{
		struct hip_echo_request *ping;

		ping = hip_get_param(ctx->input, HIP_PARAM_ECHO_REQUEST_SIGN);
		if (ping) {
			int ln = hip_get_param_contents_len(ping);
			HIP_IFEL(hip_build_param_echo(i2, ping + 1, ln, 1, 0), -1, 
				 "Error while creating echo reply parameter\n");
		}
	}

	/************* HMAC ************/
	HIP_IFEL(hip_build_param_hmac_contents(i2, &ctx->hip_hmac_out),
		 -1, "Building of HMAC failed\n");

	/********** Signature **********/
	/* Build a digest of the packet built so far. Signature will
	   be calculated over the digest. */
	HIP_IFEL(entry->sign(entry->our_priv, i2), -EINVAL, "Could not create signature\n");

	/********** ECHO_RESPONSE (OPTIONAL) ************/
	/* must reply */
	{
	     struct hip_echo_request *ping;
	     
	     ping = hip_get_param(ctx->input, HIP_PARAM_ECHO_REQUEST);
	     if (ping) {
		  int ln = hip_get_param_contents_len(ping);
		  HIP_IFEL(hip_build_param_echo(i2, (ping + 1), ln, 0, 0), -1,
			   "Error while creating echo reply parameter\n");
	     }
	}
	
      	/********** I2 packet complete **********/
	memset(&spi_in_data, 0, sizeof(struct hip_spi_in_item));
	spi_in_data.spi = spi_in;
	spi_in_data.ifindex = hip_devaddr2ifindex(r1_daddr);
	HIP_LOCK_HA(entry);
	HIP_IFEB(hip_hadb_add_spi(entry, HIP_SPI_DIRECTION_IN, &spi_in_data), -1, HIP_UNLOCK_HA(entry));

	entry->esp_transform = transform_esp_suite;
	HIP_DEBUG("Saving base exchange encryption data to entry \n");
	HIP_DEBUG_HIT("our_hit: ", &entry->hit_our);
	HIP_DEBUG_HIT("peer_hit: ", &entry->hit_peer);
	/* Store the keys until we receive R2 */
	HIP_IFEB(hip_store_base_exchange_keys(entry, ctx, 1), -1, HIP_UNLOCK_HA(entry));

	/* todo: Also store the keys that will be given to ESP later */
	HIP_IFE(hip_hadb_get_peer_addr(entry, &daddr), -1); 

	/* R1 packet source port becomes the I2 packet destination port. */
	err = entry->hadb_xmit_func->
	     hip_send_pkt(r1_daddr, &daddr,
			  (entry->nat_mode ? HIP_NAT_UDP_PORT : 0),
			  r1_info->src_port, i2, entry, 1);
	HIP_IFEL(err < 0, -ECOMM, "Sending I2 packet failed.\n");

 out_err:
	if (i2)
		HIP_FREE(i2);

	return err;
}

int hip_handle_r1(struct hip_common *r1,
		  struct in6_addr *r1_saddr,
		  struct in6_addr *r1_daddr,
		  hip_ha_t *entry,
		  hip_portpair_t *r1_info)
{
	int err = 0, retransmission = 0;
        int n_addrs = 0, loc_size = 0;
	uint64_t solved_puzzle;
	uint64_t I;
	struct hip_context *ctx = NULL;
	struct hip_host_id *peer_host_id;
	struct hip_r1_counter *r1cntr;
	struct hip_reg_info *reg_info;
	struct hip_dh_public_value *dhpv = NULL;
        struct hip_locator *locator;
#ifdef CONFIG_HIP_HI3
	struct hip_locator_info_addr_item* first;
	struct netdev_address *n;
	hip_list_t *item, *tmp;
	int ii = 0;
	int use_ip4 = 1;
#endif

	_HIP_DEBUG("hip_handle_r1() invoked.\n");

	if (entry->state == HIP_STATE_I2_SENT) {
		HIP_DEBUG("Retransmission\n");
		retransmission = 1;
	} else {
		HIP_DEBUG("Not a retransmission\n");
	}

	HIP_IFEL(!(ctx = HIP_MALLOC(sizeof(struct hip_context), GFP_KERNEL)), -ENOMEM,
		 "Could not allocate memory for context\n");
	memset(ctx, 0, sizeof(struct hip_context));
	ctx->input = r1;

	/* According to the section 8.6 of the base draft, we must first check
	   signature. */
	
	/* Blinded R1 packets do not contain HOST ID parameters,
	 * so the verification must be delayd to the R2 */
	if (!hip_blind_get_status()) {
		/* Store the peer's public key to HA and validate it */
		/** @todo Do not store the key if the verification fails. */
		HIP_IFEL(!(peer_host_id = hip_get_param(r1, HIP_PARAM_HOST_ID)), -ENOENT,
			 "No HOST_ID found in R1\n");
	
		HIP_IFE(hip_init_peer(entry, r1, peer_host_id), -EINVAL); 
		HIP_IFEL(entry->verify(entry->peer_pub, r1), -EINVAL,
			 "Verification of R1 signature failed\n");
        }	

	/* R1 packet had destination port 50500, which means that the peer is
	   behind NAT. We set NAT mode "on" and set the send funtion to 
	   "hip_send_udp". The client UDP port is not stored until the handling
	   of R2 packet. Don't know if the entry is already locked... */
	if(r1_info->dst_port == HIP_NAT_UDP_PORT) {
		HIP_LOCK_HA(entry);
		entry->nat_mode = 1;
		hip_hadb_set_xmit_function_set(entry, &nat_xmit_func_set);
		HIP_UNLOCK_HA(entry);
	}

        /***** LOCATOR PARAMETER ******/
        locator = hip_get_param(r1, HIP_PARAM_LOCATOR);
        if (locator)
            {
                /* Lets save the LOCATOR to the entry 'till we
                   get the esp_info in r2 then handle it */
                n_addrs = hip_get_locator_addr_item_count(locator);
                loc_size = sizeof(struct hip_locator) +
                    (n_addrs * sizeof(struct hip_locator_info_addr_item));
                HIP_IFEL(!(entry->locator = malloc(loc_size)), 
                       -1, "Malloc for entry->locators failed\n");             
                memcpy(entry->locator, locator, loc_size);

#ifdef CONFIG_HIP_HI3
		if( r1_info->hi3_in_use && n_addrs > 0 ) 
		{
			first = (char*)locator+sizeof(struct hip_locator);
			memcpy(r1_saddr, &first->address, sizeof(struct in6_addr));

			list_for_each_safe(item, tmp, addresses, ii)
				{
					n = list_entry(item);
					if (ipv6_addr_is_hit(hip_cast_sa_addr(&n->addr)))
						continue;
					if (!IN6_IS_ADDR_V4MAPPED(hip_cast_sa_addr(&n->addr)))
					{
						memcpy(r1_daddr, hip_cast_sa_addr(&n->addr),
						       hip_sa_addr_len(&n->addr));
						ii = -1;
						use_ip4 = 0;
						break;
					}
				}
			if( use_ip4 ) 
			{
				list_for_each_safe(item, tmp, addresses, ii)
					{
						n = list_entry(item);
						if (ipv6_addr_is_hit(hip_cast_sa_addr(&n->addr)))
							continue;
						if (IN6_IS_ADDR_V4MAPPED(hip_cast_sa_addr(&n->addr)))
						{
							memcpy(r1_daddr, hip_cast_sa_addr(&n->addr),
							       hip_sa_addr_len(&n->addr));
							ii = -1;
							break;
						}
					}
			}

			struct in6_addr daddr;

			memcpy(&entry->local_address, r1_daddr, sizeof(struct in6_addr));

			hip_hadb_get_peer_addr(entry, &daddr);
			hip_hadb_delete_peer_addrlist_one(entry, &daddr);
			hip_hadb_add_peer_addr(entry, r1_saddr, 0, 0,
					       PEER_ADDR_STATE_ACTIVE);
		}

#endif
	    }
        else
            HIP_DEBUG("R1 did not have locator\n");

	/* Check if the incoming R1 has a REG_INFO parameter. */
	reg_info = hip_get_param(r1, HIP_PARAM_REG_INFO);

	if (reg_info) {
		int i;
		uint8_t current_reg_type = 0;
		uint8_t size_of_lifetimes = sizeof(reg_info->min_lifetime)
			+ sizeof(reg_info->max_lifetime);
		int typecount;
	
		/* Registration types begin after "Min Lifetime" and "Max
		   Lifetime" fields. */
		uint8_t *reg_types = (uint8_t *)
			(hip_get_param_contents_direct(reg_info)) + size_of_lifetimes;

		typecount = hip_get_param_contents_len(reg_info) - size_of_lifetimes;

		/* Check draft-ietf-hip-registration-02 chapter 3.1. */
		if(typecount == 0){
			HIP_DEBUG("REG_INFO had no services listed.\n");
			HIP_INFO("Responder is currently unable to provide "\
				 "services due to transient conditions.\n");
		}

		HIP_DEBUG("Responder offers %d %s.\n", typecount,
			  (typecount == 1) ? "service" : "services");
		HIP_HEXDUMP("Reg types are (one byte each): ", reg_types, typecount);

		/* Loop through all the registration types found in REG_INFO parameter. */ 
		for(i = 0; i < typecount; i++){
		     current_reg_type = reg_types[i];
		     
		     switch(current_reg_type){
#ifdef CONFIG_HIP_ESCROW
		     case HIP_SERVICE_ESCROW:
			  HIP_INFO("Responder offers escrow service.\n");
						
			  HIP_KEA *kea;
			  kea = hip_kea_find(&entry->hit_our);
			  if (kea && kea->keastate == HIP_KEASTATE_REGISTERING) {
			       HIP_DEBUG("Registering to escrow service.\n");
			       hip_keadb_put_entry(kea);
			  } 
			  else if(kea){
			       kea->keastate = HIP_KEASTATE_INVALID;
			       HIP_DEBUG("Not doing escrow registration, "\
					 "invalid kea state.\n");
			       hip_keadb_put_entry(kea);	  
			  }
			  else{
			       HIP_DEBUG("Not doing escrow registration.\n");
			  }

			  break;
#endif /* CONFIG_HIP_ESCROW */
#ifdef CONFIG_HIP_RVS
		     case HIP_SERVICE_RENDEZVOUS:
			  HIP_INFO("Responder offers rendezvous service.\n");
			  
			  /* If we have requested for RVS service in I1, we
			     store the info of responder's capability here. */
			  if(entry->local_controls & HIP_HA_CTRL_LOCAL_REQ_RVS)
			  {
			       hip_hadb_set_peer_controls(
				    entry, HIP_HA_CTRL_PEER_RVS_CAPABLE);
			  }
			  break;
		     case HIP_SERVICE_RELAY_UDP_HIP:
			  HIP_INFO("Responder offers UDP relay service for "\
				   "HIP packets.\n");
			  
			  /* If we have requested for HIP UDP Relay service in
			     I1, we store the info of responder's capability
			     here. */
			  if(entry->local_controls & HIP_HA_CTRL_LOCAL_REQ_HIPUDP)
			  {
			       hip_hadb_set_peer_controls(
				    entry, HIP_HA_CTRL_PEER_HIPUDP_CAPABLE);

			  }
			  break;
#endif /* CONFIG_HIP_RVS */
		     default:
			  HIP_INFO("Responder offers unsupported service.\n");
		     }
		}
	}
#ifdef CONFIG_HIP_ESCROW
	else {
		/* No REG_INFO parameter found. Cancelling registration attempt. */
		HIP_DEBUG("No REG_INFO found in R1: no services available \n");
		HIP_KEA *kea;
		kea = hip_kea_find(&entry->hit_our);
		if (kea && (kea->keastate == HIP_KEASTATE_REGISTERING))
			kea->keastate = HIP_KEASTATE_INVALID;
		if (kea)
			hip_keadb_put_entry(kea);	
		//TODO: Remove base keas	
	}
#endif /* CONFIG_HIP_ESCROW */

	/* R1 generation check */

	/* we have problems with creating precreated R1s in reasonable
	   fashion... so we don't mind about generations */
	r1cntr = hip_get_param(r1, HIP_PARAM_R1_COUNTER);

	/* Do control bit stuff here... */

	/* We must store the R1 generation counter, _IF_ it exists */
	if (r1cntr) {
		HIP_DEBUG("Storing R1 generation counter\n");
		HIP_LOCK_HA(entry);
		entry->birthday = r1cntr->generation;
		HIP_UNLOCK_HA(entry);
	}

	/* solve puzzle: if this is a retransmission, we have to preserve
	   the old solution */
	if (!retransmission) {
		struct hip_puzzle *pz = NULL;

		HIP_IFEL(!(pz = hip_get_param(r1, HIP_PARAM_PUZZLE)), -EINVAL,
			 "Malformed R1 packet. PUZZLE parameter missing\n");
		HIP_IFEL((solved_puzzle =
			  entry->hadb_misc_func->hip_solve_puzzle(pz, r1, HIP_SOLVE_PUZZLE)) == 0, 
			 -EINVAL, "Solving of puzzle failed\n");
		I = pz->I;
		entry->puzzle_solution = solved_puzzle;
		entry->puzzle_i = pz->I;
	} else {
		I = entry->puzzle_i;
		solved_puzzle = entry->puzzle_solution;
	}

	/* calculate shared secret and create keying material */
	ctx->dh_shared_key = NULL;
	/* note: we could skip keying material generation in the case
	   of a retransmission but then we'd had to fill ctx->hmac etc */
	HIP_IFEL(entry->hadb_misc_func->hip_produce_keying_material(r1, ctx, I,
							 solved_puzzle, &dhpv),
			 -EINVAL, "Could not produce keying material\n");
	
	/** @todo BLIND: What is this? */
	/* Blinded R1 packets do not contain HOST ID parameters,
	 * so the saving peer's HOST ID mus be delayd to the R2
	 */
	if (!hip_blind_get_status()) {
	  /* Everything ok, save host id to HA */
	  {
	    char *str;
	    int len;
	    HIP_IFE(hip_get_param_host_id_di_type_len(peer_host_id, &str, &len) < 0, -1);
	    HIP_DEBUG("Identity type: %s, Length: %d, Name: %s\n",
		      str, len, hip_get_param_host_id_hostname(peer_host_id));
	  }
	}

 	err = entry->hadb_misc_func->
	     hip_create_i2(ctx, solved_puzzle, r1_saddr, r1_daddr, entry,
			   r1_info, dhpv);
	
	HIP_IFEL(err < 0, -1, "Creation of I2 failed\n");

	if (entry->state == HIP_STATE_I1_SENT)
	{
		entry->state = HIP_STATE_I2_SENT;
	}

out_err:
	if (ctx->dh_shared_key)
		HIP_FREE(ctx->dh_shared_key);
	if (ctx)
		HIP_FREE(ctx);
	return err;
}

int hip_receive_r1(hip_common_t *r1, in6_addr_t *r1_saddr, in6_addr_t *r1_daddr,
		   hip_ha_t *entry, hip_portpair_t *r1_info)
{
	int state, mask = HIP_PACKET_CTRL_ANON, err = 0;

	HIP_DEBUG("hip_receive_r1() invoked.\n");

#ifdef CONFIG_HIP_OPPORTUNISTIC
	/* Check and remove the IP of the peer from the opp non-HIP database */
	hip_oppipdb_delentry(&(entry->preferred_address));
#endif

#ifdef CONFIG_HIP_BLIND
	if (hip_blind_get_status())
	  mask |= HIP_PACKET_CTRL_BLIND;
#endif
	if (ipv6_addr_any(&r1->hitr)) {
		HIP_DEBUG("Received NULL receiver HIT in R1. Not dropping\n");
	}

 	HIP_IFEL(!hip_controls_sane(ntohs(r1->control), mask), 0, 
		 "Received illegal controls in R1: 0x%x Dropping\n",
		 ntohs(r1->control));
	HIP_IFEL(!entry, -EFAULT, 
		 "Received R1 with no local state. Dropping\n");

	/* An implicit and insecure REA. If sender's address is different than
	 * the one that was mapped, then we will overwrite the mapping with the
	 * newer address. This enables us to use the rendezvous server, while
	 * not supporting the REA TLV. */
	{
		struct in6_addr daddr;
		
		hip_hadb_get_peer_addr(entry, &daddr);
		if (ipv6_addr_cmp(&daddr, r1_saddr) != 0) {
			HIP_DEBUG("Mapped address didn't match received address\n");
			HIP_DEBUG("Assuming that the mapped address was actually RVS's.\n");
			HIP_HEXDUMP("Mapping", &daddr, 16);
			HIP_HEXDUMP("Received", r1_saddr, 16);
			hip_hadb_delete_peer_addrlist_one(entry, &daddr);
			hip_hadb_add_peer_addr(entry, r1_saddr, 0, 0,
					       PEER_ADDR_STATE_ACTIVE);
		}
	}
	
	state = entry->state;
	
	HIP_DEBUG("Received R1 in state %s\n", hip_state_str(state));
	switch(state) {
	case HIP_STATE_I1_SENT:
	case HIP_STATE_I2_SENT:
	case HIP_STATE_CLOSING:
	case HIP_STATE_CLOSED:
	     /* E1. The normal case. Process, send I2, goto E2. */
	     err = entry->hadb_handle_func->
		  hip_handle_r1(r1, r1_saddr, r1_daddr, entry, r1_info);
	     HIP_LOCK_HA(entry);
	     if (err < 0)
		  HIP_ERROR("Handling of R1 failed\n");
	     HIP_UNLOCK_HA(entry);
	     break;
	case HIP_STATE_R2_SENT:
		break;
	case HIP_STATE_ESTABLISHED:
		break;
	case HIP_STATE_NONE:
	case HIP_STATE_UNASSOCIATED:
	default:
		/* Can't happen. */
		err = -EFAULT;
		HIP_ERROR("R1 received in odd state: %d. Dropping.\n", state); 
		break;
	}

	hip_put_ha(entry);

 out_err:
	return err;
}

/**
 * hip_create_r2 - Creates and transmits R2 packet.
 * @param ctx Context of processed I2 packet.
 * @param entry HA
 *
 * @return 0 on success, < 0 on error.
 */
int hip_create_r2(struct hip_context *ctx,
		  struct in6_addr *i2_saddr,
		  struct in6_addr *i2_daddr,
		  hip_ha_t *entry,
		  hip_portpair_t *i2_info)
{
	struct hip_reg_request *reg_request = NULL;
 	struct hip_common *r2 = NULL, *i2;
 	int err = 0, clear = 0;
	uint16_t mask = 0;
	uint8_t lifetime;
	uint32_t spi_in;
        
	_HIP_DEBUG("hip_create_r2() invoked.\n");
	/* Assume already locked entry */
	i2 = ctx->input;

	/* Build and send R2: IP ( HIP ( SPI, HMAC, HIP_SIGNATURE ) ) */
	HIP_IFEL(!(r2 = hip_msg_alloc()), -ENOMEM, "No memory for R2\n");


#ifdef CONFIG_HIP_BLIND
	// For blind: we must add encrypted public host id
	if (hip_blind_get_status()) {
	  HIP_DEBUG("Set HIP_PACKET_CTRL_BLIND for R2\n");
	  mask |= HIP_PACKET_CTRL_BLIND;
	  
	  // Build network header by using blinded HITs
	  entry->hadb_misc_func->
	    hip_build_network_hdr(r2, HIP_R2, mask, &entry->hit_our_blind,
				  &entry->hit_peer_blind);
	}
#endif
	/* Just swap the addresses to use the I2's destination HIT as
	 * the R2's source HIT */
	if (!hip_blind_get_status()) {
	  entry->hadb_misc_func->
	    hip_build_network_hdr(r2, HIP_R2, mask, &entry->hit_our,
				  &entry->hit_peer);
	}

 	/********** ESP_INFO **********/
	spi_in = hip_hadb_get_latest_inbound_spi(entry);
	HIP_IFEL(hip_build_param_esp_info(r2, ctx->esp_keymat_index,
					  0, spi_in), -1,
		 "building of ESP_INFO failed.\n");

#ifdef CONFIG_HIP_BLIND
	// For blind: we must add encrypted public host id
	if (hip_blind_get_status()) {
	  HIP_IFEL(hip_blind_build_r2(i2, r2, entry, &mask), 
	  	   -1, "hip_blind_build_r2 failed\n");
	}
#endif

#if defined(CONFIG_HIP_RVS) || defined(CONFIG_HIP_ESCROW)
	/********** REG_REQUEST **********/
	/* This part should only be executed in HIP relay or in the host
	   offering escrow service.
	   (hip_we_are_relay() || we_are_escrow_server()).
	   But since I don't have a way to detect if we are an escrow server
	   this part is executed on I and R also. -Lauri 27.09.2007*/
	hip_handle_regrequest(entry, i2, r2);
#endif	
 	/* HMAC2 */
	{
	     struct hip_crypto_key hmac;
	     if (entry->our_pub == NULL) HIP_DEBUG("entry->our_pub is null\n");
	     else HIP_HEXDUMP("host id for HMAC2", entry->our_pub,
			      hip_get_param_total_len(entry->our_pub));

	     memcpy(&hmac, &entry->hip_hmac_out, sizeof(hmac));
	     HIP_IFEL(hip_build_param_hmac2_contents(r2, &hmac, entry->our_pub), -1,
		      "Building of hmac failed\n");
	}

	HIP_IFEL(entry->sign(entry->our_priv, r2), -EINVAL, "Could not sign R2. Failing\n");

	err = entry->hadb_xmit_func->hip_send_pkt(i2_daddr, i2_saddr,
						  (entry->nat_mode ? HIP_NAT_UDP_PORT : 0),
	                                          entry->peer_udp_port, r2, entry, 1);
	if (err == 1) err = 0;
	HIP_IFEL(err, -ECOMM, "Sending R2 packet failed.\n");

 out_err:
	if (r2)
		HIP_FREE(r2);
        if (clear && entry) {/* Hmm, check */
		HIP_ERROR("TODO: about to do hip_put_ha, should this happen here ?\n");
		hip_put_ha(entry);
	}
	return err;
}

/**
 * Handles an incoming I2 packet.
 *
 * This function is the actual point from where the processing of I2 is started
 * and corresponding R2 is created. This function also creates a new host
 * association in the host association database if no previous association
 * matching the search key (source HIT XOR destination HIT) was found.
 *
 * @param i2       a pointer to the I2 HIP packet common header with source and
 *                 destination HITs.
 * @param i2_saddr a pointer to the source address from where the I2 packet was
 *                 received.
 * @param i2_daddr a pointer to the destination address where the I2 packet was
 *                 sent to (own address).
 * @param ha       host association corresponding to the peer.
 * @param i2_info  a pointer to the source and destination ports (when NAT is
 *                 in use).
 * @return         zero on success, or negative error value on error. Success
 *                 indicates that I2 payloads are checked and R2 is created and
 *                 sent.
 */
int hip_handle_i2(struct hip_common *i2, struct in6_addr *i2_saddr,
	 	  struct in6_addr *i2_daddr, hip_ha_t *ha,
		  hip_portpair_t *i2_info)
{
	struct hip_context *ctx = NULL;
 	struct hip_tlv_common *param = NULL;
	struct hip_host_id *host_id_in_enc = NULL;
	struct hip_r1_counter *r1cntr;
	struct hip_esp_info *esp_info = NULL;
	struct hip_spi_in_item spi_in_data;
	struct in6_addr *plain_peer_hit = NULL, *plain_local_hit = NULL;
	struct hip_dh_public_value *dhpv = NULL;
	hip_transform_suite_t esp_tfm, hip_tfm;
	hip_ha_t *entry = ha;
	char *tmp_enc = NULL, *enc = NULL;
	unsigned char *iv;
	uint64_t I, J;	
	uint32_t spi_in, spi_out;
	uint16_t crypto_len, nonce;
	int err = 0, retransmission = 0, replay = 0, use_blind = 0;
        struct hip_locator *locator;
#ifdef CONFIG_HIP_HI3
	int n_addrs = 0;
	struct hip_locator_info_addr_item* first;
	struct netdev_address *n;
	hip_list_t *item, *tmp;
	int ii = 0;
	int use_ip4 = 1;
#endif
	
	HIP_DEBUG("hip_handle_i2() invoked.\n");

	if (ntohs(i2->control) & HIP_PACKET_CTRL_BLIND && hip_blind_get_status())
		use_blind = 1;
	
	/* Assume already locked ha, if ha is not NULL. */
	HIP_IFEL(!(ctx = HIP_MALLOC(sizeof(struct hip_context), 0)),
		 -ENOMEM, "Alloc failed\n");

	memset(ctx, 0, sizeof(struct hip_context));
	
	/* Check packet validity. We MUST check that the responder HIT is one
	 of ours. Check the generation counter. We do not support generation
	 counter (our precreated R1s suck). */
	ctx->input = i2;
	r1cntr = hip_get_param(ctx->input, HIP_PARAM_R1_COUNTER);

	/* check solution for cookie */
	{
		struct hip_solution *sol;
		HIP_IFEL(!(sol = hip_get_param(ctx->input, HIP_PARAM_SOLUTION)),
			 -EINVAL, "Invalid I2: SOLUTION parameter missing\n");
		I = sol->I;
		J = sol->J;
		HIP_IFEL(!hip_verify_cookie(i2_saddr, i2_daddr, i2, sol),
			 -ENOMSG, "Cookie solution rejected\n");
	}

 	HIP_DEBUG("Cookie accepted\n");

#ifdef CONFIG_HIP_HI3
        locator = hip_get_param(i2, HIP_PARAM_LOCATOR);

        if (locator)
	{
		n_addrs = hip_get_locator_addr_item_count(locator);
	
		if( i2_info->hi3_in_use && n_addrs > 0 )
                {
                        first = (char*)locator+sizeof(struct hip_locator);
                        memcpy(i2_saddr, &first->address, sizeof(struct in6_addr));

                        list_for_each_safe(item, tmp, addresses, ii)
                                {
                                        n = list_entry(item);
                                        if (ipv6_addr_is_hit(hip_cast_sa_addr(&n->addr)))
                                                continue;
                                        if (!IN6_IS_ADDR_V4MAPPED(hip_cast_sa_addr(&n->addr)))
                                        {
                                                memcpy(i2_daddr, hip_cast_sa_addr(&n->addr),
                                                       hip_sa_addr_len(&n->addr));
                                                ii = -1;
                                                use_ip4 = 0;
                                                break;
                                        }
                                }
                        if( use_ip4 )
                        {
                                list_for_each_safe(item, tmp, addresses, ii)
                                        {
                                                n = list_entry(item);
                                                if (ipv6_addr_is_hit(hip_cast_sa_addr(&n->addr)))
                                                        continue;
                                                if (IN6_IS_ADDR_V4MAPPED(hip_cast_sa_addr(&n->addr)))
                                                {
                                                        memcpy(i2_daddr, hip_cast_sa_addr(&n->addr),
                                                               hip_sa_addr_len(&n->addr));
                                                        ii = -1;
                                                        break;
                                                }
                                        }
                        }


                }
	}
#endif


	if (entry) {
		/* If the I2 packet is a retransmission, we need reuse
		   the the SPI/keymat that was setup already when the
		   first I2 was received. */
		retransmission = 
			((entry->state == HIP_STATE_R2_SENT ||
			  entry->state == HIP_STATE_ESTABLISHED) ? 1 : 0);
		/* If the initiator is in established state (it has possibly
		   sent duplicate I2 packets), we must make sure that we are
		   reusing the old SPI as the initiator will just drop the
		   R2, thus discarding any new SPIs we create. Notice that
		   this works also in the case when initiator is not in
		   established state, as the initiator just picks up the SPI
		   from the R2. */
		if (entry->state == HIP_STATE_ESTABLISHED)
			spi_in = hip_hadb_get_latest_inbound_spi(entry);
	}

	/* Check HIP and ESP transforms, and produce keying material. */
	ctx->dh_shared_key = NULL;
	
	//#ifdef CONFIG_HIP_BLIND
	// XX TODO KARTHIK: if entry->blind then r1.hitr should be converted to plain hit
	//#endif
	
	/* Note: we could skip keying material generation in the case of a
	   retransmission but then we'd had to fill ctx->hmac etc. TH: I'm not
	   sure if this could be replaced with a function pointer which is set
	   from hadb. Usually you shouldn't have state here, right? */

	HIP_IFEL(hip_produce_keying_material(ctx->input, ctx, I, J, &dhpv), -1,
		 "Unable to produce keying material. Dropping I2\n");

	/* Verify HMAC. */
	if (hip_hidb_hit_is_our(&i2->hits)) {
		/* loopback */
		HIP_IFEL(hip_verify_packet_hmac(i2, &ctx->hip_hmac_out),
			 -ENOENT, "HMAC loopback validation on i2 failed\n");
	} else {
		HIP_IFEL(hip_verify_packet_hmac(i2, &ctx->hip_hmac_in),
			 -ENOENT, "HMAC validation on i2 failed\n");
	}
	
	/* Decrypt the HOST_ID and verify it against the sender HIT. */
	HIP_IFEL(!(enc = hip_get_param(ctx->input, HIP_PARAM_ENCRYPTED)),
		 -ENOENT, "Could not find enc parameter\n");

	HIP_IFEL(!(tmp_enc = HIP_MALLOC(hip_get_param_total_len(enc),
					GFP_KERNEL)), -ENOMEM,
		 "No memory for temporary host_id\n");

	/* Little workaround...
	 * We have a function that calculates sha1 digest and then verifies the
	 * signature. But since the sha1 digest in I2 must be calculated over
	 * the encrypted data, and the signature requires that the encrypted
	 * data to be decrypted (it contains peer's host identity), we are
	 * forced to do some temporary copying. If ultimate speed is required,
	 * then calculate the digest here as usual and feed it to signature
	 * verifier. */
	memcpy(tmp_enc, enc, hip_get_param_total_len(enc));
	
	/* Decrypt ENCRYPTED field. */
	_HIP_HEXDUMP("Recv. Key", &ctx->hip_enc_in.key, 24);
	HIP_IFEL(!(param = hip_get_param(ctx->input, HIP_PARAM_HIP_TRANSFORM)), 
		 -ENOENT, "Did not find HIP transform\n");
	HIP_IFEL((hip_tfm = hip_get_param_transform_suite_id(param, 0)) == 0,
		 -EFAULT, "Bad HIP transform\n");

	switch (hip_tfm) {
	case HIP_HIP_AES_SHA1:
 		host_id_in_enc = (struct hip_host_id *)
		  (tmp_enc + sizeof(struct hip_encrypted_aes_sha1));
 		iv = ((struct hip_encrypted_aes_sha1 *) tmp_enc)->iv;
 		/* 4 = reserved, 16 = iv */
 		crypto_len = hip_get_param_contents_len(enc) - 4 - 16;
		HIP_DEBUG("aes crypto len: %d\n", crypto_len);
		break;
	case HIP_HIP_3DES_SHA1:
 		host_id_in_enc = (struct hip_host_id *)
		  (tmp_enc + sizeof(struct hip_encrypted_3des_sha1));
 		iv = ((struct hip_encrypted_3des_sha1 *) tmp_enc)->iv;
 		/* 4 = reserved, 8 = iv */
 		crypto_len = hip_get_param_contents_len(enc) - 4 - 8;
		break;
	case HIP_HIP_NULL_SHA1:
		host_id_in_enc = (struct hip_host_id *)
			(tmp_enc + sizeof(struct hip_encrypted_null_sha1));
 		iv = NULL;
 		/* 4 = reserved */
 		crypto_len = hip_get_param_contents_len(enc) - 4;
		break;
	default:
		HIP_IFEL(1, -EINVAL, "Unknown HIP transform: %d\n", hip_tfm);
	}

	HIP_DEBUG("Crypto encrypted\n");
	/* Note: iv can be NULL */
	_HIP_HEXDUMP("IV: ", iv, 16);
	
	HIP_IFEL(hip_crypto_encrypted(host_id_in_enc, iv, hip_tfm,
				      crypto_len, &ctx->hip_enc_in.key,
				      HIP_DIRECTION_DECRYPT), -EINVAL,
		 "Decryption of Host ID failed\n");

	if (!hip_hidb_hit_is_our(&i2->hits))  {
		HIP_IFEL(hip_get_param_type(host_id_in_enc) != HIP_PARAM_HOST_ID, -EINVAL,
			 "The decrypted parameter is not a host id\n");
	}

	_HIP_HEXDUMP("Decrypted HOST_ID", host_id_in_enc,
		     hip_get_param_total_len(host_id_in_enc));

#ifdef CONFIG_HIP_BLIND
	if (use_blind) {
	  // Peer's plain hit
	  HIP_IFEL((plain_peer_hit = HIP_MALLOC(sizeof(struct in6_addr), 0)) == NULL,
		   -1, "Couldn't allocate memory\n");
	  HIP_IFEL(hip_host_id_to_hit(host_id_in_enc, plain_peer_hit, HIP_HIT_TYPE_HASH100), 
		   -1, "hip_host_id_to_hit faile\n");
	  // Local plain hit
	  HIP_IFEL((plain_local_hit = HIP_MALLOC(sizeof(struct in6_addr), 0)) == NULL,
		   -1, "Couldn't allocate memory\n");
	  HIP_IFEL(hip_blind_get_nonce(i2, &nonce), 
		   -1, "hip_blind_get_nonce failed\n");
	  HIP_IFEL(hip_plain_fingerprint(&nonce, &i2->hitr, plain_local_hit),
		   -1, "hip_plain_fingerprint failed\n");
	  HIP_IFEL(hip_blind_verify(&nonce, plain_peer_hit, &i2->hits) != 1, 
		   -1, "hip_blind_verify failed\n");
	}
#endif

	/* HMAC cannot be validated until we draw key material */

	/* NOTE! The original packet has the data still encrypted. But this is
	   not a problem, since we have decrypted the data into a temporary
	   storage and nobody uses the data in the original packet. */
	
	/* Create host association state (if not previously done). */
	if (!entry) {
	     int if_index;
	     struct sockaddr_storage ss_addr;
	     struct sockaddr *addr;
	     addr = (struct sockaddr*) &ss_addr;
	     /* We have no previous infomation on the peer, create a new HIP
		HA. */
	     HIP_DEBUG("No entry, creating new\n");
	     HIP_IFEL(!(entry = hip_hadb_create_state(GFP_KERNEL)), -ENOMSG,
		      "Failed to create or find entry\n");
	     HIP_DEBUG("After creating a new state\n");
	     /* The rest of the code assume already locked entry, so lock the
		newly created entry as well. */
	     HIP_LOCK_HA(entry);
	     if (use_blind) {
		  ipv6_addr_copy(&entry->hit_peer, plain_peer_hit);
		  hip_init_us(entry, plain_local_hit);
			HIP_DEBUG("Using blinding\n");
	     }
	     else {
		  ipv6_addr_copy(&entry->hit_peer, &i2->hits);
		  hip_init_us(entry, &i2->hitr);
			HIP_DEBUG("Not Using blinding\n");
	     }
		HIP_DEBUG("Before inserting state entry in hadb\n");
	     hip_hadb_insert_state(entry);
		HIP_DEBUG("After inserting state entry in hadb\n");
	     hip_hold_ha(entry);
	     
	     _HIP_DEBUG("HA entry created.");
	     
	     ipv6_addr_copy(&entry->local_address, i2_daddr);
	
	     HIP_IFEL(!(if_index = hip_devaddr2ifindex(&entry->local_address)), -1, 
		      "if_index NOT determined\n");
	   
	     memset(addr, 0, sizeof(struct sockaddr_storage));
	     addr->sa_family = AF_INET6;
	     memcpy(hip_cast_sa_addr(addr), &entry->local_address, hip_sa_addr_len(addr));
	     add_address_to_list(addr, if_index);
	
	}

	hip_hadb_insert_state(entry);
	hip_hold_ha(entry);
	
	_HIP_DEBUG("HA entry created.");
	
	/* If there was already state, these may be uninitialized */
	entry->hip_transform = hip_tfm;
	if (!entry->our_pub) {
		if (use_blind)
			hip_init_us(entry, plain_local_hit);
		else
			hip_init_us(entry, &i2->hitr);
	}

	/* If the incoming I2 packet has 50500 as destination port, NAT
	   mode is set on for the host association, I2 source port is
	   stored as the peer UDP port and send function is set to
	   "hip_send_udp()". Note that we must store the port not until
	   here, since the source port can be different for I1 and I2. */
	if(i2_info->dst_port == HIP_NAT_UDP_PORT)
	{
		entry->nat_mode = 1;
		entry->peer_udp_port = i2_info->src_port;
		HIP_DEBUG("entry->hadb_xmit_func: %p.\n", entry->hadb_xmit_func);
		HIP_DEBUG("SETTING SEND FUNC TO UDP for entry %p from I2 info.\n",
			  entry);
		hip_hadb_set_xmit_function_set(entry, &nat_xmit_func_set);
	}

	entry->hip_transform = hip_tfm;
	
#ifdef CONFIG_HIP_BLIND
	if (use_blind) {
	  memcpy(&entry->hit_our_blind, &i2->hitr, sizeof(struct in6_addr));
	  memcpy(&entry->hit_peer_blind, &i2->hits, sizeof(struct in6_addr));
	  entry->blind_nonce_i = nonce;
	  entry->blind = 1;
	}
#endif

	/** @todo the above should not be done if signature fails...
	    or it should be cancelled. */
	
	/* Store peer's public key and HIT to HA */
	HIP_IFE(hip_init_peer(entry, i2, host_id_in_enc), -EINVAL); 
		
	/* Validate signature */
	HIP_IFEL(entry->verify(entry->peer_pub, ctx->input), -EINVAL,
		 "Verification of I2 signature failed\n");
	
	/* If we have old SAs with these HITs delete them */
	hip_hadb_delete_inbound_spi(entry, 0);
	hip_hadb_delete_outbound_spi(entry, 0);
	{
		struct hip_esp_transform *esp_tf;
		struct hip_spi_out_item spi_out_data;

		HIP_IFEL(!(esp_tf = hip_get_param(ctx->input,
						  HIP_PARAM_ESP_TRANSFORM)),
			 -ENOENT, "Did not find ESP transform on i2\n");
		HIP_IFEL(!(esp_info = hip_get_param(ctx->input,
						    HIP_PARAM_ESP_INFO)),
			 -ENOENT, "Did not find SPI LSI on i2\n");

		if (r1cntr)
			entry->birthday = r1cntr->generation;
		entry->peer_controls |= ntohs(i2->control);

		/* move this below setup_sa */
		memset(&spi_out_data, 0, sizeof(struct hip_spi_out_item));
		spi_out_data.spi = ntohl(esp_info->new_spi);
		HIP_DEBUG("Adding spi 0x%x\n", spi_out_data.spi);
		HIP_IFE(hip_hadb_add_spi(entry, HIP_SPI_DIRECTION_OUT,
					 &spi_out_data), -1);
		entry->esp_transform = hip_select_esp_transform(esp_tf);
		HIP_IFEL((esp_tfm = entry->esp_transform) == 0, -1,
			 "Could not select proper ESP transform\n");
	}

	HIP_IFEL(hip_hadb_add_peer_addr(entry, i2_saddr, 0, 0,
					PEER_ADDR_STATE_ACTIVE), -1,
		 "Error while adding the preferred peer address\n");

	HIP_DEBUG("retransmission: %s\n", (retransmission ? "yes" : "no"));
	HIP_DEBUG("replay: %s\n", (replay ? "yes" : "no"));
	HIP_DEBUG("src %d, dst %d\n", i2_info->src_port, i2_info->dst_port);
#ifdef CONFIG_HIP_BLIND
	if (use_blind) {
	  /* Set up IPsec associations */
	  err = hip_add_sa(i2_saddr, i2_daddr,
			   &entry->hit_peer, &entry->hit_our,
			   entry, &spi_in,
			   esp_tfm,  &ctx->esp_in, &ctx->auth_in,
			   retransmission, HIP_SPI_DIRECTION_IN, 0, i2_info->src_port, 
			   i2_info->dst_port);
	}
#endif

	if (!use_blind) {
	/* Set up IPsec associations */
	hip_ha_t *entry_aux = hip_hadb_find_byhits(&ctx->input->hits, &ctx->input->hitr);
	err = hip_add_sa(i2_saddr, i2_daddr,
			 &ctx->input->hits, &ctx->input->hitr,
			 &spi_in, esp_tfm, &ctx->esp_in, &ctx->auth_in,
			 retransmission, HIP_SPI_DIRECTION_IN, 0,
			 i2_info->src_port, i2_info->dst_port);
	}
	if (err) {
		HIP_ERROR("Failed to setup inbound SA with SPI=%d\n", spi_in);
		/* if (err == -EEXIST)
		   HIP_ERROR("SA for SPI 0x%x already exists, this is perhaps a bug\n",
		   spi_in); */
		err = -1;
		hip_hadb_delete_inbound_spi(entry, 0);
		hip_hadb_delete_outbound_spi(entry, 0);
		goto out_err;
	}

	/** @todo Check -EAGAIN */
	
	/* ok, found an unused SPI to use */
	HIP_DEBUG("set up inbound IPsec SA, SPI=0x%x (host)\n", spi_in);

#ifdef CONFIG_HIP_ESCROW
    if (hip_deliver_escrow_data(i2_saddr, i2_daddr, &ctx->input->hits, 
        &ctx->input->hitr, &spi_in, esp_tfm, &ctx->esp_in, 
        HIP_ESCROW_OPERATION_ADD) != 0)
    {  
        HIP_DEBUG("Could not deliver escrow data to server\n");
    }
#endif //CONFIG_HIP_ESCROW

	spi_out = ntohl(esp_info->new_spi);
	HIP_DEBUG("Setting up outbound IPsec SA, SPI=0x%x\n", spi_out);

	HIP_DEBUG("src %d, dst %d\n", i2_info->src_port, i2_info->dst_port);

#ifdef CONFIG_HIP_BLIND
	if (use_blind) {
	   err = hip_add_sa(i2_daddr, i2_saddr,
			   &entry->hit_our, &entry->hit_peer,
			   &spi_out, esp_tfm, 
			   &ctx->esp_out, &ctx->auth_out,
			   1, HIP_SPI_DIRECTION_OUT, 0, i2_info->dst_port, i2_info->src_port);
	}
#endif

	if (!use_blind) {
/*	  err = hip_add_sa(i2_daddr, i2_saddr,
			   &ctx->input->hitr, &ctx->input->hits,
			   &spi_out, esp_tfm, 
			   &ctx->esp_out, &ctx->auth_out,
			   1, HIP_SPI_DIRECTION_OUT, 0, i2_info->dst_port, i2_info->src_port);
Tere---temporaly commented*/
	}
	if (err) {
		HIP_ERROR("Failed to setup outbound SA with SPI=%d\n",
			  spi_out);

         /* HIP_DEBUG("SA already exists for the SPI=0x%x\n", spi_out);
	    HIP_DEBUG("TODO: what to do ? currently ignored\n");
	    } else if (err) {
	    HIP_ERROR("Failed to setup IPsec SPD/SA entries, peer:dst (err=%d)\n", err);
	 */
		/* delete all IPsec related SPD/SA for this entry*/
		hip_hadb_delete_inbound_spi(entry, 0);
		hip_hadb_delete_outbound_spi(entry, 0);
		goto out_err;
	}

	/* @todo Check if err = -EAGAIN... */
	HIP_DEBUG("set up outbound IPsec SA, SPI=0x%x\n", spi_out);

#ifdef CONFIG_HIP_ESCROW
    if (hip_deliver_escrow_data(i2_daddr, i2_saddr, &ctx->input->hitr, 
        &ctx->input->hits, &spi_out, esp_tfm, &ctx->esp_out, 
        HIP_ESCROW_OPERATION_ADD) != 0)
    {  
        HIP_DEBUG("Could not deliver escrow data to server\n");
    }
#endif //CONFIG_HIP_ESCROW

#ifdef CONFIG_HIP_BLIND
    if (use_blind) {
      HIP_IFEL(hip_setup_hit_sp_pair(&entry->hit_peer,
				     &entry->hit_our,
				     i2_saddr, i2_daddr, IPPROTO_ESP, 1, 1),
	       -1, "Setting up SP pair failed\n");
    }
#endif
    if (!use_blind) {
	    HIP_IFEL(hip_setup_hit_sp_pair(&ctx->input->hits,
					   &ctx->input->hitr,
					   i2_saddr, i2_daddr, IPPROTO_ESP, 1, 1),
		     -1, "Setting up SP pair failed\n");
    }

	/* Source IPv6 address is implicitly the preferred address after the
	   base exchange. */
	HIP_IFEL(hip_hadb_add_addr_to_spi(entry, spi_out, i2_saddr, 1, 0, 1),
		 -1,  "Failed to add an address to SPI list\n");

	memset(&spi_in_data, 0, sizeof(struct hip_spi_in_item));
	spi_in_data.spi = spi_in;
	spi_in_data.ifindex = hip_devaddr2ifindex(i2_daddr);
	if (spi_in_data.ifindex) {
		HIP_DEBUG("ifindex=%d\n", spi_in_data.ifindex);
	} else
		HIP_ERROR("Couldn't get device ifindex of address\n");

	err = hip_hadb_add_spi(entry, HIP_SPI_DIRECTION_IN, &spi_in_data);
	if (err) {
		HIP_UNLOCK_HA(entry);
		HIP_ERROR("Adding of SPI failed\n");
		goto out_err;
	}

	entry->default_spi_out = spi_out;
	HIP_DEBUG("set default SPI out=0x%x\n", spi_out);

	
	HIP_IFE(hip_store_base_exchange_keys(entry, ctx, 0), -1);

	hip_hadb_insert_state(entry);
	HIP_DEBUG("state %s\n", hip_state_str(entry->state));
	HIP_IFEL(entry->hadb_misc_func->
		 hip_create_r2(ctx, i2_saddr, i2_daddr, entry, i2_info), -1, 
		 "Creation of R2 failed\n");

	/* change SA state from ACQ -> VALID, and wake up sleepers */
	//hip_finalize_sa(&entry->hit_peer, spi_out);
	//hip_finalize_sa(&entry->hit_our, spi_in);

	/* we cannot do this outside (in hip_receive_i2) since we don't have
	   the entry there and looking it up there would be unneccesary waste
	   of cycles */

	HIP_DEBUG("state is %d\n", entry->state);

	if (entry && entry->state != HIP_STATE_FILTERING_R2)
	{

/* Hmmm... Now that the RVS is compiled as a default value, we take the first
   path always. Now, is this how it is meant to be? Notice, that currently
   CONFIG_HIP_RVS does not mean that we are the RVS, but rather that the
   extension is in use. Thus we can be I, RVS or R, and as long as the
   RVS options are compiled, we always take the first path.
   
   It might be wise to create compile options for each service, and one compile
   option to indicate whether we want use the registration extension. This way
   we would get rid of the stupid dummy hip_we_are_relay(). Also, the #ifdef
   #else, #endif below would be clarified.

   -Lauri 27.09.2007 18:41.*/
#ifdef CONFIG_HIP_RVS
	     if(hip_we_are_relay())
	     {
		  entry->state = HIP_STATE_ESTABLISHED;
	     }
	     else
	     {
		  if (entry->state == HIP_STATE_UNASSOCIATED)
		  {
		       HIP_DEBUG("TODO: should wait for ESP here or "
				 "wait for implementation specific time, "
				 "moving to ESTABLISHED\n");
		       entry->state = HIP_STATE_ESTABLISHED;
		  } else if (entry->state == HIP_STATE_ESTABLISHED)
		  {
		       HIP_DEBUG("Initiator rebooted, but base exchange completed\n");
		       HIP_DEBUG("Staying in ESTABLISHED.\n");
		  } else
		  {
		    // loopback connections don't get established with this
		    //entry->state = HIP_STATE_R2_SENT;
		  }
	     }
#else
	     if (entry->state == HIP_STATE_UNASSOCIATED)
	     {
		  HIP_DEBUG("TODO: should wait for ESP here or "
			    "wait for implementation specific time, "
			    "moving to ESTABLISHED\n");
		  entry->state = HIP_STATE_ESTABLISHED;
	     } else if (entry->state == HIP_STATE_ESTABLISHED)
	     {
		  HIP_DEBUG("Initiator rebooted, but base exchange completed\n");
		  HIP_DEBUG("Staying in ESTABLISHED.\n");
	     } else {
	       // loopback connections don't get established with this
	       // entry->state = HIP_STATE_R2_SENT;
	     }
#endif /* CONFIG_HIP_RVS */
	}

        /***** LOCATOR PARAMETER ******/
	//#ifndef CONFIG_HIP_HI3
        locator = hip_get_param(i2, HIP_PARAM_LOCATOR);
        if (locator && esp_info)
            {
                HIP_IFEL(hip_update_handle_locator_parameter(entry, 
                                                             locator, esp_info),
                         -1, "hip_update_handle_locator_parameter failed\n");
            }
        else
            HIP_DEBUG("I2 did not have locator or esp_info\n");

	HIP_DEBUG("Reached %s state\n", hip_state_str(entry->state));
	//#endif /* CONFIG_HIP_HI3 */

 out_err:
	/* ha is not NULL if hip_receive_i2() fetched the HA for us.
	 * In that case we must not release our reference to it.
	 * Otherwise, if 'ha' is NULL, then we created the HIP HA in this
	 * function and we should free the reference.
	 */
	if (!ha && entry) {
		/* unlock the entry created in this function */
		HIP_UNLOCK_HA(entry);
		hip_put_ha(entry);
	}
	if (tmp_enc)
		HIP_FREE(tmp_enc);
	if (ctx->dh_shared_key)
		HIP_FREE(ctx->dh_shared_key);
	if (ctx)
		HIP_FREE(ctx);
	if (plain_local_hit)
	  HIP_FREE(plain_local_hit);
	if (plain_peer_hit)
	  HIP_FREE(plain_peer_hit);

	return err;
}

int hip_receive_i2(hip_common_t *i2, in6_addr_t *i2_saddr, in6_addr_t *i2_daddr,
		   hip_ha_t *entry, hip_portpair_t *i2_info)
{
     int state = 0, err = 0;
     uint16_t mask = HIP_PACKET_CTRL_ANON;
     _HIP_DEBUG("hip_receive_i2() invoked.\n");
	
     HIP_IFEL(ipv6_addr_any(&i2->hitr), 0,
	      "Received NULL receiver HIT in I2. Dropping\n");

     HIP_IFEL(!hip_controls_sane(ntohs(i2->control), mask), 0, 
	      "Received illegal controls in I2: 0x%x. Dropping\n",
	      ntohs(i2->control));

     if (!entry)
     {
	  state = HIP_STATE_UNASSOCIATED;
     } else 
     {
	  HIP_LOCK_HA(entry);
	  state = entry->state;
     }

     HIP_DEBUG("Received I2 in state %s\n", hip_state_str(state));
	
     switch(state) {
     case HIP_STATE_UNASSOCIATED:
	  /* Possibly no state created yet (entry == NULL), 
	     thus function pointers can't be used here. */
	  err = ((hip_handle_func_set_t *)hip_get_handle_default_func_set())->
	       hip_handle_i2(i2, i2_saddr, i2_daddr, entry, i2_info);
		
	  break;
     case HIP_STATE_I2_SENT:
	  /* WTF */
	  if (hip_hit_is_bigger(&entry->hit_our, &entry->hit_peer))
	  {
	       HIP_IFEL(hip_receive_i2(i2,i2_saddr,i2_daddr,entry,
				       i2_info), -ENOSYS,
			"Dropping HIP packet\n");
	  } else if (entry->is_loopback)
	  {
	       hip_handle_i2(i2,i2_saddr,i2_daddr,entry,i2_info);
	  }
	  break;
     case HIP_STATE_I1_SENT:
     case HIP_STATE_R2_SENT:
	  err = hip_handle_i2(i2, i2_saddr, i2_daddr, entry, i2_info);
	  break;
     case HIP_STATE_ESTABLISHED:
	  err = entry->hadb_handle_func->
	       hip_handle_i2(i2, i2_saddr, i2_daddr, entry, i2_info);
	     
	  break;
     case HIP_STATE_CLOSING:
     case HIP_STATE_CLOSED:
	  err = entry->hadb_handle_func->
	       hip_handle_i2(i2, i2_saddr, i2_daddr, entry, i2_info);
	  break;
     default:
	  HIP_ERROR("Internal state (%d) is incorrect\n", state);
	  break;
     }
	
     if (entry)
     {
	  HIP_UNLOCK_HA(entry);
	  hip_put_ha(entry);
     }

 out_err:
     if (err)
     {
	  HIP_ERROR("error (%d) occurred\n", err);
     }
	
     return err;
}

int hip_handle_r2(struct hip_common *r2,
		  struct in6_addr *r2_saddr,
		  struct in6_addr *r2_daddr,
		  hip_ha_t *entry,
		  hip_portpair_t *r2_info)
{
	struct hip_context *ctx = NULL;
 	struct hip_esp_info *esp_info = NULL;
	struct hip_spi_out_item spi_out_data;
	int tfm, err = 0;
	uint32_t spi_recvd, spi_in;
	int retransmission = 0;
        int * reg_types = NULL;
        int type_count = 0;
        

#ifdef CONFIG_HIP_HI3
	if( r2_info->hi3_in_use ) 
	{
		// In hi3 real addresses should already be in entry, received on r1 phase. 
		// 
		memcpy(r2_saddr, &entry->preferred_address, sizeof(struct in6_addr));
		memcpy(r2_daddr, &entry->local_address, sizeof(struct in6_addr));
	}
#endif

	_HIP_DEBUG("hip_handle_r2() invoked.\n");
	if (entry->state == HIP_STATE_ESTABLISHED) {
		retransmission = 1;
		HIP_DEBUG("Retransmission\n");
	} else {
		HIP_DEBUG("Not a retransmission\n");
	}

	/* assume already locked entry */
	HIP_IFE(!(ctx = HIP_MALLOC(sizeof(struct hip_context), GFP_ATOMIC)), -ENOMEM);
	memset(ctx, 0, sizeof(struct hip_context));
        ctx->input = r2;

#ifdef CONFIG_HIP_BLIND
	if (use_blind) {
	  HIP_IFEL(hip_blind_verify_r2(r2, entry), -1, "hip_blind_verify_host_id failed\n"); 
	}
#endif

        /* Verify HMAC */
	if (entry->is_loopback) {
		HIP_IFEL(hip_verify_packet_hmac2(r2, &entry->hip_hmac_out,
						 entry->peer_pub), -1, 
		 "HMAC validation on R2 failed\n");
	} else {
		HIP_IFEL(hip_verify_packet_hmac2(r2, &entry->hip_hmac_in,
						 entry->peer_pub), -1, 
		 "HMAC validation on R2 failed\n");
	}

	/* Assign a local private key to HA */
	//HIP_IFEL(hip_init_our_hi(entry), -EINVAL, "Could not assign a local host id\n");

	/* Signature validation */
 	HIP_IFEL(entry->verify(entry->peer_pub, r2), -EINVAL, "R2 signature verification failed\n");

        /* The rest */
 	HIP_IFEL(!(esp_info = hip_get_param(r2, HIP_PARAM_ESP_INFO)), -EINVAL,
		 "Parameter SPI not found\n");

	spi_recvd = ntohl(esp_info->new_spi);
	memset(&spi_out_data, 0, sizeof(struct hip_spi_out_item));
	spi_out_data.spi = spi_recvd;
	HIP_IFE(hip_hadb_add_spi(entry, HIP_SPI_DIRECTION_OUT, &spi_out_data), -1);

	memcpy(&ctx->esp_out, &entry->esp_out, sizeof(ctx->esp_out));
	memcpy(&ctx->auth_out, &entry->auth_out, sizeof(ctx->auth_out));
	HIP_DEBUG("entry should have only one spi_in now, test\n");
	spi_in = hip_hadb_get_latest_inbound_spi(entry);
	tfm = entry->esp_transform;

	HIP_DEBUG("src %d, dst %d\n", r2_info->src_port, r2_info->dst_port);

#ifdef CONFIG_HIP_BLIND
	if (use_blind) {
	  err = hip_add_sa(r2_daddr, r2_saddr,
			   &entry->hit_our, &entry->hit_peer,
			   &spi_recvd, tfm,
			   &ctx->esp_out, &ctx->auth_out, 1,
			   HIP_SPI_DIRECTION_OUT, 0, r2_info->src_port, r2_info->dst_port);
	}
#endif
	HIP_DEBUG("entry->hip_transform: \n", entry->hip_transform);
	if (!hip_blind_get_status()) {
	  err = hip_add_sa(r2_daddr, r2_saddr,
				 &ctx->input->hitr, &ctx->input->hits,
				 &spi_recvd, tfm,
				 &ctx->esp_out, &ctx->auth_out, 1,
				 HIP_SPI_DIRECTION_OUT, 0, r2_info->src_port, r2_info->dst_port);
	}

	//hip_firewall_add_bex_data(entry, &entry->hit_our, &entry->hit_peer);
	/*
	if (err == -EEXIST) {
		HIP_DEBUG("SA already exists for the SPI=0x%x\n", spi_recvd);
		HIP_DEBUG("TODO: what to do ? currently ignored\n");
	*/

	if (err) {
		HIP_ERROR("hip_add_sa failed, peer:dst (err=%d)\n", err);
		HIP_ERROR("** TODO: remove inbound IPsec SA**\n");
		err = -1;
		goto out_err;
	}
	/* XXX: Check for -EAGAIN */
	HIP_DEBUG("set up outbound IPsec SA, SPI=0x%x (host)\n", spi_recvd);

#ifdef CONFIG_HIP_ESCROW
    if (hip_deliver_escrow_data(r2_daddr, r2_saddr, &ctx->input->hitr, 
        &ctx->input->hits, &spi_recvd, tfm, &ctx->esp_out, 
        HIP_ESCROW_OPERATION_ADD) != 0)
    {  
        HIP_DEBUG("Could not deliver escrow data to server\n");
    }
#endif //CONFIG_HIP_ESCROW                          

        /* source IPv6 address is implicitly the preferred
	 * address after the base exchange */
	err = hip_hadb_add_addr_to_spi(entry, spi_recvd, r2_saddr,
				       1, 0, 1);
	if (err)
		HIP_ERROR("hip_hadb_add_addr_to_spi err=%d not handled\n", err);
	entry->default_spi_out = spi_recvd;
	HIP_DEBUG("set default SPI out=0x%x\n", spi_recvd);
	_HIP_DEBUG("add spi err ret=%d\n", err);
	//if(IN6_IS_ADDR_V4MAPPED(r2_daddr))
	//	err = hip_ipv4_devaddr2ifindex(r2_daddr);
	//else
	err = hip_devaddr2ifindex(r2_daddr);
	if (err != 0) {
	     HIP_DEBUG("ifindex=%d\n", err);
		hip_hadb_set_spi_ifindex(entry, spi_in, err);
	} else
		HIP_ERROR("Couldn't get device ifindex of address\n");
	err = 0;

        /***** LOCATOR PARAMETER ******/
	//#ifndef CONFIG_HIP_HI3
        if (entry->locator)
            {
                HIP_IFEL(hip_update_handle_locator_parameter(entry, 
                         entry->locator, esp_info),
                         -1, "hip_update_handle_locator_parameter failed\n");
            }
        else
            HIP_DEBUG("entry->locator did not have locators from r1\n");
	//#endif /* CONFIG_HIP_HI3 */

	/*
	  HIP_DEBUG("clearing the address used during the bex\n");
	  ipv6_addr_copy(&entry->bex_address, &in6addr_any);
	*/
        
	/* Registration of additional services. Check if we should expect
	   REG_RESPONSE or REG_FAILED parameter */
	
	uint8_t services[HIP_NUMBER_OF_EXISTING_SERVICES];
	
        type_count = hip_get_incomplete_registrations(&reg_types, entry, 1, services); 
        if (type_count > 0) {
                HIP_IFEL(hip_handle_registration_response(entry, r2), -1, 
                        "Error handling reg_response\n"); 
        }

	/* these will change SAs' state from ACQUIRE to VALID, and
	 * wake up any transport sockets waiting for a SA */
	//	hip_finalize_sa(&entry->hit_peer, spi_recvd);
	//hip_finalize_sa(&entry->hit_our, spi_in);

	entry->state = HIP_STATE_ESTABLISHED;
	hip_hadb_insert_state(entry);

#ifdef CONFIG_HIP_OPPORTUNISTIC
	/* Check and remove the IP of the peer from the opp non-HIP database */
	hip_oppipdb_delentry(&(entry->preferred_address));
#endif
	HIP_DEBUG("Reached ESTABLISHED state\n");
	
 out_err:

	if (entry->state == HIP_STATE_ESTABLISHED)
		hip_firewall_add_bex_data(entry, &entry->hit_our, &entry->hit_peer);
	else
		hip_firewall_add_bex_data(entry, NULL, NULL);
	
	if (ctx)
		HIP_FREE(ctx);
        if (reg_types)
                HIP_FREE(reg_types);
        return err;
}

int hip_handle_i1(struct hip_common *i1, struct in6_addr *i1_saddr,
		  struct in6_addr *i1_daddr, hip_ha_t *entry,
		  hip_portpair_t *i1_info)
{
     int err = 0;
     uint16_t nonce = 0;
     in6_addr_t dest; // For the IP address in FROM/RELAY_FROM
     in_port_t  dest_port = 0; // For the port in RELAY_FROM

     HIP_DEBUG("hip_handle_i1() invoked.\n");

     ipv6_addr_copy(&dest, &in6addr_any);
     
#ifdef CONFIG_HIP_RVS
     if(!hip_we_are_relay())
     {
	  /* This is where the Responder handles the incoming relayed I1 packet.
	     We need two things from the relayed packet:
	     1) The destination IP address and port from the FROM/RELAY_FROM
	     parameters.
	     2) The source address and source port of the I1 packet to build the
	     VIA_RVS/RELAY_TO parameter. */
	  HIP_IFEL(hip_relay_handle_from(i1, i1_saddr, &dest, &dest_port),
		   -1, "Handling of relayed I1 packet failed.\n");
     }
#endif /* CONFIG_HIP_RVS */

     /* @todo: how to the handle the blind code with RVS?? */
#ifdef CONFIG_HIP_BLIND
     if (hip_blind_get_status()) {
	  HIP_DEBUG("Blind is on\n");
	  // We need for R2 transmission: see hip_xmit_r1 below
	  HIP_IFEL(hip_blind_get_nonce(i1, &nonce), 
		   -1, "hip_blind_get_nonce failed\n");
     }
#endif
     err = hip_xmit_r1(i1, i1_saddr, i1_daddr, &dest, dest_port, i1_info,
		       &nonce);
 out_err:
     return err;
}

int hip_receive_i1(struct hip_common *i1, struct in6_addr *i1_saddr,
		   struct in6_addr *i1_daddr, hip_ha_t *entry,
		   hip_portpair_t *i1_info)
{
	int err = 0, state, mask = 0,cmphits=0;

	_HIP_DEBUG("hip_receive_i1() invoked.\n");

#ifdef CONFIG_HIP_BLIND
	if (hip_blind_get_status())
	  mask |= HIP_PACKET_CTRL_BLIND;
#endif

	HIP_ASSERT(!ipv6_addr_any(&i1->hitr));

	/* check i1 for broadcast/multicast addresses */
	if (IN6_IS_ADDR_V4MAPPED(i1_daddr)) {
		struct in_addr addr4;
		IPV6_TO_IPV4_MAP(i1_daddr, &addr4);
		if (addr4.s_addr == INADDR_BROADCAST) {
			HIP_DEBUG("Received i1 broadcast\n");
			HIP_IFEL(hip_select_source_address(i1_daddr, i1_saddr), -1,
				 "Could not find source address\n");
		}
	} else if (IN6_IS_ADDR_MULTICAST(i1_daddr)) {
			HIP_IFEL(hip_select_source_address(i1_daddr, i1_saddr), -1,
				 "Could not find source address\n");
	}

 	HIP_IFEL(!hip_controls_sane(ntohs(i1->control), mask), -1, 
		 "Received illegal controls in I1: 0x%x. Dropping\n", ntohs(i1->control));

	if (entry) {
		state = entry->state;
		hip_put_ha(entry);
	}
	else {

#ifdef CONFIG_HIP_RVS
	     if(hip_we_are_relay())
	     {
		  hip_relrec_t *rec = NULL, dummy;

		  /* Check if we have a relay record in our database matching the
		     Responder's HIT. We should find one, if the Responder is
		     registered to relay.*/
		  HIP_DEBUG_HIT("Searching relay record on HIT ", &i1->hitr);
		  memcpy(&(dummy.hit_r), &i1->hitr, sizeof(i1->hitr));
		  rec = hip_relht_get(&dummy);
		  if(rec == NULL)
		       HIP_INFO("No matching relay record found.\n");
		  else if(rec->type != HIP_RVSRELAY)
		       HIP_INFO("Matching relay record found, but it is of the"\
				"wrong type.\n");
		  else
		  {
		       hip_relay_rvs(i1, i1_saddr, i1_daddr, rec, i1_info);
		       /* We created a new I1 from scratch in the relay function.
			  The original I1 packet is now redundant. */
		       state = HIP_STATE_NONE;
		       err = -ECANCELED;
		       goto out_err;
		  }
	     }
#endif
		state = HIP_STATE_NONE;
	}

	HIP_DEBUG("Received I1 in state %s\n", hip_state_str(state));

	switch(state) {
	case HIP_STATE_NONE:
	     err = ((hip_handle_func_set_t *)hip_get_handle_default_func_set())
		  ->hip_handle_i1(i1, i1_saddr, i1_daddr, entry, i1_info);
	     break;
	case HIP_STATE_I1_SENT:
	     cmphits=hip_hit_is_bigger(&entry->hit_our, &entry->hit_peer);
	     if (cmphits == 1) {
		  HIP_IFEL(hip_receive_i1(i1,i1_saddr,i1_daddr,entry,i1_info),
			   -ENOSYS, "Dropping HIP packet\n");
		  
	     } else if (cmphits == 0) {
		  hip_handle_i1(i1,i1_saddr,i1_daddr,entry,i1_info);
		
	     } 

	     break;
	case HIP_STATE_UNASSOCIATED:
	case HIP_STATE_I2_SENT:
	case HIP_STATE_R2_SENT:
	case HIP_STATE_ESTABLISHED:
	case HIP_STATE_CLOSED:
	case HIP_STATE_CLOSING:
	     err = ((hip_handle_func_set_t *)hip_get_handle_default_func_set())
		  ->hip_handle_i1(i1, i1_saddr, i1_daddr, entry, i1_info);
	     break;
	default:
	     /* should not happen */
	     HIP_IFEL(1, -EINVAL, "DEFAULT CASE, UNIMPLEMENTED STATE HANDLING OR A BUG\n");
	}

 out_err:
	return err;
}

int hip_receive_r2(struct hip_common *hip_common,
		   struct in6_addr *r2_saddr,
		   struct in6_addr *r2_daddr,
		   hip_ha_t *entry,
		   hip_portpair_t *r2_info)
{
	int err = 0, state;
	uint16_t mask = 0;

	_HIP_DEBUG("hip_receive_r2() invoked.\n");

	HIP_IFEL(ipv6_addr_any(&hip_common->hitr), -1, 
		 "Received NULL receiver HIT in R2. Dropping\n");
	
	HIP_IFEL(!hip_controls_sane(ntohs(hip_common->control), mask), -1,
		 "Received illegal controls in R2: 0x%x. Dropping\n", ntohs(hip_common->control));
	//HIP_IFEL(!(entry = hip_hadb_find_byhits(&hip_common->hits, 
	//					&hip_common->hitr)), -EFAULT,
	//	 "Received R2 by unknown sender\n");

	HIP_IFEL(!entry, -EFAULT,
		 "Received R2 by unknown sender\n");
		 
	HIP_LOCK_HA(entry);
	state = entry->state;

	HIP_DEBUG("Received R2 in state %s\n", hip_state_str(state));
 	switch(state) {
 	case HIP_STATE_I2_SENT:
 		/* The usual case. */
 		err = entry->hadb_handle_func->hip_handle_r2(hip_common,
							     r2_saddr,
							     r2_daddr,
							     entry,
							     r2_info);
		if (err) {
			HIP_ERROR("hip_handle_r2 failed (err=%d)\n", err);
			goto out_err;
 		}
	break;

 	case HIP_STATE_ESTABLISHED:
		if (entry->is_loopback)
		    err = entry->hadb_handle_func->hip_handle_r2(hip_common,
								 r2_saddr,
								 r2_daddr,
								 entry,
								 r2_info);
		break;
	case HIP_STATE_R2_SENT:
	case HIP_STATE_UNASSOCIATED:
 	case HIP_STATE_I1_SENT:
 	default:
		HIP_IFEL(1, -EFAULT, "Dropping\n");
 	}

 out_err:
	if (entry) {
		HIP_UNLOCK_HA(entry);
		hip_put_ha(entry);
	}
	return err;
}

int hip_receive_notify(const struct hip_common *notify,
		       const struct in6_addr *notify_saddr,
		       const struct in6_addr *notify_daddr, hip_ha_t* entry)
{
	int err = 0;
	struct hip_notification *notify_param;
	uint16_t mask = HIP_PACKET_CTRL_ANON, notify_controls = 0;
	
	_HIP_DEBUG("hip_receive_notify() invoked.\n");
	
	HIP_IFEL(entry == NULL , -EFAULT,
		 "Received a NOTIFY packet from an unknown sender, ignoring "\
		 "the packet.\n");
	
	notify_controls = ntohs(notify->control);
	
	HIP_IFEL(!hip_controls_sane(notify_controls, mask), -EPROTO, 
		 "Received a NOTIFY packet with illegal controls: 0x%x, ignoring "\
		 "the packet.\n", notify_controls);

	err = hip_handle_notify(notify, notify_saddr, notify_daddr, entry);

 out_err:
	if (entry != NULL)
		hip_put_ha(entry);
	
	return err;
}

int hip_handle_notify(const struct hip_common *notify,
		      const struct in6_addr *notify_saddr,
		      const struct in6_addr *notify_daddr, hip_ha_t* entry)
{
	int err = 0;
	struct hip_common i1;
	struct hip_tlv_common *current_param = NULL;
	struct hip_notification *notification = NULL;
	struct in6_addr responder_ip, responder_hit;
	hip_tlv_type_t param_type = 0, response;
	hip_tlv_len_t param_len = 0;
	uint16_t msgtype = 0;
	in_port_t port = 0;

	/* draft-ietf-hip-base-06, Section 6.13: Processing NOTIFY packets is
	   OPTIONAL. If processed, any errors in a received NOTIFICATION parameter
	   SHOULD be logged. */

	_HIP_DEBUG("hip_receive_notify() invoked.\n");
	
	/* Loop through all the parameters in the received I1 packet. */
	while ((current_param = 
		hip_get_next_param(notify, current_param)) != NULL) {
		
		param_type = hip_get_param_type(current_param);
		
		if (param_type == HIP_PARAM_NOTIFICATION) {
			HIP_INFO("Found NOTIFICATION parameter in NOTIFY "\
				 "packet.\n");
			notification = (struct hip_notification *)current_param;
			
			param_len = hip_get_param_contents_len(current_param);
			msgtype = ntohs(notification->msgtype);
						
			switch(msgtype) {
			case HIP_NTF_UNSUPPORTED_CRITICAL_PARAMETER_TYPE:
				HIP_INFO("NOTIFICATION parameter type is "\
					 "UNSUPPORTED_CRITICAL_PARAMETER_"\
					 "TYPE.\n");
				break;
			case HIP_NTF_INVALID_SYNTAX:
				HIP_INFO("NOTIFICATION parameter type is "\
					 "INVALID_SYNTAX.\n");
				break;
			case HIP_NTF_NO_DH_PROPOSAL_CHOSEN:
				HIP_INFO("NOTIFICATION parameter type is "\
					 "NO_DH_PROPOSAL_CHOSEN.\n");
				break;
			case HIP_NTF_INVALID_DH_CHOSEN:
				HIP_INFO("NOTIFICATION parameter type is "\
					 "INVALID_DH_CHOSEN.\n");
				break;
			case HIP_NTF_NO_HIP_PROPOSAL_CHOSEN:
				HIP_INFO("NOTIFICATION parameter type is "\
					 "NO_HIP_PROPOSAL_CHOSEN.\n");
				break;
			case HIP_NTF_INVALID_HIP_TRANSFORM_CHOSEN:
				HIP_INFO("NOTIFICATION parameter type is "\
					 "INVALID_HIP_TRANSFORM_CHOSEN.\n");
				break;
			case HIP_NTF_AUTHENTICATION_FAILED:
				HIP_INFO("NOTIFICATION parameter type is "\
					 "AUTHENTICATION_FAILED.\n");
				break;
			case HIP_NTF_CHECKSUM_FAILED:
				HIP_INFO("NOTIFICATION parameter type is "\
					 "CHECKSUM_FAILED.\n");
				break;
			case HIP_NTF_HMAC_FAILED:
				HIP_INFO("NOTIFICATION parameter type is "\
					 "HMAC_FAILED.\n");
				break;
			case HIP_NTF_ENCRYPTION_FAILED:
				HIP_INFO("NOTIFICATION parameter type is "\
					 "ENCRYPTION_FAILED.\n");
				break;
			case HIP_NTF_INVALID_HIT:
				HIP_INFO("NOTIFICATION parameter type is "\
					 "INVALID_HIT.\n");
				break;
			case HIP_NTF_BLOCKED_BY_POLICY:
				HIP_INFO("NOTIFICATION parameter type is "\
					 "BLOCKED_BY_POLICY.\n");
				break;
			case HIP_NTF_SERVER_BUSY_PLEASE_RETRY:
				HIP_INFO("NOTIFICATION parameter type is "\
					 "SERVER_BUSY_PLEASE_RETRY.\n");
				break;
			case HIP_NTF_I2_ACKNOWLEDGEMENT:
				HIP_INFO("NOTIFICATION parameter type is "\
					 "I2_ACKNOWLEDGEMENT.\n");
				break;
			case HIP_PARAM_RELAY_TO:
			case HIP_PARAM_RELAY_FROM:
				response = ((msgtype == HIP_PARAM_RELAY_TO) ? HIP_I1 : HIP_NOTIFY);
				HIP_INFO("NOTIFICATION parameter type is "\
					 "RVS_NAT.\n");
				
				/* responder_hit is not currently used. */
				ipv6_addr_copy(&responder_hit, (struct in6_addr *)
					       notification->data);
				ipv6_addr_copy(&responder_ip, (struct in6_addr *)
					       &(notification->
						 data[sizeof(struct in6_addr)]));
				memcpy(&port, &(notification->
						data[2 * sizeof(struct in6_addr)]),
				       sizeof(in_port_t));

				/* If port is zero (the responder is not behind
				   a NAT) we use 50500 as the destination
				   port. */
				if(port == 0) {
					port = HIP_NAT_UDP_PORT;
				}
			       
				/* We don't need to use hip_msg_alloc(), since
				   the I1 packet is just the size of struct
				   hip_common. */ 
				memset(&i1, 0, sizeof(i1));

				entry->hadb_misc_func->
					hip_build_network_hdr(&i1,
							      response,
							      entry->local_controls,
							      &entry->hit_our,
							      &entry->hit_peer);
				
				/* Calculate the HIP header length */
				hip_calc_hdr_len(&i1);
				
				//sleep(3);

				/* This I1 packet must be send only once, which
				   is why we use NULL entry for sending. */
				err = entry->hadb_xmit_func->
					hip_send_pkt(&entry->local_address, &responder_ip,
						     (entry->nat_mode ? HIP_NAT_UDP_PORT : 0),
						     port,
						     &i1, NULL, 0);
				
				break;
			default:
				HIP_INFO("Unrecognized NOTIFICATION parameter "\
					 "type.\n");
				break;
			}
			HIP_HEXDUMP("NOTIFICATION parameter notification data:",
				    notification->data,
				    param_len 
				    - sizeof(notification->reserved)
				    - sizeof(notification->msgtype)
				);
			msgtype = 0;
		}
		else {
			HIP_INFO("Found unsupported parameter in NOTIFY "\
				 "packet.\n");
		}
	}
	
	return err;
}

int hip_receive_bos(struct hip_common *bos,
		    struct in6_addr *bos_saddr,
		    struct in6_addr *bos_daddr,
		    hip_ha_t *entry,
		    hip_portpair_t *bos_info)
{
	int err = 0, state = 0;

	_HIP_DEBUG("hip_receive_bos() invoked.\n");

	HIP_IFEL(ipv6_addr_any(&bos->hits), 0, 
		 "Received NULL sender HIT in BOS.\n");
	HIP_IFEL(!ipv6_addr_any(&bos->hitr), 0, 
		 "Received non-NULL receiver HIT in BOS.\n");
	HIP_DEBUG("Entered in hip_receive_bos...\n");
	state = entry ? entry->state : HIP_STATE_UNASSOCIATED;

	/** @todo If received BOS packet from already known sender should return
	    right now */
	HIP_DEBUG("Received BOS packet in state %s\n", hip_state_str(state));
 	switch(state) {
 	case HIP_STATE_UNASSOCIATED:
	case HIP_STATE_I1_SENT:
	case HIP_STATE_I2_SENT:
		/* Possibly no state created yet */
		err = entry->hadb_handle_func->hip_handle_bos(bos, bos_saddr, bos_daddr, entry, bos_info);
		break;
	case HIP_STATE_R2_SENT:
 	case HIP_STATE_ESTABLISHED:
		HIP_DEBUG("BOS not handled in state %s\n", hip_state_str(state));
		break;
	default:
		HIP_IFEL(1, 0, "Internal state (%d) is incorrect\n", state);
	}

	if (entry)
		hip_put_ha(entry);
 out_err:
	return err;
}
