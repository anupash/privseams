#include "close.h"

int hip_send_close(struct hip_common *msg)
{
	int err = 0;
	hip_hit_t *hit = NULL;
	hip_ha_t *entry;

	HIP_DEBUG("msg=%p\n", msg);

	if (msg)
		hit = hip_get_param_contents(msg, HIP_PARAM_HIT);

	HIP_IFEL(hip_for_each_ha(&hip_xmit_close, (void *) hit), -1,
		 "Failed to reset all HAs\n");

 out_err:

	return err;
}

int hip_xmit_close(hip_ha_t *entry, void *opaque)
{
	int err = 0, mask = 0;
	hip_hit_t *peer = (hip_hit_t *) opaque;
	struct hip_common *close = NULL;

	if (peer)
		HIP_DEBUG_HIT("Peer HIT to be closed", peer);

	if (peer && !ipv6_addr_any(peer) &&
	    memcmp(&entry->hit_peer, peer, sizeof(hip_hit_t))) {
		HIP_DEBUG("Peer HIT did not match, ignoring.\n");
		goto out_err;
	}

        if (!(entry->state == HIP_STATE_ESTABLISHED)) {
		HIP_ERROR("Not sending CLOSE message, invalid hip state "\
			  "in current host association. State is %s.\n", 
			  hip_state_str(entry->state));
		goto out_err;
	}

	HIP_DEBUG("State is ESTABLISHED in current host association, sending "\
		  "CLOSE message to peer.\n");
	
	HIP_IFE(!(close = hip_msg_alloc()), -ENOMEM);

	entry->hadb_misc_func->
		hip_build_network_hdr(close, HIP_CLOSE, mask, &entry->hit_our,
				      &entry->hit_peer);

	/********ECHO (SIGNED) **********/

	get_random_bytes(entry->echo_data, sizeof(entry->echo_data));
	HIP_IFEL(hip_build_param_echo(close, entry->echo_data,
				      sizeof(entry->echo_data), 1, 1), -1,
		 "Failed to build echo param.\n");

	/************* HMAC ************/
	HIP_IFEL(hip_build_param_hmac_contents(close,
					       &entry->hip_hmac_out),
		 -1, "Building of HMAC failed.\n");
	/********** Signature **********/
	HIP_IFEL(entry->sign(entry->our_priv, close), -EINVAL,
		 "Could not create signature.\n");

	HIP_IFEL(entry->hadb_xmit_func->
		 hip_send_pkt(NULL, &entry->preferred_address,
			      (entry->nat_mode ? HIP_NAT_UDP_PORT : 0),
			      entry->peer_udp_port, close, entry, 0),
		 -ECOMM, "Sending CLOSE message failed.\n");
	
	entry->state = HIP_STATE_CLOSING;

 out_err:
	if (close)
		HIP_FREE(close);

	return err;
}

int hip_handle_close(struct hip_common *close, hip_ha_t *entry)
{
	int err = 0, mask = 0;
	struct hip_common *close_ack = NULL;
	struct hip_echo_request *request;
	int echo_len;

	/* verify HMAC */
        if (entry->is_loopback) {
		HIP_IFEL(hip_verify_packet_hmac(close, &entry->hip_hmac_out),
			 -ENOENT, "HMAC validation on close failed.\n");
        } else {
		HIP_IFEL(hip_verify_packet_hmac(close, &entry->hip_hmac_in),
			 -ENOENT, "HMAC validation on close failed.\n");
	}

	/* verify signature */
	HIP_IFEL(entry->verify(entry->peer_pub, close), -EINVAL,
		 "Verification of close signature failed.\n");

	HIP_IFE(!(close_ack = hip_msg_alloc()), -ENOMEM);

	HIP_IFEL(!(request =
		   hip_get_param(close, HIP_PARAM_ECHO_REQUEST_SIGN)),
		 -1, "No echo request under signature.\n");
	echo_len = hip_get_param_contents_len(request);

	entry->hadb_misc_func->hip_build_network_hdr(close_ack, HIP_CLOSE_ACK,
			      mask, &entry->hit_our,
			      &entry->hit_peer);

	HIP_IFEL(hip_build_param_echo(close_ack, request + 1,
				      echo_len, 1, 0), -1,
		 "Failed to build echo param.\n");

	/************* HMAC ************/
	HIP_IFEL(hip_build_param_hmac_contents(close_ack,
					       &entry->hip_hmac_out),
		 -1, "Building of HMAC failed.\n");

	/********** Signature **********/
	HIP_IFEL(entry->sign(entry->our_priv, close_ack), -EINVAL,
		 "Could not create signature.\n");
	
	HIP_IFEL(entry->hadb_xmit_func->
		 hip_send_pkt(NULL, &entry->preferred_address, HIP_NAT_UDP_PORT,
			      entry->peer_udp_port,
			      close_ack, entry, 0),
		 -ECOMM, "Sending CLOSE ACK message failed.\n");
	
	entry->state = HIP_STATE_CLOSED;

	HIP_DEBUG("CLOSED.\n");

/* If this host has a relay hashtable, i.e. the host is a HIP UDP relay or RVS,
   then we need to delete the relay record matching the sender's HIT. */
#ifdef CONFIG_HIP_RVS
	if(hip_relay_get_status())
	{
	     hip_relrec_t *rec = NULL, dummy;
	     memcpy(&(dummy.hit_r), &(close->hits),
		    sizeof(close->hits));
	     hip_relht_rec_free(&dummy);
	     /* Check that the element really got deleted. */
	     if(hip_relht_get(&dummy) == NULL)
	     {
		  HIP_DEBUG_HIT("Deleted relay record for HIT",
				&(close->hits));
	     }
	}
#endif
	
	HIP_IFEL(hip_del_peer_info(&entry->hit_our, &entry->hit_peer), -1,
				   "Deleting peer info failed.\n");
 out_err:

	if (close_ack)
		HIP_FREE(close_ack);

	return err;
}

int hip_receive_close(struct hip_common *close,
		      hip_ha_t 		*entry) 
{
	int state = 0;
	int err = 0;
	uint16_t mask = HIP_PACKET_CTRL_ANON;

	/* XX FIX: CHECK THE SIGNATURE */

	HIP_DEBUG("\n");
	HIP_IFEL(ipv6_addr_any(&close->hitr), -1,
		 "Received NULL receiver HIT in CLOSE. Dropping\n");

	if (!hip_controls_sane(ntohs(close->control), mask)) {
		HIP_ERROR("Received illegal controls in CLOSE: 0x%x. Dropping\n",
			  ntohs(close->control));
		goto out_err;
	}

	if (!entry) {
		HIP_DEBUG("No HA for the received close\n");
		goto out_err;
	} else {
		HIP_LOCK_HA(entry);
		state = entry->state;
	}

 	switch(state) {
 	case HIP_STATE_ESTABLISHED:
	case HIP_STATE_CLOSING:
		err = entry->hadb_handle_func->hip_handle_close(close, entry);
		break;
	default:
		HIP_ERROR("Internal state (%d) is incorrect\n", state);
		break;
	}

	if (entry) {
		/* XX CHECK: is the put done twice? once already in handle? */
		HIP_UNLOCK_HA(entry);
		//hip_put_ha(entry);
	}
 out_err:
	return err;
}

int hip_handle_close_ack(struct hip_common *close_ack, hip_ha_t *entry)
{
	int err = 0;
	struct hip_echo_request *echo_resp;

	/* verify ECHO */
	HIP_IFEL(!(echo_resp =
		   hip_get_param(close_ack, HIP_PARAM_ECHO_RESPONSE_SIGN)),
		 -1, "Echo response not found\n");
	HIP_IFEL(memcmp(echo_resp + 1, entry->echo_data,
			sizeof(entry->echo_data)), -1,
		 "Echo response did not match request\n");

	/* verify HMAC */
        if (entry->is_loopback) {
		HIP_IFEL(hip_verify_packet_hmac(close_ack,
						&entry->hip_hmac_out),
			 -ENOENT, "HMAC validation on close ack failed\n");
	} else {
		HIP_IFEL(hip_verify_packet_hmac(close_ack,
						&entry->hip_hmac_in),
			 -ENOENT, "HMAC validation on close ack failed\n");
	}
	/* verify signature */
	HIP_IFEL(entry->verify(entry->peer_pub, close_ack), -EINVAL,
		 "Verification of close ack signature failed\n");

	entry->state = HIP_STATE_CLOSED;

	HIP_DEBUG("CLOSED\n");

	HIP_IFEL(hip_del_peer_info(&entry->hit_our, &entry->hit_peer), -1,
	         "Deleting peer info failed\n");

	//hip_hadb_remove_state(entry);
	//hip_delete_esp(entry);

	/* by now, if everything is according to plans, the refcnt should
	   be 1 */
	//hip_put_ha(entry);

 out_err:

	return err;
}


int hip_receive_close_ack(struct hip_common *close_ack,
			  hip_ha_t *entry) 
{
	int state = 0;
	int err = 0;
	uint16_t mask = HIP_PACKET_CTRL_ANON;

	/* XX FIX:  */

	HIP_DEBUG("\n");

	HIP_IFEL(ipv6_addr_any(&close_ack->hitr), -1,
		 "Received NULL receiver HIT in CLOSE ACK. Dropping\n");

	if (!hip_controls_sane(ntohs(close_ack->control), mask
		       //HIP_CONTROL_CERTIFICATES | HIP_PACKET_CTRL_ANON |
		       // | HIP_CONTROL_SHT_MASK | HIP_CONTROL_DHT_MASK)) {
		               )) {
		HIP_ERROR("Received illegal controls in CLOSE ACK: 0x%x. Dropping\n",
			  ntohs(close_ack->control));
		goto out_err;
	}
	
	if (!entry) {
		HIP_DEBUG("No HA for the received close ack\n");
		goto out_err;
	} else {
		HIP_LOCK_HA(entry);
		state = entry->state;
	}

 	switch(state) {
	case HIP_STATE_CLOSING:
	case HIP_STATE_CLOSED:
		err = entry->hadb_handle_func->hip_handle_close_ack(close_ack, entry);
		break;
	default:
		HIP_ERROR("Internal state (%d) is incorrect\n", state);
		break;
	}

 out_err:
	return err;
}
