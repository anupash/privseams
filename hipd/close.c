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
		HIP_DEBUG_HIT("peer HIT to be closed", peer);

	if (peer && !ipv6_addr_any(peer) &&
	    memcmp(&entry->hit_peer, peer, sizeof(hip_hit_t))) {
		HIP_DEBUG("Peer HIT did not match, ignoring\n");
		goto out_err;
	}

	HIP_DEBUG("Sending close to peer\n");

	HIP_IFE(!(close = hip_msg_alloc()), -ENOMEM);

	mask = hip_create_control_flags(0, 0, HIP_CONTROL_SHT_TYPE1,
					HIP_CONTROL_DHT_TYPE1);
	entry->hadb_misc_func->hip_build_network_hdr(close, HIP_CLOSE, mask, &entry->hit_our,
			      &entry->hit_peer);

	/********ECHO (SIGNED) **********/

	get_random_bytes(entry->echo_data, sizeof(entry->echo_data));
	HIP_IFEL(hip_build_param_echo(close, entry->echo_data,
				      sizeof(entry->echo_data), 1, 1), -1,
		 "Failed to build echo param\n");

	/************* HMAC ************/
	HIP_IFEL(hip_build_param_hmac_contents(close,
					       &entry->hip_hmac_out),
		 -1, "Building of HMAC failed\n");

	/********** Signature **********/
	HIP_IFEL(entry->sign(entry->our_priv, close), -EINVAL,
		 "Could not create signature\n");
	
	HIP_IFE(entry->hadb_xmit_func->hip_csum_send(NULL,
						     &entry->preferred_address,
						     close, entry, 0), -1);

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
	HIP_IFEL(hip_verify_packet_hmac(close, &entry->hip_hmac_in),
		 -ENOENT, "HMAC validation on close failed\n");

	/* verify signature */
	HIP_IFEL(entry->verify(entry->peer_pub, close), -EINVAL,
		 "Verification of close signature failed\n");

	HIP_IFE(!(close_ack = hip_msg_alloc()), -ENOMEM);

	HIP_IFEL(!(request =
		   hip_get_param(close, HIP_PARAM_ECHO_REQUEST_SIGN)),
		 -1, "No echo request under signature\n");
	echo_len = hip_get_param_contents_len(request);

	mask = hip_create_control_flags(0, 0, HIP_CONTROL_SHT_TYPE1,
					HIP_CONTROL_DHT_TYPE1);
	entry->hadb_misc_func->hip_build_network_hdr(close_ack, HIP_CLOSE_ACK,
			      mask, &entry->hit_our,
			      &entry->hit_peer);

	HIP_IFEL(hip_build_param_echo(close_ack, request + 1,
				      echo_len, 1, 0), -1,
		 "Failed to build echo param\n");

	/************* HMAC ************/
	HIP_IFEL(hip_build_param_hmac_contents(close_ack,
					       &entry->hip_hmac_out),
		 -1, "Building of HMAC failed\n");

	/********** Signature **********/
	HIP_IFEL(entry->sign(entry->our_priv, close_ack), -EINVAL,
		 "Could not create signature\n");

	HIP_IFE(entry->hadb_xmit_func->hip_csum_send(NULL,
						     &entry->preferred_address,
						     close_ack, entry, 0), -1);

	entry->state = HIP_STATE_CLOSED;

	HIP_DEBUG("CLOSED\n");

	HIP_IFEL(hip_del_peer_info(&entry->hit_peer,
				  &entry->preferred_address), -1,
				   "Deleting peer info failed\n");
	//hip_hadb_remove_state(entry);
	//hip_delete_esp(entry);

	/* by now, if everything is according to plans, the refcnt should
	   be 1 */
	hip_put_ha(entry);

 out_err:

	if (close_ack)
		HIP_FREE(close_ack);

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
	HIP_IFEL(hip_verify_packet_hmac(close_ack, &entry->hip_hmac_in),
		 -ENOENT, "HMAC validation on close ack failed\n");

	/* verify signature */
	HIP_IFEL(entry->verify(entry->peer_pub, close_ack), -EINVAL,
		 "Verification of close ack signature failed\n");

	entry->state = HIP_STATE_CLOSED;

	HIP_DEBUG("CLOSED\n");

	/* Note: I had some problems with deletion of peer info. Try to close
	   a SA and then to re-establish without rmmod or killing
	   the hipd when you test the CLOSE. -miika */

	HIP_IFEL(hip_del_peer_info(&entry->hit_peer,
				   &entry->preferred_address), -1,
		 "Deleting peer info failed\n");

	//hip_hadb_remove_state(entry);
	//hip_delete_esp(entry);

	/* by now, if everything is according to plans, the refcnt should
	   be 1 */
	hip_put_ha(entry);

 out_err:

	return err;
}
