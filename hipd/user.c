/** @file
 * This file defines a user message handling function for the Host Identity
 * Protocol (HIP).
 * 
 * We don't currently have a workqueue. The functionality in this file mostly
 * covers catching userspace messages only.
 *
 * @author  Miika Komu <miika_iki.fi>
 * @author  Kristian Slavov <kslavov_hiit.fi>
 * @author  Bing Zhou <bingzhou_cc.hut.fi>
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl.txt">GNU/GPL</a>.
 */
#include "user.h"

/**
 * Handles a user message.
 *
 * @param  msg  a pointer to the received user message HIP packet.
 * @param  src  
 * @return zero on success, or negative error value on error.
 * @see    hip_so.
 */ 
int hip_handle_user_msg(struct hip_common *msg, 
			const struct sockaddr_un *src) {
	hip_hit_t *hit;
	hip_hit_t *src_hit, *dst_hit;
	struct in6_addr *src_ip, *dst_ip;
	hip_ha_t *entry = NULL;
	int err = 0;
	int msg_type;
	int n = 0;
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
		if(err){
		  HIP_ERROR("add peer mapping failed.\n");
		  goto out_err;
		}
		
		n = hip_sendto(msg, src);
		if(n < 0){
		  HIP_ERROR("hip_sendto() failed.\n");
		  err = -1;
		  goto out_err;
		}
		break;
#if 0
	case SO_HIP_DEL_PEER_MAP_HIT_IP:
		err = hip_del_peer_map(msg);
		break;
#endif
	case SO_HIP_RST:
		err = hip_send_close(msg);
		break;
	case SO_HIP_BOS:
		err = hip_send_bos(msg);
		break;
	case SO_HIP_SET_NAT_ON:
		/* Sets a flag for each host association that the current
		   machine is behind a NAT. */
		HIP_DEBUG("Handling NAT ON user message.\n");
		HIP_IFEL(hip_nat_on(), -1,
			 "Error when setting daemon NAT status to \"on\"\n");
		break;
	case SO_HIP_SET_NAT_OFF:
		/* Removes the NAT flag from each host association. */
		HIP_DEBUG("Handling NAT OFF user message.\n");
		HIP_IFEL(hip_nat_off(), -1,
			 "Error when setting daemon NAT status to \"on\"\n");
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
		dst_hit = hip_get_param_contents(msg, HIP_PARAM_HIT);
		hip_inc_cookie_difficulty(dst_hit);
		break;
	case SO_HIP_CONF_PUZZLE_DEC:
		dst_hit = hip_get_param_contents(msg, HIP_PARAM_HIT);
		hip_dec_cookie_difficulty(dst_hit);
		break;
#ifdef CONFIG_HIP_OPPORTUNISTIC
	case SO_HIP_SET_OPPORTUNISTIC_MODE:
	  	err = hip_set_opportunistic_mode(msg);
		break;
	case SO_HIP_GET_PEER_HIT: // we get try to get real hit instead of phit
	  { 
	    err = hip_get_peer_hit(msg, src);
	    if(err){
	      HIP_ERROR("get pseudo hit failed.\n");
	      goto out_err;
	    }
	    // PHIT = calculate a pseudo hit
	    // hip_hadb_add_peer_info(PHIT, IP) -> SP: INIT_SRC_HIT + RESP_PSEUDO_HIT
	    // hip_hadb_find_byhits(SRC_HIT, PHIT);
	    // if (exists(hashtable(SRC_HIT, DST_PHIT)) { // two consecutive base exchanges
	    //   msg = REAL_DST_HIT
	    //   sendto(src, msg);
	    // } else {
	    //   add_to_hash_table(index=XOR(SRC_HIT, DST_PHIT), value=src);
	    //   hip_send_i1(SRC_HIT, PHIT);
	    // }
	  }
	  break;
	case SO_HIP_QUERY_IP_HIT_MAPPING:
	  {
	    	err = hip_query_ip_hit_mapping(msg);
		if(err){
		  HIP_ERROR("query ip hit mapping failed.\n");
		  goto out_err;
		}
		
		n = hip_sendto(msg, src);
		if(n < 0){
		  HIP_ERROR("hip_sendto() failed.\n");
		  err = -1;
		  goto out_err;
		}
		HIP_DEBUG("mapping result sent\n");
	  }
	  break;	  
	case SO_HIP_QUERY_OPPORTUNISTIC_MODE:
	  {
	    	err = hip_query_opportunistic_mode(msg);
		if(err){
		  HIP_ERROR("query opportunistic mode failed.\n");
		  goto out_err;
		}
		
		n = hip_sendto(msg, src);
		if(n < 0){
		  HIP_ERROR("hip_sendto() failed.\n");
		  err = -1;
		  goto out_err;
		}
		HIP_DEBUG("opportunistic mode value is sent\n");
	  }
	  break;
#endif
#ifdef CONFIG_HIP_ESCROW
/** @todo create kea with own hit (params: server_hit, rules) 
    - send i1 hip_add_peer_map */
	case SO_HIP_ADD_ESCROW:
		HIP_DEBUG("handling escrow user message.\n");
	 	HIP_IFEL(!(dst_hit = hip_get_param_contents(msg,
							    HIP_PARAM_HIT)),
			 -1, "no hit found\n");
		HIP_IFEL(!(dst_ip = hip_get_param_contents(msg,
							   HIP_PARAM_IPV6_ADDR)),
			 -1, "no ip found\n");
		HIP_IFEL(hip_add_peer_map(msg), -1, "add escrow map\n");
		HIP_IFEL(!(entry = hip_hadb_try_to_find_by_peer_hit(dst_hit)),
			 -1, "internal error: no hadb entry found\n");
		
		HIP_KEA *kea;

		HIP_IFEL(hip_for_each_hi(hip_kea_create_base_entry, dst_hit), 0,
	         "for_each_hi err.\n");	
		
		HIP_DEBUG("Added kea base entry.\n");
		//ipv6_addr_copy(&kea->server_hit, dst_hit);
		
		// TODO: how to know later that we want to do registration? with kea state?
		kea = hip_kea_find(&entry->hit_our);
		if (kea) {
			HIP_DEBUG("Found kea base entry.\n");
			kea->keastate = HIP_KEASTATE_REGISTERING;
			hip_keadb_put_entry(kea);
		}
		else {
			HIP_DEBUG("Could not find kea base entry!!!!!!!!!!!\n");
		}
		
		HIP_IFEL(hip_send_i1(&entry->hit_our, dst_hit, entry),
			 -1, "sending i1 failed\n");
	
		break;
		
	case SO_HIP_OFFER_ESCROW:
		HIP_DEBUG("Handling escrow service user message.\n");
		
		HIP_IFE(hip_services_add(HIP_ESCROW_SERVICE), -1);
	
		hip_services_set_active(HIP_ESCROW_SERVICE);
		if (hip_services_is_active(HIP_ESCROW_SERVICE))
			HIP_DEBUG("Escrow service is now active.\n");
		err = hip_recreate_all_precreated_r1_packets();	
		break;

#endif /* CONFIG_HIP_ESCROW */
#ifdef CONFIG_HIP_RVS
		
	case SO_HIP_ADD_RENDEZVOUS:
		/* draft-ietf-hip-registration-02 RVS registration. Responder
		   (of I,RVS,R hierarchy) handles this message. Message
		   indicates that the current machine wants to register to a rvs
		   server. This message is received from hipconf. */
		HIP_DEBUG("Handling ADD RENDEZVOUS user message.\n");
		
		/* Get rvs ip and hit given as commandline parameters to hipconf. */
		HIP_IFEL(!(dst_hit = hip_get_param_contents(
				   msg, HIP_PARAM_HIT)), -1, "no hit found\n");
		HIP_IFEL(!(dst_ip = hip_get_param_contents(
				   msg, HIP_PARAM_IPV6_ADDR)), -1, "no ip found\n");
		/* Add HIT to IP mapping of rvs to hadb. */ 
		HIP_IFEL(hip_add_peer_map(msg), -1, "add rvs map\n");
		/* Fetch the hadb entry just created. */
		HIP_IFEL(!(entry = hip_hadb_try_to_find_by_peer_hit(dst_hit)),
			 -1, "internal error: no hadb entry found\n");
		
		/* Set a rvs request flag. */
		HIP_IFEL(hip_rvs_set_request_flag(&entry->hit_our, dst_hit),
			 -1, "setting of rvs request flag failed\n");

		/* Send a I1 packet to rvs. */
		HIP_IFEL(hip_send_i1(&entry->hit_our, dst_hit, entry),
			 -1, "sending i1 failed\n");
		break;
	
	case SO_HIP_OFFER_RENDEZVOUS:
		/* draft-ietf-hip-registration-02 RVS registration. Rendezvous
		   server handles this message. Message indicates that the
		   current machine is willing to offer rendezvous service. This
		   message is received from hipconf. */
		HIP_DEBUG("Handling OFFER RENDEZVOUS user message.\n");
		
		HIP_IFE(hip_services_add(HIP_RENDEZVOUS_SERVICE), -1);
		hip_services_set_active(HIP_RENDEZVOUS_SERVICE);
		
		if (hip_services_is_active(HIP_RENDEZVOUS_SERVICE)){
			HIP_DEBUG("Rendezvous service is now active.\n");
		}
		
		err = hip_recreate_all_precreated_r1_packets();
		break;
	
#endif
	default:
		HIP_ERROR("Unknown socket option (%d)\n", msg_type);
		err = -ESOCKTNOSUPPORT;
	}

 out_err:
	return err;
}
