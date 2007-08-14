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
int hip_handle_user_msg(struct hip_common *msg, const struct sockaddr_in6 *src)
{
	hip_hit_t *hit, *src_hit, *dst_hit;
	struct in6_addr *src_ip, *dst_ip;
	struct in6_addr my_src,my_dst;
	hip_ha_t *entry = NULL;
	int err = 0, msg_type, n = 0, len = 0, state=0;
	hip_ha_t * server_entry = NULL;
	HIP_KEA * kea = NULL;
	int send_response = (src ? 1 : 0);

	HIP_DEBUG("handling user msg of family=%d from port=%d\n",
		  src->sin6_family, &src->sin6_port);

	err = hip_check_userspace_msg(msg);
	if (err)
	{
		HIP_ERROR("HIP socket option was invalid\n");
		goto out_err;
	}

	msg_type = hip_get_msg_type(msg);
	switch(msg_type)
	{
	case SO_HIP_ADD_LOCAL_HI:
		err = hip_handle_add_local_hi(msg);
		break;
	case SO_HIP_DEL_LOCAL_HI:
		err = hip_handle_del_local_hi(msg);
		break;
	case SO_HIP_ADD_PEER_MAP_HIT_IP:
		err = hip_add_peer_map(msg);
		if(err)
		{
		  HIP_ERROR("add peer mapping failed.\n");
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
		HIP_IFEL(hip_nat_on(), -1, "Error when setting daemon NAT status to \"on\"\n");
		hip_agent_update_status(HIP_NAT_ON, NULL, 0);
		break;
	case SO_HIP_SET_NAT_OFF:
		/* Removes the NAT flag from each host association. */
		HIP_DEBUG("Handling NAT OFF user message.\n");
		HIP_IFEL(hip_nat_off(), -1, "Error when setting daemon NAT status to \"off\"\n");
		hip_agent_update_status(HIP_NAT_OFF, NULL, 0);
		break;

	case SO_HIP_SET_DEBUG_ALL:
		/* Displays all debugging messages. */
		HIP_DEBUG("Handling DEBUG ALL user message.\n");
		HIP_IFEL(hip_set_logdebug(LOGDEBUG_ALL), -1,
			 "Error when setting daemon DEBUG status to ALL\n");
		break;
	case SO_HIP_SET_DEBUG_MEDIUM:
		/* Removes debugging messages. */
		HIP_DEBUG("Handling DEBUG MEDIUM user message.\n");
		HIP_IFEL(hip_set_logdebug(LOGDEBUG_MEDIUM), -1,
			 "Error when setting daemon DEBUG status to MED\n");
		break;
	case SO_HIP_SET_DEBUG_NONE:
		/* Removes debugging messages. */
		HIP_DEBUG("Handling DEBUG NONE user message.\n");
		HIP_IFEL(hip_set_logdebug(LOGDEBUG_NONE), -1,
			 "Error when setting daemon DEBUG status to NONE\n");
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
	case SO_HIP_GET_PEER_HIT:
		err = hip_opp_get_peer_hit(msg, src);
		if(err){
			HIP_ERROR("get pseudo hit failed.\n");
			send_response = 1;
			if (err == -11) /* immediate fallback, do not pass */
			 	err = 0;
			goto out_err;
		} else {
			send_response = 0;
                }
		/* skip sending of return message; will be sent later in R1 */
		goto out_err;
	  break;
	case SO_HIP_QUERY_IP_HIT_MAPPING:
	  {
	    	err = hip_query_ip_hit_mapping(msg);
		if(err){
		  HIP_ERROR("query ip hit mapping failed.\n");
		  goto out_err;
		}
	  }
	  break;	  
	case SO_HIP_QUERY_OPPORTUNISTIC_MODE:
	  {
	    	err = hip_query_opportunistic_mode(msg);
		if(err){
		  HIP_ERROR("query opportunistic mode failed.\n");
		  goto out_err;
		}
		
		HIP_DEBUG("opportunistic mode value is sent\n");
	  }
	  break;
#endif
#ifdef CONFIG_HIP_BLIND
	case SO_HIP_SET_BLIND_ON:
		HIP_DEBUG("Blind on!!\n");
		HIP_IFEL(hip_set_blind_on(), -1, "hip_set_blind_on failed\n");
		break;
	case SO_HIP_SET_BLIND_OFF:
		HIP_DEBUG("Blind off!!\n");
		HIP_IFEL(hip_set_blind_off(), -1, "hip_set_blind_off failed\n");
		break;
#endif
#ifdef CONFIG_HIP_OPENDHT
	case SO_HIP_DHT_GW:
		{
			char tmp_ip_str[20];
			int tmp_ttl, tmp_port;
			int *pret;
			int ret;
			struct in_addr tmp_v4;
			struct hip_opendht_gw_info *gw_info;
	
			HIP_IFEL(!(gw_info = hip_get_param(msg, HIP_PARAM_OPENDHT_GW_INFO)), -1,
						"no gw struct found\n");
			memset(&tmp_ip_str,'\0',20);
			tmp_ttl = gw_info->ttl;
			tmp_port = htons(gw_info->port);
			
	
			IPV6_TO_IPV4_MAP(&gw_info->addr, &tmp_v4); 
			pret = inet_ntop(AF_INET, &tmp_v4, tmp_ip_str, 20); 
			HIP_DEBUG("Got address %s, port %d, TTL %d from hipconf\n", 
						tmp_ip_str, tmp_port, tmp_ttl);
			ret = resolve_dht_gateway_info (tmp_ip_str, &opendht_serving_gateway);
			if (ret == 0)
			{
				HIP_DEBUG("Serving gateway changed\n");
				hip_opendht_fqdn_sent = 0;
				hip_opendht_hit_sent = 0;
			}
			else
			{
				HIP_ERROR("Error in changing the serving gateway!");
			}
			
		}
		break;
#endif 
#ifdef CONFIG_HIP_OPENDHT
	case SO_HIP_DHT_SERVING_GW:
		{
		/*
		struct in_addr ip_gw;
		struct in6_addr ip_gw_mapped;
		int rett = 0, errr = 0;
		struct sockaddr_in *sa = (struct sockaddr_in*)opendht_serving_gateway.ai_addr;
		rett = inet_pton(AF_INET, inet_ntoa(sa->sin_addr), &ip_gw);
		IPV4_TO_IPV6_MAP(&ip_gw, &ip_gw_mapped);
		errr = hip_build_param_opendht_gw_info(msg, &ip_gw_mapped, 
												opendht_serving_gateway_port,
												opendht_serving_gateway_ttl);
		if (errr)
			{
			HIP_ERROR("Build param hit failed: %s\n", strerror(errr));
			goto out_err;
			}
		errr = hip_build_user_hdr(msg, SO_HIP_DHT_SERVING_GW, 0);
		if (errr)
			{
			HIP_ERROR("Build hdr failed: %s\n", strerror(errr));
			}
		*/
		}
		break;
#endif
#ifdef CONFIG_HIP_ESCROW
	case SO_HIP_ADD_ESCROW:
		HIP_DEBUG("handling escrow user message (add).\n");
	 	HIP_IFEL(!(dst_hit = hip_get_param_contents(msg,
							    HIP_PARAM_HIT)),
			 -1, "no hit found\n");
		HIP_IFEL(!(dst_ip = hip_get_param_contents(msg,
							   HIP_PARAM_IPV6_ADDR)),
			 -1, "no ip found\n");
		HIP_IFEL(hip_add_peer_map(msg), -1, "add escrow map\n");
		HIP_IFEL(hip_for_each_hi(hip_kea_create_base_entry, dst_hit), 0,
	         "for_each_hi err.\n");	
		HIP_DEBUG("Added kea base entry.\n");
		
		HIP_IFEL(hip_for_each_hi(hip_launch_escrow_registration, dst_hit), 0,
	         "for_each_hi err.\n");	
		break;
	
	case SO_HIP_DEL_ESCROW:
		HIP_DEBUG("handling escrow user message (delete).\n");
		HIP_IFEL(!(dst_hit = hip_get_param_contents(msg, HIP_PARAM_HIT)),
				-1, "no hit found\n");
		HIP_IFEL(!(dst_ip = hip_get_param_contents(msg, 
				HIP_PARAM_IPV6_ADDR)), -1, "no ip found\n");
		HIP_IFEL(!(server_entry = hip_hadb_try_to_find_by_peer_hit(dst_hit)), 
				-1, "Could not find server entry");
		HIP_IFEL(!(kea = hip_kea_find(&server_entry->hit_our)), -1, 
			"Could not find kea base entry");
		if (ipv6_addr_cmp(dst_hit, &kea->server_hit) == 0)
		{
			// Cancel registration (REG_REQUEST with zero lifetime)
			HIP_IFEL(hip_for_each_hi(hip_launch_cancel_escrow_registration, dst_hit), 0,
					"for_each_hi err.\n");
			hip_keadb_put_entry(kea);
			HIP_IFEL(hip_for_each_ha(hip_remove_escrow_data, dst_hit), 
					0, "for_each_hi err.\n");	
			HIP_IFEL(hip_kea_remove_base_entries(), 0,
					"Could not remove base entries\n");	
			HIP_DEBUG("Removed kea base entries.\n");	
		}
		/** @todo Not filtering I1, when handling escrow user message! */
		HIP_IFEL(hip_send_i1(&entry->hit_our, dst_hit, entry),
			 -1, "sending i1 failed\n");
		break;
		
	case SO_HIP_OFFER_ESCROW:
		HIP_DEBUG("Handling add escrow service -user message.\n");
		
		HIP_IFEL(hip_services_add(HIP_ESCROW_SERVICE), -1, 
                        "Error while adding service\n");
	
		hip_services_set_active(HIP_ESCROW_SERVICE);
		if (hip_services_is_active(HIP_ESCROW_SERVICE))
			HIP_DEBUG("Escrow service is now active.\n");
		HIP_IFEL(hip_recreate_all_precreated_r1_packets(), -1, 
                        "Failed to recreate R1-packets\n"); 

		if (hip_firewall_is_alive())
		{
				HIP_IFEL(hip_firewall_set_escrow_active(1), -1, 
						"Failed to deliver activation message to firewall\n");
		}
		break;
	
	case SO_HIP_CANCEL_ESCROW:
		HIP_DEBUG("Handling del escrow service -user message.\n");
		if (hip_firewall_is_alive())
		{
			HIP_IFEL(hip_firewall_set_escrow_active(0), -1, 
				"Failed to deliver activation message to firewall\n");
		}
		HIP_IFEL(hip_services_remove(HIP_ESCROW_SERVICE), -1, 
				"Error while removing service\n");
		HIP_IFEL(hip_recreate_all_precreated_r1_packets(), -1, 
				"Failed to recreate R1-packets\n"); 
		
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
		/** @todo Not filtering I1, when handling rvs message! */
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
	case SO_HIP_GET_HITS:
		
		hip_msg_init(msg);
		err = hip_for_each_hi(hip_host_id_entry_to_endpoint, msg);
		break;
	
	case SO_HIP_GET_HA_INFO:
		hip_msg_init(msg);
		hip_build_user_hdr(msg, SO_HIP_GET_HA_INFO, 0);
		err = hip_for_each_ha(hip_handle_get_ha_info, msg);
		break;
	case SO_HIP_DEFAULT_HIT:
		hip_msg_init(msg);
		err =  hip_select_default_hit(&my_src, &my_dst,msg);
		break;
	case SO_HIP_HANDOFF_ACTIVE:
		//hip_msg_init(msg);
		is_active_handover=1;
		//hip_build_user_hdr(msg, SO_HIP_HANDOFF_ACTIVE, 0);
		
		break;

	case SO_HIP_HANDOFF_LAZY:
		//hip_msg_init(msg);
		is_active_handover=0;
		//hip_build_user_hdr(msg,SO_HIP_HANDOFF_LAZY, 0);
		break;

	case SO_HIP_RESTART:
		HIP_DEBUG("Restart message received, restarting HIP daemon now!!!\n");
		hipd_set_flag(HIPD_FLAG_RESTART);
		hip_close(SIGINT);
		break;
	
	default:
		HIP_ERROR("Unknown socket option (%d)\n", msg_type);
		err = -ESOCKTNOSUPPORT;
	}

 out_err:

	if (send_response) {
		if (err)
			hip_set_msg_err(msg, 1);
		/* send a response (assuming that it is written to the msg */
		len = hip_get_msg_total_len(msg);
		n = hip_sendto(msg, src);
	
		if(n != len) {
			HIP_ERROR("hip_sendto() failed.\n");
			err = -1;
		} else {
			HIP_DEBUG("Response sent ok\n");
		
		}
	} else {
		HIP_DEBUG("No response sent\n");
	}

	return err;
}
