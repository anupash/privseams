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
int hip_handle_user_msg(struct hip_common *msg, const struct sockaddr *originator)
{
	hip_hit_t *hit = NULL, *src_hit = NULL, *dst_hit = NULL;
	in6_addr_t *src_ip = NULL, *dst_ip = NULL;
	hip_ha_t *entry = NULL, *server_entry = NULL;
	int err = 0, msg_type = 0, n = 0, len = 0, state=0;
	HIP_KEA * kea = NULL;
	int send_response = 0;
	union {
		struct sockaddr_in6 in6;
		struct sockaddr_un un;
        } src;
	int root_port = 0;	
	int is_un = 0;

	is_un = ((originator->sa_family == AF_UNIX) ? 1 : 0);

	memcpy(&src.un, originator, hip_sockaddr_len(originator));

	if (!is_un && src.in6.sin6_port < 1024)
		root_port = 1;
	else
		root_port = 0;

	HIP_DEBUG("handling user msg of family=%d from port=%d\n",
		  (is_un ? 0 : src.in6.sin6_family),
		  (is_un ? 0 : src.in6.sin6_port));

	err = hip_check_userspace_msg(msg);

	if (err)
	{
		HIP_ERROR("HIP socket option was invalid\n");
		goto out_err;
	}
	
	msg_type = hip_get_msg_type(msg);
	HIP_DEBUG("Message type %d\n", msg_type);
      
	/* if the src is a AF_UNIX socket and the name is HIP_AGENTADDR_PATH. Then all operations are allowed. but if port < 1024 the root operator is allowed for every operation  otherwise it is non-root and we have to check what is allowed. */

	/* (((struct sockaddr_in6 *)(&msg->msg_name))->sin6_family == AF_UNIX */
	/* /agent/connhipd.c:     strcpy(agent_addr.sun_path, HIP_AGENTADDR_PATH); */
	/* struct sockaddr_un {char sun_path[108]; } */

	if (root_port || ((strcmp(&src.un.sun_path,HIP_AGENTADDR_PATH) == 0) && is_un))
	{
		HIP_DEBUG("The operation is allowed.\n");
	}		
	else
	{
		switch(msg_type)
		{
		case HIP_SO_ANY_MIN:
			break;
		case HIP_SO_ANY_MAX:
			break;
		case SO_HIP_GET_PEER_HIT:
			break;
		case SO_HIP_GET_HA_INFO:
			break;
		case SO_HIP_GET_HITS:
			break;	
		case SO_HIP_GET_PEER_HIT_FROM_FIREWALL:
			break;
		case SO_HIP_ADD_PEER_MAP_HIT_IP:
			break;
		case SO_HIP_DEL_PEER_MAP_HIT_IP:
			break;
		case SO_HIP_SET_MY_EID:
			break;
		case SO_HIP_SET_PEER_EID:
			break;
		case SO_HIP_NULL_OP:
			break;
		case SO_HIP_QUERY_OPPORTUNISTIC_MODE:
			break;
		case SO_HIP_ANSWER_OPPORTUNISTIC_MODE_QUERY:
			break;
		case SO_HIP_SET_PSEUDO_HIT:
			break;
		case SO_HIP_QUERY_IP_HIT_MAPPING:
			break;             
		case SO_HIP_ANSWER_IP_HIT_MAPPING_QUERY:
			break;      
		case SO_HIP_SET_PEER_HIT:
			break;                     
		case SO_HIP_DEFAULT_HIT:
			break;                      
		case SO_HIP_TRIGGER_BEX:
			break;
		default:
			HIP_ERROR("The operation isn't allowed.\n");
			goto out_err;
		}
	}
	
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
        case SO_HIP_SET_LOCATOR_ON:
                HIP_DEBUG("Setting LOCATOR ON\n");
                hip_locator_status = SO_HIP_SET_LOCATOR_ON;
                HIP_DEBUG("hip_locator status =  %d (should be %d)\n", 
                          hip_locator_status, SO_HIP_SET_LOCATOR_ON);
                HIP_DEBUG("Recreate all R1s\n");
                hip_recreate_all_precreated_r1_packets();
                break;
        case SO_HIP_SET_LOCATOR_OFF:
                HIP_DEBUG("Setting LOCATOR OFF\n");
                hip_locator_status = SO_HIP_SET_LOCATOR_OFF;
                HIP_DEBUG("hip_locator status =  %d (should be %d)\n", 
                          hip_locator_status, SO_HIP_SET_LOCATOR_OFF);
                hip_recreate_all_precreated_r1_packets();
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
			 "Error when setting daemon DEBUG status to MEDIUM\n");
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
		err = hip_opp_get_peer_hit(msg, src, 0);
		if(err){
			_HIP_ERROR("get pseudo hit failed.\n");
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
        case SO_HIP_DHT_GW:
	{
		char tmp_ip_str[20];
		int tmp_ttl, tmp_port;
		const char *pret;
		int ret;
		struct in_addr tmp_v4;
		struct hip_opendht_gw_info *gw_info;

		HIP_IFEL(!(gw_info = hip_get_param(msg, HIP_PARAM_OPENDHT_GW_INFO)), -1,
			 "No gw struct found\n");
		memset(&tmp_ip_str,'\0',20);
		tmp_ttl = gw_info->ttl;
		tmp_port = htons(gw_info->port);
           

		IPV6_TO_IPV4_MAP(&gw_info->addr, &tmp_v4); 
		/** 
		 * @todo this gives a compiler warning! warning: assignment from
		 * incompatible pointer type
		 */
		pret = inet_ntop(AF_INET, &tmp_v4, tmp_ip_str, 20); 
		HIP_DEBUG("Got address %s, port %d, TTL %d from hipconf\n", 
			  tmp_ip_str, tmp_port, tmp_ttl);
		ret = resolve_dht_gateway_info (tmp_ip_str, &opendht_serving_gateway);
		if (ret == 0)
		{
			HIP_DEBUG("Serving gateway changed\n");
			hip_opendht_fqdn_sent = 0;
			hip_opendht_hit_sent = 0;
			hip_opendht_error_count = 0;
		}
		else
		{
			HIP_DEBUG("Error in changing the serving gateway!");
		}
	}
	break; 
        case SO_HIP_DHT_SERVING_GW:
	{
		struct in_addr ip_gw;
		struct in6_addr ip_gw_mapped;
		int rett = 0, errr = 0;
		struct sockaddr_in *sa;
		if (opendht_serving_gateway == NULL) {
			opendht_serving_gateway = malloc(sizeof(struct addrinfo));
			memset(opendht_serving_gateway, 0, sizeof(struct addrinfo));
		}
		if (opendht_serving_gateway->ai_addr == NULL) {
			opendht_serving_gateway->ai_addr = malloc(sizeof(struct sockaddr_in));
			memset(opendht_serving_gateway->ai_addr, 0, sizeof(struct sockaddr_in));
		}
		sa = (struct sockaddr_in*)opendht_serving_gateway->ai_addr;
		rett = inet_pton(AF_INET, inet_ntoa(sa->sin_addr), &ip_gw);
		IPV4_TO_IPV6_MAP(&ip_gw, &ip_gw_mapped);
		HIP_DEBUG_HIT("dht gateway address (mapped) to be sent", &ip_gw_mapped);
		memset(msg, 0, HIP_MAX_PACKET);
		HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_DHT_SERVING_GW, 0), -1,
			 "Building of daemon header failed\n");
		_HIP_DUMP_MSG(msg);
		if (hip_opendht_inuse == SO_HIP_DHT_ON) {
			errr = hip_build_param_opendht_gw_info(msg, &ip_gw_mapped, 
							       opendht_serving_gateway_ttl,
							       opendht_serving_gateway_port);
		} else { /* not in use mark port and ttl to 0 */
			errr = hip_build_param_opendht_gw_info(msg, &ip_gw_mapped, 0,0);
		}
		
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
		HIP_DEBUG("Building gw_info complete\n");
	}
	break;

        case SO_HIP_DHT_SET:
	{
                extern char opendht_name_mapping;
                err = 0;
                struct hip_opendht_set *name_info; 
                HIP_IFEL(!(name_info = hip_get_param(msg, HIP_PARAM_OPENDHT_SET)), -1,
                         "no name struct found\n");
                _HIP_DEBUG("Name in name_info %s\n" , name_info->name);
                memcpy(&opendht_name_mapping, &name_info->name, HIP_HOST_ID_HOSTNAME_LEN_MAX);
                HIP_DEBUG("Name received from hipconf %s\n", &opendht_name_mapping);
	}
	break;
        case SO_HIP_TRANSFORM_ORDER:
	{
                extern int hip_transform_order;
                err = 0;
                struct hip_opendht_set *name_info; 
                HIP_IFEL(!(name_info = hip_get_param(msg, HIP_PARAM_OPENDHT_SET)), -1,
                         "no name struct found (should contain transform order\n");
                _HIP_DEBUG("Transform order received from hipconf:  %s\n" , name_info->name);
                hip_transform_order = atoi(name_info->name);
                hip_recreate_all_precreated_r1_packets();
	}
	break;
        case SO_HIP_DHT_ON:
                HIP_DEBUG("Setting DHT ON\n");
                hip_opendht_inuse = SO_HIP_DHT_ON;
                HIP_DEBUG("hip_opendht_inuse =  %d (should be %d)\n", 
                          hip_opendht_inuse, SO_HIP_DHT_ON);
                break;
        case SO_HIP_DHT_OFF:
                HIP_DEBUG("Setting DHT OFF\n");
                hip_opendht_inuse = SO_HIP_DHT_OFF;
                HIP_DEBUG("hip_opendht_inuse =  %d (should be %d)\n", 
                          hip_opendht_inuse, SO_HIP_DHT_OFF);
                break;

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
		
		/* Set a escrow request flag. Should this be done for every entry? */
		hip_hadb_set_local_controls(entry, HIP_HA_CTRL_LOCAL_REQ_ESCROW);

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
		HIP_IFEL(hip_send_i1(&entry->hit_our, dst_hit, server_entry),
			 -1, "sending i1 failed\n");
		break;
		
	case SO_HIP_OFFER_ESCROW:
		HIP_DEBUG("Handling add escrow service -user message.\n");
		
		HIP_IFEL(hip_services_add(HIP_SERVICE_ESCROW), -1, 
			 "Error while adding service\n");
	
		hip_services_set_active(HIP_SERVICE_ESCROW);

		hip_set_srv_status(HIP_SERVICE_ESCROW, HIP_SERVICE_ON);

		if (hip_services_is_active(HIP_SERVICE_ESCROW))
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
		
		hip_set_srv_status(HIP_SERVICE_ESCROW, HIP_SERVICE_OFF);
		
		HIP_IFEL(hip_services_remove(HIP_ESCROW_SERVICE), -1, 
			 "Error while removing service\n");
		HIP_IFEL(hip_recreate_all_precreated_r1_packets(), -1, 
			 "Failed to recreate R1-packets\n"); 
		
		break;
#endif /* CONFIG_HIP_ESCROW */
#ifdef CONFIG_HIP_RVS
	case SO_HIP_ADD_RVS:
	{
		/* draft-ietf-hip-registration-02 RVS registration. Responder
		   (of I,RVS,R hierarchy) handles this message. Message
		   indicates that the current machine wants to register to a rvs
		   server. This message is received from hipconf. */
		HIP_DEBUG("Handling ADD RENDEZVOUS user message.\n");

		struct hip_reg_request *reg_req = NULL;
		hip_pending_request_t *pending_req = NULL;
		uint8_t *reg_types = NULL;
		int i = 0, type_count = 0;
		
		/* Get RVS IP address, HIT and requested lifetime given as
		   commandline parameters to hipconf. */
		
		dst_hit = hip_get_param_contents(msg,HIP_PARAM_HIT);
		dst_ip  = hip_get_param_contents(msg, HIP_PARAM_IPV6_ADDR);
		reg_req = hip_get_param(msg, HIP_PARAM_REG_REQUEST);
				
		if(dst_hit == NULL) {
			HIP_ERROR("No HIT parameter found from the user "\
				  "message.\n");
			err = -1;
			goto out_err;
		}else if(dst_ip == NULL) {
			HIP_ERROR("No IPV6 parameter found from the user "\
				  "message.\n");
			err = -1;
			goto out_err;
		}else if(reg_req == NULL) {
			HIP_ERROR("No REG_REQUEST parameter found from the "\
				  "user message.\n");
			err = -1;
			goto out_err;
		}
		
		/* Add HIT to IP address mapping of RVS to haDB. */ 
		HIP_IFEL(hip_add_peer_map(msg), -1, "Error on adding server "\
			 "HIT to IP address mapping to the haDB.\n");
		
		/* Fetch the haDB entry just created. */
		entry = hip_hadb_try_to_find_by_peer_hit(dst_hit);
		
		if(entry == NULL) {
			HIP_ERROR("Error on fetching server HIT to IP address "\
				  "mapping from the haDB.\n");
			err = -1;
			goto out_err;
		}
		
		reg_types  = reg_req->reg_type;
		type_count = hip_get_param_contents_len(reg_req) -
			sizeof(reg_req->lifetime);
		
		for(;i < type_count; i++) {
			pending_req = (hip_pending_request_t *)
				malloc(sizeof(hip_pending_request_t));
			if(pending_req == NULL) {
				HIP_ERROR("Error on allocating memory for a "\
					  "pending registration request.\n");
				err = -1;
				goto out_err;	
			}

			pending_req->entry    = entry;
			pending_req->reg_type = reg_types[i];
			pending_req->lifetime = reg_req->lifetime;
			
			HIP_DEBUG("Adding pending request.\n");
			hip_add_pending_request(pending_req);

			/* Set the request flag. */
			switch(reg_types[i]){
			case HIP_SERVICE_RENDEZVOUS:
				hip_hadb_set_local_controls(
					entry, HIP_HA_CTRL_LOCAL_REQ_RVS);
				break;
			case HIP_SERVICE_RELAY:
				hip_hadb_set_local_controls(
					entry, HIP_HA_CTRL_LOCAL_REQ_RELAY);
				break;
			case HIP_SERVICE_ESCROW:
				hip_hadb_set_local_controls(
					entry, HIP_HA_CTRL_LOCAL_REQ_ESCROW);
				break;
			default:
				HIP_INFO("Undefined service type requested in "\
					 "the service request.\n");
				break;
			}
		}

		HIP_DEBUG("KING KONG.\n");
		
		/* Set a RVS request flag. */
		//hip_hadb_set_local_controls(entry, HIP_HA_CTRL_LOCAL_REQ_RVS);
		/* Send a I1 packet to RVS. */
		/** @todo Not filtering I1, when handling RVS message! */
		HIP_IFEL(hip_send_i1(&entry->hit_our, dst_hit, entry),
			 -1, "Error on sending I1 packet to the server.\n");
		break;
	}
	case SO_HIP_OFFER_RVS:
		/* draft-ietf-hip-registration-02 RVS registration. Rendezvous
		   server handles this message. Message indicates that the
		   current machine is willing to offer rendezvous service. This
		   message is received from hipconf. */
		HIP_DEBUG("Handling OFFER RENDEZVOUS user message.\n");
		
		HIP_IFE(hip_services_add(HIP_SERVICE_RENDEZVOUS), -1);
		hip_services_set_active(HIP_SERVICE_RENDEZVOUS);
		
		hip_set_srv_status(HIP_SERVICE_RENDEZVOUS, HIP_SERVICE_ON);

		if (hip_services_is_active(HIP_SERVICE_RENDEZVOUS)){
			HIP_DEBUG("Rendezvous service is now active.\n");
			hip_relay_set_status(HIP_RELAY_ON);
		}
	     
		err = hip_recreate_all_precreated_r1_packets();
		break;

	case SO_HIP_ADD_RELAY:
		/* draft-ietf-hip-registration-02 HIPRELAY registration.
		   Responder (of I,Relay,R hierarchy) handles this message. Message
		   indicates that the current machine wants to register to a HIP
		   relay server. This message is received from hipconf. */
		HIP_DEBUG("Handling ADD HIPRELAY user message.\n");
		
		/* Get HIP relay IP address and HIT that were given as commandline
		   parameters to hipconf. */
		HIP_IFEL(!(dst_hit = hip_get_param_contents(msg, HIP_PARAM_HIT)),
			 -1, "Relay server HIT was not found from the message.\n");
		HIP_IFEL(!(dst_ip = hip_get_param_contents(
				   msg, HIP_PARAM_IPV6_ADDR)), -1, "Relay server "\
			 "IP address was not found from the message.\n");
		/* Create a new host association database entry from the message
		   received from the hipconf. This creates a HIT to IP mapping
		   of the relay server. */
		HIP_IFEL(hip_add_peer_map(msg), -1, "Failed to create a new host "
			 "association database entry for the relay server.\n");
		/* Fetch the host association database entry just created. */
		HIP_IFEL(!(entry = hip_hadb_try_to_find_by_peer_hit(dst_hit)),
			 -1, "Unable to find host association database entry "\
			 "matching relay server's HIT.\n");
	     
		/* Set a hiprelay request flag. */
		hip_hadb_set_local_controls(entry, HIP_HA_CTRL_LOCAL_REQ_RELAY);

		/* Since we are requesting UDP relay, we assume that we are behind
		   a NAT. Therefore we set the NAT status on. This is needed only
		   for the current host association, but since keep-alives are sent
		   currently only if the global NAT status is on, we must call
		   hip_nat_on() (which in turn sets the NAT status on for all host
		   associations). */
		HIP_IFEL(hip_nat_on(), -1, "Error when setting daemon NAT status"\
			 "to \"on\"\n");
		hip_agent_update_status(HIP_NAT_ON, NULL, 0);

		/* Send a I1 packet to relay. */
		HIP_IFEL(hip_send_i1(&entry->hit_our, dst_hit, entry),
			 -1, "sending i1 failed\n");
		break;
	     
	case SO_HIP_OFFER_HIPRELAY:
		/* draft-ietf-hip-registration-02 HIPRELAY registration. Relay
		   server handles this message. Message indicates that the
		   current machine is willing to offer relay service. This
		   message is received from hipconf. */
		HIP_DEBUG("Handling OFFER HIPRELAY user message.\n");
		
		HIP_IFE(hip_services_add(HIP_SERVICE_RELAY), -1);
		hip_services_set_active(HIP_SERVICE_RELAY);
		
		hip_set_srv_status(HIP_SERVICE_RELAY, HIP_SERVICE_ON);

		if (hip_services_is_active(HIP_SERVICE_RELAY)){
			HIP_DEBUG("UDP relay service for HIP packets"\
				  "is now active.\n");
			hip_relay_set_status(HIP_RELAY_ON);
		}
		
		err = hip_recreate_all_precreated_r1_packets();
		break;
		
	case SO_HIP_REINIT_RVS:
	case SO_HIP_REINIT_RELAY:
		HIP_DEBUG("Handling REINIT RELAY or REINIT RVS user message.\n");
		HIP_IFEL(hip_relay_reinit(), -1, "Unable to reinitialize "\
			 "the HIP relay / RVS service.\n");
		
		break;
		
	case SO_HIP_CANCEL_RVS:
		HIP_DEBUG("Handling CANCEL RVS user message.\n");
		HIP_IFEL(hip_services_remove(HIP_SERVICE_RENDEZVOUS), -1,
			 "Failed to remove HIP_SERVICE_RENDEZVOUS");
		hip_set_srv_status(HIP_SERVICE_RENDEZVOUS, HIP_SERVICE_OFF);
		
		hip_relht_free_all_of_type(HIP_RVSRELAY);
		/* If all off the relay records were freed we can set the relay
		   status "off". */
		if(hip_relht_size() == 0) {
			hip_relay_set_status(HIP_RELAY_OFF);
		}
		
		/* We have to recreate the R1 packets so that they do not
		   advertise the RVS service anymore. I.e. we're removing
		   the REG_INFO parameters here. */
		err = hip_recreate_all_precreated_r1_packets();
		break;
		
	case SO_HIP_CANCEL_HIPRELAY:
		HIP_DEBUG("Handling CANCEL RELAY user message.\n");
		HIP_IFEL(hip_services_remove(HIP_SERVICE_RELAY), -1,
			 "Failed to remove HIP_SERVICE_RELAY");
		hip_set_srv_status(HIP_SERVICE_RELAY, HIP_SERVICE_OFF);

		hip_relht_free_all_of_type(HIP_FULLRELAY);
		/* If all off the relay records were freed we can set the relay
		   status "off". */
		if(hip_relht_size() == 0) {
			hip_relay_set_status(HIP_RELAY_OFF);
		}
		
		/* We have to recreate the R1 packets so that they do not
		   advertise the RVS service anymore. I.e. we're removing
		   the REG_INFO parameters here. */
		err = hip_recreate_all_precreated_r1_packets();
		break;
#endif
	case SO_HIP_GET_HITS:		
		/** 
		 * @todo passing argument 1 of 'hip_for_each_hi' from incompatible
		 * pointer type
		 */
		hip_msg_init(msg);
		err = hip_for_each_hi(hip_host_id_entry_to_endpoint, msg);
		break;	
	case SO_HIP_GET_HA_INFO:
		hip_msg_init(msg);
		hip_build_user_hdr(msg, SO_HIP_GET_HA_INFO, 0);
		/** 
		 * @todo passing argument 1 of 'hip_for_each_hi' from incompatible
		 * pointer type
		 */
		err = hip_for_each_ha(hip_handle_get_ha_info, msg);
		break;
	case SO_HIP_DEFAULT_HIT:
		hip_msg_init(msg);
		err =  hip_get_default_hit_msg(msg);
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

#ifdef CONFIG_HIP_OPPTCP
	case SO_HIP_GET_PEER_HIT_FROM_FIREWALL:
		err = hip_opp_get_peer_hit(msg, src, 1);
		if(err){
			_HIP_ERROR("get pseudo hit failed.\n");
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
	case SO_HIP_SET_OPPTCP_ON:
		HIP_DEBUG("Setting opptcp on!!\n");
		hip_set_opportunistic_tcp_status(1);
		break;

	case SO_HIP_SET_OPPTCP_OFF:
		HIP_DEBUG("Setting opptcp off!!\n");
		hip_set_opportunistic_tcp_status(0);
		break;

	case SO_HIP_OPPTCP_UNBLOCK_APP:
		hip_opptcp_unblock(msg, src);
		break;

	case SO_HIP_OPPTCP_OPPIPDB_ADD_ENTRY:
		hip_opptcp_add_entry(msg, src);
		break;

	case SO_HIP_OPPTCP_SEND_TCP_PACKET:
		hip_opptcp_send_tcp_packet(msg, src);
		break;

#endif
	case SO_HIP_TRIGGER_BEX:
		dst_hit = hip_get_param_contents(msg, HIP_PARAM_HIT);
		HIP_IFEL(hip_add_peer_map(msg), -1, "trigger bex\n");
		/* Fetch the hadb entry just created. */
		HIP_IFEL(!(entry = hip_hadb_try_to_find_by_peer_hit(dst_hit)),
			 -1, "internal error: no hadb entry found\n");
		HIP_IFEL(hip_send_i1(&entry->hit_our, dst_hit, entry),
			 -1, "sending i1 failed\n");

		goto out_err;
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
