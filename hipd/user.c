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
 * @author  Tao Wan  <twan_cc.hut.fi>
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl.txt">GNU/GPL</a>.
 */
#include "user.h"
#include "esp_prot_ext.h"
#include "hchain_anchordb.h"

int hip_userspace_ipsec_activate(struct hip_common *msg);
int hip_esp_protection_extension_transform(struct hip_common *msg);

int hip_sendto(const struct hip_common *msg, const struct sockaddr *dst){
        return sendto(hip_user_sock, msg, hip_get_msg_total_len(msg),
                   0, (struct sockaddr *)dst, hip_sockaddr_len(dst));
}

/**
 * Handles a user message.
 *
 * @param  msg  a pointer to the received user message HIP packet.
 * @param  src  
 * @return zero on success, or negative error value on error.
 * @see    hip_so.
 */ 
int hip_handle_user_msg(struct hip_common *msg,
			struct sockaddr_in6 *src)
{
	hip_hit_t *hit = NULL, *src_hit = NULL, *dst_hit = NULL;
	hip_lsi_t *lsi, *src_lsi = NULL, *dst_lsi = NULL;
	in6_addr_t *src_ip = NULL, *dst_ip = NULL;
	hip_ha_t *entry = NULL, *server_entry = NULL;
	int err = 0, msg_type = 0, n = 0, len = 0, state = 0, reti = 0, dhterr = 0;
	int access_ok = 0, send_response = 1, is_root;
	HIP_KEA * kea = NULL;
	struct hip_tlv_common *param = NULL;

	HIP_ASSERT(src->sin6_family == AF_INET6);

	err = hip_check_userspace_msg(msg);
	if (err)
	{
		HIP_ERROR("HIP socket option was invalid\n");
		goto out_err;
	}
	
	msg_type = hip_get_msg_type(msg);
	HIP_DEBUG("Message type %d\n", msg_type);

	HIP_DEBUG("handling user msg of family=%d from port=%d\n",
		  src->sin6_family, ntohs(src->sin6_port));

	is_root = (ntohs(src->sin6_port) < 1024);

	if (is_root)
		access_ok = 1;
	else if (!is_root &&
		 (msg_type >= HIP_SO_ANY_MIN && msg_type <= HIP_SO_ANY_MAX))
		access_ok = 1;

	/* const struct sockaddr_in6 *src */

	if (access_ok)
	{
		HIP_DEBUG("The operation is allowed.\n");
	}		
	else
	{
		HIP_ERROR("The operation isn't allowed.\n", msg_type);
		err = -1;
		goto out_err;
			
	}

	if (ntohs(src->sin6_port) == HIP_AGENT_PORT)
		return hip_recv_agent(msg);
	
	switch(msg_type)
	{
	case SO_HIP_ADD_LOCAL_HI:
		err = hip_handle_add_local_hi(msg);
		break;
	case SO_HIP_DEL_LOCAL_HI:
		err = hip_handle_del_local_hi(msg);
		break;
	case SO_HIP_ADD_PEER_MAP_HIT_IP:	
		HIP_DEBUG("Handling SO_HIP_ADD_PEER_MAP_HIT_IP.\n");
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
		hip_agent_update_status(SO_HIP_SET_NAT_ON, NULL, 0);
		break;
	case SO_HIP_SET_NAT_OFF:
		/* Removes the NAT flag from each host association. */
		HIP_DEBUG("Handling NAT OFF user message.\n");
		HIP_IFEL(hip_nat_off(), -1, "Error when setting daemon NAT status to \"off\"\n");
		hip_agent_update_status(SO_HIP_SET_NAT_OFF, NULL, 0);
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
		_HIP_DEBUG("Handling DEBUG ALL user message.\n");
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
		err = hip_opp_get_peer_hit(msg, src);
	
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
       case SO_HIP_SET_TCPTIMEOUT_ON:
               HIP_DEBUG("Setting TCP TIMEOUT ON\n");
               hip_tcptimeout_status = SO_HIP_SET_TCPTIMEOUT_ON;
               HIP_DEBUG("hip tcp timeout status =  %d (should be %d)\n",
                      hip_tcptimeout_status, SO_HIP_SET_TCPTIMEOUT_ON);
               
               /* paramters setting to do here */
               HIP_IFEL(set_new_tcptimeout_parameters_value(), -1,
                         "set new tcptimeout parameters error\n");
               break;
       
        case SO_HIP_SET_TCPTIMEOUT_OFF:
                HIP_DEBUG("Setting TCP TIMEOUT OFF\n");
                hip_tcptimeout_status = SO_HIP_SET_TCPTIMEOUT_OFF;
                HIP_DEBUG("hip tcp timeout status =  %d (should be %d)\n",
                        hip_tcptimeout_status, SO_HIP_SET_TCPTIMEOUT_OFF);
                
                /* paramters resetting */
                HIP_IFEL(reset_default_tcptimeout_parameters_value(), -1,
                         "reset tcptimeout parameters to be default error\n");

                break;

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
	    	   
		if (hip_opendht_inuse == SO_HIP_DHT_ON) {
  		        errr = hip_build_param_opendht_gw_info(msg, &ip_gw_mapped,
							       opendht_serving_gateway_ttl,
							       opendht_serving_gateway_port);
		} else { /* not in use mark port and ttl to 0 so 'client' knows*/
  		        errr = hip_build_param_opendht_gw_info(msg, &ip_gw_mapped, 0,0);
		}
	    
		if (errr) {
		        HIP_ERROR("Build param hit failed: %s\n", strerror(errr));
			goto out_err;
		}
		errr = hip_build_user_hdr(msg, SO_HIP_DHT_SERVING_GW, 0);
		if (errr){
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
        case SO_HIP_CERT_SPKI_VERIFY:
                {
                        HIP_DEBUG("Got an request to verify SPKI cert\n");
                        reti = hip_cert_spki_verify(msg);   
                        HIP_IFEL(reti, -1, "Verifying SPKI cert returned an error\n");
                        HIP_DEBUG("SPKI cert verified sending it back to requester\n");
                } 
                break;
        case SO_HIP_CERT_SPKI_SIGN:
                {
                        HIP_DEBUG("Got an request to sign SPKI cert sequence\n");
                        reti = hip_cert_spki_sign(msg, hip_local_hostid_db);   
                        HIP_IFEL(reti, -1, "Signing SPKI cert returned an error\n");
                        HIP_DEBUG("SPKI cert signed sending it back to requester\n");   
                } 
                break;
        case SO_HIP_TRANSFORM_ORDER:
	{
                extern int hip_transform_order;
                err = 0;
                struct hip_opendht_set *name_info; 
                HIP_IFEL(!(name_info = hip_get_param(msg, HIP_PARAM_OPENDHT_SET)), -1,
                         "no name struct found (should contain transform order)\n");
                _HIP_DEBUG("Transform order received from hipconf:  %s\n" , name_info->name);
                hip_transform_order = atoi(name_info->name);
                hip_recreate_all_precreated_r1_packets();
	}
	break;
        case SO_HIP_DHT_ON:
        	{
                HIP_DEBUG("Setting DHT ON\n");
                hip_opendht_inuse = SO_HIP_DHT_ON;
                HIP_DEBUG("hip_opendht_inuse =  %d (should be %d)\n", 
                          hip_opendht_inuse, SO_HIP_DHT_ON);
        	}
		
                dhterr = 0;
                dhterr = hip_init_dht();
                if (dhterr < 0) HIP_DEBUG("Initializing DHT returned error\n");
		
            break;
            
        case SO_HIP_DHT_OFF:
        	{
                HIP_DEBUG("Setting DHT OFF\n");
                hip_opendht_inuse = SO_HIP_DHT_OFF;
                HIP_DEBUG("hip_opendht_inuse =  %d (should be %d)\n", 
                          hip_opendht_inuse, SO_HIP_DHT_OFF);
        	}
            break;
                
        case SO_HIP_SET_HIPPROXY_ON:
        	{
        		int n, err;
        		
        		//firewall socket address
        		struct sockaddr_in6 sock_addr;     		
        		bzero(&sock_addr, sizeof(sock_addr));
        		sock_addr.sin6_family = AF_INET6;
        		sock_addr.sin6_port = htons(HIP_FIREWALL_PORT);
        		sock_addr.sin6_addr = in6addr_loopback;
        		
        		HIP_DEBUG("Setting HIP PROXY ON\n");
        		hip_set_hip_proxy_on();
      			hip_build_user_hdr(msg, SO_HIP_SET_HIPPROXY_ON, 0);
        		
        		n = hip_sendto(msg, &sock_addr);
    			
        		HIP_IFEL(n < 0, 0, "sendto() failed on agent socket.\n");

        		if (err == 0)
        		{
        			HIP_DEBUG("SEND HIPPROXY STATUS OK.\n");
        		}
        	}
        	break;
        		
        case SO_HIP_SET_HIPPROXY_OFF:
        	{
        		int n, err;
        		
        		//firewall socket address
        		struct sockaddr_in6 sock_addr;     		
        		bzero(&sock_addr, sizeof(sock_addr));
        		sock_addr.sin6_family = AF_INET6;
        		sock_addr.sin6_port = htons(HIP_FIREWALL_PORT);
        		sock_addr.sin6_addr = in6addr_loopback;
        		
        		HIP_DEBUG("Setting HIP PROXY OFF\n");
        		hip_set_hip_proxy_off();
      			hip_build_user_hdr(msg, SO_HIP_SET_HIPPROXY_OFF, 0);
        		
        		n = hip_sendto(msg, &sock_addr);
    			
        		HIP_IFEL(n < 0, 0, "sendto() failed on agent socket.\n");

        		if (err == 0)
        		{
        			HIP_DEBUG("SEND HIPPROXY STATUS OK.\n");
        		}
        	}
        	break; 
        		
        case SO_HIP_HIPPROXY_STATUS_REQUEST:
        	{
        		int n, err;
        		
        		//firewall socket address
        		struct sockaddr_in6 sock_addr;     		
        		bzero(&sock_addr, sizeof(sock_addr));
        		sock_addr.sin6_family = AF_INET6;
        		sock_addr.sin6_port = htons(HIP_FIREWALL_PORT);
        		sock_addr.sin6_addr = in6addr_loopback;
        		
        		HIP_DEBUG("Received HIPPROXY Status Request from firewall\n");
     		
        		memset(msg, 0, sizeof(struct hip_common));
        		
        		if(hip_get_hip_proxy_status() == 0)
        			hip_build_user_hdr(msg, SO_HIP_SET_HIPPROXY_OFF, 0);
        		
        		if(hip_get_hip_proxy_status() == 1)
        			hip_build_user_hdr(msg, SO_HIP_SET_HIPPROXY_ON, 0);
        		
        		n = hip_sendto(msg, &sock_addr);
 //   			HIP_DEBUG("SENDTO ERRNO: 0x%x\n", errno);
    			
        		HIP_IFEL(n < 0, 0, "sendto() failed on agent socket.\n");

        		if (err == 0)
        		{
        			HIP_DEBUG("SEND HIPPROXY STATUS OK.\n");
        		}
        		//SEND RESPONSE();
        	}
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
		HIP_IFEL(!(dst_ip = hip_get_param_contents(
				   msg, HIP_PARAM_IPV6_ADDR)), -1, "no ip found\n");
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
	
		//hip_services_set_active(HIP_SERVICE_ESCROW);

		hip_set_srv_status(HIP_SERVICE_ESCROW, HIP_SERVICE_ON);

		/*if (hip_services_is_active(HIP_SERVICE_ESCROW))
		  HIP_DEBUG("Escrow service is now active.\n");*/
		HIP_IFEL(hip_recreate_all_precreated_r1_packets(), -1, 
			 "Failed to recreate R1-packets\n"); 
		
		if (hip_firewall_is_alive()) {
			HIP_IFEL(hip_firewall_set_escrow_active(1), -1, 
				 "Failed to deliver activation message to "\
				 "firewall\n");
		}
		
		break;
	
	case SO_HIP_CANCEL_ESCROW:
		HIP_DEBUG("Handling del escrow service -user message.\n");
		if (hip_firewall_is_alive()) {
			HIP_IFEL(hip_firewall_set_escrow_active(0), -1, 
				 "Failed to deliver cancellation message to "\
				 "firewall\n");
		}
		
		hip_set_srv_status(HIP_SERVICE_ESCROW, HIP_SERVICE_OFF);
		
		//HIP_IFEL(hip_services_remove(HIP_ESCROW_SERVICE), -1, 
		// "Error while removing service\n");
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
		
		//HIP_IFE(hip_services_add(HIP_SERVICE_RENDEZVOUS), -1);
		//hip_services_set_active(HIP_SERVICE_RENDEZVOUS);
		
		hip_set_srv_status(HIP_SERVICE_RENDEZVOUS, HIP_SERVICE_ON);
		hip_relay_set_status(HIP_RELAY_ON);

		/*if (hip_services_is_active(HIP_SERVICE_RENDEZVOUS)){
			HIP_DEBUG("Rendezvous service is now active.\n");
			}*/
	     
		err = hip_recreate_all_precreated_r1_packets();
		break;

	case SO_HIP_ADD_RELAY:
	{
		hip_pending_request_t *pending_req = NULL;

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
		
		pending_req = (hip_pending_request_t *)
			malloc(sizeof(hip_pending_request_t));
		if(pending_req == NULL) {
			HIP_ERROR("Error on allocating memory for a "\
				  "pending registration request.\n");
			err = -1;
			goto out_err;	
		}

		pending_req->entry    = entry;
		pending_req->reg_type = HIP_SERVICE_RELAY;
		/* Use a hard coded value for now. */
		pending_req->lifetime = 200;
		
		HIP_DEBUG("Adding pending request.\n");
		hip_add_pending_request(pending_req);

		/* Since we are requesting UDP relay, we assume that we are behind
		   a NAT. Therefore we set the NAT status on. This is needed only
		   for the current host association, but since keep-alives are sent
		   currently only if the global NAT status is on, we must call
		   hip_nat_on() (which in turn sets the NAT status on for all host
		   associations). */
		HIP_IFEL(hip_nat_on(), -1, "Error when setting daemon NAT status"\
			 "to \"on\"\n");
		hip_agent_update_status(SO_HIP_SET_NAT_ON, NULL, 0);

		/* Send a I1 packet to relay. */
		HIP_IFEL(hip_send_i1(&entry->hit_our, dst_hit, entry),
			 -1, "sending i1 failed\n");
		break;
	}    
	case SO_HIP_OFFER_HIPRELAY:
		/* draft-ietf-hip-registration-02 HIPRELAY registration. Relay
		   server handles this message. Message indicates that the
		   current machine is willing to offer relay service. This
		   message is received from hipconf. */
		HIP_DEBUG("Handling OFFER HIPRELAY user message.\n");
		
		//HIP_IFE(hip_services_add(HIP_SERVICE_RELAY), -1);
		//hip_services_set_active(HIP_SERVICE_RELAY);
		
		hip_set_srv_status(HIP_SERVICE_RELAY, HIP_SERVICE_ON);
		hip_relay_set_status(HIP_RELAY_ON);

		/*if (hip_services_is_active(HIP_SERVICE_RELAY)){
		  HIP_DEBUG("UDP relay service for HIP packets"\
		  "is now active.\n");
				  
		  }*/
		
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
		//HIP_IFEL(hip_services_remove(HIP_SERVICE_RENDEZVOUS), -1,
		// "Failed to remove HIP_SERVICE_RENDEZVOUS");
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
		//HIP_IFEL(hip_services_remove(HIP_SERVICE_RELAY), -1,
		// "Failed to remove HIP_SERVICE_RELAY");
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
	case SO_HIP_OPPTCP_UNBLOCK_AND_BLACKLIST:
		hip_opptcp_unblock_and_blacklist(msg, src);
		break;
#if 0
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
	case SO_HIP_OPPTCP_UNBLOCK_APP:
		hip_opptcp_unblock(msg, src);
		break;
	case SO_HIP_OPPTCP_OPPIPDB_ADD_ENTRY:
		hip_opptcp_add_entry(msg, src);
		break;
#endif
	case SO_HIP_OPPTCP_SEND_TCP_PACKET:
		hip_opptcp_send_tcp_packet(msg, src); 
		
		break;
	case SO_HIP_GET_PROXY_LOCAL_ADDRESS:
	{
		//firewall socket address
		struct sockaddr_in6 sock_addr;     		
		bzero(&sock_addr, sizeof(sock_addr));
		sock_addr.sin6_family = AF_INET6;
		sock_addr.sin6_port = htons(HIP_FIREWALL_PORT);
		sock_addr.sin6_addr = in6addr_loopback;		
		HIP_DEBUG("GET HIP PROXY LOCAL ADDRESS\n");
		hip_get_local_addr(msg);
//		hip_build_user_hdr(msg, HIP_HIPPROXY_LOCAL_ADDRESS, 0);
		n = hip_sendto(msg, &sock_addr);		
		HIP_IFEL(n < 0, 0, "sendto() failed on fw socket.\n");
		if (err == 0)
		{
			HIP_DEBUG("SEND HIPPROXY LOCAL ADDRESS OK.\n");
		}
		break;
	}
	case SO_HIP_TRIGGER_BEX:
		HIP_DEBUG("SO_HIP_TRIGGER_BEX\n");
		hip_firewall_status = 1;
		err = hip_netdev_trigger_bex_msg(msg);
		break;
	case SO_HIP_USERSPACE_IPSEC:
		HIP_DUMP_MSG(msg);
		err = hip_userspace_ipsec_activate(msg);
		break;
	case SO_HIP_ESP_PROT_EXT_TRANSFORM:
		HIP_DUMP_MSG(msg);
		err = hip_esp_protection_extension_transform(msg);
		break;	
	case SO_HIP_IPSEC_UPDATE_ANCHOR_LIST:
		HIP_DUMP_MSG(msg);
		err = update_anchor_db(msg);
		break;
	case SO_HIP_IPSEC_NEXT_ANCHOR:
		// TODO implement
		/* hip_send_update(struct hip_hadb_state *entry,
		    struct hip_locator_info_addr_item *addr_list,
		    int addr_count, int ifindex, int flags, 
		    int is_add, struct sockaddr* addr) */
		break;
	case SO_HIP_GET_LSI_PEER:
	case SO_HIP_GET_LSI_OUR:
		while((param = hip_get_next_param(msg, param))){
			if (hip_get_param_type(param) == HIP_PARAM_HIT){
		    		if (!src_hit)
		      			src_hit = (struct in6_addr *)hip_get_param_contents_direct(param);
		    		else 
		      			dst_hit = (struct in6_addr *)hip_get_param_contents_direct(param);
		  	}
	  	}
		if (src_hit && dst_hit){
		        entry = hip_hadb_find_byhits(src_hit, dst_hit);
		        if (entry){
			        lsi = (msg_type == SO_HIP_GET_LSI_PEER) ? &entry->lsi_peer : &entry->lsi_our;
			        /*if(msg_type == SO_HIP_GET_LSI_PEER)
		                        lsi = &aux->lsi_peer;
			        else if(msg_type == SO_HIP_GET_LSI_OUR)
				lsi = &aux->lsi_our;*/
		        }
		}
	        break;
	case SO_HIP_IS_OUR_LSI:
		lsi = (hip_lsi_t *)hip_get_param_contents(msg, SO_HIP_PARAM_LSI);
	  	if (!hip_hidb_exists_lsi(lsi))
	    		lsi = NULL;
	  	break;
	case SO_HIP_GET_STATE_HA:
	case SO_HIP_GET_PEER_HIT_BY_LSIS:
		while((param = hip_get_next_param(msg, param))){
	    		if (hip_get_param_type(param) == SO_HIP_PARAM_LSI){
	      			if (!src_lsi)
					src_lsi = (struct in_addr *)hip_get_param_contents_direct(param);
	      			else 
					dst_lsi = (struct in_addr *)hip_get_param_contents_direct(param);
	    		}
	  	}

	  	entry = hip_hadb_try_to_find_by_pair_lsi(src_lsi, dst_lsi);
          	if (entry && (entry->state == HIP_STATE_ESTABLISHED || 
		    msg_type == SO_HIP_GET_PEER_HIT_BY_LSIS)){
	    		HIP_DEBUG("Entry found in the ha database \n\n");
	      		src_hit = &entry->hit_our;
	      		dst_hit = &entry->hit_peer;
	  	}
	  	break;
	default:
		HIP_ERROR("Unknown socket option (%d)\n", msg_type);
		err = -ESOCKTNOSUPPORT;
	}

 out_err:

	if (send_response) {
	        HIP_DEBUG("Send response\n");
		if (err)
		        hip_set_msg_err(msg, 1);
		else{
		        if ((msg_type == SO_HIP_TRIGGER_BEX && lsi) ||
		            ((msg_type == SO_HIP_GET_STATE_HA || msg_type == SO_HIP_GET_PEER_HIT_BY_LSIS) 
			    && src_hit && dst_hit)){
		                HIP_IFEL(hip_build_param_contents(msg, (void *)src_hit,
					 HIP_PARAM_HIT, sizeof(struct in6_addr)), -1,
				 	 "build param HIP_PARAM_HIT  failed\n");
		    		HIP_IFEL(hip_build_param_contents(msg, (void *)dst_hit,
					 HIP_PARAM_HIT, sizeof(struct in6_addr)), -1,
				 	 "build param HIP_PARAM_HIT  failed\n");
		        }
			if (((msg_type == SO_HIP_GET_LSI_PEER || msg_type == SO_HIP_GET_LSI_OUR) 
			    && lsi) || msg_type == SO_HIP_IS_OUR_LSI)
		                HIP_IFEL(hip_build_param_contents(msg, (void *)lsi,
					 SO_HIP_PARAM_LSI, sizeof(hip_lsi_t)), -1,
				 	 "build param HIP_PARAM_LSI  failed\n");
		}

		len = hip_get_msg_total_len(msg);
		n = hip_sendto(msg, src);
		if(n != len)	
			err = -1;
		else
			HIP_DEBUG("Response sent ok\n");	
	} else
		HIP_DEBUG("No response sent\n");

	return err;
}

// TODO extend to allow switching back to kernel-mode
int hip_userspace_ipsec_activate(struct hip_common *msg)
{
	struct hip_tlv_common *param = NULL;
	int err = 0, activate = 0;
	
	// process message and store anchor elements in the db
	param = (struct hip_tlv_common *)hip_get_param(msg, HIP_PARAM_INT);
	activate = *((int *)hip_get_param_contents_direct(param));
	
	// set global variable
	hip_use_userspace_ipsec = activate;
	HIP_DEBUG("userspace ipsec activate: %i \n", activate);
	
	/* remove the policies from the kernel-mode IPsec, otherwise app-packets
	 * will be captured and processed by the kernel */
	HIP_DEBUG("flushing all ipsec policies...\n");
	default_ipsec_func_set.hip_flush_all_policy();
	HIP_DEBUG("flushing all ipsec SAs...\n");
	default_ipsec_func_set.hip_flush_all_sa();
	
	/* we have to modify the ipsec function pointers to call the ones
	 * located in userspace from now on */
	HIP_DEBUG("re-initializing the hadb...\n");
	hip_uninit_hadb();
	hip_init_hadb();
	
  out_err:
	return err;
}

/** 
 * activates the esp protection extension in the hipd
 * 
 * NOTE: this is called by the hipd when receiving the respective message
 * from the firewall
 **/
// TODO extend to allow switching back to kernel-mode
int hip_esp_protection_extension_transform(struct hip_common *msg)
{
	struct hip_tlv_common *param = NULL;
	int err = 0;
	uint8_t transform = 0;
	extern uint8_t hip_esp_prot_ext_transform;
	
	// process message and store anchor elements in the db
	param = (struct hip_tlv_common *)hip_get_param(msg, HIP_PARAM_UINT);
	transform = *((uint8_t *)hip_get_param_contents_direct(param));
	HIP_DEBUG("esp protection extension transform: %u \n", transform);
	
	// right now we only support the default transform
	if (transform > ESP_PROT_TRANSFORM_UNUSED)
	{
		hip_esp_prot_ext_transform = transform;
		
		HIP_DEBUG("switched to esp protection extension\n");
	}
	else
	{
		hip_esp_prot_ext_transform = ESP_PROT_TRANSFORM_UNUSED;
		
		HIP_DEBUG("switched to normal esp mode\n");
	}
	
	/* we have to make sure that the precalculated R1s include the esp
	 * protection extension transform */
	HIP_DEBUG("recreate all R1s\n");
	HIP_IFEL(hip_recreate_all_precreated_r1_packets(), -1, "failed to recreate all R1s\n");
	
  out_err:
  	return err;
}
