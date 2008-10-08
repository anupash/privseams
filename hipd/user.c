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
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 */
#include "user.h"

int hip_sendto_user(const struct hip_common *msg, const struct sockaddr *dst){
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
int hip_handle_user_msg(hip_common_t *msg, struct sockaddr_in6 *src)
{
	hip_hit_t *hit = NULL, *src_hit = NULL, *dst_hit = NULL;
	hip_lsi_t *lsi, *src_lsi = NULL, *dst_lsi = NULL;
	in6_addr_t *src_ip = NULL, *dst_ip = NULL;
	hip_ha_t *entry = NULL, *server_entry = NULL;
	int err = 0, msg_type = 0, n = 0, len = 0, state = 0, reti = 0;
	int access_ok = 0, send_response = 1, is_root = 0, dhterr = 0;
	HIP_KEA * kea = NULL;
	struct hip_tlv_common *param = NULL;
	extern int hip_icmp_interval;
	struct hip_heartbeat * heartbeat;
	char host[NI_MAXHOST];

	HIP_ASSERT(src->sin6_family == AF_INET6); 
	HIP_DEBUG("User message from port %d\n", htons(src->sin6_port));

	err = hip_check_userspace_msg(msg);

	if (err) {
		HIP_ERROR("HIP socket option was invalid.\n");
		goto out_err;
	}

	msg_type = hip_get_msg_type(msg);

	is_root = (ntohs(src->sin6_port) < 1024);
	if (is_root) {
		access_ok = 1;
	} else if (!is_root &&
		   (msg_type >= HIP_SO_ANY_MIN && msg_type <= HIP_SO_ANY_MAX)) {
		access_ok = 1;
	}

	if (!access_ok) {
		HIP_ERROR("The user does not have privilege for this "
			  "operation. The operation is cancelled.\n");
		err = -1;
		goto out_err;

	}

	if (ntohs(src->sin6_port) == HIP_AGENT_PORT) {
		return hip_recv_agent(msg);
	}

	HIP_DEBUG("HIP user message type is: %s.\n",
		  hip_message_type_name(msg_type));

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
//modify by santtu
#if 0
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
#endif
	case SO_HIP_SET_NAT_ICE_UDP:
		HIP_DEBUG("Setting LOCATOR ON, when ice is on\n");
        hip_locator_status = SO_HIP_SET_LOCATOR_ON;
        HIP_DEBUG("hip_locator status =  %d (should be %d)\n",
                  hip_locator_status, SO_HIP_SET_LOCATOR_ON);


	case SO_HIP_SET_NAT_NONE:
	case SO_HIP_SET_NAT_PLAIN_UDP:
		HIP_IFEL(hip_user_nat_mode(msg_type), -1, "Error when setting daemon NAT status to \"on\"\n");
		hip_agent_update_status(msg_type, NULL, 0);

		HIP_DEBUG("Recreate all R1s\n");
		hip_recreate_all_precreated_r1_packets();
		break;
//end modify

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
        case SO_HIP_HEARTBEAT:
		heartbeat = hip_get_param(msg, HIP_PARAM_HEARTBEAT);
		hip_icmp_interval = heartbeat->heartbeat;
		heartbeat_counter = hip_icmp_interval;
		HIP_DEBUG("Received heartbeat interval (%d seconds)\n",hip_icmp_interval);
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
		if (err){
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
        case SO_HIP_CERT_X509V3_SIGN:
                {
                        HIP_DEBUG("Got an request to sign X509v3 cert\n");
                        reti = hip_cert_x509v3_handle_request_to_sign(msg, 
                                                                      hip_local_hostid_db);   
                        HIP_IFEL(reti, -1, "Signing of x509v3 cert returned an error\n");
                        HIP_DEBUG("X509v3 cert signed sending it back to requester\n");   
                } 
                break;
        case SO_HIP_CERT_X509V3_VERIFY:
                {
                        HIP_DEBUG("Got an request to verify X509v3 cert\n");
                        reti = hip_cert_x509v3_handle_request_to_verify(msg);   
                        HIP_IFEL(reti, -1, "Verification of x509v3 cert "
                                 "returned an error\n");
                        HIP_DEBUG("X509v3 verification ended "
                                  "sending it back to requester\n");   
                } 
                break;
        case SO_HIP_TRANSFORM_ORDER:
	{
                extern int hip_transform_order;
                err = 0;
                struct hip_transformation_order *transorder;
                HIP_IFEL(!(transorder = hip_get_param(msg, HIP_PARAM_TRANSFORM_ORDER)), -1,
                         "no transform order struct found (should contain transform order)\n");
                HIP_DEBUG("Transform order received from hipconf: %d\n" ,transorder->transorder);
                hip_transform_order = transorder->transorder;
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
			/* warning: passing argument 2 of 'hip_sendto' from
			   incompatible pointer type. 04.07.2008. */
        		n = hip_sendto_user(msg, &sock_addr);

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
        		/* warning: passing argument 2 of 'hip_sendto' from
			   incompatible pointer type. 04.07.2008. */
        		n = hip_sendto_user(msg, &sock_addr);

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

        		/* warning: passing argument 2 of 'hip_sendto' from
			   incompatible pointer type. 04.07.2008. */
        		n = hip_sendto_user(msg, &sock_addr);

        		HIP_IFEL(n < 0, 0, "sendto() failed on agent socket.\n");

        		if (err == 0)
        		{
        			HIP_DEBUG("SEND HIPPROXY STATUS OK.\n");
        		}
        		//SEND RESPONSE();
        	}
        	break;

#ifdef CONFIG_HIP_ESCROW
	case SO_HIP_OFFER_ESCROW:
		HIP_DEBUG("Handling add escrow service -user message.\n");

		HIP_IFEL(hip_services_add(HIP_SERVICE_ESCROW), -1,
			 "Error while adding service\n");

		hip_set_srv_status(HIP_SERVICE_ESCROW, HIP_SERVICE_ON);

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

		HIP_IFEL(hip_recreate_all_precreated_r1_packets(), -1,
			 "Failed to recreate R1-packets\n");

		break;
#endif /* CONFIG_HIP_ESCROW */
#ifdef CONFIG_HIP_RVS
	case SO_HIP_ADD_DEL_SERVER:
	{
		/* RFC 5203 service registration. The requester, i.e. the client
		   of the server handles this message. Message indicates that
		   the hip daemon wants either to register to a server for
		   additional services or it wants to cancel a registration.
		   Cancellation is identified with a zero lifetime. */
		struct hip_reg_request *reg_req = NULL;
		hip_pending_request_t *pending_req = NULL;
		uint8_t *reg_types = NULL;
		int i = 0, type_count = 0;
		
		_HIP_DEBUG("Handling ADD DEL SERVER user message.\n");

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

		/* Add HIT to IP address mapping of the server to haDB. */
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
			pending_req->created  = time(NULL);

			HIP_DEBUG("Adding pending service request for service %u.\n",
				  reg_types[i]);
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
#ifdef CONFIG_HIP_ESCROW
			case HIP_SERVICE_ESCROW:
				HIP_KEA * kea = NULL;

				/* Set a escrow request flag. Should this be
				   done for every entry? */
				hip_hadb_set_local_controls(
					entry, HIP_HA_CTRL_LOCAL_REQ_ESCROW);
				/* Cancel registration to the escrow service. */
				if(reg_req->lifetime == 0) {
					HIP_IFEL((kea =
						  hip_kea_find(&entry->hit_our))
						 == NULL, -1,
						 "Could not find kea base entry.\n");

					if (ipv6_addr_cmp(dst_hit, &kea->server_hit) == 0) {
						HIP_IFEL(hip_for_each_hi(
								 hip_launch_cancel_escrow_registration,
								 dst_hit), 0,
							 "Error when doing "\
							 "hip_launch_cancel_escrow_registration() "\
							 "for each HI.\n");
						HIP_IFEL(hip_for_each_ha(
								 hip_remove_escrow_data,
								 dst_hit), 0,
							 "Error when doing "\
							 "hip_remove_escrow_data() "\
							 "for each HI.\n");
						HIP_IFEL(hip_kea_remove_base_entries(),
							 0, "Could not remove "\
							 "KEA base entries.\n");
					}
				}
				/* Register to the escrow service. */
				else {
					/* Create a KEA base entry. */
					HIP_IFEL(hip_for_each_hi(
							 hip_kea_create_base_entry,
							 dst_hit), 0,
						 "Error when doing "\
						 "hip_kea_create_base_entry() "\
						 "for each HI.\n");

					HIP_IFEL(hip_for_each_hi(
							 hip_launch_escrow_registration,
							 dst_hit), 0,
						 "Error when doing "\
						 "hip_launch_escrow_registration() "\
						 "for each HI.\n");
				}

				break;
#endif /* CONFIG_HIP_ESCROW */
			default:
				HIP_INFO("Undefined service type (%u) "\
					 "requested in the service "\
					 "request.\n", reg_types[i]);
				/* For testing purposes we allow the user to
				   request services that HIPL does not support.
				*/
				hip_hadb_set_local_controls(
					entry, HIP_HA_CTRL_LOCAL_REQ_UNSUP);
				/*
				  HIP_DEBUG("Deleting pending service request "\
				  "for service %u.\n", reg_types[i]);
				  hip_del_pending_request_by_type(entry,
				  reg_types[i]);
				*/
				break;
			}
		}

		/* Send a I1 packet to the server (registrar). */
		/** @todo When registering to a service or cancelling a service,
		    we should first check the state of the host association that
		    is registering. When it is ESTABLISHED or R2-SENT, we have
		    already successfully carried out a base exchange and we
		    must use an UPDATE packet to carry a REG_REQUEST parameter.
		    When the state is not ESTABLISHED or R2-SENT, we launch a
		    base exchange using an I1 packet. */
		HIP_IFEL(hip_send_i1(&entry->hit_our, dst_hit, entry), -1,
			 "Error on sending I1 packet to the server.\n");
		break;
	}
	case SO_HIP_OFFER_RVS:
		/* draft-ietf-hip-registration-02 RVS registration. Rendezvous
		   server handles this message. Message indicates that the
		   current machine is willing to offer rendezvous service. This
		   message is received from hipconf. */
		HIP_DEBUG("Handling OFFER RENDEZVOUS user message.\n");

		hip_set_srv_status(HIP_SERVICE_RENDEZVOUS, HIP_SERVICE_ON);
		hip_relay_set_status(HIP_RELAY_ON);

		err = hip_recreate_all_precreated_r1_packets();
		break;
#if 0
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
#if 0
		//removed by santtu here
		/*
		 * nat mode is more complex now, we must set nat mode
		 * seperated, not alway assume that if relay is on, nat
		 * is plain UDP mode.
		 * */
		/* Since we are requesting UDP relay, we assume that we are behind
		   a NAT. Therefore we set the NAT status on. This is needed only
		   for the current host association, but since keep-alives are sent
		   currently only if the global NAT status is on, we must call
		   hip_nat_on() (which in turn sets the NAT status on for all host
		   associations). */
		HIP_IFEL(hip_nat_on(), -1, "Error when setting daemon NAT status"\
			 "to \"on\"\n");
		hip_agent_update_status(SO_HIP_SET_NAT_ON, NULL, 0);
		//end remove
#endif
		/* Send a I1 packet to relay. */
		HIP_IFEL(hip_send_i1(&entry->hit_our, dst_hit, entry),
			 -1, "sending i1 failed\n");
		break;
	}
#endif /* 0 */
	case SO_HIP_OFFER_HIPRELAY:
		/* draft-ietf-hip-registration-02 HIPRELAY registration. Relay
		   server handles this message. Message indicates that the
		   current machine is willing to offer relay service. This
		   message is received from hipconf. */
		HIP_DEBUG("Handling OFFER HIPRELAY user message.\n");

		hip_set_srv_status(HIP_SERVICE_RELAY, HIP_SERVICE_ON);
		hip_relay_set_status(HIP_RELAY_ON);

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
#endif /* CONFIG_HIP_RVS */
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
		 * @todo passing argument 1 of 'hip_for_each_ha' from incompatible
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
                //hip_build_user_hdr(msg, HIP_HIPPROXY_LOCAL_ADDRESS, 0);
		n = hip_sendto_user(msg, &sock_addr);
		HIP_IFEL(n < 0, 0, "sendto() failed on fw socket.\n");
		if (err == 0) {
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
	case SO_HIP_RESTART_DUMMY_INTERFACE:
		set_up_device(HIP_HIT_DEV, 0);
		err = set_up_device(HIP_HIT_DEV, 1);
		break;
	case SO_HIP_ESP_PROT_TFM:
		HIP_DUMP_MSG(msg);
		err = esp_prot_set_preferred_transforms(msg);
		break;
	case SO_HIP_BEX_STORE_UPDATE:
		HIP_DUMP_MSG(msg);
		err = anchor_db_update(msg);
		break;
	case SO_HIP_TRIGGER_UPDATE:
		HIP_DUMP_MSG(msg);
		err = esp_prot_handle_trigger_update_msg(msg);
		break;
	case SO_HIP_ANCHOR_CHANGE:
		HIP_DUMP_MSG(msg);
		err = esp_prot_handle_anchor_change_msg(msg);
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
	default:
		HIP_ERROR("Unknown socket option (%d)\n", msg_type);
		err = -ESOCKTNOSUPPORT;
	}

 out_err:

	if (send_response) {
	        HIP_DEBUG("Send response\n");
		if (err)
		        hip_set_msg_err(msg, 1);
		len = hip_get_msg_total_len(msg);
		n = hip_sendto_user(msg, src);
		if(n != len)
			err = -1;
		else
			HIP_DEBUG("Response sent ok\n");
	} else
		HIP_DEBUG("No response sent\n");

	return err;
}
