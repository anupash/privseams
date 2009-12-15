/*
 * Firewall control
 *
 */

#include "firewall_control.h"
#include "firewall.h" /* extern int esp_relay */
#include "proxy.h"
#include "cache.h"
#include "user_ipsec_fw_msg.h"
#include "firewalldb.h"
#include "sysopp.h"
#include "sava_api.h"

// TODO move to relay implementation, this file should only distribute msg to extension
static int hip_fw_init_esp_relay()
{
	extern int esp_relay;
	extern int filter_traffic;
	int err = 0;

	esp_relay = 1;
	filter_traffic = 1;

	return err;
}

// TODO move to sava implementation, this file should only distribute msg to extension
static void hip_fw_uninit_esp_relay()
{
	extern int esp_relay;

	esp_relay = 0;
}

static int handle_bex_state_update(struct hip_common * msg)
{
	struct in6_addr *src_hit = NULL, *dst_hit = NULL;
	struct hip_tlv_common *param = NULL;
	int err = 0, msg_type = 0;

	msg_type = hip_get_msg_type(msg);

	/* src_hit */
        param = (struct hip_tlv_common *)hip_get_param(msg, HIP_PARAM_HIT);
	src_hit = (struct in6_addr *) hip_get_param_contents_direct(param);
	HIP_DEBUG_HIT("Source HIT: ", src_hit);

	/* dst_hit */
	param = hip_get_next_param(msg, param);
	dst_hit = (struct in6_addr *) hip_get_param_contents_direct(param);
	HIP_DEBUG_HIT("Destination HIT: ", dst_hit);

	/* update bex_state in firewalldb */
	switch(msg_type)
	{
	        case SO_HIP_FW_BEX_DONE:
		        err = firewall_set_bex_state(src_hit,
						     dst_hit,
						     (dst_hit ? 1 : -1));
			break;
                case SO_HIP_FW_UPDATE_DB:
		        err = firewall_set_bex_state(src_hit, dst_hit, 0);
			break;
                default:
		        break;
	}
	return err;
}

/** distributes a userspace message to the respective extension by packet type
 *
 * @param	msg pointer to the received user message
 * @param
 * @return	0 on success, else -1
 */
int handle_msg(struct hip_common * msg)
{
	extern int hip_lsi_support;
	extern int system_based_opp_mode;
	extern int hip_proxy_status;
	extern int hip_opptcp;
	extern int hip_fw_sock;
	extern int hip_datapacket_mode;
	int type, err = 0;
	struct hip_common *msg_out = NULL;

	HIP_DEBUG("Handling message from hipd\n");

	type = hip_get_msg_type(msg);

	HIP_DEBUG("of type %d\n", type);
	
	switch(type) {
	case SO_HIP_FW_I2_DONE:
	        hip_fw_update_sava(msg);
		break;
	case SO_HIP_FW_BEX_DONE:
	case SO_HIP_FW_UPDATE_DB:
	        if(hip_lsi_support)
	          handle_bex_state_update(msg);
		break;
	case SO_HIP_IPSEC_ADD_SA:
		HIP_DEBUG("Received add sa request from hipd\n");
		HIP_IFEL(handle_sa_add_request(msg), -1,
				"hip userspace sadb add did NOT succeed\n");
		break;
	case SO_HIP_IPSEC_DELETE_SA:
		HIP_DEBUG("Received delete sa request from hipd\n");
		HIP_IFEL(handle_sa_delete_request(msg), -1,
				"hip userspace sadb delete did NOT succeed\n");
		break;
	case SO_HIP_IPSEC_FLUSH_ALL_SA:
		HIP_DEBUG("Received flush all sa request from hipd\n");
		HIP_IFEL(handle_sa_flush_all_request(msg), -1,
				"hip userspace sadb flush all did NOT succeed\n");
		break;
	case SO_HIP_SET_HIPPROXY_ON:
	        HIP_DEBUG("Received HIP PROXY STATUS: ON message from hipd\n");
	        HIP_DEBUG("Proxy is on\n");
		if (!hip_proxy_status)
			hip_fw_init_proxy();
		hip_proxy_status = 1;
		break;
	case SO_HIP_SET_HIPPROXY_OFF:
		HIP_DEBUG("Received HIP PROXY STATUS: OFF message from hipd\n");
		HIP_DEBUG("Proxy is off\n");
		if (hip_proxy_status)
			hip_fw_uninit_proxy();
		hip_proxy_status = 0;
		break;
	case SO_HIP_SET_SAVAH_CLIENT_ON:
	        HIP_DEBUG("Received HIP_SAVAH_CLIENT_STATUS: ON message from hipd \n");
		hip_fw_init_sava_client();
	        break;
	case SO_HIP_SET_SAVAH_CLIENT_OFF:
	        _HIP_DEBUG("Received HIP_SAVAH_CLIENT_STATUS: OFF message from hipd \n");
		hip_fw_uninit_sava_client();
	        break;
	case SO_HIP_SET_SAVAH_SERVER_OFF:
	        _HIP_DEBUG("Received HIP_SAVAH_SERVER_STATUS: OFF message from hipd \n");
		hip_fw_uninit_sava_router();
	        break;
        case SO_HIP_SET_SAVAH_SERVER_ON: 
	        HIP_DEBUG("Received HIP_SAVAH_SERVER_STATUS: ON message from hipd \n");
		hip_fw_init_sava_router();
	        break;
	case SO_HIP_SET_OPPTCP_ON:
		HIP_DEBUG("Opptcp on\n");
		if (!hip_opptcp)
			hip_fw_init_opptcp();
		hip_opptcp = 1;
		break;
	case SO_HIP_SET_OPPTCP_OFF:
		HIP_DEBUG("Opptcp on\n");
		if (hip_opptcp)
			hip_fw_uninit_opptcp();
		hip_opptcp = 0;
		break;
	case SO_HIP_GET_PEER_HIT:
		if (hip_proxy_status)
			err = hip_fw_proxy_set_peer_hit(msg);
		else if (system_based_opp_mode)
			err = hip_fw_sys_opp_set_peer_hit(msg);
		break;
	case SO_HIP_TURN_INFO:
		// struct hip_turn_info *turn = hip_get_param_contents(HIP_PARAM_TURN_INFO);
		// save to database
		break;
	case SO_HIP_RESET_FIREWALL_DB:
		hip_firewall_cache_delete_hldb();
		hip_firewall_delete_hldb();
		break;
	case SO_HIP_OFFER_FULLRELAY:
		if (!esp_relay) {
			HIP_DEBUG("Enabling ESP relay\n");
			hip_fw_init_esp_relay();
		} else {
			HIP_DEBUG("ESP relay already enabled\n");
		}
		break;
	case SO_HIP_CANCEL_FULLRELAY:
		HIP_DEBUG("Disabling ESP relay\n");
		hip_fw_uninit_esp_relay();
		break;
       //Prabhu enable hip datapacket mode 
        case SO_HIP_SET_DATAPACKET_MODE_ON:
		HIP_DEBUG("Setting HIP DATA PACKET MODE ON \n "); 
		hip_datapacket_mode = 1;
                break;

       //Prabhu enable hip datapacket mode 
        case SO_HIP_SET_DATAPACKET_MODE_OFF:
		HIP_DEBUG("Setting HIP DATA PACKET MODE OFF \n "); 
		hip_datapacket_mode = 0;
                break;

	case SO_HIP_FIREWALL_STATUS:
		msg_out = hip_msg_alloc();
		HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_FIREWALL_START, 0), -1,
				"Couldn't build message to daemon\n");
		HIP_IFEL(hip_send_recv_daemon_info(msg, 1, hip_fw_sock), -1,
				"Couldn't notify daemon of firewall presence\n");
		break;

	default:
		HIP_ERROR("Unhandled message type %d\n", type);
		err = -1;
		break;
	}
 out_err:
	if (msg_out)
		free(msg_out);
	return err;
}

// TODO move to proxy implementation, this file should only distribute msg to extension
#ifdef CONFIG_HIP_HIPPROXY
int request_hipproxy_status(void)
{
        struct hip_common *msg = NULL;
        int err = 0;
        HIP_DEBUG("Sending hipproxy msg to hipd.\n");
        HIP_IFEL(!(msg = HIP_MALLOC(HIP_MAX_PACKET, 0)), -1, "alloc\n");
        hip_msg_init(msg);
        HIP_IFEL(hip_build_user_hdr(msg,
                SO_HIP_HIPPROXY_STATUS_REQUEST, 0),
                -1, "Build hdr failed\n");

        //n = hip_sendto(msg, &hip_firewall_addr);

        //n = sendto(hip_fw_sock, msg, hip_get_msg_total_len(msg),
        //		0,(struct sockaddr *)dst, sizeof(struct sockaddr_in6));

        HIP_IFEL(hip_send_recv_daemon_info(msg, 1, hip_fw_sock), -1,
		 "HIP_HIPPROXY_STATUS_REQUEST: Sendto HIPD failed.\n");
	HIP_DEBUG("HIP_HIPPROXY_STATUS_REQUEST: Sendto hipd ok.\n");

out_err:
	if(msg)
		free(msg);
        return err;
}
#endif /* CONFIG_HIP_HIPPROXY */



