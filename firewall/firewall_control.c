/*
 * Firewall control
 *
 */

#ifdef HAVE_CONFIG_H
  #include "config.h"
#endif /* HAVE_CONFIG_H */

#include "firewall_control.h"
#include "firewall.h" /* extern int esp_relay */
#include "cache.h"
#include "user_ipsec_fw_msg.h"
#include "firewalldb.h"
#include "sysopp.h"

// TODO move to relay implementation, this file should only distribute msg to extension
static int hip_fw_init_esp_relay(void)
{
	int err = 0;

	esp_relay = 1;
	filter_traffic = 1;

	return err;
}

static void hip_fw_uninit_esp_relay(void)
{

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
	int type, err = 0;
	struct hip_common *msg_out = NULL;

	HIP_DEBUG("Handling message from hipd\n");

	type = hip_get_msg_type(msg);

	HIP_DEBUG("of type %d\n", type);
	
	switch(type) {
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
	case SO_HIP_FIREWALL_STATUS:
		msg_out = hip_msg_alloc();
		HIP_IFEL(hip_build_user_hdr(msg_out, SO_HIP_FIREWALL_START, 0), -1,
				"Couldn't build message to daemon\n");
		HIP_IFEL(hip_send_recv_daemon_info(msg_out, 1, hip_fw_sock), -1,
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
