/**
 * @file firewall/firewall_control.c
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl.txt">GNU/GPL</a>
 *
 * Firewall communication interface with hipd. Firewall can send messages
 * asynchronously (recommended) or synchronously (not recommended because
 * other messages may intervene).
 *
 * @brief Firewall communication interface with hipd
 *
 * @author Miika Komu <miika@iki.fi>
 */

/* required for s6_addr32 */
#define _BSD_SOURCE

#ifdef HAVE_CONFIG_H
  #include "config.h"
#endif /* HAVE_CONFIG_H */

#include "firewall_control.h"
#include "firewall.h" /* extern int esp_relay */
#include "proxy.h"
#include "cache.h"
#include "user_ipsec_fw_msg.h"
#include "firewalldb.h"
#include "sysopp.h"
#include "sava_api.h"

/**
 * Change the state of hadb state cache in the firewall
 *
 * @param msg the message containing hadb cache information
 *
 * @return zero on success, non-zero on error
 */
static int hip_handle_bex_state_update(struct hip_common *msg)
{
    struct in6_addr *src_hit     = NULL, *dst_hit = NULL;
    struct hip_tlv_common *param = NULL;
    int err                      = 0, msg_type = 0;

    msg_type = hip_get_msg_type(msg);

    /* src_hit */
    param    = (struct hip_tlv_common *) hip_get_param(msg, HIP_PARAM_HIT);
    src_hit  = (struct in6_addr *) hip_get_param_contents_direct(param);
    HIP_DEBUG_HIT("Source HIT: ", src_hit);

    /* dst_hit */
    param    = hip_get_next_param(msg, param);
    dst_hit  = (struct in6_addr *) hip_get_param_contents_direct(param);
    HIP_DEBUG_HIT("Destination HIT: ", dst_hit);

    /* update bex_state in firewalldb */
    switch (msg_type) {
    case SO_HIP_FW_BEX_DONE:
        err = hip_firewall_set_bex_state(src_hit,
                                         dst_hit,
                                         (dst_hit ? 1 : -1));
        break;
    case SO_HIP_FW_UPDATE_DB:
        err = hip_firewall_set_bex_state(src_hit, dst_hit, 0);
        break;
    default:
        break;
    }
    return err;
}

/**
 * distribute a message from hipd to the respective extension handler
 *
 * @param   msg pointer to the received user message
 * @return  0 on success, else -1
 */
int hip_handle_msg(struct hip_common *msg)
{
    int type, err = 0;
    struct hip_common *msg_out = NULL;

    HIP_DEBUG("Handling message from hipd\n");

    type = hip_get_msg_type(msg);

    HIP_DEBUG("of type %d\n", type);

    switch (type) {
    case SO_HIP_FW_I2_DONE:
        hip_fw_update_sava(msg);
        break;
    case SO_HIP_FW_BEX_DONE:
    case SO_HIP_FW_UPDATE_DB:
        if (hip_lsi_support) {
            hip_handle_bex_state_update(msg);
        }
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
        if (!hip_proxy_status) {
            hip_fw_init_proxy();
        }
        hip_proxy_status = 1;
        break;
    case SO_HIP_SET_HIPPROXY_OFF:
        HIP_DEBUG("Received HIP PROXY STATUS: OFF message from hipd\n");
        HIP_DEBUG("Proxy is off\n");
        if (hip_proxy_status) {
            hip_fw_uninit_proxy();
        }
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
        if (!hip_opptcp) {
            hip_fw_init_opptcp();
        }
        hip_opptcp = 1;
        break;
    case SO_HIP_SET_OPPTCP_OFF:
        HIP_DEBUG("Opptcp on\n");
        if (hip_opptcp) {
            hip_fw_uninit_opptcp();
        }
        hip_opptcp = 0;
        break;
    case SO_HIP_GET_PEER_HIT:
        if (hip_proxy_status) {
            err = hip_fw_proxy_set_peer_hit(msg);
        } else if (system_based_opp_mode) {
            err = hip_fw_sys_opp_set_peer_hit(msg);
        }
        break;
    case SO_HIP_TURN_INFO:
        // struct hip_turn_info *turn = hip_get_param_contents(HIP_PARAM_TURN_INFO);
        // save to database
        break;
    case SO_HIP_RESET_FIREWALL_DB:
        hip_firewall_cache_delete_hldb(0);
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
    case SO_HIP_SET_DATAPACKET_MODE_ON:
        HIP_DEBUG("Setting HIP DATA PACKET MODE ON \n ");
        hip_datapacket_mode = 1;
        break;
    case SO_HIP_SET_DATAPACKET_MODE_OFF:
        HIP_DEBUG("Setting HIP DATA PACKET MODE OFF \n ");
        hip_datapacket_mode = 0;
        break;
    case SO_HIP_FW_FLUSH_SYS_OPP_HIP:
        if (system_based_opp_mode) {
            HIP_DEBUG("Flushing system-based opportunistic mode " \
                      "iptables chains\n");
            hip_fw_flush_system_based_opp_chains();
        }
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
    if (msg_out) {
        free(msg_out);
    }
    return err;
}
