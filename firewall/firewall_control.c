/*
 * Copyright (c) 2010-2011 Aalto University and RWTH Aachen University.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

/**
 * @file
 * Firewall communication interface with hipd. Firewall can send messages
 * asynchronously (recommended) or synchronously (not recommended because
 * other messages may intervene).
 *
 * @brief Firewall communication interface with hipd
 */

#define _BSD_SOURCE

#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

#include "lib/core/builder.h"
#include "lib/core/debug.h"
#include "lib/core/ife.h"
#include "lib/core/message.h"
#include "lib/core/protodefs.h"
#include "cache.h"
#include "firewall.h"
#include "user_ipsec_fw_msg.h"
#include "user_ipsec_sadb.h"
#include "firewall_control.h"

#include "modules/signaling/firewall/signaling_hipfw_user_msg.h"

/**
 * Change the state of hadb state cache in the firewall
 *
 * @param msg the message containing hadb cache information
 *
 * @return zero on success, non-zero on error
 */
static int hip_handle_bex_state_update(struct hip_common *msg)
{
    const struct in6_addr       *src_hit = NULL, *dst_hit = NULL;
    const struct hip_tlv_common *param   = NULL;
    int                          err     = 0, msg_type = 0;

    msg_type = hip_get_msg_type(msg);

    /* src_hit */
    param   = hip_get_param(msg, HIP_PARAM_HIT);
    src_hit = hip_get_param_contents_direct(param);
    HIP_DEBUG_HIT("Source HIT: ", src_hit);

    /* dst_hit */
    param   = hip_get_next_param(msg, param);
    dst_hit = hip_get_param_contents_direct(param);
    HIP_DEBUG_HIT("Destination HIT: ", dst_hit);

    /* update bex_state in firewalldb */
    switch (msg_type) {
    case HIP_MSG_FW_BEX_DONE:
        err = hip_firewall_cache_set_bex_state(src_hit, dst_hit,
                                               HIP_STATE_ESTABLISHED);
        break;
    case HIP_MSG_FW_UPDATE_DB:
        err = hip_firewall_cache_set_bex_state(src_hit, dst_hit,
                                               HIP_STATE_NONE);
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
    int                type, err = 0;
    struct hip_common *msg_out = NULL;

    HIP_DEBUG("Handling message from hipd\n");

    type = hip_get_msg_type(msg);

    HIP_DEBUG("of type %d\n", type);

    switch (type) {
    case HIP_MSG_FW_BEX_DONE:
    case HIP_MSG_FW_UPDATE_DB:
        if (hip_lsi_support) {
            hip_handle_bex_state_update(msg);
        }
        break;
    case HIP_MSG_IPSEC_ADD_SA:
        HIP_DEBUG("Received add sa request from hipd\n");
        HIP_IFEL(handle_sa_add_request(msg), -1,
                 "hip userspace sadb add did NOT succeed\n");
        break;
    case HIP_MSG_IPSEC_DELETE_SA:
        HIP_DEBUG("Received delete sa request from hipd\n");
        HIP_IFEL(handle_sa_delete_request(msg), -1,
                 "hip userspace sadb delete did NOT succeed\n");
        break;
    case HIP_MSG_IPSEC_FLUSH_ALL_SA:
        HIP_DEBUG("Received flush all sa request from hipd\n");
        hip_sadb_flush();
        break;
    case HIP_MSG_RESET_FIREWALL_DB:
        hip_firewall_cache_delete_hldb(0);
        break;
    case HIP_MSG_OFFER_FULLRELAY:
        if (!esp_relay) {
            HIP_DEBUG("Enabling ESP relay\n");
            hip_fw_init_esp_relay();
        } else {
            HIP_DEBUG("ESP relay already enabled\n");
        }
        break;
    case HIP_MSG_CANCEL_FULLRELAY:
        HIP_DEBUG("Disabling ESP relay\n");
        hip_fw_uninit_esp_relay();
        break;
    case HIP_MSG_FIREWALL_STATUS:
        msg_out = hip_msg_alloc();
        HIP_IFEL(hip_build_user_hdr(msg_out, HIP_MSG_FIREWALL_START, 0), -1,
                 "Couldn't build message to daemon\n");
        HIP_IFEL(hip_send_recv_daemon_info(msg_out, 1, hip_fw_sock), -1,
                 "Couldn't notify daemon of firewall presence\n");
        break;
    case HIP_MSG_SIGNALING_FIRST_CONNECTION_REQUEST:
        signaling_hipfw_handle_first_connection_request(msg);
        break;
    case HIP_MSG_SIGNALING_SECOND_CONNECTION_REQUEST:
        signaling_hipfw_handle_second_connection_request(msg);
        break;
    case HIP_MSG_SIGNALING_CONNECTION_UPDATE_REQUEST:
        signaling_hipfw_handle_connection_update_request(msg);
        break;
    case HIP_MSG_SIGNALING_CONFIRMATION:
        signaling_hipfw_handle_connection_confirmation(msg);
        break;
    default:
        HIP_ERROR("Unhandled message type %d\n", type);
        err = -1;
        break;
    }
out_err:
    free(msg_out);
    return err;
}
