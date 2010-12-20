/**
 * @file
 *
 * Copyright (c) 2010 Aalto University) and RWTH Aachen University.
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
 *
 * @author Henrik Ziegeldorf <henrik.ziegeldorf@rwth-aachen.de>
 *
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <math.h>
#include <stdlib.h>
#include <unistd.h>

#include "lib/core/common.h"
#include "lib/core/debug.h"
#include "lib/core/builder.h"
#include "lib/core/ife.h"
#include "lib/core/prefix.h"
#include "lib/core/icomm.h"
#include "lib/core/hip_udp.h"

#include "hipd/hadb.h"
#include "hipd/user.h"
#include "hipd/output.h"


#include "modules/update/hipd/update.h"
#include "modules/signaling/lib/signaling_common_builder.h"
#include "modules/signaling/lib/signaling_prot_common.h"
#include "modules/signaling/lib/signaling_oslayer.h"
#include "modules/signaling/lib/signaling_user_api.h"
#include "signaling_hipd_state.h"
#include "signaling_hipd_msg.h"
#include "signaling_hipd_user_msg.h"

int update_sent = 0;

int signaling_get_update_type(hip_common_t *msg) {
    int err = 0;
    const hip_tlv_common_t * param = NULL;
    HIP_IFEL(!(param = hip_get_param(msg, HIP_PARAM_SIGNALING_APPINFO)),
            -1, "No appinfo parameter found, no signaling update type.\n");

    if((param = hip_get_param(msg, HIP_PARAM_SEQ))) {
        return SIGNALING_FIRST_BEX_UPDATE;
    }

    if((param = hip_get_param(msg, HIP_PARAM_ACK))) {
            return SIGNALING_SECOND_BEX_UPDATE;
    }

out_err:
    return err;
}

/*
 * Builds a complete update message from scratch.
 * Setting either seq or ack_id to
 *
 */
static hip_common_t *build_update_message(hip_ha_t *ha, int type, struct signaling_connection_context *ctx, uint32_t seq) {
    int err = 0;
    uint16_t mask = 0;
    hip_common_t *msg_buf = NULL;

    /* Allocate and build message */
    HIP_IFEL(!(msg_buf = hip_msg_alloc()),
            -ENOMEM, "Out of memory while allocation memory for the bex update packet\n");
    hip_build_network_hdr(msg_buf, HIP_UPDATE, mask, &ha->hit_our, &ha->hit_peer);

    if(type == SIGNALING_FIRST_BEX_UPDATE) {
        /* Add sequence number */
        HIP_IFEL(hip_build_param_seq(msg_buf, seq),
                -1, "Building of SEQ parameter failed\n");
    } else if (type == SIGNALING_SECOND_BEX_UPDATE) {
        /* Add ACK paramater */
        HIP_IFEL(hip_build_param_ack(msg_buf, seq),
                 -1, "Building of ACK parameter failed\n");
    }


    /* Add Appinfo */
    HIP_IFEL(signaling_build_param_application_context(msg_buf, ctx),
            -1, "Building of APPInfo parameter failed\n");

    /* Add authentication */
    HIP_IFEL(hip_build_param_hmac_contents(msg_buf, &ha->hip_hmac_out),
            -1, "Building of HMAC failed\n");
    HIP_IFEL(ha->sign(ha->our_priv_key, msg_buf),
            -EINVAL, "Could not sign UPDATE. Failing\n");

out_err:
    if(err) {
        return NULL;
    }
    return msg_buf;
}

/*
 * Triggers either first or second bex update message.
 * The decision, which one is sent, can be made from type of trigger_msg,
 * which is either HIP_MSG_SIGNALING_TRIGGER_NEW_CONNECTION or
 * HIP_UPDATE.
 *
 * @param trigger_msg the message, that triggered this update.
 */
int signaling_trigger_bex_update(struct hip_common *trigger_msg) {
    int err = 0;
    hip_ha_t *ha = NULL;
    const hip_hit_t * our_hit = NULL;
    const hip_hit_t * peer_hit = NULL;
    hip_common_t * update_packet_to_send = NULL;
    const struct signaling_param_app_context * appinfo = NULL;
    struct signaling_hipd_state * sig_state = NULL;
    uint32_t seq_id = 0;
    const struct hip_seq * par_seq = NULL;
    const struct hip_tlv_common *param = NULL;
    struct update_state * updatestate = NULL;
    int type = 0;

    HIP_IFEL(!trigger_msg,
            -1, "Trigger MSG must not be NULL\n");

    /* TODO: implement proper retransmit handling */
    if(update_sent) {
        HIP_DEBUG("Update already on its way... waiting... \n");
        goto out_err;
    }

    HIP_IFEL(!(appinfo = hip_get_param(trigger_msg, HIP_PARAM_SIGNALING_APPINFO)),
            -1, "Message contains no portinformation (appinfo parameter). cannot build update.\n");

    /* Set type, hits, seq/ack.
     * We have to distinguish between the two different messages that triggered this update. */
    if(hip_get_msg_type(trigger_msg) == HIP_UPDATE) {
        type = SIGNALING_SECOND_BEX_UPDATE;
        our_hit = &trigger_msg->hits;
        peer_hit = &trigger_msg->hitr;
        HIP_IFEL(!(ha = hip_hadb_find_byhits(our_hit, peer_hit)),
                     -1, "Failed to retrieve hadb entry.\n");
        HIP_IFEL(!(par_seq = hip_get_param(trigger_msg, HIP_PARAM_SEQ)),
                -1, "Message contains no seq parameter.\n");
        seq_id = ntohl(par_seq->update_id);

        // now request applicationcontext from hipfw
        // on success this will put the app context into our state
        HIP_IFEL(!(param = hip_get_param(trigger_msg, HIP_PARAM_SIGNALING_APPINFO)),
                 -1, "Message contains no app info parameter.\n");
        HIP_IFEL(signaling_send_connection_request(our_hit, peer_hit, (const struct signaling_param_app_context *) param),
                 -1, "failed to request/get application context");

    } else if(hip_get_msg_type(trigger_msg) == HIP_MSG_SIGNALING_REQUEST_CONNECTION) {
        HIP_DEBUG("Triggering new update bex for following connection.\n");
        signaling_param_application_context_print(appinfo);
        type = SIGNALING_FIRST_BEX_UPDATE;
        param = hip_get_param(trigger_msg, HIP_PARAM_HIT);
        if (param && hip_get_param_type(param) == HIP_PARAM_HIT) {
            peer_hit = hip_get_param_contents_direct(param);
            if (ipv6_addr_is_null(peer_hit)) {
                peer_hit = NULL;
            }
        }
        param = hip_get_next_param(trigger_msg, param);
        if (param && hip_get_param_type(param) == HIP_PARAM_HIT) {
            our_hit = hip_get_param_contents_direct(param);
            if (ipv6_addr_is_null(our_hit)) {
                our_hit = NULL;
            }
        }
        HIP_IFEL(!(ha = hip_hadb_find_byhits(our_hit, peer_hit)),
                     -1, "Failed to retrieve hadb entry.\n");
        HIP_IFEL(!(updatestate = (struct update_state *) lmod_get_state_item(ha->hip_modular_state, "update")),
                -1, "Could not get update state for host association.\n");
        updatestate->update_id_out++;
        seq_id = hip_update_get_out_id(updatestate);


    } else {
        HIP_DEBUG("Message is not update trigger.\n");
        err = -1;
        goto out_err;
    }

    /* Application lookup from local state*/
    HIP_IFEL(!(sig_state = (struct signaling_hipd_state *) lmod_get_state_item(ha->hip_modular_state, "signaling_hipd_state")),
            -1, "failed to retrieve state for signaling ports\n");

    /* Build and send */
    HIP_IFEL(!(update_packet_to_send = build_update_message(ha, type, &sig_state->ctx, seq_id)),
            -1, "Failed to build update.\n");
    err = hip_send_pkt(NULL,
                       &ha->peer_addr,
                       (ha->nat_mode ? hip_get_local_nat_udp_port() : 0),
                       ha->peer_udp_port,
                       update_packet_to_send,
                       ha,
                       1);

    update_sent = 1;

out_err:
    return err;
}

/*
 * Just a dummy.
 *
 * Here we should do checks with local policies about the application information we're given,
 * e.g. accept that application or not.
 */
int signaling_check_appinfo(UNUSED const uint8_t packet_type, UNUSED const uint32_t ha_state, UNUSED struct hip_packet_context *ctx) {
    return 0;
}

/*
 * Just a dummy.
 *
 * Here we should do checks with local policies about the user information we're given,
 * e.g. accept that user or not.
 */
int signaling_check_userinfo(UNUSED const uint8_t packet_type, UNUSED const uint32_t ha_state, UNUSED struct hip_packet_context *ctx) {
    int err = 0;
    const struct signaling_param_user_context *userinfo = NULL;

    HIP_IFEL(!(userinfo = (const struct signaling_param_user_context *) hip_get_param(ctx->input_msg, HIP_PARAM_SIGNALING_USERINFO)),
            -1, "No application info parameter found in the message.\n");

    signaling_param_user_context_print(userinfo);

out_err:
    return err;
}

/*
 * Process application information in an I2 packet.
 * We have to send a request to the firewall for the connection with this context,
 * and expect our own connection context from the hipfw to send it in the R2.
 *
 */
int signaling_handle_i2_app_context(UNUSED const uint8_t packet_type, UNUSED const uint32_t ha_state, struct hip_packet_context *ctx)
{
	int err = -1;
	const struct signaling_param_app_context *appinfo = NULL;

	HIP_IFEL(!(appinfo = (const struct signaling_param_app_context *) hip_get_param(ctx->input_msg, HIP_PARAM_SIGNALING_APPINFO)),
	        -1, "No application info parameter found in the message.\n");

	signaling_param_application_context_print(appinfo);

	signaling_send_connection_request(&ctx->input_msg->hits, &ctx->input_msg->hitr, appinfo);

out_err:
	return err;
}

/*
 * Process application information in an R2 packet.
 * This completes a BEX with application context for which this HIPD process was the initiator.
 * So, we have to confirm the new connection to the hipfw/oslayer.
 *
 */
int signaling_handle_r2_app_context(UNUSED const uint8_t packet_type, UNUSED const uint32_t ha_state, struct hip_packet_context *ctx)
{
    int err = -1;
    const struct signaling_param_app_context *appinfo = NULL;

    HIP_IFEL(!(appinfo = (const struct signaling_param_app_context *) hip_get_param(ctx->input_msg, HIP_PARAM_SIGNALING_APPINFO)),
            -1, "No application info parameter found in the message.\n");

    signaling_param_application_context_print(appinfo);

    signaling_send_connection_confirmation(&ctx->input_msg->hits, &ctx->input_msg->hitr, appinfo);

out_err:
    return err;
}

/*
 * Handle a BEX update
 */
int signaling_handle_bex_update(UNUSED const uint8_t packet_type, UNUSED const uint32_t ha_state, struct hip_packet_context *ctx)
{
    int err = 0;
    const struct signaling_param_app_context * appinfo = NULL;

    HIP_IFEL(!(appinfo = (const struct signaling_param_app_context *) hip_get_param(ctx->input_msg, HIP_PARAM_SIGNALING_APPINFO)),
            -1, "No application info parameter found in the message (should be there..).\n");

    HIP_DEBUG("Received update bex with following appinfo.\n");
    signaling_param_application_context_print(appinfo);

    if(signaling_get_update_type(ctx->input_msg) == SIGNALING_FIRST_BEX_UPDATE) {
        HIP_DEBUG("Received FIRST BEX Update... \n");
        HIP_IFEL(signaling_trigger_bex_update(ctx->input_msg),
                -1, "failed to trigger second bex update. \n");
        HIP_IFEL(signaling_send_connection_confirmation(&ctx->input_msg->hits, &ctx->input_msg->hitr, appinfo),
                -1, "failed to notify fw to update scdb\n");
    } else if (signaling_get_update_type(ctx->input_msg) == SIGNALING_SECOND_BEX_UPDATE) {
        HIP_DEBUG("Received SECOND BEX Update... \n");
        update_sent = 0;
        HIP_IFEL(signaling_send_connection_confirmation(&ctx->input_msg->hits, &ctx->input_msg->hitr, appinfo),
                -1, "failed to notify fw to update scdb\n");
    }

out_err:
    return err;
}

int signaling_i2_add_user_sig(UNUSED const uint8_t packet_type, UNUSED const uint32_t ha_state, struct hip_packet_context *ctx)
{
    int err = 0;
    hip_ha_t *entry = NULL;
    unsigned char sig_buf[1000];
    int sig_len = 10;
    struct signaling_hipd_state *sig_state;

    /* Get the global state */
    HIP_IFEL(!(entry = hip_hadb_find_byhits(&ctx->output_msg->hits, &ctx->output_msg->hitr)),
                 -1, "Failed to retrieve hadb entry.\n");
    HIP_IFEL(!(sig_state = lmod_get_state_item(entry->hip_modular_state, "signaling_hipd_state")),
                 -1, "failed to retrieve state for signaling\n");

    HIP_IFEL(signaling_user_api_get_uname(sig_state->ctx.user_ctx.euid, &sig_state->ctx.user_ctx),
             -1, "Could not get user name \n");
    sig_len = signaling_user_api_get_signature(sig_state->ctx.user_ctx.euid,
                                               sig_state->ctx.user_ctx.username,
                                               strlen(sig_state->ctx.user_ctx.username),
                                               sig_buf);

    HIP_IFEL(sig_len < 0,
             -1, "Could not build user signature \n");

    HIP_IFEL(signaling_build_param_user_context(ctx->output_msg, &sig_state->ctx.user_ctx, sig_buf, sig_len),
            -1, "Building of param user_sig for I2 failed.\n");

out_err:
    return err;
}

int signaling_i2_add_appinfo(UNUSED const uint8_t packet_type, UNUSED const uint32_t ha_state, struct hip_packet_context *ctx)
{
	int err = 0;
    hip_ha_t *entry = NULL;
    struct signaling_hipd_state *sig_state;

    /* Get the global state */
    HIP_IFEL(!(entry = hip_hadb_find_byhits(&ctx->output_msg->hits, &ctx->output_msg->hitr)),
                 -1, "Failed to retrieve hadb entry.\n");
    HIP_IFEL(!(sig_state = lmod_get_state_item(entry->hip_modular_state, "signaling_hipd_state")),
                 -1, "failed to retrieve state for signaling\n");
    HIP_IFEL(signaling_build_param_application_context(ctx->output_msg, &sig_state->ctx),
            -1, "Building of param appinfo for I2 failed.\n");
    HIP_DEBUG("Building application context for I2 successful.\n");

out_err:
	return err;
}

int signaling_r2_add_user_sig(UNUSED const uint8_t packet_type, UNUSED const uint32_t ha_state, struct hip_packet_context *ctx)
{
    return signaling_i2_add_user_sig(packet_type, ha_state, ctx);
}

int signaling_r2_add_appinfo(UNUSED const uint8_t packet_type, UNUSED const uint32_t ha_state, struct hip_packet_context *ctx)
{
	int err = 0;
    hip_ha_t *entry                                    = NULL;
    struct signaling_hipd_state *sig_state             = NULL;

	/* Port information is included in the I2 (ctx->input_msg). Add it to global state.
	 * Note: This could be done in another function but to do it here saves one lookup in hadb. */

    /* Get the connection context from the global state */
    HIP_IFEL(!(entry = hip_hadb_find_byhits(&ctx->output_msg->hits, &ctx->output_msg->hitr)),
                 -1, "Failed to retrieve hadb entry.\n");
    HIP_IFEL(!(sig_state = lmod_get_state_item(entry->hip_modular_state, "signaling_hipd_state")),
                 -1, "failed to retrieve state for signaling\n");
    HIP_IFEL(signaling_build_param_application_context(ctx->output_msg, &sig_state->ctx),
            -1, "Building of param appinfo for R2 failed.\n");
    HIP_DEBUG("Building application context for I2 successful.\n");

out_err:
	return err;
}
