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
static hip_common_t *build_update_message(hip_ha_t *ha, const int type, struct signaling_connection_context *ctx, const uint32_t seq) {
    int err                 = 0;
    uint16_t mask           = 0;
    hip_common_t *msg_buf   = NULL;
    int sig_len             = 0;
    unsigned char sig_buf[1000];


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

    /* Add user auth */
    sig_len = signaling_user_api_get_signature(ctx->user_ctx.euid,
                                               ctx->user_ctx.username,
                                               strlen(ctx->user_ctx.username),
                                               sig_buf);
    if(sig_len < 0) {
        HIP_DEBUG("Could not build user signature \n");
    } else {
        HIP_IFEL(signaling_build_param_user_context(msg_buf, &ctx->user_ctx, sig_buf, sig_len),
                 -1, "Building of param user_sig for I2 failed.\n");
    }

out_err:
    if(err) {
        return NULL;
    }
    return msg_buf;
}

/**
 * Send the first UPDATE message for an application that wants to establish a new connection.
 *
 * @param src_hit   the HIT of the initiator of the update exchange
 * @param dst_hit   the HIT of the responder of the update exchange
 *
 * @return 0 on success, negative on error
 */
int signaling_send_first_update(const struct in6_addr *src_hit, const struct in6_addr *dst_hit) {
    int err                                 = 0;
    uint32_t seq_id                         = 0;
    hip_ha_t *ha                            = NULL;
    struct signaling_hipd_state * sig_state = NULL;
    struct update_state * updatestate       = NULL;
    hip_common_t * update_packet_to_send    = NULL;

    /* sanity tests */
    HIP_IFEL(!src_hit, -1, "No source HIT given \n");
    HIP_IFEL(!dst_hit, -1, "No destination HIT given \n");

    /* Lookup and update state */
    HIP_IFEL(!(ha = hip_hadb_find_byhits(src_hit, dst_hit)),
             -1, "Failed to retrieve hadb entry.\n");
    HIP_IFEL(!(updatestate = (struct update_state *) lmod_get_state_item(ha->hip_modular_state, "update")),
             -1, "Could not get update state for host association.\n");
    HIP_IFEL(!(sig_state = (struct signaling_hipd_state *) lmod_get_state_item(ha->hip_modular_state, "signaling_hipd_state")),
            -1, "failed to retrieve state for signaling ports\n");
    updatestate->update_id_out++;
    seq_id = hip_update_get_out_id(updatestate);

    /* Build and send the first update */
    HIP_IFEL(!(update_packet_to_send = build_update_message(ha, SIGNALING_FIRST_BEX_UPDATE, &sig_state->ctx, seq_id)),
             -1, "Failed to build update.\n");
    err = hip_send_pkt(NULL,
                       &ha->peer_addr,
                       (ha->nat_mode ? hip_get_local_nat_udp_port() : 0),
                       ha->peer_udp_port,
                       update_packet_to_send,
                       ha,
                       1);

out_err:
    return err;
}

/**
 * Send the second UPDATE message for an application that wants to establish a new connection.
 *
 * @param first_update  the update message to which we want to respond
 *
 * @return 0 on success, negative on error
 */
int signaling_send_second_update(const struct hip_common *first_update) {
    int err                                         = 0;
    uint32_t seq_id                                 = 0;
    const struct in6_addr *src_hit                  = NULL;
    const struct in6_addr *dst_hit                  = NULL;
    const struct hip_seq * par_seq                  = NULL;
    hip_ha_t *ha                                    = NULL;
    struct signaling_hipd_state * sig_state         = NULL;
    struct update_state * updatestate               = NULL;
    hip_common_t * update_packet_to_send            = NULL;
    struct signaling_connection_context conn_ctx;


    /* sanity checks */
    HIP_IFEL(!first_update, -1, "Need received update message to build a response \n");

    /* Lookup state */
    src_hit = &first_update->hitr;
    dst_hit = &first_update->hits;
    HIP_IFEL(!(ha = hip_hadb_find_byhits(src_hit, dst_hit)),
                 -1, "Failed to retrieve hadb entry.\n");
    HIP_IFEL(!(sig_state = (struct signaling_hipd_state *) lmod_get_state_item(ha->hip_modular_state, "signaling_hipd_state")),
            -1, "failed to retrieve state for signaling ports\n");
    HIP_IFEL(!(updatestate = (struct update_state *) lmod_get_state_item(ha->hip_modular_state, "update")),
             -1, "Could not get update state for host association.\n");

    /* get the sequence number that we have to acknowledge */
    HIP_IFEL(!(par_seq = hip_get_param(first_update, HIP_PARAM_SEQ)),
            -1, "Message contains no seq parameter.\n");
    seq_id = ntohl(par_seq->update_id);

    /* now request connection context from hipfw
     * on success this will put the local connection context into our local state */
    HIP_IFEL(signaling_init_connection_context_from_msg(&conn_ctx, first_update),
             -1, "Could not init connection context from first update \n");
    signaling_send_connection_context_request(src_hit, dst_hit, &conn_ctx);

    /* Build and send the second update */
    HIP_IFEL(!(update_packet_to_send = build_update_message(ha, SIGNALING_SECOND_BEX_UPDATE, &sig_state->ctx, seq_id)),
             -1, "Failed to build update.\n");
    err = hip_send_pkt(NULL,
                       &ha->peer_addr,
                       (ha->nat_mode ? hip_get_local_nat_udp_port() : 0),
                       ha->peer_udp_port,
                       update_packet_to_send,
                       ha,
                       1);

    /* progress update sequence to currently processed update */
    if (updatestate->update_id_in < seq_id) {
        updatestate->update_id_in = seq_id;
    }

out_err:
    return err;
}

/*
 * Process application information in an I2 packet.
 * We have to send a request to the firewall for the connection with this context,
 * and expect our own connection context from the hipfw to send it in the R2.
 *
 */
static int signaling_handle_i2_app_context(UNUSED const uint8_t packet_type, UNUSED const uint32_t ha_state, struct hip_packet_context *ctx)
{
    int err = 0;
    struct signaling_connection_context conn_ctx;

    HIP_IFEL(signaling_init_connection_context_from_msg(&conn_ctx, ctx->input_msg),
             -1, "Could not init connection context from R2 \n");
    signaling_send_connection_context_request(&ctx->input_msg->hits, &ctx->input_msg->hitr, &conn_ctx);

out_err:
	return err;
}

/*
 * Process application information in an R2 packet.
 * This completes a BEX with application context for which this HIPD process was the initiator.
 * So, we have to confirm the new connection to the hipfw/oslayer.
 *
 */
static int signaling_handle_r2_app_context(UNUSED const uint8_t packet_type, UNUSED const uint32_t ha_state, struct hip_packet_context *ctx)
{
    int err = 0;
    struct signaling_connection_context conn_ctx;

    HIP_IFEL(signaling_init_connection_context_from_msg(&conn_ctx, ctx->input_msg),
             -1, "Could not init connection context from R2 \n");
    conn_ctx.connection_status = SIGNALING_CONN_ALLOWED;
    signaling_send_connection_confirmation(&ctx->input_msg->hits, &ctx->input_msg->hitr, &conn_ctx);

out_err:
    return err;
}

/*
 * Process user context information in an I2 packet.
 */
static int signaling_handle_i2_user_context(UNUSED const uint8_t packet_type, UNUSED const uint32_t ha_state, struct hip_packet_context *ctx)
{
    int err = 0;
    struct signaling_user_context usr_ctx;

    HIP_IFEL(signaling_init_user_context(&usr_ctx), -1, "Could not init user context\n");
    HIP_IFEL(signaling_build_user_context(hip_get_param(ctx->input_msg, HIP_PARAM_SIGNALING_USERINFO), &usr_ctx),
             -1, "Could not build user context from user context parameter\n");
    signaling_user_context_print(&usr_ctx, "", 1);

out_err:
    return err;
}

/*
 * Process user context information in an R2 packet.
 */
static int signaling_handle_r2_user_context(UNUSED const uint8_t packet_type, UNUSED const uint32_t ha_state, struct hip_packet_context *ctx)
{
    return signaling_handle_r2_user_context(packet_type, ha_state, ctx);
}

/*
 * Handles an incomding I2 packet.
 */
int signaling_handle_incoming_i2(const uint8_t packet_type, UNUSED const uint32_t ha_state, struct hip_packet_context *ctx) {
    int err     = 0;

    HIP_IFEL(packet_type != HIP_I2, -1, "Not an I2 Packet\n")
    signaling_handle_i2_user_context(packet_type, ha_state, ctx);
    signaling_handle_i2_app_context(packet_type, ha_state, ctx);

out_err:
    return err;
}

/*
 * Handles an incoming R2 packet.
 */
int signaling_handle_incoming_r2(const uint8_t packet_type, UNUSED const uint32_t ha_state, struct hip_packet_context *ctx) {
    int err     = 0;

    HIP_IFEL(packet_type != HIP_R2, -1, "Not an R2 Packet\n")
    signaling_handle_r2_user_context(packet_type, ha_state, ctx);
    signaling_handle_r2_app_context(packet_type, ha_state, ctx);

out_err:
    return err;
}

/*
 * Handle a BEX update
 */
int signaling_handle_incoming_update(UNUSED const uint8_t packet_type, UNUSED const uint32_t ha_state, struct hip_packet_context *ctx)
{
    int err = 0;
    struct signaling_connection_context conn_ctx;

    HIP_IFEL(signaling_init_connection_context_from_msg(&conn_ctx, ctx->input_msg),
             -1, "Could not init connection context from UPDATE \n");

    if(signaling_get_update_type(ctx->input_msg) == SIGNALING_FIRST_BEX_UPDATE) {
        HIP_DEBUG("Received FIRST BEX Update... \n");
        HIP_IFEL(signaling_send_second_update(ctx->input_msg),
                 -1, "failed to trigger second bex update. \n");
    } else if (signaling_get_update_type(ctx->input_msg) == SIGNALING_SECOND_BEX_UPDATE) {
        HIP_DEBUG("Received SECOND BEX Update... \n");
        conn_ctx.connection_status = SIGNALING_CONN_ALLOWED;
        HIP_IFEL(signaling_send_connection_confirmation(&ctx->input_msg->hits, &ctx->input_msg->hitr, &conn_ctx),
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
