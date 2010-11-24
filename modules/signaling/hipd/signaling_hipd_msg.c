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
#include "signaling_hipd_msg.h"

int update_sent = 0;

/** generic send function used to send the below created messages
 *
 * @param msg   the message to be sent
 * @return      0, if correct, else != 0
 */
static int signaling_hipd_send_to_fw(const struct hip_common *msg)
{
    struct sockaddr_in6 hip_fw_addr;
    struct in6_addr loopback = in6addr_loopback;
    int err                  = 0;

    HIP_ASSERT(msg != NULL);

    // destination is firewall
    hip_fw_addr.sin6_family = AF_INET6;
    hip_fw_addr.sin6_port   = htons(HIP_FIREWALL_PORT);
    ipv6_addr_copy(&hip_fw_addr.sin6_addr, &loopback);

    err = hip_sendto_user(msg, (struct sockaddr *) &hip_fw_addr);
    if (err < 0) {
        HIP_ERROR("Sending message to firewall failed\n");

        err = -1;
        goto out_err;
    } else {
        HIP_DEBUG("Sending message to firewall successful\n");

        // this is needed if we want to use HIP_IFEL
        err = 0;
    }

out_err:
    return err;
}

static int build_first_bex_update_msg(hip_common_t *update_packet_to_send,
                                UNUSED hip_common_t *msg,
                                hip_ha_t *ha)
{
    int err                                     = 0;
    uint16_t mask                               = 0;
    struct signaling_state * sig_state = NULL;
    struct update_state *localstate             = NULL;

    /* Allocate and build message */
    hip_build_network_hdr(update_packet_to_send,
                          HIP_UPDATE,
                          mask,
                          &ha->hit_our,
                          &ha->hit_peer);

    /* Add sequence number */
    HIP_IFEL(!(localstate = (struct update_state *) lmod_get_state_item(ha->hip_modular_state, "update")),
            -1, "Could not get update state for host association.\n");
    localstate->update_id_out++;
    HIP_DEBUG("outgoing UPDATE ID=%u\n", hip_update_get_out_id(localstate));
    HIP_IFEL(hip_build_param_seq(update_packet_to_send, hip_update_get_out_id(localstate)),
            -1, "Building of SEQ parameter failed\n");

    /* Add Appinfo */
    HIP_IFEL(!(sig_state = (struct signaling_state *) lmod_get_state_item(ha->hip_modular_state, "signaling_state")),
            -1, "failed to retrieve state for signaling ports\n");
    HIP_IFEL(signaling_build_param_appinfo(update_packet_to_send, sig_state),
            -1, "Building of APPInfo parameter failed\n");

    /* Add HMAC */
    HIP_IFEL(hip_build_param_hmac_contents(update_packet_to_send, &ha->hip_hmac_out),
            -1, "Building of HMAC failed\n");

    /* Add SIGNATURE */
    HIP_IFEL(ha->sign(ha->our_priv_key, update_packet_to_send),
            -EINVAL, "Could not sign UPDATE. Failing\n");

out_err:
    return err;
}

static int build_second_bex_update_msg(struct hip_packet_context *ctx,
                                       hip_ha_t *ha)
{
    int err                                     = 0;
    uint16_t mask                               = 0;
    struct signaling_state * sig_state = NULL;
    const struct hip_seq *seq                   = NULL;
    const struct signaling_param_appinfo * appinfo = NULL;

    HIP_DEBUG("Creating the SECOND BEX UPDATE packet\n");

    /* Allocate and build message. */
    hip_build_network_hdr(ctx->output_msg,
                          HIP_UPDATE,
                          mask,
                          &ha->hit_our,
                          &ha->hit_peer);

    /* Add ACK paramater */
    seq = hip_get_param(ctx->input_msg, HIP_PARAM_SEQ);
    HIP_IFEL(hip_build_param_ack(ctx->output_msg, ntohl(seq->update_id)),
             -1, "Building of ACK parameter failed\n");

    /* Set new ports
     * TODO: Fix this, hack! */
    HIP_IFEL(!(sig_state = (struct signaling_state *) lmod_get_state_item(ha->hip_modular_state, "signaling_state")),
                 -1, "failed to retrieve state for signaling\n");
    appinfo = hip_get_param(ctx->input_msg, HIP_PARAM_SIGNALING_APPINFO);
    sig_state->connection.src_port = ntohs(appinfo->dest_port);
    sig_state->connection.dest_port = ntohs(appinfo->src_port);

    // Add Appinfo
    signaling_build_param_appinfo(ctx->output_msg, sig_state);

    // Add HMAC
    HIP_IFEL(hip_build_param_hmac_contents(ctx->output_msg,
                                           &ha->hip_hmac_out), -1, "Building of HMAC failed\n");

    // Add SIGNATURE
    HIP_IFEL(ha->sign(ha->our_priv_key, ctx->output_msg), -EINVAL,
             "Could not sign UPDATE 2. Failing\n");

out_err:
    return err;
}

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

static int signaling_trigger_second_bex_update(struct hip_packet_context * ctx) {
    int err = 0;
    const hip_hit_t * our_hit = NULL;
    const hip_hit_t * peer_hit = NULL;
    hip_ha_t *ha = NULL;

    /* Get hits */
    our_hit = &ctx->input_msg->hits;
    peer_hit = &ctx->input_msg->hitr;

    /* Get the host association */
    HIP_IFEL(!(ha = hip_hadb_find_byhits(our_hit, peer_hit)),
                 -1, "Failed to retrieve hadb entry.\n");

    /* Build the update message */
    HIP_IFEL(!(ctx->output_msg = hip_msg_alloc()),
             -ENOMEM, "Allocation of update bex failed\n");
    HIP_IFEL(build_second_bex_update_msg(ctx, ha),
            -1, "Failed to build second BEX update.\n");

    /* Send the update bex message */
    err = hip_send_pkt(NULL,
                       &ha->peer_addr,
                       (ha->nat_mode ? hip_get_local_nat_udp_port() : 0),
                       ha->peer_udp_port,
                       ctx->output_msg,
                       ha,
                       1);

out_err:
    return err;
}

/*
 * Do a BEX_UPDATE.
 */
int signaling_trigger_first_bex_update(struct hip_common *msg, UNUSED struct sockaddr_in6 *src) {
    int err = 0;
    hip_ha_t *ha = NULL;
    hip_common_t * update_packet_to_send = NULL;
    const hip_tlv_common_t * param = NULL;
    const hip_hit_t * our_hit = NULL;
    const hip_hit_t * peer_hit = NULL;
    struct signaling_state *sig_state = NULL;

    HIP_DEBUG("Received request to trigger a update BEX. \n");

    /* TODO: implement retransmit handling */
    if(update_sent) {
        HIP_DEBUG("Update already on its way... waiting... \n");
        goto out_err;
    }

    /* Get the corresponding host association */
    param = hip_get_param(msg, HIP_PARAM_HIT);
    if (param && hip_get_param_type(param) == HIP_PARAM_HIT) {
        peer_hit = hip_get_param_contents_direct(param);
        if (ipv6_addr_is_null(peer_hit)) {
            peer_hit = NULL;
        } else {
            HIP_DEBUG_HIT("got dest hit:", peer_hit);
        }
    }
    param = hip_get_next_param(msg, param);
    if (param && hip_get_param_type(param) == HIP_PARAM_HIT) {
        our_hit = hip_get_param_contents_direct(param);
        if (ipv6_addr_is_null(our_hit)) {
            our_hit = NULL;
        } else {
            HIP_DEBUG_HIT("got src hit:", our_hit);
        }
    }
    HIP_IFEL(!(ha = hip_hadb_find_byhits(our_hit, peer_hit)),
                 -1, "Failed to retrieve hadb entry, cannot save port state.\n");

    /* Set new ports ports
     * TODO: fix this hack */
    HIP_IFEL(!(sig_state = (struct signaling_state *) lmod_get_state_item(ha->hip_modular_state, "signaling_state")),
                 -1, "failed to retrieve state for signaling\n");
    param = hip_get_param(msg, HIP_PARAM_SIGNALING_APPINFO);
    sig_state->connection.src_port = ntohs(((const struct signaling_param_appinfo *) param)->src_port);
    sig_state->connection.dest_port = ntohs(((const struct signaling_param_appinfo *) param)->dest_port);

    /* Build the update message */
    HIP_IFEL(!(update_packet_to_send = hip_msg_alloc()), -ENOMEM,
             "Out of memory while allocation memory for the bex update packet\n");
    HIP_IFEL(build_first_bex_update_msg(update_packet_to_send, msg, ha),
            -1, "Failed to build BEX update.\n");


    /* Send the update bex message */
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
 * Tell the firewall to add a scdb entry for the completed BEX or update BEX.
 */
int signaling_send_scdb_add(UNUSED const uint8_t packet_type, UNUSED const uint32_t ha_state, struct hip_packet_context *ctx)
{
    struct hip_common *msg = NULL;
    int err                = 0;
    const struct signaling_param_appinfo *appinfo = NULL;

    /* Get the appinfo parameter */
    HIP_IFEL(!(appinfo = (const struct signaling_param_appinfo *) hip_get_param(ctx->input_msg, HIP_PARAM_SIGNALING_APPINFO)),
            -1, "No application info parameter found in the message.\n");

    /* Build the user message */
    HIP_IFEL(!(msg = malloc(HIP_MAX_PACKET)),
            -1, "alloc memory for adding scdb entry\n");
    hip_msg_init(msg);
    HIP_IFEL(hip_build_user_hdr(msg, HIP_MSG_SIGNALING_CDB_ADD_CONN, 0), -1,
              "build hdr failed\n");

     /* Include Hits */
    HIP_IFEL(hip_build_param_contents(msg, &ctx->input_msg->hits,
                                       HIP_PARAM_HIT,
                                       sizeof(hip_hit_t)), -1,
              "build param contents (src hit) failed\n");

    HIP_IFEL(hip_build_param_contents(msg, &ctx->input_msg->hitr,
                                       HIP_PARAM_HIT,
                                       sizeof(hip_hit_t)), -1,
              "build param contents (src hit) failed\n");

    /* Include appinfo parameter (copy it...) */
    hip_build_param(msg, appinfo);

    /* Send */
    HIP_IFEL(signaling_hipd_send_to_fw(msg), -1, "failed to send add scdb-msg to fw\n");

out_err:
    return err;
}

/*
 * Print all application information included in the packet.
 */
int signaling_handle_appinfo(UNUSED const uint8_t packet_type, UNUSED const uint32_t ha_state, struct hip_packet_context *ctx)
{
	int err = -1;
	const struct signaling_param_appinfo *appinfo = NULL;

	/* Get the parameter */
	HIP_IFEL(!(appinfo = (const struct signaling_param_appinfo *) hip_get_param(ctx->input_msg, HIP_PARAM_SIGNALING_APPINFO)),
	        -1, "No application info parameter found in the message.\n");

	/* Print out contents */
	signaling_param_appinfo_print(appinfo);

out_err:
	return err;
}

/*
 * Handle a BEX update
 */
int signaling_handle_bex_update(UNUSED const uint8_t packet_type, UNUSED const uint32_t ha_state, struct hip_packet_context *ctx)
{
    int err = 0;

    if(signaling_get_update_type(ctx->input_msg) == SIGNALING_FIRST_BEX_UPDATE) {
        HIP_DEBUG("Received FIRST BEX Update... \n");
        HIP_IFEL(signaling_trigger_second_bex_update(ctx),
                -1, "failed to process second bex update. \n");
        HIP_IFEL(signaling_send_scdb_add(packet_type, ha_state, ctx),
                -1, "failed to notify fw to update scdb\n");
    } else if (signaling_get_update_type(ctx->input_msg) == SIGNALING_SECOND_BEX_UPDATE) {
        HIP_DEBUG("Received SECOND BEX Update... \n");
        update_sent = 0;
        HIP_IFEL(signaling_send_scdb_add(packet_type, ha_state, ctx),
                -1, "failed to notify fw to update scdb\n");
    }

out_err:
    return err;
}


int signaling_i2_add_appinfo(UNUSED const uint8_t packet_type, UNUSED const uint32_t ha_state, struct hip_packet_context *ctx)
{
	int err = 0;
    hip_ha_t *entry = NULL;
    struct signaling_state *sig_state;

    /* Get the global state */
    HIP_IFEL(!(entry = hip_hadb_find_byhits(&ctx->output_msg->hits, &ctx->output_msg->hitr)),
                 -1, "Failed to retrieve hadb entry.\n");
    HIP_IFEL(!(sig_state = lmod_get_state_item(entry->hip_modular_state, "signaling_state")),
                 -1, "failed to retrieve state for signaling\n");
    // HIP_DEBUG("Got state from HADB: ports src: %d dest %d \n", sig_state->connection.src_port, sig_state->connection.dest_port);

    HIP_IFEL(signaling_build_param_appinfo(ctx->output_msg, sig_state),
            -1, "Building of param appinfo for I2 failed.\n");
    HIP_DEBUG("Successfully included param appinfo into I2 Packet.\n");

out_err:
	return err;
}

int signaling_r2_add_appinfo(UNUSED const uint8_t packet_type, UNUSED const uint32_t ha_state, struct hip_packet_context *ctx)
{
	int err = 0;
	const struct signaling_param_appinfo *param;
	uint16_t src_port = 0, dest_port = 0;
    hip_ha_t *entry = NULL;
    struct signaling_state *sig_state;

	/* Port information is included in the I2 (ctx->input_msg). Add it to global state.
	 * Note: This could be done in another function but to do it here saves one lookup in hadb. */

    /* Get the global state */
    HIP_IFEL(!(entry = hip_hadb_find_byhits(&ctx->output_msg->hits, &ctx->output_msg->hitr)),
                 -1, "Failed to retrieve hadb entry.\n");
    HIP_IFEL(!(sig_state = lmod_get_state_item(entry->hip_modular_state, "signaling_state")),
                 -1, "failed to retrieve state for signaling\n");

    /* If we got some state, save the ports and hits to it */
    param = (const struct signaling_param_appinfo *) hip_get_param(ctx->input_msg, HIP_PARAM_SIGNALING_APPINFO);
    if(param && hip_get_param_type(param) == HIP_PARAM_SIGNALING_APPINFO) {
        dest_port = ntohs(((const struct signaling_param_appinfo *) param)->src_port);
        src_port = ntohs(((const struct signaling_param_appinfo *) param)->dest_port);
        sig_state->connection.src_port = src_port;
        sig_state->connection.dest_port = dest_port;
        memcpy(&sig_state->connection.src_hit, &ctx->output_msg->hits, sizeof(hip_hit_t));
        memcpy(&sig_state->connection.dest_hit, &ctx->output_msg->hitr, sizeof(hip_hit_t));
        HIP_DEBUG("Saved connection information for R2.\n");
        HIP_DEBUG_HIT("\tsrc_hit", &sig_state->connection.src_hit);
        HIP_DEBUG_HIT("\tdest_hit", &sig_state->connection.dest_hit);
        HIP_DEBUG("\tsrc port: %d dest port: %d \n", sig_state->connection.src_port, sig_state->connection.dest_port);
    }

    /* Now we can build the param into the R2 packet */
    HIP_IFEL(signaling_build_param_appinfo(ctx->output_msg, sig_state),
            -1, "Building of param appinfo for R2 failed.\n");
    HIP_DEBUG("Successfully included param appinfo into R2 Packet.\n");

out_err:
	return err;
}
