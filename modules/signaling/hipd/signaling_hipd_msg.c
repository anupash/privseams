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

#include "hipd/hadb.h"
#include "hipd/user.h"

#include "modules/signaling/hipd/signaling_hipd_builder.h"
#include "modules/signaling/lib/signaling_prot_common.h"
#include "signaling_hipd_msg.h"

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

/*
 * Tell the firewall to add a scdb entry for the completed BEX.
 */
int signaling_send_scdb_add(UNUSED const uint8_t packet_type, UNUSED const uint32_t ha_state, struct hip_packet_context *ctx)
{
    struct hip_common *msg = NULL;
    int err                = 0;
    const struct signaling_param_appinfo *appinfo = NULL;

    /* Get the parameter */
    HIP_IFEL(!(appinfo = (const struct signaling_param_appinfo *) hip_get_param(ctx->input_msg, HIP_PARAM_SIGNALING_APPINFO)),
            -1, "No application info parameter found in the message.\n");

    /* Build the user message */
    HIP_IFEL(!(msg = malloc(HIP_MAX_PACKET)), -1,
              "alloc memory for adding scdb entry\n");
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
