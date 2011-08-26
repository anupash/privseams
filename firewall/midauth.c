/*
 * Copyright (c) 2010 Aalto University and RWTH Aachen University.
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
 * This file provides a framework for modifying HIP packets. It includes
 * adding new parameters in the correct order and adapting the various
 * headers.
 *
 * @brief Framework for the midauth extensions
 *
 * @note: According to draft-heer-hip-middle-auth-00 we SHOULD support IP-level
 * fragmentation for IPv6 and MUST support IP-level fragmentation for IPv4.
 * Currently we do neither.
 */

#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/netfilter.h>

#include "lib/core/builder.h"
#include "lib/core/debug.h"
#include "lib/core/ife.h"
#include "lib/core/protodefs.h"
#include "lib/core/solve.h"
#include "pisa.h"
#include "midauth.h"


static struct midauth_handlers handlers;

/**
 * Verify that the challenge response in a packet is valid
 *
 * @param solution      challenge response parameter
 * @param initiator_hit HIT of the initiator
 * @param responder_hit HIT of the receiver
 * @return    0 on success, <0 otherwise
 */
int midauth_verify_challenge_response(const struct hip_challenge_response *const solution,
                                      const hip_hit_t initiator_hit,
                                      const hip_hit_t responder_hit)
{
    int                      err = 0;
    struct puzzle_hash_input puzzle_input;
    uint8_t                  digest[HIP_AH_SHA_LEN];

    HIP_IFEL(hip_build_digest(HIP_DIGEST_SHA1, solution->opaque, 24, digest) < 0,
             -1, "Building of SHA1 Random seed I failed\n");

    memcpy(puzzle_input.puzzle,
           &digest[HIP_AH_SHA_LEN - PUZZLE_LENGTH],
           PUZZLE_LENGTH);
    puzzle_input.initiator_hit = initiator_hit;
    puzzle_input.responder_hit = responder_hit;
    memcpy(puzzle_input.solution, solution->J, PUZZLE_LENGTH);

    HIP_IFEL(hip_verify_puzzle_solution(&puzzle_input, solution->K),
             -1, "Solution is wrong\n");

out_err:
    return err;
}

/**
 * Move the last HIP parameter to the correct position according to its
 * parameter type. Will probably break the packet if something is moved in
 * front of a signature.
 *
 * @param hip the HIP packet
 * @return 0 on success
 */
static int midauth_relocate_last_hip_parameter(struct hip_common *hip)
{
    int                    err = 0, len, total_len, offset;
    char                   buffer[HIP_MAX_PACKET], *ptr = (char *) hip;
    struct hip_tlv_common *i = NULL, *last = NULL;
    hip_tlv                type;

    while ((i = hip_get_next_param_readwrite(hip, i))) {
        last = i;
    }

    HIP_IFEL(last == NULL, -1, "Trying to relocate in an empty packet!\n");

    total_len = hip_get_msg_total_len(hip);
    len       = hip_get_param_total_len(last);
    type      = hip_get_param_type(last);

    HIP_IFEL(len > (int) sizeof(buffer), -1,
             "Last parameter's length exceeds HIP_MAX_PACKET\n");

    /* @todo check for signature parameter to avoid broken packets */

    memcpy(buffer, last, len);
    i = NULL;

    while ((i = hip_get_next_param_readwrite(hip, i))) {
        if (hip_get_param_type(i) > type) {
            offset = (char *) i - (char *) hip;

            memmove(ptr + offset + len, ptr + offset,
                    total_len - offset - len);
            memcpy(ptr + offset, buffer, len);
            break;
        }
    }

out_err:
    return err;
}

/**
 * Creates a challenge request and adds it to a forwarded HIP
 * packet.
 *
 * @param ctx          connection context of the modified packet
 * @param val_K        puzzle difficulty
 * @param ltime        lifetime of the challenge in s
 * @param opaque       contents of the opaque data field
 * @param opaque_len   length of the opaque data field
 * @return 0 on success, <0 otherwise
 */
int midauth_add_challenge_request(struct hip_fw_context *ctx, uint8_t val_K,
                                  uint8_t ltime,
                                  uint8_t *opaque,
                                  uint8_t opaque_len)
{
    struct hip_common *hip = ctx->transport_hdr.hip;
    int                err = 0;

    ctx->modified = 1;

    HIP_IFEL(hip_build_param_challenge_request(hip, val_K, ltime,
                                               opaque, opaque_len),
             -1, "Failed to build challenge_request parameter\n");
    HIP_IFEL(midauth_relocate_last_hip_parameter(hip), -1,
             "Failed to relocate new challenge_request parameter\n");

out_err:
    return err;
}

int midauth_handler_accept(UNUSED struct hip_fw_context *ctx)
{
    return NF_ACCEPT;
}

/**
 * Drops a packet. Used in midauth_handlers as a default handler.
 *
 * @param ctx context of the packet
 * @return NF_DROP
 */
static int midauth_handler_drop(UNUSED struct hip_fw_context *ctx)
{
    return NF_DROP;
}

/**
 * Distinguish the different UPDATE packets.
 *
 * @param ctx context of the modified packet
 * @return the verdict, either NF_ACCEPT or NF_DROP
 */
static midauth_handler filter_midauth_update(const struct hip_fw_context *ctx)
{
    if (hip_get_param(ctx->transport_hdr.hip, HIP_PARAM_LOCATOR)) {
        return handlers.u1;
    }
    if (hip_get_param(ctx->transport_hdr.hip, HIP_PARAM_ECHO_REQUEST)) {
        return handlers.u2;
    }
    if (hip_get_param(ctx->transport_hdr.hip, HIP_PARAM_ECHO_RESPONSE)) {
        return handlers.u3;
    }

    HIP_ERROR("Unknown UPDATE format, rejecting the request!\n");
    return midauth_handler_drop;
}

/**
 * Packet handler dispatcher function. Classifies packets based on
 * their type and calls the appropriate type-specific handler functions.
 *
 * @param ctx HIP connection context
 * @return the verdict, either NF_ACCEPT or NF_DROP
 */
int midauth_filter_hip(struct hip_fw_context *ctx)
{
    int             verdict   = NF_ACCEPT;
    midauth_handler h         = NULL;
    midauth_handler h_default = midauth_handler_accept;
    /* @todo change this default value to midauth_handler_drop to
     * disallow unknown message types */

    switch (ctx->transport_hdr.hip->type_hdr) {
    case HIP_I1:
        h = handlers.i1;
        break;
    case HIP_R1:
        h = handlers.r1;
        break;
    case HIP_I2:
        h = handlers.i2;
        break;
    case HIP_R2:
        h = handlers.r2;
        break;
    case HIP_UPDATE:
        h = filter_midauth_update(ctx);
        break;
    case HIP_CLOSE:
        h = handlers.close;
        break;
    case HIP_CLOSE_ACK:
        h = handlers.close_ack;
        break;
    default:
        HIP_DEBUG("filtering default message type\n");
        break;
    }

    if (!h) {
        h = h_default;
    }
    verdict = h(ctx);

    /* do not change packet when it is dropped */
    if (verdict != NF_ACCEPT) {
        ctx->modified = 0;
    }

    return verdict;
}

/**
 * Call the initializer functions
 */
void midauth_init(void)
{
    pisa_init(&handlers);
}
