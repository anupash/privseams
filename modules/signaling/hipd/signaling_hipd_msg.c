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
 * @author Anupam Ashish <anupam.ashish@rwth-aachen.de>
 *
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <math.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "lib/core/common.h"
#include "lib/core/debug.h"
#include "lib/core/builder.h"
#include "lib/core/ife.h"
#include "lib/core/prefix.h"
#include "lib/core/hostid.h"
#include "lib/core/icomm.h"
#include "lib/core/hip_udp.h"
#include "lib/core/crypto.h"
#include "lib/tool/pk.h"

#include "hipd/hadb.h"
#include "hipd/user.h"
#include "hipd/output.h"
#include "hipd/close.h"
#include "hipd/hipd.h"
#include "hipd/hidb.h"
#include "hipd/input.h"

#include "modules/update/hipd/update.h"
#include "modules/update/hipd/update_builder.h"
#include "modules/update/hipd/update_locator.h"

#include "modules/signaling/lib/signaling_common_builder.h"
#include "modules/signaling/lib/signaling_oslayer.h"
#include "modules/signaling/lib/signaling_user_api.h"
#include "modules/signaling/lib/signaling_x509_api.h"
#include "modules/signaling/lib/signaling_user_management.h"
#include "signaling_hipd_state.h"
#include "signaling_hipd_msg.h"
#include "signaling_hipd_user_msg.h"

int update_sent = 0;

unsigned char mb_dh_pub_key[] = {
    0x5F, 0x4A, 0x82, 0x8B, 0x95, 0x99, 0x9B, 0xEE, 0xCE, 0xD2,
    0x90, 0x5C, 0xC8, 0x80, 0xD5, 0xCB, 0x76, 0x76, 0x1F, 0xEC,
    0xF3, 0xC3, 0x29, 0x60, 0x85, 0x0C, 0xF5, 0x62, 0x77, 0x61,
    0x04, 0x0F, 0x21, 0x00, 0x69, 0xF0, 0x31, 0xBA, 0xBF, 0x4E,
    0x4B, 0xCE, 0x91, 0x38, 0xCB, 0x47, 0x82, 0xBB, 0x6D, 0xBB,
    0xA4, 0x52, 0x9B, 0xC4, 0xC7, 0x6E, 0x2D, 0xB3, 0x99, 0x33,
    0x67, 0x44, 0xDF, 0x42, 0xCF, 0xFA, 0x23, 0x3E, 0x2F, 0x98,
    0x0F, 0x47, 0xD2, 0xEB, 0x8F, 0x02, 0xB4, 0xDD, 0x86, 0xB0,
    0xA2, 0x30, 0xA8, 0x86, 0xB9, 0xCA, 0x0B, 0x68, 0xCE, 0xD1,
    0xB0, 0xED, 0xEF, 0x69, 0x3D, 0xBA, 0x82, 0x13, 0xBC, 0x04,
    0xB7, 0x7C, 0xF1, 0xFB, 0xEB, 0xD7, 0x3E, 0x08, 0x12, 0x7A,
    0xE2, 0xCE, 0x3B, 0xCF, 0x9D, 0xC8, 0xFE, 0x34, 0xB2, 0x55,
    0x16, 0xFB, 0xFA, 0x77, 0x0A, 0x1B, 0x32, 0x58, 0x4A, 0x52,
    0xE2, 0xCF, 0x8A, 0xC0, 0x04, 0xFA, 0x58, 0xA6, 0x33, 0x3F,
    0x0B, 0xB7, 0xE7, 0xEE, 0x8D, 0x2D, 0x74, 0x92, 0x4A, 0x16,
    0x1D, 0x27, 0x49, 0x40, 0x60, 0xA7, 0xFB, 0xDB, 0x1E, 0xFC,
    0x3D, 0x75, 0xA6, 0x69, 0x71, 0x0F, 0xC6, 0xA9, 0x2D, 0x51,
    0x8E, 0x9B, 0xC6, 0xA0, 0x23, 0x58, 0x66, 0x9E, 0xD9, 0x1F,
    0xFB, 0x33, 0x35, 0x41, 0xEF, 0x5C, 0xBB, 0xD2, 0x7C, 0xF3,
    0xF5, 0x01
};

uint16_t mb_dh_pub_key_len = DH_PUB_KEY_SIZE;
DH      *dh                = NULL;

/*
 *   Wrapper for hip_send_close(...).
 *
 *   @param peer_hit    the hit of the peer to close
 *   @return            0 on success, negative on error
 */
/*
 * static int signaling_close_peer(hip_hit_t *peer_hit)
 * {
 *  int                err     = 0;
 *  uint16_t           mask    = 0;
 *  struct hip_common *msg_buf = NULL;
 *
 *   Allocate and build message
 *  HIP_IFEL(!(msg_buf = hip_msg_alloc()),
 *           -ENOMEM, "Out of memory while allocation memory for the bex update packet\n");
 *  hip_build_network_hdr(msg_buf, HIP_UPDATE, mask, peer_hit, peer_hit);
 *
 *   Add hit to close, this parameter is critical.
 *  HIP_IFEL(hip_build_param_contents(msg_buf, peer_hit, HIP_PARAM_HIT, sizeof(hip_hit_t)),
 *           -1, "build param contents (dst hit) failed\n");
 *
 *  HIP_IFEL(hip_send_close(msg_buf, 0),
 *           -1, "Could not close hip associaton\n");
 *
 *  return 0;
 *
 * out_err:
 *  return err;
 * }
 */

/*
 * Builds either a U1, U2 or U3 update message.
 *
 * @param ha    the host association
 * @param type  the upade type (U1, U2 or U3)
 * @param conn  the connection
 *
 * @return      the update message
 */
static struct hip_common *build_update_message(struct hip_hadb_state *ha,
                                               const int type,
                                               struct signaling_connection *conn,
                                               struct hip_packet_context *ctx)
{
    uint16_t                           mask        = 0;
    struct hip_common                 *msg_buf     = NULL;
    struct hip_common                 *locator_msg = NULL;
    struct hip_locator_info_addr_item *locators    = NULL;
    struct update_state               *localstate  = NULL;
    struct signaling_hipd_state       *sig_state   = NULL;

    /* Allocate and build message */
    if (type == SIGNALING_FIRST_BEX_UPDATE) {
        if (!(msg_buf = hip_msg_alloc())) {
            HIP_ERROR("Out of memory while allocation memory for the bex update packet\n");
            return NULL;
        }

        if (ctx != NULL) {
            free(ctx->output_msg);
            ctx->output_msg = msg_buf;
        }
        hip_build_network_hdr(msg_buf, HIP_UPDATE, mask, &ha->hit_our, &ha->hit_peer);
        localstate = lmod_get_state_item(ha->hip_modular_state, "update");
    } else {
        msg_buf = ctx->output_msg;
    }

    /* Add sequence number in U1 and U2 */
    if (type == SIGNALING_FIRST_BEX_UPDATE) {
        if (hip_build_param_esp_info(msg_buf,
                                     ha->current_keymat_index,
                                     ha->spi_inbound_current,
                                     ha->spi_inbound_current)) {
            HIP_ERROR("Could not build param esp_info\n");
            return NULL;
        }
        locator_msg = hip_msg_alloc();
        hip_create_locators(locator_msg, &locators);
        hip_build_param_locator(msg_buf,
                                locators,
                                address_count);
        localstate->update_id_out++;
        HIP_DEBUG("outgoing UPDATE ID=%u\n", hip_update_get_out_id(localstate));
        if (hip_build_param_seq(msg_buf, hip_update_get_out_id(localstate))) {
            HIP_ERROR("Building of SEQ parameter failed\n");
            free(msg_buf);
            return NULL;
        }
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Start PERF_CONN_U1_DIFFIE_HELLMAN\n");
        hip_perf_start_benchmark(perf_set, PERF_CONN_U1_DIFFIE_HELLMAN);
#endif
        if (signaling_add_param_dh_to_hip_update(msg_buf)) {
            HIP_DEBUG("Could not add add Diffie Hellman parameter to the HIP Update\n");
            free(msg_buf);
            return NULL;
        }
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Stop PERF_CONN_U1_DIFFIE_HELLMAN\n");
        hip_perf_stop_benchmark(perf_set, PERF_CONN_U1_DIFFIE_HELLMAN);
#endif
        if (signaling_build_param_signaling_connection(msg_buf, conn)) {
            HIP_ERROR("Building of connection identifier parameter failed\n");
            free(msg_buf);
            return NULL;
        }
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Start PERF_CONN_U1_HMAC\n");
        hip_perf_start_benchmark(perf_set, PERF_CONN_U1_HMAC);
#endif
        /* Add host authentication */
        if (hip_build_param_hmac_contents(msg_buf, &ha->hip_hmac_out)) {
            HIP_ERROR("Building of HMAC failed\n");
            free(msg_buf);
            return NULL;
        }
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Stop PERF_CONN_U1_HMAC\n");
        hip_perf_stop_benchmark(perf_set, PERF_CONN_U1_HMAC);
#endif
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Start PERF_CONN_U1_HOST_SIGN\n");
        hip_perf_start_benchmark(perf_set, PERF_CONN_U1_HOST_SIGN);
#endif
        if (ha->sign(ha->our_priv_key, msg_buf)) {
            HIP_ERROR("Could not sign UPDATE. Failing\n");
            free(msg_buf);
            return NULL;
        }
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Stop PERF_CONN_U1_HOST_SIGN\n");
        hip_perf_stop_benchmark(perf_set, PERF_CONN_U1_HOST_SIGN);
#endif
    } else if (type == SIGNALING_SECOND_BEX_UPDATE) {
        if ((sig_state = (struct signaling_hipd_state *) lmod_get_state_item(ha->hip_modular_state, "signaling_hipd_state"))) {
            /* Handle only unsigned service offers only. Signed service offers will be handled separately*/
            if (sig_state->flag_offer_type != OFFER_SIGNED) {
#ifdef CONFIG_HIP_PERFORMANCE
                HIP_DEBUG("Start PERF_CONN_U1_HANDLE_SELECTIVE_SIGNED_OFFER, PERF_CONN_U1_HANDLE_UNSIGNED_SERVICE_OFFER\n");
                hip_perf_start_benchmark(perf_set, PERF_CONN_U1_HANDLE_UNSIGNED_SERVICE_OFFER);
                hip_perf_start_benchmark(perf_set, PERF_CONN_U1_HANDLE_SELECTIVE_SIGNED_OFFER);
#endif
                signaling_i2_handle_service_offers_common(HIP_UPDATE, ha->state, ctx, sig_state->flag_offer_type);
            }
        } else {
            HIP_DEBUG("No hipd state found, could not build HIP Update\n");
            free(msg_buf);
            return NULL;
        }
    } else if (type == SIGNALING_THIRD_BEX_UPDATE) {
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Start PERF_CONN_U2_HANDLE_SELECTIVE_SIGNED_OFFER, PERF_CONN_U2_HANDLE_UNSIGNED_SERVICE_OFFER, "
                  "PERF_CONN_U2_HANDLE_SIGNED_OFFER\n");
        hip_perf_start_benchmark(perf_set, PERF_CONN_U2_HANDLE_UNSIGNED_SERVICE_OFFER);
        hip_perf_start_benchmark(perf_set, PERF_CONN_U2_HANDLE_SELECTIVE_SIGNED_OFFER);
        hip_perf_start_benchmark(perf_set, PERF_CONN_U2_HANDLE_SIGNED_OFFER);
#endif
        signaling_r2_handle_service_offers(HIP_UPDATE, ha->state, ctx);
    }

    free(locator_msg);
    return msg_buf;
}

/**
 * Send the first UPDATE message for an application that wants to establish a new connection.
 *
 * @param src_hit   the HIT of the initiator of the update exchange
 * @param dst_hit   the HIT of the responder of the update exchange
 * @param ctx       the connection context for which to send the update exchange
 *
 * @return 0 on success, negative on error
 */
int signaling_send_first_update(const struct in6_addr *src_hit,
                                const struct in6_addr *dst_hit,
                                struct signaling_connection *conn)
{
    int                    err                   = 0;
    struct hip_hadb_state *ha                    = NULL;
    struct hip_common     *update_packet_to_send = NULL;

    /* sanity tests */
    HIP_IFEL(!src_hit,  -1, "No source HIT given \n");
    HIP_IFEL(!dst_hit,  -1, "No destination HIT given \n");
    HIP_IFEL(!conn,     -1, "No connection context given \n");

    /* Lookup and update state */
    HIP_IFEL(!(ha = hip_hadb_find_byhits(src_hit, dst_hit)),
             -1, "Failed to retrieve hadb entry.\n");

    /* Build and send the first update */
    HIP_IFEL(!(update_packet_to_send = build_update_message(ha, SIGNALING_FIRST_BEX_UPDATE, conn, NULL)),
             -1, "Failed to build update.\n");
    err = hip_send_pkt(NULL,
                       &ha->peer_addr,
                       (ha->nat_mode ? hip_get_local_nat_udp_port() : 0),
                       ha->peer_udp_port,
                       update_packet_to_send,
                       ha,
                       1);

    free(update_packet_to_send);
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
int signaling_send_second_update(UNUSED const uint8_t packet_type,
                                 UNUSED const uint32_t ha_state,
                                 struct hip_packet_context *ctx)
{
    int                          err                   = 0;
    const struct in6_addr       *src_hit               = NULL;
    const struct in6_addr       *dst_hit               = NULL;
    struct hip_common           *update_packet_to_send = NULL;
    struct signaling_connection *conn                  = NULL;

    /* sanity checks */
    HIP_IFEL(!ctx->input_msg, -1, "Need received update message to build a response \n");

    /* Lookup state */
    src_hit = &ctx->input_msg->hitr;
    dst_hit = &ctx->input_msg->hits;
    if (ctx->hadb_entry) {
        HIP_IFEL(!(ctx->hadb_entry = hip_hadb_find_byhits(src_hit, dst_hit)),
                 -1, "Failed to retrieve hadb entry.\n");
    }

    /* Build and send the second update */
    HIP_IFEL(!(update_packet_to_send = build_update_message(ctx->hadb_entry, SIGNALING_SECOND_BEX_UPDATE, conn,  ctx)),
             -1, "Failed to build update.\n");

out_err:
    return err;
}

/**
 * Send the third UPDATE message for an application that wants to establish a new connection.
 *
 * @param second_update  the update message to which we want to respond
 *
 * @return 0 on success, negative on error
 */
int signaling_send_third_update(UNUSED const uint8_t packet_type,
                                UNUSED const uint32_t ha_state,
                                struct hip_packet_context *ctx)
{
    int                          err                   = 0;
    const struct in6_addr       *src_hit               = NULL;
    const struct in6_addr       *dst_hit               = NULL;
    struct signaling_hipd_state *sig_state             = NULL;
    struct hip_common           *update_packet_to_send = NULL;
    struct signaling_connection *conn                  = NULL;
    struct signaling_connection  conn_tmp;

    /* sanity checks */
    HIP_IFEL(!ctx->input_msg, -1, "Need received update message to build a response \n");

    /* Lookup state */
    src_hit = &ctx->input_msg->hitr;
    dst_hit = &ctx->input_msg->hits;
    if (ctx->hadb_entry) {
        HIP_IFEL(!(ctx->hadb_entry = hip_hadb_find_byhits(src_hit, dst_hit)),
                 -1, "Failed to retrieve hadb entry.\n");
    }
    HIP_IFEL(!(sig_state = (struct signaling_hipd_state *) lmod_get_state_item(ctx->hadb_entry->hip_modular_state, "signaling_hipd_state")),
             -1, "failed to retrieve state for signaling ports\n");

    /* get the connection state */
    signaling_init_connection_from_msg(&conn_tmp, ctx->input_msg, IN);
    HIP_IFEL(!(conn = signaling_hipd_state_get_connection(sig_state, conn_tmp.id, conn_tmp.src_port, conn_tmp.dst_port)),
             -1, "Could not retrieve local connection state for conn id %d src_port = %u dst_port = %u \n", conn_tmp.id, conn_tmp.src_port, conn_tmp.dst_port);

    /* Build and send the second update */
    HIP_IFEL(!(update_packet_to_send = build_update_message(ctx->hadb_entry, SIGNALING_THIRD_BEX_UPDATE, conn, ctx)),
             -1, "Failed to build update.\n");

out_err:
    return err;
}

/**
 * Build and send a notification about failed connection establishment.
 *
 * @param reason    the reason why the authentication failed
 */
int signaling_send_connection_failed_ntf(struct hip_hadb_state *ha,
                                         const int reason,
                                         const struct signaling_connection *conn)
{
    int                err     = 0;
    uint16_t           mask    = 0;
    struct hip_common *msg_buf = NULL;

    /* Sanity checks */
    HIP_IFEL(!ha, -1, "Given host association is NULL \n");

    /* Allocate and build message */
    HIP_IFEL(!(msg_buf = hip_msg_alloc()),
             -ENOMEM, "Out of memory while allocation memory for the bex update packet\n");
    hip_build_network_hdr(msg_buf, HIP_NOTIFY, mask, &ha->hit_our, &ha->hit_peer);

    /* Append notification parameter */
    signaling_build_param_connection_fail(msg_buf, reason);

    /* Append connection identifier */
    signaling_build_param_signaling_connection(msg_buf, conn);

    /* Sign the packet */
    HIP_IFEL(ha->sign(ha->our_priv_key, msg_buf),
             -EINVAL, "Could not sign UPDATE. Failing\n");

    err = hip_send_pkt(NULL,
                       &ha->peer_addr,
                       (ha->nat_mode ? hip_get_local_nat_udp_port() : 0),
                       ha->peer_udp_port,
                       msg_buf,
                       ha,
                       1);
out_err:
    return err;
}

/**
 * Build and send a notification about failed user authentication.
 *
 * @param reason    the reason why the authentication failed
 */
int signaling_send_user_auth_failed_ntf(struct hip_hadb_state *ha,
                                        const int reason)
{
    int                err     = 0;
    uint16_t           mask    = 0;
    struct hip_common *msg_buf = NULL;

    /* Sanity checks */
    HIP_IFEL(!ha, -1, "Given host association is NULL \n");

    /* Allocate and build message */
    HIP_IFEL(!(msg_buf = hip_msg_alloc()),
             -ENOMEM, "Out of memory while allocation memory for the bex update packet\n");
    hip_build_network_hdr(msg_buf, HIP_NOTIFY, mask, &ha->hit_our, &ha->hit_peer);

    /* Append notification parameter */
    signaling_build_param_user_auth_fail(msg_buf, reason);

    /* Sign the packet */
    HIP_IFEL(ha->sign(ha->our_priv_key, msg_buf),
             -EINVAL, "Could not sign UPDATE. Failing\n");

    err = hip_send_pkt(NULL,
                       &ha->peer_addr,
                       (ha->nat_mode ? hip_get_local_nat_udp_port() : 0),
                       ha->peer_udp_port,
                       msg_buf,
                       ha,
                       1);
out_err:
    return err;
}

int signaling_send_user_certificate_chain_ack(struct hip_hadb_state *ha,
                                              const uint32_t seq,
                                              const struct signaling_connection *const conn,
                                              uint32_t network_id)
{
    int                err     = 0;
    uint32_t           mask    = 0;
    struct hip_common *msg_buf = NULL;

    /* sanity checks */
    HIP_IFEL(!conn, -1, "Need connection state to build connection identifier from\n");
    HIP_IFEL(!ha, -1, "Need host association state to send message \n");

    /* Allocate and build a new message */
    HIP_IFEL(!(msg_buf = hip_msg_alloc()),
             -ENOMEM, "Out of memory while allocation memory for the user cert update packet\n");
    hip_build_network_hdr(msg_buf, HIP_UPDATE, mask, &ha->hit_our, &ha->hit_peer);

    /* Add ACK paramater for sequence number of last certificate update */
    HIP_IFEL(hip_build_param_ack(msg_buf, seq),
             -1, "Building of ACK parameter failed\n");

    /* Add connection id */
    HIP_IFEL(signaling_build_param_certificate_chain_identifier(msg_buf, conn->id, network_id),
             -1, "Building of connection identifier parameter failed\n");

    /* Add host authentication */
    HIP_IFEL(hip_build_param_hmac_contents(msg_buf, &ha->hip_hmac_out),
             -1, "Building of HMAC failed\n");
    HIP_IFEL(ha->sign(ha->our_priv_key, msg_buf),
             -EINVAL, "Could not sign certificate chain acknowledgment. Failing\n");

    /* send the message */
    err = hip_send_pkt(NULL,
                       &ha->peer_addr,
                       (ha->nat_mode ? hip_get_local_nat_udp_port() : 0),
                       ha->peer_udp_port,
                       msg_buf,
                       ha,
                       1);

out_err:
    return err;
}

/**
 * Send a whole certificate chain, possibly dstributed over multiple messages.
 * TODO: Refactor this and move the building parts to the builder.
 *
 * @param ha   the host association for the connection on which to send the certificate chain
 * @param uid  the id of the user, whose certificate chain is sent
 * @return  0 on success, negative on error
 */
int signaling_send_user_certificate_chain(struct hip_hadb_state *ha, struct signaling_connection *conn, uint32_t network_id)
{
    int                  err         = 0;
    uint16_t             mask        = 0;
    struct hip_common   *msg_buf     = NULL;
    struct update_state *updatestate = NULL;
    STACK_OF(X509) * cert_chain = NULL;
    X509 *cert = NULL;
    int   total_cert_count;
    int   next_id = 1;
    int   sent    = 0;
    int   i       = 0;

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_SEND_CERT_CHAIN\n");
    hip_perf_start_benchmark(perf_set, PERF_SEND_CERT_CHAIN);
#endif

    /* sanity checks */
    HIP_IFEL(!ha, -1, "Given HA is NULL \n");
    HIP_IFEL(!(updatestate = (struct update_state *) lmod_get_state_item(ha->hip_modular_state, "update")),
             -1, "Could not get update state for host association.\n");

    /* Get the users certificate chain */
/*    HIP_IFEL(!(cert_chain = signaling_user_api_get_user_certificate_chain(conn->ctx_out.user.uid)),
 *           -1, "Could not get certificate for user with id %d\n", conn->ctx_out.user.uid);*/
    total_cert_count = sk_X509_num(cert_chain);
    HIP_DEBUG("Sending a total of %d certificates from users chain.\n", total_cert_count);

    while (total_cert_count - next_id >= 0) {
        /* Allocate and build a new message */
        HIP_IFEL(!(msg_buf = hip_msg_alloc()),
                 -ENOMEM, "Out of memory while allocation memory for the user cert update packet\n");
        hip_build_network_hdr(msg_buf, HIP_UPDATE, mask, &ha->hit_our, &ha->hit_peer);

        /* Add sequence number */
        updatestate->update_id_out++;
        HIP_IFEL(hip_build_param_seq(msg_buf, hip_update_get_out_id(updatestate)),
                 -1, "Building of SEQ parameter failed\n");

        /* Put as much certificate parameter into the message as possible */
        sent = signaling_build_param_cert_chain(msg_buf, cert_chain, next_id, total_cert_count,
                                                signaling_get_free_message_space(msg_buf, ha));
        i++;
        switch (sent) {
        case -1:
            HIP_ERROR("Error sending certificate chain \n");
            err = -1;
            goto out_err;
        case 0:
            HIP_DEBUG("Sent all certificates \n");
            break;
        default:
            next_id += sent;
            break;
        }

        /* Add the connection identifier */
        HIP_IFEL(signaling_build_param_certificate_chain_identifier(msg_buf, conn->id, network_id),
                 -1, "Could not build certificate chain identifier for certificate update packet \n");

        /* Mac and sign the packet */
        HIP_IFEL(hip_build_param_hmac_contents(msg_buf, &ha->hip_hmac_out),
                 -1, "Building of HMAC failed\n");
        HIP_IFEL(ha->sign(ha->our_priv_key, msg_buf),
                 -EINVAL, "Could not sign UPDATE. Failing\n");

/*
 *      HIP_DEBUG("Sending certificate chain for subject id %d up to certificate %d of %d\n",
 *                conn->ctx_out.user.uid, next_id - 1, total_cert_count);
 */

        err = hip_send_pkt(NULL,
                           &ha->peer_addr,
                           (ha->nat_mode ? hip_get_local_nat_udp_port() : 0),
                           ha->peer_udp_port,
                           msg_buf,
                           ha,
                           1);
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Write PERF_UPDATE_HOST_SIGN\n");
        hip_perf_write_benchmark(perf_set, PERF_UPDATE_HOST_SIGN);
#endif
        /* free message for the next run */
        free(msg_buf);
        msg_buf = NULL;
    }

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop PERF_SEND_CERT_CHAIN\n");
    hip_perf_stop_benchmark(perf_set, PERF_SEND_CERT_CHAIN);
    HIP_DEBUG("Start PERF_CERT_UP_CERT_ACK\n");
    hip_perf_start_benchmark(perf_set, PERF_CERT_UP_CERT_ACK);
#endif

    return 0;

out_err:
    sk_X509_free(cert_chain);
    X509_free(cert);
    free(msg_buf);
    return err;
}

/*
 * Handles an incoming R2 packet.
 *
 * Process connection context in an R2 packet.
 * This completes a BEX with application context for which this HIPD process was the initiator.
 */
int signaling_handle_incoming_r2(const uint8_t packet_type, UNUSED const uint32_t ha_state, struct hip_packet_context *ctx)
{
    int                          err       = 0;
    struct signaling_hipd_state *sig_state = NULL;
    struct signaling_connection  recv_conn;
    struct signaling_connection *conn = NULL;

    /* sanity checks */
    if (packet_type == HIP_R2) {
        HIP_DEBUG("Handling an R2\n");
    } else if (packet_type == HIP_UPDATE) {
        HIP_DEBUG("Handling the third bex update like R2\n");
    } else {
        HIP_ERROR("Packet is neither R2 nor third bex update.\n");
        err = -1;
        goto out_err;
    }


    // FIXME Why do we need to update anything here?
    /* Get the connection from state and update it with the information in the R2. */
    HIP_IFEL(!(sig_state = (struct signaling_hipd_state *) lmod_get_state_item(ctx->hadb_entry->hip_modular_state, "signaling_hipd_state")),
             -1, "failed to retrieve state for signaling module\n");
    HIP_IFEL(signaling_init_connection_from_msg(&recv_conn, ctx->input_msg, IN),
             -1, "Could not init connection context from R2/U2 \n");
    signaling_connection_print(&recv_conn, "\t");
    HIP_IFEL(!(conn = signaling_hipd_state_get_connection(sig_state, recv_conn.id, recv_conn.src_port, recv_conn.dst_port)),
             -1, "Could not get connection state for connection in R2\n");

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop PERF_R2, PERF_COMPLETE_BEX\n");
    hip_perf_stop_benchmark(perf_set, PERF_R2);
    hip_perf_stop_benchmark(perf_set, PERF_COMPLETE_BEX);
#endif

    signaling_connection_print(conn, "\t");

    /* Notify hipfw about the completed exchange */
    if (packet_type == HIP_R2) {
        HIP_IFEL(signaling_send_connection_confirmation(&ctx->hadb_entry->hit_our, &ctx->hadb_entry->hit_peer, conn),
                 -1, "Failed to communicate new connection information from R2/U2 to hipfw \n");
    } else if (packet_type == HIP_UPDATE) {
        HIP_IFEL(signaling_send_connection_confirmation(&ctx->hadb_entry->hit_peer, &ctx->hadb_entry->hit_our, conn),
                 -1, "Failed to communicate new connection information from R2/U2 to hipfw \n");
    }

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_CERTIFICATE_EXCHANGE, PERF_RECEIVE_CERT_CHAIN\n");
    hip_perf_start_benchmark(perf_set, PERF_CERTIFICATE_EXCHANGE);
    hip_perf_start_benchmark(perf_set, PERF_RECEIVE_CERT_CHAIN);
#endif

out_err:
#ifdef CONFIG_HIP_PERFORMANCE
    /* The packet is on the wire, so write all tests now.. */
    HIP_DEBUG("Write PERF_USER_COMM PERF_X509_VERIFY_CERT_CHAIN, PERF_I3_HOST_SIGN, PERF_SEND_CERT_CHAIN, \n");
    hip_perf_write_benchmark(perf_set, PERF_X509_VERIFY_CERT_CHAIN);
    hip_perf_write_benchmark(perf_set, PERF_SEND_CERT_CHAIN);
    HIP_DEBUG("Write PERF_R2, PERF_I2_R2, PERF_HIPD_R2_FINISH, PERF_R2_VERIFY_HOST_SIG, PERF_R2_VERIFY_USER_SIG, PERF_USER_COMM,"
              "PERF_R2_VERIFY_HMAC, PERF_COMPLETE_BEX \n");
    hip_perf_write_benchmark(perf_set, PERF_USER_COMM);
    hip_perf_write_benchmark(perf_set, PERF_R2);
    hip_perf_write_benchmark(perf_set, PERF_I2_R2);
    hip_perf_write_benchmark(perf_set, PERF_R2_VERIFY_HOST_SIG);
    hip_perf_write_benchmark(perf_set, PERF_R2_VERIFY_HMAC);
    hip_perf_write_benchmark(perf_set, PERF_R2_VERIFY_USER_SIG);
    hip_perf_write_benchmark(perf_set, PERF_R2_VERIFY_USER_PUBKEY);
    hip_perf_write_benchmark(perf_set, PERF_HIPD_R2_FINISH);
    hip_perf_write_benchmark(perf_set, PERF_COMPLETE_BEX);

    HIP_DEBUG("Write PERF_CONN_U3\n");
    hip_perf_write_benchmark(perf_set, PERF_CONN_U3);
#endif

    return err;
}

/**
 * Handle an UPDATE message that contains (parts from) a user certificate chain.
 *
 * @return 0 on success
 */
static int signaling_handle_incoming_certificate_udpate(UNUSED const uint8_t packet_type, UNUSED const uint32_t ha_state, struct hip_packet_context *ctx)
{
    int                                         err           = 0;
    const struct signaling_param_cert_chain_id *param_cert_id = NULL;
    X509                                       *cert          = NULL;
    struct signaling_hipd_state                *sig_state     = NULL;
    struct signaling_connection                *conn          = NULL;
    const struct hip_seq                       *param_seq     = NULL;
    struct userdb_certificate_context          *cert_ctx      = NULL;
    struct signaling_port_pair                  ports;
    uint32_t                                    network_id;
    uint32_t                                    conn_id;

    /* sanity checks */
    HIP_IFEL(!ctx->input_msg,  -1, "Message is NULL\n");

    /* Get connection identifier and context */
    HIP_IFEL(!(sig_state = (struct signaling_hipd_state *) lmod_get_state_item(ctx->hadb_entry->hip_modular_state, "signaling_hipd_state")),
             -1, "failed to retrieve state\n");
    HIP_IFEL(!(param_cert_id = hip_get_param(ctx->input_msg, HIP_PARAM_SIGNALING_CERT_CHAIN_ID)),
             -1, "No connection identifier found in the message, cannot handle certificates.\n");
    conn_id    = ntohl(param_cert_id->connection_id);
    network_id = ntohl(param_cert_id->network_id);
    HIP_IFEL(!(conn = signaling_hipd_state_get_connection(sig_state, conn_id, ports.src_port, ports.dst_port)),
             -1, "No connection context for connection id \n");

    /* Process certificates and check completeness*/
    //err = userdb_add_certificates_from_msg(ctx->input_msg, conn->ctx_in.userdb_entry);
    if (err < 0) {
        HIP_ERROR("Internal error while processing certificates \n");
        err = -1;
        goto out_err;
    } else if (err > 0) {
        HIP_DEBUG("Waiting for further certificate updates because chain is incomplete. \n");
        //userdb_entry_print(conn->ctx_in.userdb_entry);
        return 0;
    }

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop PERF_RECEIVE_CERT_CHAIN\n");
    hip_perf_stop_benchmark(perf_set, PERF_RECEIVE_CERT_CHAIN);
    HIP_DEBUG("Start PERF_HANDLE_CERT_CHAIN\n");
    hip_perf_start_benchmark(perf_set, PERF_HANDLE_CERT_CHAIN);
#endif

    /* We have received a complete chain */
    HIP_DEBUG("Received complete certificate chain.\n");
/*    HIP_IFEL(!(cert_ctx = userdb_get_certificate_context(conn->ctx_in.userdb_entry,
 *                                                       &ctx->input_msg->hits,
 *                                                       &ctx->input_msg->hitr,
 *                                                       network_id)),
 *           -1, "Could not retrieve users certificate chain\n");*/
    stack_reverse(&cert_ctx->cert_chain);
    //userdb_entry_print(conn->ctx_in.userdb_entry);

    /* Match the public key */
    cert = sk_X509_pop(cert_ctx->cert_chain);
/*
 *  HIP_IFEL(!match_public_key(cert, conn->ctx_in.userdb_entry->pub_key),
 *           -1, "Users public key does not match with the key in the received certificate chain\n");
 */

    /* Verify the certificate chain */
    if (!verify_certificate_chain(cert, CERTIFICATE_INDEX_TRUSTED_DIR, NULL, cert_ctx->cert_chain)) {
        /* Public key verification was successful, so we save the chain */
        sk_X509_push(cert_ctx->cert_chain, cert);
        userdb_save_user_certificate_chain(cert_ctx->cert_chain);

        /* We send an ack */
        HIP_IFEL(!(param_seq = hip_get_param(ctx->input_msg, HIP_PARAM_SEQ)),
                 -1, "Cannot build ack for last certificate update, because corresponding UPDATE has no sequence number \n");
        signaling_send_user_certificate_chain_ack(ctx->hadb_entry, ntohl(param_seq->update_id), conn, network_id);

#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Stop PERF_HANDLE_CERT_CHAIN\n");
        hip_perf_stop_benchmark(perf_set, PERF_HANDLE_CERT_CHAIN);
#endif

        /* We confirm to the firewall if we're done, i.e. if the authentication of
         * our local user has not been requested or is already completed.
         * If not, we'll confirm when we receive our own certifiate ack. */
/*        if (!signaling_flag_check(conn->ctx_out.flags, USER_AUTH_REQUEST)) {
 *          signaling_send_connection_update_request(&ctx->hadb_entry->hit_our, &ctx->hadb_entry->hit_peer, conn_short, conn);
 * #ifdef CONFIG_HIP_PERFORMANCE
 *          HIP_DEBUG("Stop and write PERF_NEW_CONN\n");
 *          hip_perf_stop_benchmark(perf_set, PERF_NEW_CONN);
 *          hip_perf_write_benchmark(perf_set, PERF_NEW_CONN);
 * #endif
 *
 *      }
 */ } else {
        HIP_DEBUG("Rejecting certificate chain. Chain will not be saved. \n");
    }
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Write PERF_X509_VERIFY_CERT_CHAIN, PERF_CERTIFICATE_EXCHANGE, PERF_HANDLE_CERT_CHAIN, PERF_UPDATE_HOST_SIGN, PERF_RECEIVE_CERT_CHAIN\n");
    hip_perf_write_benchmark(perf_set, PERF_X509_VERIFY_CERT_CHAIN);
    hip_perf_write_benchmark(perf_set, PERF_CERTIFICATE_EXCHANGE);
    hip_perf_write_benchmark(perf_set, PERF_HANDLE_CERT_CHAIN);
    hip_perf_write_benchmark(perf_set, PERF_UPDATE_HOST_SIGN);
    hip_perf_write_benchmark(perf_set, PERF_RECEIVE_CERT_CHAIN);
#endif

out_err:
    return err;
}

static int signaling_handle_incoming_certificate_update_ack(UNUSED const uint8_t packet_type, UNUSED const uint32_t ha_state, struct hip_packet_context *ctx)
{
    int                                         err           = 0;
    const struct signaling_param_cert_chain_id *param_cert_id = NULL;
    struct signaling_hipd_state                *sig_state     = NULL;
    struct signaling_connection                *existing_conn = NULL;
    uint32_t                                    conn_id;
    struct signaling_port_pair                  ports;


#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop PERF_CERT_UP_CERT_ACK\n");
    hip_perf_stop_benchmark(perf_set, PERF_CERT_UP_CERT_ACK);
#endif

    /* sanity checks */
    HIP_IFEL(!ctx->input_msg,  -1, "Message is NULL\n");

    /* get connection identifier and context */
    HIP_IFEL(!(sig_state = (struct signaling_hipd_state *) lmod_get_state_item(ctx->hadb_entry->hip_modular_state, "signaling_hipd_state")),
             -1, "failed to retrieve state\n");
    HIP_IFEL(!(param_cert_id = hip_get_param(ctx->input_msg, HIP_PARAM_SIGNALING_CERT_CHAIN_ID)),
             0, "No connection identifier found in the message, cannot handle certificates.\n");
    conn_id =  ntohl(param_cert_id->connection_id);
    HIP_IFEL(!(existing_conn = signaling_hipd_state_get_connection(sig_state, conn_id, ports.src_port, ports.dst_port)),
             -1, "No connection context for connection id \n");

    /* unflag user authentication flag */
/*
 *  signaling_flag_unset(&existing_conn->ctx_out.flags, USER_AUTH_REQUEST);
 *
 *   Check if we're done with this connection or if authentication failed or we have to wait for additional authentication
 *  if (signaling_flag_check(existing_conn->ctx_in.flags, USER_AUTH_REQUEST)) {
 *      HIP_DEBUG("Auth uncompleted, waiting for authentication of remote user.\n");
 *  } else {
 *      HIP_DEBUG("Auth completed after update ack \n");
 *      signaling_send_connection_update_request(&ctx->hadb_entry->hit_our, &ctx->hadb_entry->hit_peer, conn_short, existing_conn);
 * #ifdef CONFIG_HIP_PERFORMANCE
 *      HIP_DEBUG("Stop and write PERF_NEW_CONN\n");
 *      hip_perf_stop_benchmark(perf_set, PERF_NEW_CONN);
 *      hip_perf_write_benchmark(perf_set, PERF_NEW_CONN);
 * #endif
 *  }
 */

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Write PERF_CERTIFICATE_EXCHANGE, PERF_CERT_UP_CERT_ACK\n");
    hip_perf_write_benchmark(perf_set, PERF_CERTIFICATE_EXCHANGE);
    hip_perf_write_benchmark(perf_set, PERF_CERT_UP_CERT_ACK);
#endif

out_err:
    return err;
}

/*
 * Handle an update
 */
int signaling_handle_incoming_update(UNUSED const uint8_t packet_type, UNUSED const uint32_t ha_state, struct hip_packet_context *ctx)
{
    int err = 0;
    int update_type;

    /* Sanity checks */
    HIP_IFEL((update_type = signaling_get_update_type(ctx->input_msg)) < 0,
             -1, "This is no signaling update packet\n");

    /* Handle the different update types */
    switch (update_type) {
    case SIGNALING_FIRST_BEX_UPDATE:
        /* This can be handled like R1 */
        HIP_DEBUG("Received FIRST BEX Update... \n");
        HIP_IFEL(signaling_send_second_update(packet_type, ha_state, ctx),
                 -1, "failed to trigger second bex update. \n");
        break;

    case SIGNALING_SECOND_BEX_UPDATE:
        /* This can be handled like an R2 */
        HIP_DEBUG("Received SECOND BEX Update... \n");
        HIP_IFEL(signaling_send_third_update(packet_type, ha_state, ctx),
                 -1, "failed to trigger Third BEX update. \n");
        break;

    case SIGNALING_THIRD_BEX_UPDATE:
        /* This can be handled like an I3 */
        HIP_DEBUG("Received THIRD BEX Update... \n");
        HIP_IFEL(signaling_handle_incoming_r2(packet_type, ha_state, ctx),
                 -1, "Could not process third bex update \n");
        break;

    case SIGNALING_FIRST_USER_CERT_CHAIN_UPDATE:
        HIP_DEBUG("Received certificate Update... \n");
        err = signaling_handle_incoming_certificate_udpate(packet_type, ha_state, ctx);
        break;

    case SIGNALING_SECOND_USER_CERT_CHAIN_UPDATE:
        HIP_DEBUG("Received certificate Update Ack... \n");
        err = signaling_handle_incoming_certificate_update_ack(packet_type, ha_state, ctx);
        break;

    default:
        HIP_DEBUG("Received unknown UPDATE type. \n");
        break;
    }

out_err:
    return err;
}

static int signaling_handle_notify_connection_failed(UNUSED const uint8_t packet_type, UNUSED const uint32_t ha_state, struct hip_packet_context *ctx)
{
    struct signaling_hipd_state                       *sig_state    = NULL;
    struct signaling_connection                       *conn         = NULL;
    const struct hip_notification                     *notification = NULL;
    const struct signaling_ntf_connection_failed_data *ntf_data     = NULL;
    const struct hip_tlv_common                       *param        = NULL;
    const struct hip_cert                             *param_cert   = NULL;
    X509                                              *cert         = NULL;
    EVP_PKEY                                          *pub_key      = NULL;
    int                                                reason       = 0;
    int                                                err          = 1;
    const struct in6_addr                             *peer_hit     = NULL;
    const struct in6_addr                             *our_hit      = NULL;
    const struct in6_addr                             *src_hit      = NULL;
    int                                                origin       = 0;
    struct hip_hadb_state                             *ha           = NULL;
    struct signaling_connection                        recv_conn;

    /* Get connection context */
    HIP_IFEL(!(notification = hip_get_param(ctx->input_msg, HIP_PARAM_NOTIFICATION)),
             -1, "Message contains no notification parameter.\n");
    signaling_init_connection(&recv_conn);
    HIP_IFEL(signaling_init_connection_from_msg(&recv_conn, ctx->input_msg, IN),
             -1, "Could not init connection context from the HIP_NOTIFY \n");

    /* Is this from a middlebox or the peer host? */
    param = hip_get_param(ctx->input_msg, HIP_PARAM_HIT);
    if (param && hip_get_param_type(param) == HIP_PARAM_HIT) {
        peer_hit = hip_get_param_contents_direct(param);
        if (ipv6_addr_is_null(peer_hit)) {
            peer_hit = NULL;
            HIP_DEBUG("HIT = NULL \n");
        }
    }
    if (!ctx->hadb_entry || (peer_hit && ipv6_addr_cmp(peer_hit, &ctx->hadb_entry->hit_peer))) {
        HIP_DEBUG("Notification comes from a middlebox.\n");
        origin  = 1; // 1 = from middlebox
        our_hit = &ctx->input_msg->hitr;
        src_hit = &ctx->input_msg->hits;
    } else {
        HIP_DEBUG("Notification comes from peer host.\n");
        origin   = 0;
        our_hit  = &ctx->input_msg->hitr;
        peer_hit = src_hit = &ctx->input_msg->hits;
    }

    HIP_INFO_HIT(" NTF src:   ", src_hit);
    HIP_INFO_HIT(" NTF our:   ", our_hit);
    HIP_INFO_HIT(" NTF other: ", peer_hit);

    /* Try to find connection */
    HIP_IFEL(!(ha = hip_hadb_find_byhits(our_hit, peer_hit)),
             -1, "No HA entry found for HITs, no need to update state.\n");
    HIP_IFEL(!(sig_state = lmod_get_state_item(ha->hip_modular_state, "signaling_hipd_state")),
             -1, "failed to retrieve state for signaling\n");
    HIP_IFEL(!(conn = signaling_hipd_state_get_connection(sig_state, recv_conn.id, recv_conn.src_port, recv_conn.dst_port)),
             -1, "Connection does not exist. \n");

    /* Now verify the signature */
    if (origin) {
        if (!(param_cert = hip_get_param(ctx->input_msg, HIP_PARAM_CERT))) {
            HIP_ERROR("Notification contains no certificate, cannot verify signature!\n");
        } else if (signaling_DER_to_X509((const unsigned char *) (param_cert + 1),
                                         ntohs(param_cert->length) - sizeof(struct hip_cert) + sizeof(struct hip_tlv_common),
                                         &cert)) {
            HIP_ERROR("Notification contains broken certificate, cannot verify signature!\n");
        } else {
            pub_key = X509_get_pubkey(cert);
            switch (EVP_PKEY_type(pub_key->type)) {
            case EVP_PKEY_EC:
#ifdef CONFIG_HIP_PERFORMANCE
                HIP_DEBUG("Start PERF_NOTIFY_VERIFY_HOST_SIG\n");
                hip_perf_start_benchmark(perf_set, PERF_NOTIFY_VERIFY_HOST_SIG);
#endif
                err = hip_ecdsa_verify(EVP_PKEY_get1_EC_KEY(pub_key), ctx->input_msg);
#ifdef CONFIG_HIP_PERFORMANCE
                HIP_DEBUG("Stop PERF_NOTIFY_VERIFY_HOST_SIG\n");
                hip_perf_stop_benchmark(perf_set, PERF_NOTIFY_VERIFY_HOST_SIG);
#endif
                break;
            case EVP_PKEY_RSA:
#ifdef CONFIG_HIP_PERFORMANCE
                HIP_DEBUG("Start PERF_NOTIFY_VERIFY_HOST_SIG\n");
                hip_perf_start_benchmark(perf_set, PERF_NOTIFY_VERIFY_HOST_SIG);
#endif
                err = hip_rsa_verify(EVP_PKEY_get1_EC_KEY(pub_key), ctx->input_msg);
#ifdef CONFIG_HIP_PERFORMANCE
                HIP_DEBUG("Stop PERF_NOTIFY_VERIFY_HOST_SIG\n");
                hip_perf_stop_benchmark(perf_set, PERF_NOTIFY_VERIFY_HOST_SIG);
#endif
                break;
            default:
                HIP_IFEL(1, -1, "Unknown algorithm\n");
                break;
            }
            if (err) {
                HIP_ERROR("signature on notification did not verify correctly\n");
                return -1;
            }
        }
    } else {
        /* Verify signature */
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Start PERF_NOTIFY_VERIFY_HOST_SIG\n");
        hip_perf_start_benchmark(perf_set, PERF_NOTIFY_VERIFY_HOST_SIG);
#endif
        HIP_IFEL(ctx->hadb_entry->verify(ha->peer_pub_key,
                                         ctx->input_msg),
                 -EINVAL,
                 "Verification of Notification signature failed\n");
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Stop PERF_NOTIFY_VERIFY_HOST_SIG\n");
        hip_perf_stop_benchmark(perf_set, PERF_NOTIFY_VERIFY_HOST_SIG);
#endif
    }
    HIP_DEBUG("Verified signature on notification...\n");

    /* Get notification data */
    ntf_data =  (const struct signaling_ntf_connection_failed_data *) notification->data;
    reason   = ntohs(ntf_data->reason);
    HIP_DEBUG("Received connection failed notification for following reasons:\n");
    if (reason) {
        if (reason & APPLICATION_BLOCKED) {
            HIP_DEBUG("\t -> Application blocked.\n");
        }
        if (reason & USER_BLOCKED) {
            HIP_DEBUG("\t -> User blocked.\n");
        }
        if (reason & HOST_BLOCKED) {
            HIP_DEBUG("\t -> Host blocked.\n");
        }
        if (reason & PRIVATE_REASON) {
            HIP_DEBUG("\t -> Reason is private.\n");
        }
    } else {
        HIP_DEBUG("\t -> Invalid reason.\n");
    }

    /* Adapt connection status */
    //conn->status = SIGNALING_CONN_BLOCKED;
    /* TODO handle this */
    //signaling_send_connection_update_request(our_hit, peer_hit, conn);

out_err:
    return err;
}

int signaling_handle_incoming_notification(UNUSED const uint8_t packet_type, UNUSED const uint32_t ha_state,
                                           struct hip_packet_context *ctx)
{
    int                            err = 0;
    const struct hip_notification *ntf = NULL;


    HIP_IFEL(!(ntf = hip_get_param(ctx->input_msg, HIP_PARAM_NOTIFICATION)),
             -1, "Could not get notification parameter from NOTIFY msg.\n");

    switch (ntohs(ntf->msgtype)) {
    case SIGNALING_CONNECTION_FAILED:
        HIP_DEBUG("Got notification about failed connection.\n");
        err = signaling_handle_notify_connection_failed(packet_type, ha_state, ctx);
        break;
    case SIGNALING_USER_AUTH_FAILED:
        HIP_DEBUG("Got notification about failed user authentication.\n");
        break;
    }
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Write PERF_NOTIFY_VERIFY_HOST_SIG\n");
    hip_perf_write_benchmark(perf_set, PERF_NOTIFY_VERIFY_HOST_SIG);
#endif
out_err:
    return err;
}

int signaling_mac_and_sign_handler(UNUSED const uint8_t packet_type, UNUSED const uint32_t ha_state,
                                   struct hip_packet_context *ctx)
{
    int                          err = 0;
    struct signaling_hipd_state *sig_state;
    int                          update_type = -1;

    HIP_IFEL(!ctx->hadb_entry, 0, "No hadb entry.\n");
    HIP_IFEL(!(sig_state = lmod_get_state_item(ctx->hadb_entry->hip_modular_state, "signaling_hipd_state")),
             0, "failed to retrieve state for signaling\n");
    if (packet_type == HIP_UPDATE) {
        HIP_IFEL((update_type = signaling_get_update_type(ctx->input_msg)) < 0, -1,
                 "Can't handle HIP_UPDATE of this type\n");
    }

    if (packet_type == HIP_R1 || (update_type == SIGNALING_FIRST_BEX_UPDATE || update_type == SIGNALING_SECOND_BEX_UPDATE)) {
        if (sig_state->flag_offer_type == OFFER_SELECTIVE_SIGNED) {
#ifdef CONFIG_HIP_PERFORMANCE
            HIP_DEBUG("Start PERF_CONN_U2_SELECTIVE_HMAC, PERF_CONN_U3_SELECTIVE_HMAC, "
                      "PERF_I2_SELECTIVE_HMAC\n");
            hip_perf_start_benchmark(perf_set, PERF_I2_SELECTIVE_HMAC);
            hip_perf_start_benchmark(perf_set, PERF_CONN_U2_SELECTIVE_HMAC);
            hip_perf_start_benchmark(perf_set, PERF_CONN_U3_SELECTIVE_HMAC);
#endif
            HIP_IFEL(signaling_build_param_selective_hmac(ctx->output_msg, &ctx->hadb_entry->hip_hmac_out,
                                                          HIP_PARAM_SIGNALING_SELECTIVE_HMAC), -1,
                     "Building of Selective HMAC failed\n");
#ifdef CONFIG_HIP_PERFORMANCE
            HIP_DEBUG("Stop PERF_CONN_U2_SELECTIVE_HMAC, PERF_CONN_U3_SELECTIVE_HMAC, "
                      "PERF_I2_SELECTIVE_HMAC\n");
            hip_perf_stop_benchmark(perf_set, PERF_I2_SELECTIVE_HMAC);
            hip_perf_stop_benchmark(perf_set, PERF_CONN_U2_SELECTIVE_HMAC);
            hip_perf_stop_benchmark(perf_set, PERF_CONN_U3_SELECTIVE_HMAC);

            HIP_DEBUG("Start PERF_CONN_U2_SELECTIVE_HOST_SIGN, PERF_CONN_U3_SELECTIVE_HOST_SIGN, "
                      "PERF_I2_SELECTIVE_HOST_SIGN\n");
            hip_perf_start_benchmark(perf_set, PERF_I2_SELECTIVE_HOST_SIGN);
            hip_perf_start_benchmark(perf_set, PERF_CONN_U2_SELECTIVE_HOST_SIGN);
            hip_perf_start_benchmark(perf_set, PERF_CONN_U3_SELECTIVE_HOST_SIGN);
#endif
            switch (HIP_DEFAULT_HI_ALGO) {
            case HIP_HI_RSA:
                if (signaling_hip_rsa_selective_sign(ctx->hadb_entry->our_priv_key, ctx->output_msg)) {
                    HIP_ERROR("Could not create signature\n");
                    return -EINVAL;
                }
                break;
            case HIP_HI_ECDSA:
                if (signaling_hip_ecdsa_selective_sign(ctx->hadb_entry->our_priv_key, ctx->output_msg)) {
                    HIP_ERROR("Could not create signature\n");
                    return -EINVAL;
                }
                break;
            case HIP_HI_DSA:
                if (signaling_hip_dsa_selective_sign(ctx->hadb_entry->our_priv_key, ctx->output_msg)) {
                    HIP_ERROR("Could not create signature\n");
                    return -EINVAL;
                }
                break;
            }
#ifdef CONFIG_HIP_PERFORMANCE
            HIP_DEBUG("Stop PERF_CONN_U2_SELECTIVE_HOST_SIGN, PERF_CONN_U3_SELECTIVE_HOST_SIGN, "
                      "PERF_I2_SELECTIVE_HOST_SIGN\n");
            hip_perf_stop_benchmark(perf_set, PERF_I2_SELECTIVE_HOST_SIGN);
            hip_perf_stop_benchmark(perf_set, PERF_CONN_U2_SELECTIVE_HOST_SIGN);
            hip_perf_stop_benchmark(perf_set, PERF_CONN_U3_SELECTIVE_HOST_SIGN);
#endif
        } else {
            if (hip_mac_and_sign_packet(ctx->output_msg, ctx->hadb_entry)) {
                HIP_ERROR("failed to sign and mac outbound packet\n");
                return -1;
            }
        }
    } else if (update_type == SIGNALING_THIRD_BEX_UPDATE) {
        sig_state->flag_user_sig = 0;
    }

out_err:
    return err;
}

int signaling_hmac2_and_sign(const uint8_t packet_type, const uint32_t ha_state,
                             struct hip_packet_context *ctx)
{
    int                          err = 0;
    struct signaling_hipd_state *sig_state;

    HIP_IFEL(!ctx->hadb_entry, 0, "No hadb entry.\n");
    HIP_IFEL(!(sig_state = lmod_get_state_item(ctx->hadb_entry->hip_modular_state, "signaling_hipd_state")),
             0, "failed to retrieve state for signaling\n");

    if (sig_state->flag_offer_type == OFFER_SELECTIVE_SIGNED) {
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Start PERF_R2_SELECTIVE_HMAC\n");
        hip_perf_start_benchmark(perf_set, PERF_R2_SELECTIVE_HMAC);
#endif
        if (signaling_build_param_selective_hmac2(ctx->output_msg,
                                                  &ctx->hadb_entry->hip_hmac_out,
                                                  ctx->hadb_entry->our_pub)) {
            HIP_ERROR("Failed to build parameter HMAC2 contents.\n");
            return -1;
        }
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Stop PERF_R2_SELECTIVE_HMAC\n");
        hip_perf_stop_benchmark(perf_set, PERF_R2_SELECTIVE_HMAC);

        HIP_DEBUG("Start PERF_R2_SELECTIVE_HOST_SIGN\n");
        hip_perf_start_benchmark(perf_set, PERF_R2_SELECTIVE_HOST_SIGN);
#endif
        switch (HIP_DEFAULT_HI_ALGO) {
        case HIP_HI_RSA:
            if (signaling_hip_rsa_selective_sign(ctx->hadb_entry->our_priv_key, ctx->output_msg)) {
                HIP_ERROR("Could not create signature\n");
                return -EINVAL;
            }
            break;
        case HIP_HI_ECDSA:
            if (signaling_hip_ecdsa_selective_sign(ctx->hadb_entry->our_priv_key, ctx->output_msg)) {
                HIP_ERROR("Could not create signature\n");
                return -EINVAL;
            }
            break;
        case HIP_HI_DSA:
            if (signaling_hip_dsa_selective_sign(ctx->hadb_entry->our_priv_key, ctx->output_msg)) {
                HIP_ERROR("Could not create signature\n");
                return -EINVAL;
            }
            break;
        }
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Stop PERF_R2_SELECTIVE_HOST_SIGN\n");
        hip_perf_stop_benchmark(perf_set, PERF_R2_SELECTIVE_HOST_SIGN);
#endif
    } else {
        if (hip_hmac2_and_sign(packet_type, ha_state, ctx)) {
            HIP_ERROR("failed to sign and mac outbound packet\n");
            return -1;
        }
    }

out_err:
    return err;
}

int signaling_add_user_signature(UNUSED const uint8_t packet_type, UNUSED const uint32_t ha_state, struct hip_packet_context *ctx)
{
    int                          err = 0;
    struct signaling_hipd_state *sig_state;


    HIP_IFEL(!ctx->hadb_entry, 0, "No hadb entry.\n");
    HIP_IFEL(!(sig_state = lmod_get_state_item(ctx->hadb_entry->hip_modular_state, "signaling_hipd_state")),
             0, "failed to retrieve state for signaling\n");

    if (sig_state->flag_user_sig == 1) {
        HIP_DEBUG("Request for the user to sign this packet.\n");
        HIP_IFEL(signaling_build_param_user_signature(ctx->output_msg, sig_state->pending_conn->uid,
                                                      (sig_state->flag_offer_type == OFFER_SELECTIVE_SIGNED ? 1 : 0)),
                 0, "User failed to sign packet.\n");
    }

    HIP_IFEL(signaling_hipd_state_initialize_offer_groups(sig_state), -1,
             "Could not reinitialize the service offer groups storage\n");
    HIP_IFEL(signaling_hipd_state_initialize_mb_certs(sig_state), -1,
             "Could not reinitialize the service offer groups storage\n");

out_err:
    return err;
}

int signaling_generic_handle_service_offers(const uint8_t packet_type, struct hip_packet_context *ctx,
                                            struct signaling_connection *recv_conn,
                                            uint16_t flag_service_offer_signed,
                                            struct signaling_flags_info_req   *flags_info_requested,
                                            uint8_t role /*Role of the end-point on receiving HIP_UPDATE*/)
{
    int                                  err       = 0;
    struct signaling_hipd_state         *sig_state = NULL;
    struct signaling_param_service_offer param_service_offer;
    const struct hip_tlv_common         *param = NULL;

    HIP_IFEL(!ctx->hadb_entry, 0, "No hadb entry.\n");
    HIP_IFEL(!(sig_state = lmod_get_state_item(ctx->hadb_entry->hip_modular_state, "signaling_hipd_state")),
             0, "failed to retrieve state for signaling\n");

    // Check if the context has already been looked up
    if (packet_type == HIP_I2 || (packet_type == HIP_UPDATE && role == RESPONDER)) {
        if (signaling_check_if_app_or_user_info_req(ctx) == 1) {
            signaling_get_connection_context(recv_conn, &sig_state->pending_conn_context, RESPONDER);
        } else {
            memcpy(&sig_state->pending_conn_context.host, &signaling_persistent_host, sizeof(struct signaling_host_context));
        }
        signaling_port_pairs_from_hipd_state_by_app_name(sig_state, recv_conn->application_name,
                                                         sig_state->pending_conn_context.app.sockets);
    } else {
        /* As connection context has already been fetched, we can reuse the value at pending_{conn, conn_context} */
        signaling_port_pairs_from_hipd_state_by_app_name(sig_state, sig_state->pending_conn->application_name,
                                                         sig_state->pending_conn_context.app.sockets);
    }

    if (flag_service_offer_signed == OFFER_SIGNED) {
        signaling_build_response_to_service_offer_s(ctx, *recv_conn, sig_state, flags_info_requested);
    } else if (flag_service_offer_signed == OFFER_UNSIGNED || flag_service_offer_signed == OFFER_SELECTIVE_SIGNED) {
        if ((param = hip_get_param(ctx->input_msg, HIP_PARAM_SIGNALING_SERVICE_OFFER))) {
            do {
                if (hip_get_param_type(param) == HIP_PARAM_SIGNALING_SERVICE_OFFER) {
                    HIP_IFEL(signaling_copy_service_offer(&param_service_offer, (const struct signaling_param_service_offer *) (param)),
                             -1, "Could not copy connection context\n");
                    /* Verify Service Signature for Selective Signing*/
                    if (flag_service_offer_signed == OFFER_SELECTIVE_SIGNED) {
#ifdef CONFIG_HIP_PERFORMANCE
                        if (packet_type == HIP_UPDATE) {
                            HIP_DEBUG("Start PERF_CONN_U2_VERIFY_MBOX_SIGN, PERF_CONN_U3_VERIFY_MBOX_SIGN\n");
                            hip_perf_start_benchmark(perf_set, PERF_CONN_U2_VERIFY_MBOX_SIGN);
                            hip_perf_start_benchmark(perf_set, PERF_CONN_U3_VERIFY_MBOX_SIGN);
                        } else {
                            HIP_DEBUG("Start PERF_I2_VERIFY_MBOX_SIGN, PERF_R2_VERIFY_MBOX_SIGN\n");
                            hip_perf_start_benchmark(perf_set, PERF_I2_VERIFY_MBOX_SIGN);
                            hip_perf_start_benchmark(perf_set, PERF_R2_VERIFY_MBOX_SIGN);
                        }
#endif
                        HIP_IFEL((signaling_verify_mb_sig_selective_s(sig_state, &param_service_offer) != 1),
                                 -1, " Error verifying service signature on selective ack\n");
#ifdef CONFIG_HIP_PERFORMANCE
                        if (packet_type == HIP_UPDATE) {
                            HIP_DEBUG("Stop PERF_CONN_U2_VERIFY_MBOX_SIGN, PERF_CONN_U3_VERIFY_MBOX_SIGN\n");
                            hip_perf_stop_benchmark(perf_set, PERF_CONN_U2_VERIFY_MBOX_SIGN);
                            hip_perf_stop_benchmark(perf_set, PERF_CONN_U3_VERIFY_MBOX_SIGN);
                        } else {
                            HIP_DEBUG("Stop PERF_I2_VERIFY_MBOX_SIGN, PERF_R2_VERIFY_MBOX_SIGN\n");
                            hip_perf_stop_benchmark(perf_set, PERF_I2_VERIFY_MBOX_SIGN);
                            hip_perf_stop_benchmark(perf_set, PERF_R2_VERIFY_MBOX_SIGN);
                        }
#endif
                    }
                    if (signaling_get_info_req_from_service_offer(&param_service_offer, flags_info_requested)) {
                        HIP_DEBUG("Building of application context parameter failed.\n");
                        err = 0;
                    }
                }
            } while ((param = hip_get_next_param(ctx->input_msg, param)));
        } else {
            HIP_DEBUG("No Service Offer from middleboxes. Nothing to do.\n");
        }
        if (signaling_build_response_to_service_offer_u(ctx->output_msg, *recv_conn,
                                                        &sig_state->pending_conn_context,
                                                        flags_info_requested)) {
            HIP_DEBUG("Building of application context parameter failed.\n");
            err = 0;
        }
    }
out_err:
    return err;
}

int signaling_update_check_packet(UNUSED const uint8_t packet_type, UNUSED const uint32_t ha_state,
                                  struct hip_packet_context *ctx)
{
    int                          err         = 0;
    const struct hip_tlv_common *param       = NULL;
    int                          update_type = 0;

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_UPDATE\n");
    hip_perf_start_benchmark(perf_set, PERF_UPDATE);
#endif

    /* RFC 5201 Section 5.4.4: If there is no corresponding HIP association,
     * the implementation MAY reply with an ICMP Parameter Problem. */
    HIP_IFEL(!ctx->hadb_entry, -1, "No host association database entry found.\n");

    HIP_IFEL((update_type = signaling_get_update_type(ctx->input_msg)) < 0, -1,
             "HIP Update type can't be determined\n");
    ;
    /* The HMAC parameter covers the same parts of a packet as the PK signature.
     * Therefore, we can omit the signature check at the end-host. */
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_CONN_U1, PERF_CONN_U2, PERF_CONN_U3\n");
    hip_perf_start_benchmark(perf_set, PERF_CONN_U1);
    hip_perf_start_benchmark(perf_set, PERF_CONN_U2);
    hip_perf_start_benchmark(perf_set, PERF_CONN_U3);

    HIP_DEBUG("Start PERF_CONN_U1_VERIFY_HMAC, PERF_CONN_U2_VERIFY_HMAC, PERF_CONN_U3_VERIFY_HMAC\n");
    hip_perf_start_benchmark(perf_set, PERF_CONN_U1_VERIFY_HMAC);
    hip_perf_start_benchmark(perf_set, PERF_CONN_U2_VERIFY_HMAC);
    hip_perf_start_benchmark(perf_set, PERF_CONN_U3_VERIFY_HMAC);

    if (update_type == SIGNALING_FIRST_BEX_UPDATE) {
        HIP_DEBUG("Start PERF_NEW_UPDATE_CONN_RESPONDER\n");
        hip_perf_start_benchmark(perf_set, PERF_NEW_UPDATE_CONN_RESPONDER);
    }
#endif
    if ((param = hip_get_param(ctx->input_msg, HIP_PARAM_SIGNALING_SELECTIVE_HMAC))) {
        HIP_IFEL(signaling_verify_packet_selective_hmac(ctx->input_msg,
                                                        &ctx->hadb_entry->hip_hmac_in,
                                                        HIP_PARAM_SIGNALING_SELECTIVE_HMAC), -1,
                 "Verification of selective hmac was not successful\n");
    } else {
        HIP_IFEL(hip_verify_packet_hmac(ctx->input_msg,
                                        &ctx->hadb_entry->hip_hmac_in),
                 -1,
                 "HMAC validation on UPDATE failed.\n");
    }
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop PERF_CONN_U1_VERIFY_HMAC, PERF_CONN_U2_VERIFY_HMAC, PERF_CONN_U3_VERIFY_HMAC\n");
    hip_perf_stop_benchmark(perf_set, PERF_CONN_U1_VERIFY_HMAC);
    hip_perf_stop_benchmark(perf_set, PERF_CONN_U2_VERIFY_HMAC);
    hip_perf_stop_benchmark(perf_set, PERF_CONN_U3_VERIFY_HMAC);
#endif
out_err:
    ctx->error = err;
    return err;
}

int signaling_update_check_offer_type(const uint8_t packet_type,
                                      const uint32_t ha_state, struct hip_packet_context *ctx)
{
    int err = 0;
    HIP_DEBUG("Checking if need for encryption\n");
    HIP_IFEL(signaling_i2_check_offer_type(packet_type, ha_state, ctx),
             -1, "Coud check if encrypting endpoint information required or not\n");
out_err:
    return err;
}

int signaling_update_add_diffie_hellman(UNUSED const uint8_t packet_type, UNUSED const uint32_t ha_state,
                                        struct hip_packet_context *ctx)
{
    int err         = 0;
    int update_type = -1;

    if (packet_type == HIP_UPDATE) {
        HIP_IFEL((update_type = signaling_get_update_type(ctx->input_msg)) < 0,
                 -1, "This is no signaling update packet\n");
    }

    if (update_type == SIGNALING_FIRST_BEX_UPDATE) {
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Start PERF_CONN_U1_DIFFIE_HELLMAN, PERF_CONN_U2_DIFFIE_HELLMAN\n");
        hip_perf_start_benchmark(perf_set, PERF_CONN_U1_DIFFIE_HELLMAN);
        hip_perf_start_benchmark(perf_set, PERF_CONN_U2_DIFFIE_HELLMAN);
#endif
        HIP_IFEL(signaling_add_param_dh_to_hip_update(ctx->output_msg), -1,
                 "Could not add add Diffie Hellman parameter to the HIP Update\n");
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Stop PERF_CONN_U1_DIFFIE_HELLMAN, PERF_CONN_U2_DIFFIE_HELLMAN\n");
        hip_perf_stop_benchmark(perf_set, PERF_CONN_U1_DIFFIE_HELLMAN);
        hip_perf_stop_benchmark(perf_set, PERF_CONN_U2_DIFFIE_HELLMAN);
#endif
    }
out_err:
    return err;
}

int signaling_update_group_service_offers(const uint8_t packet_type,
                                          const uint32_t ha_state, struct hip_packet_context *ctx)
{
    int err         = 0;
    int update_type = -1;
    if (packet_type == HIP_UPDATE) {
        HIP_IFEL((update_type = signaling_get_update_type(ctx->input_msg)) < 0,
                 -1, "This is no signaling update packet\n");
    }

    if (update_type == SIGNALING_FIRST_BEX_UPDATE || update_type == SIGNALING_SECOND_BEX_UPDATE) {
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Start PERF_CONN_U1_GROUP_SERVICE_OFFERS, PERF_CONN_U2_GROUP_SERVICE_OFFERS\n");
        hip_perf_start_benchmark(perf_set, PERF_CONN_U1_GROUP_SERVICE_OFFERS);
        hip_perf_start_benchmark(perf_set, PERF_CONN_U2_GROUP_SERVICE_OFFERS);
#endif
        HIP_DEBUG("Grouping sevice offers\n");
        HIP_IFEL(signaling_i2_group_service_offers(packet_type, ha_state, ctx),
                 -1, "Could not group service offers\n");
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Stop PERF_CONN_U1_GROUP_SERVICE_OFFERS, PERF_CONN_U2_GROUP_SERVICE_OFFERS\n");
        hip_perf_stop_benchmark(perf_set, PERF_CONN_U1_GROUP_SERVICE_OFFERS);
        hip_perf_stop_benchmark(perf_set, PERF_CONN_U2_GROUP_SERVICE_OFFERS);
#endif
    }

out_err:
    return err;
}

/*
 * Receive the signed service offers from the service provider in an update packet and respond to them.
 */
int signaling_update_handle_signed_service_offers(const uint8_t packet_type, const uint32_t ha_state, struct hip_packet_context *ctx)
{
    int                          err         = 0;
    struct signaling_hipd_state *sig_state   = NULL;
    int                          update_type = 0;

    HIP_IFEL(!(sig_state = lmod_get_state_item(ctx->hadb_entry->hip_modular_state, "signaling_hipd_state")),
             0, "failed to retrieve state for signaling\n");

    HIP_IFEL((update_type = signaling_get_update_type(ctx->input_msg)) < 0, -1,
             "Can't handle HIP_UPDATE of this type\n");

    if (sig_state->flag_offer_type == OFFER_SIGNED && (update_type == SIGNALING_FIRST_BEX_UPDATE ||
                                                       update_type == SIGNALING_SECOND_BEX_UPDATE)) {
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Start PERF_CONN_U1_HANDLE_SIGNED_OFFER\n");
        hip_perf_start_benchmark(perf_set, PERF_CONN_U1_HANDLE_SIGNED_OFFER);
#endif
        HIP_DEBUG("Message contains signed service offer. Handling them accordingly! \n");
        HIP_IFEL(signaling_i2_handle_service_offers_common(packet_type, ha_state, ctx, OFFER_SIGNED), -1,
                 "Could not handle service Service Offers for I2\n");
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Stop PERF_CONN_U1_HANDLE_SIGNED_OFFER\n");
        hip_perf_stop_benchmark(perf_set, PERF_CONN_U1_HANDLE_SIGNED_OFFER);
#endif
    } else {
        HIP_DEBUG("No signed service offers in the HIP message. Will look for unsigned service offers in a few moment!\n");
    }
out_err:
    return err;
}

int signaling_update_add_signed_service_ack_and_sig_conn(const uint8_t packet_type,
                                                         const uint32_t ha_state, struct hip_packet_context *ctx)
{
    int err         = 0;
    int update_type = 0;

    HIP_IFEL((update_type = signaling_get_update_type(ctx->input_msg)) < 0, -1,
             "Can't handle HIP_UPDATE of this type\n");

    if (update_type == SIGNALING_FIRST_BEX_UPDATE || update_type == SIGNALING_SECOND_BEX_UPDATE) {
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Start PERF_CONN_U2_SIGNED_ACK, PERF_CONN_U3_SIGNED_ACK\n");
        hip_perf_start_benchmark(perf_set, PERF_CONN_U2_SIGNED_ACK);
        hip_perf_start_benchmark(perf_set, PERF_CONN_U3_SIGNED_ACK);
#endif
        HIP_IFEL(signaling_i2_add_signed_service_ack_and_sig_conn(packet_type, ha_state, ctx),
                 -1, "Could not add signed service acks and signalling connection to HIP_UPDATE\n");
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Stop PERF_CONN_U2_SIGNED_ACK, PERF_CONN_U3_SIGNED_ACK\n");
        hip_perf_stop_benchmark(perf_set, PERF_CONN_U2_SIGNED_ACK);
        hip_perf_stop_benchmark(perf_set, PERF_CONN_U3_SIGNED_ACK);
#endif
    }
out_err:
    return err;
}

int signaling_i2_check_hmac(UNUSED const uint8_t packet_type,
                            UNUSED const uint32_t ha_state, struct hip_packet_context *ctx)
{
    int                          err   = 0;
    const struct hip_tlv_common *param = NULL;
    /* Verify HMAC. */
    if ((param = hip_get_param(ctx->input_msg, HIP_PARAM_SIGNALING_SELECTIVE_HMAC))) {
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Start PERF_I2_VERIFY_SELECTIVE_HMAC\n");
        hip_perf_start_benchmark(perf_set, PERF_I2_VERIFY_SELECTIVE_HMAC);
#endif
        if (hip_hidb_hit_is_our(&ctx->input_msg->hits) &&
            hip_hidb_hit_is_our(&ctx->input_msg->hitr)) {
            HIP_IFEL(signaling_verify_packet_selective_hmac(ctx->input_msg,
                                                            &ctx->hadb_entry->hip_hmac_out,
                                                            HIP_PARAM_SIGNALING_SELECTIVE_HMAC), -1,
                     "Verification of selective hmac was not successful\n");
        } else {
            HIP_IFEL(signaling_verify_packet_selective_hmac(ctx->input_msg,
                                                            &ctx->hadb_entry->hip_hmac_in,
                                                            HIP_PARAM_SIGNALING_SELECTIVE_HMAC), -1,
                     "Verification of selective hmac was not successful\n");
        }
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Stop PERF_I2_VERIFY_SELECTIVE_HMAC\n");
        hip_perf_stop_benchmark(perf_set, PERF_I2_VERIFY_SELECTIVE_HMAC);
#endif
    } else {
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Start PERF_I2_VERIFY_HMAC\n");
        hip_perf_start_benchmark(perf_set, PERF_I2_VERIFY_HMAC);
#endif
        if (hip_hidb_hit_is_our(&ctx->input_msg->hits) &&
            hip_hidb_hit_is_our(&ctx->input_msg->hitr)) {
            HIP_IFEL(hip_verify_packet_hmac(ctx->input_msg,
                                            &ctx->hadb_entry->hip_hmac_out),
                     -EPROTO,
                     "HMAC loopback validation on I2 failed. Dropping\n");
        } else {
            HIP_IFEL(hip_verify_packet_hmac(ctx->input_msg,
                                            &ctx->hadb_entry->hip_hmac_in),
                     -EPROTO,
                     "HMAC validation on I2 failed. Dropping the I2 packet.\n");
        }
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Stop PERF_I2_VERIFY_HMAC\n");
        hip_perf_stop_benchmark(perf_set, PERF_I2_VERIFY_HMAC);
#endif
    }
out_err:
    if (err) {
        ctx->error = err;
    }
    return err;
}

int signaling_i2_check_signature(const uint8_t packet_type,
                                 const uint32_t ha_state, struct hip_packet_context *ctx)
{
    int                          err   = 0;
    const struct hip_tlv_common *param = NULL;
    if ((param = hip_get_param(ctx->input_msg, HIP_PARAM_SIGNALING_SELECTIVE_SIGNATURE))) {
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Start PERF_I2_VERIFY_SELECTIVE_HOST_SIG\n");
        hip_perf_start_benchmark(perf_set, PERF_I2_VERIFY_SELECTIVE_HOST_SIG);
#endif
        switch (HIP_DEFAULT_HI_ALGO) {
        case HIP_HI_RSA:
            HIP_IFEL(signaling_hip_rsa_selective_verify(ctx->hadb_entry->peer_pub_key,
                                                        ctx->input_msg), -1,
                     "RSA Signature verification in I2 failed\n");
            break;
        case HIP_HI_ECDSA:
            HIP_IFEL(signaling_hip_ecdsa_selective_verify(ctx->hadb_entry->peer_pub_key,
                                                          ctx->input_msg), -1,
                     "ECDSA Signature verification in I2 failed\n");
            break;
        case HIP_HI_DSA:
            HIP_IFEL(signaling_hip_dsa_selective_verify(ctx->hadb_entry->peer_pub_key,
                                                        ctx->input_msg), -1,
                     "DSA Signature verification in I2 failed\n");
            break;
        }
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Stop PERF_I2_VERIFY_SELECTIVE_HOST_SIG\n");
        hip_perf_stop_benchmark(perf_set, PERF_I2_VERIFY_SELECTIVE_HOST_SIG);
#endif
    } else {
        HIP_IFEL(hip_check_i2_signature(packet_type, ha_state, ctx), -1,
                 "Signature verification in i2 successful\n");
    }
out_err:
    return err;
}

int signaling_i2_check_offer_type(UNUSED const uint8_t packet_type,
                                  UNUSED const uint32_t ha_state, struct hip_packet_context *ctx)
{
    int                          err       = 0;
    struct signaling_hipd_state *sig_state = NULL;

    HIP_IFEL(!ctx->hadb_entry, 0, "No hadb entry.\n");
    HIP_IFEL(!(sig_state = lmod_get_state_item(ctx->hadb_entry->hip_modular_state, "signaling_hipd_state")),
             0, "failed to retrieve state for signaling\n");
    sig_state->flag_offer_type = signaling_hip_msg_contains_signed_service_offer(ctx->input_msg);

    HIP_DEBUG("OFFER_TYPE = %u \n", sig_state->flag_offer_type);
out_err:
    return err;
}

int signaling_i2_group_service_offers(UNUSED const uint8_t packet_type,
                                      UNUSED const uint32_t ha_state,
                                      struct hip_packet_context *ctx)
{
    int                          err       = 0;
    int                          j         = 0, k = 0;
    struct signaling_hipd_state *sig_state = NULL;
    struct service_offer_groups  offer_groups[MAX_NUM_OFFER_GROUPS];
    struct service_offer_groups  temp_offer_grp = { { 0 } };

    HIP_IFEL(!ctx->hadb_entry, 0, "No hadb entry.\n");
    HIP_IFEL(!(sig_state = lmod_get_state_item(ctx->hadb_entry->hip_modular_state, "signaling_hipd_state")),
             0, "failed to retrieve state for signaling\n");

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_R2_GROUP_SERVICE_OFFERS, PERF_I2_GROUP_SERVICE_OFFERS\n");
    hip_perf_start_benchmark(perf_set, PERF_I2_GROUP_SERVICE_OFFERS);
    hip_perf_start_benchmark(perf_set, PERF_R2_GROUP_SERVICE_OFFERS);
#endif
    if (sig_state->flag_offer_type == OFFER_SIGNED) {
        signaling_hipd_state_initialize_offer_groups(sig_state);
        HIP_DEBUG("Inside group_Service_offers\n");
        for (j = 0; j < MAX_NUM_OFFER_GROUPS; j++) {
            offer_groups[j] = temp_offer_grp;
        }

        /* Information requests into individual place holders. We will merge the groups later */
        signaling_split_info_req_to_groups(sig_state, offer_groups, ctx);
        HIP_DEBUG("Service_offers split into groups\n");

        /* Merge the groups which have similar requests */
        signaling_merge_info_req_to_similar_groups(offer_groups, sig_state);
        HIP_DEBUG("Similar Service_offers merged.\n");

        /*Now print the offer groups*/
        for (j = 0; sig_state->offer_groups[j] != NULL; j++) {
            HIP_DEBUG("=============================================================\n");
            for (k = 0; k < sig_state->offer_groups[j]->num_info_req; k++) {
                HIP_DEBUG("Info requested =  %d at j = %d\n", sig_state->offer_groups[j]->info_requests[k], j);
            }

            for (k = 0; k < sig_state->offer_groups[j]->num_mboxes; k++) {
                HIP_DEBUG("Info requested by %d\n", sig_state->offer_groups[j]->mbox[k]);
            }
            HIP_DEBUG("=============================================================\n");
        }
    } else if (sig_state->flag_offer_type == OFFER_SELECTIVE_SIGNED) {
        signaling_hipd_state_initialize_offer_groups(sig_state);
        HIP_DEBUG("Inside group_Service_offers\n");
        for (j = 0; j < MAX_NUM_OFFER_GROUPS; j++) {
            offer_groups[j] = temp_offer_grp;
        }

        /* Information requests into individual place holders. We will merge the groups later */
        signaling_split_info_req_to_groups(sig_state, offer_groups, ctx);
        HIP_DEBUG("Service_offers split into groups\n");

        /* Build the info remove list to be used when building selective
         * service acknowledgement*/
        signaling_remove_list_info_req(offer_groups, sig_state);
        HIP_DEBUG("Info req remove list built.\n");

        /*Now print the offer groups*/
        for (j = 0; sig_state->offer_groups[j] != NULL; j++) {
            HIP_DEBUG("=============================================================\n");
            for (k = 0; k < sig_state->offer_groups[j]->num_info_req; k++) {
                HIP_DEBUG("Info to be removed =  %d at j = %d\n", sig_state->offer_groups[j]->info_requests[k], j);
            }

            for (k = 0; k < sig_state->offer_groups[j]->num_mboxes; k++) {
                HIP_DEBUG("Info to be removed by %d\n", sig_state->offer_groups[j]->mbox[k]);
            }
            HIP_DEBUG("=============================================================\n");
        }
    }
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop PERF_R2_GROUP_SERVICE_OFFERS, PERF_I2_GROUP_SERVICE_OFFERS\n");
    hip_perf_stop_benchmark(perf_set, PERF_I2_GROUP_SERVICE_OFFERS);
    hip_perf_stop_benchmark(perf_set, PERF_R2_GROUP_SERVICE_OFFERS);
#endif
out_err:
    return err;
}

/*
 * Receive the service offers from the service provider and respond to them.
 */
int signaling_i2_handle_signed_service_offers(const uint8_t packet_type, const uint32_t ha_state, struct hip_packet_context *ctx)
{
    int                          err       = 0;
    struct signaling_hipd_state *sig_state = NULL;

    HIP_DEBUG("Handling Signed Service offers from the mbox\n");
    HIP_IFEL(!(sig_state = lmod_get_state_item(ctx->hadb_entry->hip_modular_state, "signaling_hipd_state")),
             0, "failed to retrieve state for signaling\n");

    if (sig_state->flag_offer_type == OFFER_SIGNED) {
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Start PERF_I2_HANDLE_SIGNED_SERVICE_OFFER\n");
        hip_perf_start_benchmark(perf_set, PERF_I2_HANDLE_SIGNED_SERVICE_OFFER);
#endif
        HIP_DEBUG("Message contains signed service offer. Handling them accordingly! \n");
        HIP_IFEL(signaling_i2_handle_service_offers_common(packet_type, ha_state, ctx, OFFER_SIGNED), -1,
                 "Could not handle service Service Offers for I2\n");
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Stop PERF_I2_HANDLE_SIGNED_SERVICE_OFFER\n");
        hip_perf_stop_benchmark(perf_set, PERF_I2_HANDLE_SIGNED_SERVICE_OFFER);
#endif
    } else {
        HIP_DEBUG("No signed service offers in the HIP message. Will look for unsigned service offers in a few moment!\n");
    }

out_err:
    return err;
}

/*
 * Receive the service offers from the service provider and respond to them.
 */
int signaling_i2_handle_unsigned_service_offers(const uint8_t packet_type, const uint32_t ha_state, struct hip_packet_context *ctx)
{
    int                          err       = 0;
    struct signaling_hipd_state *sig_state = NULL;
    HIP_IFEL(!(sig_state = lmod_get_state_item(ctx->hadb_entry->hip_modular_state, "signaling_hipd_state")),
             0, "failed to retrieve state for signaling\n");

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_I2_HANDLE_UNSIGNED_SERVICE_OFFER, PERF_I2_HANDLE_SELECTIVE_SIGNED_OFFER\n");
    hip_perf_start_benchmark(perf_set, PERF_I2_HANDLE_UNSIGNED_SERVICE_OFFER);
    hip_perf_start_benchmark(perf_set, PERF_I2_HANDLE_SELECTIVE_SIGNED_OFFER);
#endif
    if (sig_state->flag_offer_type != OFFER_SIGNED) {
        HIP_DEBUG("Message contains unsigned service offer. Handling them accordingly! \n");
        HIP_IFEL(signaling_i2_handle_service_offers_common(packet_type, ha_state, ctx, sig_state->flag_offer_type), -1,
                 "Could not handle service Service Offers for I2\n");
    }

out_err:
    return err;
}

/*
 * Receive the service offers from the service provider and respond to them.
 */
int signaling_i2_handle_service_offers_common(UNUSED const uint8_t packet_type, UNUSED const uint32_t ha_state,
                                              struct hip_packet_context *ctx, uint8_t flag)
{
    int                             err       = 0;
    struct signaling_hipd_state    *sig_state = NULL;
    struct signaling_connection     temp_conn;
    struct signaling_connection     new_conn;
    struct signaling_connection    *conn;
    struct signaling_flags_info_req flags_info_requested;
    int                             update_type = 0;

    /* sanity checks */
    HIP_IFEL(!ctx->hadb_entry, 0, "No hadb entry.\n");
    HIP_IFEL(!(sig_state = lmod_get_state_item(ctx->hadb_entry->hip_modular_state, "signaling_hipd_state")),
             0, "failed to retrieve state for signaling\n");

    if (packet_type == HIP_UPDATE) {
        HIP_IFEL((update_type = signaling_get_update_type(ctx->input_msg)) < 0, -1,
                 "Can't handle HIP_UPDATE of this type\n");
        if (update_type == SIGNALING_FIRST_BEX_UPDATE) {
            HIP_DEBUG("Handling a first update U1 just like R1\n");
            HIP_IFEL(signaling_init_connection_from_msg(&new_conn, ctx->input_msg, IN),
                     -1, "Could not init connection context from I2 \n");
            HIP_DEBUG("Adding the connection information to the hipd state.\n");
            HIP_IFEL(!(conn = signaling_hipd_state_add_connection(sig_state, &new_conn)),
                     -1, "Could not add new connection to hipd state. \n");
            HIP_DEBUG("Adding to hipd state since it's an update\n");
        } else if (update_type == SIGNALING_SECOND_BEX_UPDATE) {
            HIP_DEBUG("Handling a second update U2 just like I2\n");
        }
    } else if (packet_type == HIP_R1) {
        HIP_DEBUG("Handling an R1\n");
        // We have already looked for connection context after sending I1 or the FIRST BEX UPDATE, so must not be NULL
        /* Sanity Check*/
        if (!sig_state->pending_conn) {
            HIP_DEBUG("We have no connection context for this host associtaion. \n");
            return 0;
        }
    } else {
        HIP_ERROR("Packet is neither R1 nor first update U1.\n");
        err = -1;
        goto out_err;
    }

    // I will look into if I can improve the logic
    signaling_init_connection(&temp_conn);
    memcpy(&temp_conn, sig_state->pending_conn, sizeof(struct signaling_connection));
    temp_conn.src_port = htons(sig_state->pending_conn->src_port);
    temp_conn.dst_port = htons(sig_state->pending_conn->dst_port);

    signaling_info_req_flag_init(&flags_info_requested);
    HIP_IFEL(signaling_hipd_state_initialize_service_ack(sig_state), -1,
             "Could not reinitialize the service ack storage\n");

    // Adding response to service offers
    HIP_IFEL(signaling_generic_handle_service_offers(packet_type, ctx,
                                                     sig_state->pending_conn, flag,
                                                     &flags_info_requested, (packet_type == HIP_UPDATE &&
                                                                             update_type == SIGNALING_SECOND_BEX_UPDATE) ? INITIATOR : RESPONDER),
             -1, "Could not handle service offer\n");

    if (signaling_info_req_flag_check(&flags_info_requested, USER_INFO_ID)) {
        sig_state->flag_user_sig = 1;
    }

    /* Now adding the signaling connection to the HIP_I2 message*/
    if (flag != OFFER_SIGNED) {
#ifdef CONFIG_HIP_PERFORMANCE
        if (packet_type == HIP_R1) {
            HIP_DEBUG("Stop PERF_I2_HANDLE_UNSIGNED_SERVICE_OFFER, PERF_I2_HANDLE_SELECTIVE_SIGNED_OFFER\n");
            hip_perf_stop_benchmark(perf_set, PERF_I2_HANDLE_UNSIGNED_SERVICE_OFFER);
            hip_perf_stop_benchmark(perf_set, PERF_I2_HANDLE_SELECTIVE_SIGNED_OFFER);
        } else if (packet_type == HIP_UPDATE) {
            HIP_DEBUG("Stop PERF_CONN_U1_HANDLE_UNSIGNED_SERVICE_OFFER, PERF_CONN_U1_HANDLE_SELECTIVE_SIGNED_OFFER\n");
            hip_perf_stop_benchmark(perf_set, PERF_CONN_U1_HANDLE_UNSIGNED_SERVICE_OFFER);
            hip_perf_stop_benchmark(perf_set, PERF_CONN_U1_HANDLE_SELECTIVE_SIGNED_OFFER);
        }
#endif
        HIP_IFEL(hip_build_param_contents(ctx->output_msg, &temp_conn, HIP_PARAM_SIGNALING_CONNECTION, sizeof(struct signaling_connection)),
                 -1, "build signaling_connection failed \n");
    }

    // Now Add the service acknowledgements
    if (flag == OFFER_UNSIGNED) {
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Start PERF_I2_UNSIGNED_SERVICE_ACK, PERF_CONN_U2_UNSIGNED_ACK\n");
        hip_perf_start_benchmark(perf_set, PERF_I2_UNSIGNED_SERVICE_ACK);
        hip_perf_start_benchmark(perf_set, PERF_CONN_U2_UNSIGNED_ACK);
#endif
        HIP_IFEL(signaling_build_service_ack_u(ctx->input_msg, ctx->output_msg),
                 -1, "Building Acknowledgment to Service Offer failed");
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Stop PERF_I2_UNSIGNED_SERVICE_ACK, PERF_CONN_U2_UNSIGNED_ACK\n");
        hip_perf_stop_benchmark(perf_set, PERF_I2_UNSIGNED_SERVICE_ACK);
        hip_perf_stop_benchmark(perf_set, PERF_CONN_U2_UNSIGNED_ACK);
#endif
    } else if (flag == OFFER_SELECTIVE_SIGNED) {
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Start PERF_I2_SELECTIVE_SIGNED_SERVICE_ACK, PERF_CONN_U2_SELECTIVE_SIGNED_ACK\n");
        hip_perf_start_benchmark(perf_set, PERF_I2_SELECTIVE_SIGNED_SERVICE_ACK);
        hip_perf_start_benchmark(perf_set, PERF_CONN_U2_SELECTIVE_SIGNED_ACK);
#endif
        HIP_IFEL(signaling_build_service_ack_selective_s(ctx->input_msg, ctx->output_msg, sig_state),
                 -1, "Building Acknowledgment to Service Offer failed");
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Stop PERF_I2_SELECTIVE_SIGNED_SERVICE_ACK, PERF_CONN_U2_SELECTIVE_SIGNED_ACK\n");
        hip_perf_stop_benchmark(perf_set, PERF_I2_SELECTIVE_SIGNED_SERVICE_ACK);
        hip_perf_stop_benchmark(perf_set, PERF_CONN_U2_SELECTIVE_SIGNED_ACK);
#endif
    }

out_err:
    return err;
}

/*
 * This has to be done when signed service offers are received because the signaling_connection and service ack have to added after building
 * HOST_ID and ESP_TRANSFORM
 */
int signaling_i2_add_signed_service_ack_and_sig_conn(UNUSED const uint8_t packet_type,
                                                     UNUSED const uint32_t ha_state, struct hip_packet_context *ctx)
{
    int                          err         = 0;
    int                          update_type = -1;
    struct signaling_hipd_state *sig_state;
    struct signaling_connection  temp_conn;


    HIP_DEBUG("Building signaling connection and signed service ack\n");
    HIP_IFEL(!ctx->hadb_entry, 0, "No hadb entry.\n");
    HIP_IFEL(!(sig_state = lmod_get_state_item(ctx->hadb_entry->hip_modular_state, "signaling_hipd_state")),
             0, "failed to retrieve state for signaling\n");

    if (sig_state->flag_offer_type == OFFER_SIGNED) {
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Start PERF_I2_SIGNED_SERVICE_ACK\n");
        hip_perf_start_benchmark(perf_set, PERF_I2_SIGNED_SERVICE_ACK);
#endif
        if (packet_type == HIP_UPDATE) {
            HIP_IFEL((update_type = signaling_get_update_type(ctx->input_msg)) < 0,
                     -1, "This is no signaling update packet\n");
        }


        if (packet_type == HIP_R1 || update_type == SIGNALING_FIRST_BEX_UPDATE ||
            update_type == SIGNALING_SECOND_BEX_UPDATE) {
            signaling_init_connection(&temp_conn);
            memcpy(&temp_conn, sig_state->pending_conn, sizeof(struct signaling_connection));
            temp_conn.src_port = htons(sig_state->pending_conn->src_port);
            temp_conn.dst_port = htons(sig_state->pending_conn->dst_port);
            HIP_IFEL(hip_build_param_contents(ctx->output_msg, &temp_conn, HIP_PARAM_SIGNALING_CONNECTION, sizeof(struct signaling_connection)),
                     -1, "build signaling_connection failed \n");
        }

        /* ========== Create and send the ack for signed service offer  ===============*/
        HIP_IFEL(signaling_build_service_ack_s(sig_state, ctx, mb_dh_pub_key, mb_dh_pub_key_len),
                 -1, "Could not build ack for signed service offer\n");
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Start PERF_I2_SIGNED_SERVICE_ACK\n");
        hip_perf_start_benchmark(perf_set, PERF_I2_SIGNED_SERVICE_ACK);
#endif
    }
    HIP_DEBUG("Signation connection and service acknowledgement added \n");
out_err:
    return err;
}

int signaling_r2_check_hmac2_and_sign(UNUSED const uint8_t packet_type,
                                      UNUSED const uint32_t ha_state, struct hip_packet_context *ctx)
{
    int                          err   = 0;
    const struct hip_tlv_common *param = NULL;
    /* Verify HMAC. */
    if ((param = hip_get_param(ctx->input_msg, HIP_PARAM_SIGNALING_SELECTIVE_HMAC))) {
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Start PERF_R2_VERIFY_SELECTIVE_HMAC\n");
        hip_perf_start_benchmark(perf_set, PERF_R2_VERIFY_SELECTIVE_HMAC);
#endif
        if (hip_hidb_hit_is_our(&ctx->input_msg->hits) &&
            hip_hidb_hit_is_our(&ctx->input_msg->hitr)) {
            HIP_IFEL(signaling_verify_packet_selective_hmac2(ctx->input_msg,
                                                             &ctx->hadb_entry->hip_hmac_out,
                                                             ctx->hadb_entry->peer_pub), -1,
                     "Verification of selective hmac was not successful\n");
        } else {
            HIP_IFEL(signaling_verify_packet_selective_hmac2(ctx->input_msg,
                                                             &ctx->hadb_entry->hip_hmac_in,
                                                             ctx->hadb_entry->peer_pub), -1,
                     "Verification of selective hmac was not successful\n");
        }
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Stop PERF_R2_VERIFY_SELECTIVE_HMAC\n");
        hip_perf_stop_benchmark(perf_set, PERF_R2_VERIFY_SELECTIVE_HMAC);
#endif
    } else {
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Start PERF_R2_VERIFY_HMAC\n");
        hip_perf_start_benchmark(perf_set, PERF_R2_VERIFY_HMAC);
#endif
        if (hip_hidb_hit_is_our(&ctx->input_msg->hits) &&
            hip_hidb_hit_is_our(&ctx->input_msg->hitr)) {
            HIP_IFEL(hip_verify_packet_hmac2(ctx->input_msg,
                                             &ctx->hadb_entry->hip_hmac_out,
                                             ctx->hadb_entry->peer_pub),
                     -EPROTO,
                     "HMAC loopback validation on I2 failed. Dropping\n");
        } else {
            HIP_IFEL(hip_verify_packet_hmac2(ctx->input_msg,
                                             &ctx->hadb_entry->hip_hmac_in,
                                             ctx->hadb_entry->peer_pub),
                     -EPROTO,
                     "HMAC validation on I2 failed. Dropping the I2 packet.\n");
        }
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Stop PERF_R2_VERIFY_HMAC\n");
        hip_perf_stop_benchmark(perf_set, PERF_R2_VERIFY_HMAC);
#endif
    }

    /* Validate signature */
    if ((param = hip_get_param(ctx->input_msg, HIP_PARAM_SIGNALING_SELECTIVE_SIGNATURE))) {
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Start PERF_R2_VERIFY_SELECTIVE_HOST_SIG\n");
        hip_perf_start_benchmark(perf_set, PERF_R2_VERIFY_SELECTIVE_HOST_SIG);
#endif
        switch (HIP_DEFAULT_HI_ALGO) {
        case HIP_HI_RSA:
            HIP_IFEL(signaling_hip_rsa_selective_verify(ctx->hadb_entry->peer_pub_key,
                                                        ctx->input_msg), -1,
                     "RSA Signature verification in I2 failed\n");
            break;
        case HIP_HI_ECDSA:
            HIP_IFEL(signaling_hip_ecdsa_selective_verify(ctx->hadb_entry->peer_pub_key,
                                                          ctx->input_msg), -1,
                     "ECDSA Signature verification in I2 failed\n");
            break;
        case HIP_HI_DSA:
            HIP_IFEL(signaling_hip_dsa_selective_verify(ctx->hadb_entry->peer_pub_key,
                                                        ctx->input_msg), -1,
                     "DSA Signature verification in I2 failed\n");
            break;
        }
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Stop PERF_R2_VERIFY_SELECTIVE_HOST_SIG\n");
        hip_perf_stop_benchmark(perf_set, PERF_R2_VERIFY_SELECTIVE_HOST_SIG);
#endif
    } else {
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Start PERF_R2_VERIFY_HOST_SIG\n");
        hip_perf_start_benchmark(perf_set, PERF_R2_VERIFY_HOST_SIG);
#endif
        /* Validate signature */
        HIP_IFEL(ctx->hadb_entry->verify(ctx->hadb_entry->peer_pub_key,
                                         ctx->input_msg),
                 -EINVAL,
                 "R2 signature verification failed.\n");
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Stop PERF_R2_VERIFY_HOST_SIG\n");
        hip_perf_stop_benchmark(perf_set, PERF_R2_VERIFY_HOST_SIG);
#endif
    }
out_err:
    if (err) {
        ctx->error = err;
    }
    return err;
}

int signaling_r2_check_offer_type(const uint8_t packet_type,
                                  const uint32_t ha_state, struct hip_packet_context *ctx)
{
    int err = 0;
    HIP_IFEL(signaling_i2_check_offer_type(packet_type, ha_state, ctx),
             -1, "Coud check if encrypting endpoint information required or not\n");
out_err:
    return err;
}

int signaling_r2_group_service_offers(const uint8_t packet_type,
                                      const uint32_t ha_state, struct hip_packet_context *ctx)
{
    int err = 0;
    HIP_IFEL(signaling_i2_group_service_offers(packet_type, ha_state, ctx),
             -1, "Could not group service offers\n");
out_err:
    return err;
}

/*
 * Receive the service offers from the service provider with the R2 packet and respond to them
 */
int signaling_r2_handle_service_offers(UNUSED const uint8_t packet_type, UNUSED const uint32_t ha_state,
                                       struct hip_packet_context *ctx)
{
    int                             err       = 0;
    struct signaling_hipd_state    *sig_state = NULL;
    struct signaling_connection     new_conn;
    struct signaling_connection    *conn;
    struct signaling_connection     temp_conn;
    struct signaling_flags_info_req flags_info_requested;

    /* sanity checks */
    if (packet_type == HIP_I2) {
        HIP_DEBUG("Handling an I2\n");
    } else if (packet_type == HIP_UPDATE) {
        HIP_DEBUG("Handling a Second BEX update U2 just like I2\n");
    } else {
        HIP_ERROR("Packet is neither I2 nor Second BEX update.\n");
        err = -1;
        goto out_err;
    }


    HIP_IFEL(!ctx->hadb_entry, 0, "No hadb entry.\n");
    HIP_IFEL(!(sig_state = (struct signaling_hipd_state *) lmod_get_state_item(ctx->hadb_entry->hip_modular_state, "signaling_hipd_state")),
             -1, "failed to retrieve state for signaling module\n");
    HIP_IFEL(signaling_init_connection_from_msg(&new_conn, ctx->input_msg, IN),
             -1, "Could not knit connection context from I2 \n");
    signaling_init_connection(&temp_conn);

    signaling_info_req_flag_init(&flags_info_requested);
    HIP_IFEL(signaling_hipd_state_initialize_service_ack(sig_state), -1,
             "Could not reinitialize the service ack storage\n");


    if (sig_state->flag_offer_type != OFFER_SIGNED || packet_type != HIP_UPDATE) {
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Start PERF_R2_HANDLE_UNSIGNED_SERVICE_OFFER, PERF_R2_HANDLE_SELECTIVE_SIGNED_OFFER, PERF_R2_HANDLE_SIGNED_SERVICE_OFFER\n");
        hip_perf_start_benchmark(perf_set, PERF_R2_HANDLE_UNSIGNED_SERVICE_OFFER);
        hip_perf_start_benchmark(perf_set, PERF_R2_HANDLE_SELECTIVE_SIGNED_OFFER);
        hip_perf_start_benchmark(perf_set, PERF_R2_HANDLE_SIGNED_SERVICE_OFFER);
#endif
        HIP_IFEL(signaling_generic_handle_service_offers(packet_type, ctx, &new_conn,
                                                         sig_state->flag_offer_type,
                                                         &flags_info_requested, INITIATOR), -1,
                 "Could not handle service offer\n");
        // Now adding the signaling connection to the HIP_R2 message
        memcpy(&temp_conn, &new_conn, sizeof(struct signaling_connection));
        temp_conn.src_port = htons(new_conn.src_port);
        temp_conn.dst_port = htons(new_conn.dst_port);
        HIP_IFEL(hip_build_param_contents(ctx->output_msg, &temp_conn, HIP_PARAM_SIGNALING_CONNECTION, sizeof(struct signaling_connection)),
                 -1, "build signaling_connection failed \n");
    }

#ifdef CONFIG_HIP_PERFORMANCE
    if (packet_type == HIP_UPDATE) {
        HIP_DEBUG("Stop PERF_CONN_U2_HANDLE_SELECTIVE_SIGNED_OFFER, PERF_CONN_U2_HANDLE_UNSIGNED_SERVICE_OFFER, "
                  "PERF_CONN_U2_HANDLE_SIGNED_OFFER\n");
        hip_perf_stop_benchmark(perf_set, PERF_CONN_U2_HANDLE_UNSIGNED_SERVICE_OFFER);
        hip_perf_stop_benchmark(perf_set, PERF_CONN_U2_HANDLE_SELECTIVE_SIGNED_OFFER);
        hip_perf_stop_benchmark(perf_set, PERF_CONN_U2_HANDLE_SIGNED_OFFER);
    } else {
        HIP_DEBUG("Stop PERF_R2_HANDLE_UNSIGNED_SERVICE_OFFER, PERF_R2_HANDLE_SELECTIVE_SIGNED_OFFER, PERF_R2_HANDLE_SIGNED_SERVICE_OFFER\n");
        hip_perf_stop_benchmark(perf_set, PERF_R2_HANDLE_UNSIGNED_SERVICE_OFFER);
        hip_perf_stop_benchmark(perf_set, PERF_R2_HANDLE_SELECTIVE_SIGNED_OFFER);
        hip_perf_stop_benchmark(perf_set, PERF_R2_HANDLE_SIGNED_SERVICE_OFFER);
    }
#endif

    if (signaling_info_req_flag_check(&flags_info_requested, USER_INFO_ID)) {
        sig_state->flag_user_sig = 1;
    }

    // Now Add the service acknowledgements
    if (sig_state->flag_offer_type == OFFER_UNSIGNED) {
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Start PERF_R2_UNSIGNED_SERVICE_ACK, PERF_CONN_U3_UNSIGNED_ACK\n");
        hip_perf_start_benchmark(perf_set, PERF_R2_UNSIGNED_SERVICE_ACK);
        hip_perf_start_benchmark(perf_set, PERF_CONN_U3_UNSIGNED_ACK);
#endif
        HIP_IFEL(signaling_build_service_ack_u(ctx->input_msg, ctx->output_msg), -1, "Building Acknowledgment to Service Offer failed");
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Stop PERF_R2_UNSIGNED_SERVICE_ACK, PERF_CONN_U3_UNSIGNED_ACK\n");
        hip_perf_stop_benchmark(perf_set, PERF_R2_UNSIGNED_SERVICE_ACK);
        hip_perf_stop_benchmark(perf_set, PERF_CONN_U3_UNSIGNED_ACK);
#endif
    } else if (sig_state->flag_offer_type == OFFER_SELECTIVE_SIGNED) {
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Start PERF_R2_SELECTIVE_SIGNED_SERVICE_ACK, PERF_CONN_U3_SELECTIVE_SIGNED_ACK\n");
        hip_perf_start_benchmark(perf_set, PERF_R2_SELECTIVE_SIGNED_SERVICE_ACK);
        hip_perf_start_benchmark(perf_set, PERF_CONN_U3_SELECTIVE_SIGNED_ACK);
#endif
        HIP_IFEL(signaling_build_service_ack_selective_s(ctx->input_msg, ctx->output_msg, sig_state), -1, "Building Acknowledgment to Service Offer failed");
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Stop PERF_R2_SELECTIVE_SIGNED_SERVICE_ACK, PERF_CONN_U3_SELECTIVE_SIGNED_ACK\n");
        hip_perf_stop_benchmark(perf_set, PERF_R2_SELECTIVE_SIGNED_SERVICE_ACK);
        hip_perf_stop_benchmark(perf_set, PERF_CONN_U3_SELECTIVE_SIGNED_ACK);
#endif
    } else if (packet_type != HIP_UPDATE) {
        HIP_IFEL(signaling_r2_add_signed_service_ack_and_sig_conn(packet_type, ha_state, ctx), -1,
                 "Building Acknowledgment to signed Service Offer failed\n");
    }

    if (packet_type == HIP_I2) {
        HIP_DEBUG("Adding the connection information to the hipd state.\n");
        HIP_IFEL(!(conn = signaling_hipd_state_add_connection(sig_state, &new_conn)),
                 -1, "Could not add new connection to hipd state. \n");
        HIP_DEBUG("Added requests to Service Offer. Sending the request to end-point firewall (hipfw)\n");
        // Tell the firewall/oslayer about the new connection and await it's decision
        HIP_IFEL(signaling_send_connection_confirmation(&ctx->input_msg->hits, &ctx->input_msg->hitr, conn),
                 -1, "Failed to communicate new connection received in I2 to HIPFW\n");
    } else if (packet_type == HIP_UPDATE) {
        HIP_DEBUG("Added requests to Service Offer. Sending the request to end-point firewall (hipfw)\n");
        // Tell the firewall/oslayer about the new connection and await it's decision
        HIP_IFEL(signaling_send_connection_confirmation(&ctx->input_msg->hitr, &ctx->input_msg->hits, &new_conn),
                 -1, "Failed to communicate new connection received in I2 to HIPFW\n");
    }

out_err:
    return err;
}

int signaling_r2_add_signed_service_ack_and_sig_conn(UNUSED const uint8_t packet_type,
                                                     UNUSED const uint32_t ha_state, struct hip_packet_context *ctx)
{
    int err = 0;
    HIP_IFEL(signaling_i2_add_signed_service_ack_and_sig_conn(packet_type, ha_state, ctx),
             -1, "Could not add signed service acks and signalling connection to R2\n");
out_err:
    return err;
}

int signaling_hipd_state_cleanup(UNUSED const uint8_t packet_type,
                                 UNUSED const uint32_t ha_state, struct hip_packet_context *ctx)
{
    int                          err = 0;
    struct signaling_hipd_state *sig_state;


    HIP_IFEL(!ctx->hadb_entry, 0, "No hadb entry.\n");
    HIP_IFEL(!(sig_state = lmod_get_state_item(ctx->hadb_entry->hip_modular_state, "signaling_hipd_state")),
             0, "failed to retrieve state for signaling\n");

    HIP_IFEL(signaling_hipd_state_initialize_service_ack(sig_state), -1,
             "Could not reinitialize the service ack storage\n");
    HIP_IFEL(signaling_hipd_state_initialize_offer_groups(sig_state), -1,
             "Could not reinitialize the service offer groups storage\n");
    HIP_IFEL(signaling_hipd_state_initialize_mb_certs(sig_state), -1,
             "Could not reinitialize the service offer groups storage\n");

out_err:
    return err;
}
