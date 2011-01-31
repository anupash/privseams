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

#include "hipd/hadb.h"
#include "hipd/user.h"
#include "hipd/output.h"


#include "modules/update/hipd/update.h"
#include "modules/signaling/lib/signaling_common_builder.h"

#include "modules/signaling/lib/signaling_oslayer.h"
#include "modules/signaling/lib/signaling_user_api.h"
#include "modules/signaling/lib/signaling_x509_api.h"
#include "modules/signaling/lib/signaling_user_management.h"
#include "signaling_hipd_state.h"
#include "signaling_hipd_msg.h"
#include "signaling_hipd_user_msg.h"

int update_sent = 0;

/**
 * Determine the type of a signaling UPDATE message.
 *
 * @param msg   the UPDATE message
 *
 * @return the signaling update type, or negative if this is no siganling update message
 */
int signaling_get_update_type(struct hip_common *msg) {
    int err = -1;
    const struct signaling_param_app_context *param_app_ctx     = NULL;
    const struct hip_seq *param_seq                             = NULL;
    const struct hip_ack *param_ack                             = NULL;
    const struct hip_cert *param_cert                           = NULL;

    param_app_ctx   = hip_get_param(msg, HIP_PARAM_SIGNALING_APPINFO);
    param_seq       = hip_get_param(msg, HIP_PARAM_SEQ);
    param_ack       = hip_get_param(msg, HIP_PARAM_ACK);
    param_cert      = hip_get_param(msg, HIP_PARAM_CERT);

    if (param_app_ctx && param_seq) {
        return SIGNALING_FIRST_BEX_UPDATE;
    } else if (param_app_ctx && param_ack) {
        return SIGNALING_SECOND_BEX_UPDATE;
    } else if (param_cert && param_seq) {
        return SIGNALING_FIRST_USER_CERT_CHAIN_UPDATE;
    } else if (param_cert && param_ack) {
        return SIGNALING_SECOND_USER_CERT_CHAIN_UPDATE;
    }

    return err;
}

/*
 * Builds either a U1, U2 or U3 update message.
 *
 * @param ha    the host association
 * @param type  the upade type (U1, U2 or U3)
 * @param conn  the connection
 * @param seq   the sequence number for U1 and U2
 * @param ack   the ack number for U2 and U3
 *
 * @return      the update message
 */
static hip_common_t *build_update_message(hip_ha_t *ha,
                                          const int type,
                                          struct signaling_connection *conn,
                                          const uint32_t seq,
                                          const uint32_t ack) {
    int err                 = 0;
    uint16_t mask           = 0;
    struct hip_common *msg_buf   = NULL;

    /* sanity checks */
    HIP_IFEL(!conn, -1, "Cannot build update message from NULL-connection \n");

    /* Allocate and build message */
    HIP_IFEL(!(msg_buf = hip_msg_alloc()),
            -ENOMEM, "Out of memory while allocation memory for the bex update packet\n");
    hip_build_network_hdr(msg_buf, HIP_UPDATE, mask, &ha->hit_our, &ha->hit_peer);

    /* Add sequence number in U1 and U2 */
    if(type == SIGNALING_FIRST_BEX_UPDATE || type == SIGNALING_SECOND_BEX_UPDATE) {
        HIP_IFEL(hip_build_param_seq(msg_buf, seq),
                -1, "Building of SEQ parameter failed\n");
    }
    /* Add ACK paramater in U2 and U3 */
    if (type == SIGNALING_SECOND_BEX_UPDATE || type == SIGNALING_THIRD_BEX_UPDATE) {
        HIP_IFEL(hip_build_param_ack(msg_buf, ack),
                 -1, "Building of ACK parameter failed\n");
    }

    /* Add connection id, this paremeter is critical. */
    HIP_IFEL(signaling_build_param_connection_identifier(msg_buf, conn),
             -1, "Building of connection identifier parameter failed\n");

    /* Add application and user context.
     * These parameters (as well as the user's signature are non-critical */
    if (type == SIGNALING_FIRST_BEX_UPDATE || type == SIGNALING_SECOND_BEX_UPDATE) {
        if(signaling_build_param_application_context(msg_buf, conn->sockets, &conn->ctx_out.app)) {
            HIP_DEBUG("Building of application context parameter failed\n");
        }
        if(signaling_build_param_user_context(msg_buf, &conn->ctx_out.user)) {
            HIP_DEBUG("Building of user conext parameter failed.\n");
        }
    }

    /* Add host authentication */
    HIP_IFEL(hip_build_param_hmac_contents(msg_buf, &ha->hip_hmac_out),
            -1, "Building of HMAC failed\n");
    HIP_IFEL(ha->sign(ha->our_priv_key, msg_buf),
            -EINVAL, "Could not sign UPDATE. Failing\n");

    /* Add user authentication */
    if(signaling_build_param_user_signature(msg_buf, conn->ctx_out.user.uid)) {
        HIP_DEBUG("User failed to sign UPDATE.\n");
    }

    return msg_buf;

out_err:
    free(msg_buf);
    return NULL;
}

/**
 * Send an I3.
 *
 * @param src_hit   the HIT of the initiator of the BEX
 * @param dst_hit   the HIT of the responder of the BEX
 * @param ctx       the connection context, of the responder which is confirmed in the I3
 *
 * @return 0 on success, negative on error
 */
int signaling_send_I3(hip_ha_t *ha, struct signaling_connection *conn) {
    int err                    = 0;
    uint16_t mask              = 0;
    hip_common_t * msg_buf     = NULL;

    /* sanity tests */
    HIP_IFEL(!ha,       -1, "No host association given \n");
    HIP_IFEL(!conn,     -1, "No connection context given \n");

    /* Allocate and build message */
    HIP_IFEL(!(msg_buf = hip_msg_alloc()),
          -ENOMEM, "Out of memory while allocation memory for the I3 packet\n");
    hip_build_network_hdr(msg_buf, HIP_I3, mask, &ha->hit_our, &ha->hit_peer);

    /* Add certificates if required */

    /* Add connection id. This parameter is critical. */
    HIP_IFEL(signaling_build_param_connection_identifier(msg_buf, conn),
             -1, "Building of connection identifier parameter failed\n");

    /* Add user_auth_request parameter, if received in R2
     * This parameter is critical, if flagged. */
    if (signaling_flag_check(conn->ctx_in.flags, USER_AUTH_REQUEST)) {
        HIP_IFEL(signaling_build_param_user_auth_req_s(msg_buf, 0),
                 -1, "Failed to build signed user authentication request\n");
    }

    /* Add host authentication. */
    HIP_IFEL(hip_build_param_hmac_contents(msg_buf, &ha->hip_hmac_out),
             -1, "Building of HMAC failed\n");
    HIP_IFEL(ha->sign(ha->our_priv_key, msg_buf),
             -EINVAL, "Could not sign I3. Failing\n");

    err = hip_send_pkt(NULL,
                       &ha->peer_addr,
                       (ha->nat_mode ? hip_get_local_nat_udp_port() : 0),
                       ha->peer_udp_port,
                       msg_buf,
                       ha,
                       1);

out_err:
    free(msg_buf);
    return err;
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
                                struct signaling_connection *conn) {
    int err                                 = 0;
    uint32_t seq_id                         = 0;
    hip_ha_t *ha                            = NULL;
    struct update_state * updatestate       = NULL;
    struct hip_common * update_packet_to_send    = NULL;

    /* sanity tests */
    HIP_IFEL(!src_hit, -1, "No source HIT given \n");
    HIP_IFEL(!dst_hit, -1, "No destination HIT given \n");
    HIP_IFEL(!conn,    -1, "No connection context given \n");

    /* Lookup and update state */
    HIP_IFEL(!(ha = hip_hadb_find_byhits(src_hit, dst_hit)),
             -1, "Failed to retrieve hadb entry.\n");
    HIP_IFEL(!(updatestate = (struct update_state *) lmod_get_state_item(ha->hip_modular_state, "update")),
             -1, "Could not get update state for host association.\n");
    updatestate->update_id_out++;
    seq_id = hip_update_get_out_id(updatestate);

    /* Build and send the first update */
    HIP_IFEL(!(update_packet_to_send = build_update_message(ha, SIGNALING_FIRST_BEX_UPDATE, conn, seq_id, 0)),
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
    uint32_t ack_id                                 = 0;
    const struct in6_addr *src_hit                  = NULL;
    const struct in6_addr *dst_hit                  = NULL;
    const struct hip_seq * par_seq                  = NULL;
    hip_ha_t *ha                                    = NULL;
    struct signaling_hipd_state * sig_state         = NULL;
    struct update_state * updatestate               = NULL;
    struct hip_common * update_packet_to_send       = NULL;
    struct signaling_connection_context *local_conn_ctx = NULL;
    struct signaling_connection_context remote_conn_ctx;
    struct signaling_connection *conn               = NULL;
    struct signaling_connection conn_tmp;

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
    updatestate->update_id_out++;
    seq_id = hip_update_get_out_id(updatestate);

    /* get the connection state */
    signaling_init_connection_from_msg(&conn_tmp, first_update, IN);
    HIP_IFEL(!(conn = signaling_hipd_state_get_connection(sig_state, conn_tmp.id)),
             -1, "Could not retrieve local connection state for conn id %d \n", conn_tmp.id);

    /* get the sequence number that we have to acknowledge */
    HIP_IFEL(!(par_seq = hip_get_param(first_update, HIP_PARAM_SEQ)),
            -1, "Message contains no seq parameter.\n");
    ack_id = ntohl(par_seq->update_id);

    /* Build and send the second update */
    HIP_IFEL(!(update_packet_to_send = build_update_message(ha, SIGNALING_SECOND_BEX_UPDATE, conn, seq_id, ack_id)),
             -1, "Failed to build update.\n");
    err = hip_send_pkt(NULL,
                       &ha->peer_addr,
                       (ha->nat_mode ? hip_get_local_nat_udp_port() : 0),
                       ha->peer_udp_port,
                       update_packet_to_send,
                       ha,
                       1);

    /* progress update sequence to currently processed update */
    if (updatestate->update_id_in < ack_id) {
        updatestate->update_id_in = ack_id;
    }

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
int signaling_send_third_update(UNUSED const struct hip_common *second_update) {
    int err                                         = 0;
    uint32_t ack_id                                 = 0;
    const struct in6_addr *src_hit                  = NULL;
    const struct in6_addr *dst_hit                  = NULL;
    const struct hip_seq * par_seq                  = NULL;
    hip_ha_t *ha                                    = NULL;
    struct signaling_hipd_state * sig_state         = NULL;
    struct update_state * updatestate               = NULL;
    hip_common_t * update_packet_to_send            = NULL;
    struct signaling_connection *conn               = NULL;
    struct signaling_connection conn_tmp;

    /* sanity checks */
    HIP_IFEL(!second_update, -1, "Need received update message to build a response \n");

    /* Lookup state */
    src_hit = &second_update->hitr;
    dst_hit = &second_update->hits;
    HIP_IFEL(!(ha = hip_hadb_find_byhits(src_hit, dst_hit)),
                 -1, "Failed to retrieve hadb entry.\n");
    HIP_IFEL(!(sig_state = (struct signaling_hipd_state *) lmod_get_state_item(ha->hip_modular_state, "signaling_hipd_state")),
            -1, "failed to retrieve state for signaling ports\n");
    HIP_IFEL(!(updatestate = (struct update_state *) lmod_get_state_item(ha->hip_modular_state, "update")),
             -1, "Could not get update state for host association.\n");

    /* get the connection state */
    signaling_init_connection_from_msg(&conn_tmp, second_update, IN);
    HIP_IFEL(!(conn = signaling_hipd_state_get_connection(sig_state, conn_tmp.id)),
             -1, "Could not retrieve local connection state for conn id %d \n", conn_tmp.id);

    /* get the sequence number that we have to acknowledge */
    HIP_IFEL(!(par_seq = hip_get_param(second_update, HIP_PARAM_SEQ)),
            -1, "Message contains no seq parameter.\n");
    ack_id = ntohl(par_seq->update_id);

    /* Build and send the second update */
    HIP_IFEL(!(update_packet_to_send = build_update_message(ha, SIGNALING_THIRD_BEX_UPDATE, conn, 0, ack_id)),
             -1, "Failed to build update.\n");
    err = hip_send_pkt(NULL,
                       &ha->peer_addr,
                       (ha->nat_mode ? hip_get_local_nat_udp_port() : 0),
                       ha->peer_udp_port,
                       update_packet_to_send,
                       ha,
                       1);

    /* progress update sequence to currently processed update */
    if (updatestate->update_id_in < ack_id) {
        updatestate->update_id_in = ack_id;
    }

out_err:
    return err;
}

/**
 * Build and send a notification about failed user authentication.
 *
 * @param reason    the reason why the authentication failed
 */
int signaling_send_user_auth_failed_ntf(hip_ha_t *ha,
                                        const int reason) {
    int err                 = 0;
    uint16_t mask           = 0;
    struct hip_common *msg_buf   = NULL;

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

int signaling_send_user_certificate_chain_ack(hip_ha_t *ha,
                                              const uint32_t seq,
                                              const struct signaling_connection *const conn,
                                              uint32_t network_id) {
    int err = 0;
    uint32_t mask = 0;
    hip_common_t *msg_buf = NULL;

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
    HIP_IFEL(signaling_build_param_connection_identifier(msg_buf, conn),
             -1, "Building of connection identifier parameter failed\n");

    /* Add original auth request */
    HIP_IFEL(signaling_build_param_user_auth_req_s(msg_buf, network_id),
             -1, "Could not build a copy of the user auth request into certificate ack packet \n");

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
int signaling_send_user_certificate_chain(hip_ha_t *ha, struct signaling_connection *conn, uint32_t network_id) {
    int err = 0;
    uint16_t mask           = 0;
    struct hip_common *msg_buf = NULL;
    struct update_state * updatestate       = NULL;
    STACK_OF(X509) *cert_chain = NULL;
    X509 *cert = NULL;
    int total_cert_count;
    int next_id = 1;
    int sent = 0;
    int i = 0;

    /* sanity checks */
    HIP_IFEL(!ha, -1, "Given HA is NULL \n");
    HIP_IFEL(!(updatestate = (struct update_state *) lmod_get_state_item(ha->hip_modular_state, "update")),
             -1, "Could not get update state for host association.\n");

    /* Get the users certificate chain */
    HIP_IFEL(!(cert_chain = signaling_user_api_get_user_certificate_chain(conn->ctx_out.user.uid)),
             -1, "Could not get certificate for user with id %d\n", conn->ctx_out.user.uid);
    total_cert_count = sk_X509_num(cert_chain);
    HIP_DEBUG("Sending a total of %d certificates from users chain.\n", total_cert_count);

    while(total_cert_count - next_id >= 0) {
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
        }

        /* Add the connection identifier */
        HIP_IFEL(signaling_build_param_connection_identifier(msg_buf, conn),
                 -1, "Could not build connection identifier for certificate update packet \n");

        /* Add the network identifier */
        HIP_IFEL(signaling_build_param_user_auth_req_s(msg_buf, network_id),
                 -1, "Could not build a copy of the user auth request into certificate update packet \n");

        /* Mac and sign the packet */
        HIP_IFEL(hip_build_param_hmac_contents(msg_buf, &ha->hip_hmac_out),
                 -1, "Building of HMAC failed\n");
        HIP_IFEL(ha->sign(ha->our_priv_key, msg_buf),
                 -EINVAL, "Could not sign UPDATE. Failing\n");

        HIP_DEBUG("Sending certificate chain for subject id %d up to certificate %d of %d\n",
                  conn->ctx_out.user.uid, next_id - 1, total_cert_count);

        err = hip_send_pkt(NULL,
                           &ha->peer_addr,
                           (ha->nat_mode ? hip_get_local_nat_udp_port() : 0),
                           ha->peer_udp_port,
                           msg_buf,
                           ha,
                           1);

        /* free message for the next run */
        free(msg_buf);
        msg_buf = NULL;
    }

    return 0;

out_err:
    sk_X509_free(cert_chain);
    X509_free(cert);
    free(msg_buf);
    return err;
}

/*
 * Handles an incoming I2 packet.
 *
 * Process connection context information in an I2 packet.
 * We have to send a request to the firewall for the connection with this context,
 * and expect our own connection context from the hipfw to send it in the R2.
 * We have to wait for the I3 to fully open the connection.
 */
int signaling_handle_incoming_i2(const uint8_t packet_type, UNUSED const uint32_t ha_state, struct hip_packet_context *ctx) {
    int err = 0;
    struct signaling_hipd_state * sig_state = NULL;
    struct signaling_connection new_conn;
    struct signaling_connection *conn;

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_HANDLE_I2\n");
    hip_perf_start_benchmark(perf_set, PERF_HANDLE_I2);
#endif

    /* Sanity checks */
    if (packet_type == HIP_I2) {
        HIP_DEBUG("Handling an I2\n");
    } else if (packet_type == HIP_UPDATE) {
        HIP_DEBUG("Handling an first bex update like I2\n");
    } else {
        HIP_ERROR("Packet is neither I2 nor first bex update.\n");
        err = -1;
        goto out_err;
    }

    /* Since this is a new connection, we have to setup new state as a responder
     * and fill the new state with the information in the I2 */
    HIP_IFEL(!(sig_state = (struct signaling_hipd_state *) lmod_get_state_item(ctx->hadb_entry->hip_modular_state, "signaling_hipd_state")),
             -1, "failed to retrieve state for signaling module\n");
    HIP_IFEL(signaling_init_connection_from_msg(&new_conn, ctx->input_msg, IN),
             -1, "Could not init connection context from I2 \n");
    new_conn.side = RESPONDER;
    HIP_IFEL(!(conn = signaling_hipd_state_add_connection(sig_state, &new_conn)),
             -1, "Could not add new connection to hipd state. \n");
    HIP_DEBUG("HIPD state after receiving I2 \n");
    signaling_hipd_state_print(sig_state);

    /* Try to authenticate the user and set flags accordingly */
    signaling_handle_user_signature(ctx->input_msg, conn, IN);

    /* The host is authed because this packet went through all the default hip checking functions */
    signaling_flag_set(&conn->ctx_in.flags, HOST_AUTHED);

    /* Tell the firewall/oslayer about the new connection and await it's decision */
    HIP_IFEL(signaling_send_first_connection_request(&ctx->input_msg->hits, &ctx->input_msg->hitr, conn),
             -1, "Failed to communicate new connection received in I2 to HIPFW\n");

    /* If connection has been blocked by the oslayer.
     * send an error notification with the reason and discard the i2. */
    if (conn->status == SIGNALING_CONN_BLOCKED) {
        HIP_DEBUG("Firewall has blocked incoming connection from I2, sending error notification to initiator... \n");
        // todo: send error notification
        return -1;
    }

#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Stop PERF_HANDLE_I2\n");
        hip_perf_stop_benchmark(perf_set, PERF_HANDLE_I2);
#endif

out_err:
    return err;
}

/*
 * Handles an incoming R2 packet.
 *
 * Process connection context in an R2 packet.
 * This completes a BEX with application context for which this HIPD process was the initiator.
 * So, we have to confirm the new connection to the hipfw/oslayer and send the I3.
 */
int signaling_handle_incoming_r2(const uint8_t packet_type, UNUSED const uint32_t ha_state, struct hip_packet_context *ctx) {
    int err                                                  = 0;
    struct signaling_hipd_state *sig_state                   = NULL;
    struct signaling_connection recv_conn;
    struct signaling_connection *conn               = NULL;
    const struct signaling_param_user_auth_request *param_usr_auth = NULL;

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_HANDLE_R2\n");
    hip_perf_start_benchmark(perf_set, PERF_HANDLE_R2);
#endif


    /* sanity checks */
    if (packet_type == HIP_R2) {
        HIP_DEBUG("Handling an R2\n");
    } else if (packet_type == HIP_UPDATE) {
        HIP_DEBUG("Handling a second bex update like R2\n");
    } else {
        HIP_ERROR("Packet is neither R2 nor second bex update.\n");
        err = -1;
        goto out_err;
    }

    /* Get the connection from state and update it with the information in the R2. */
    HIP_IFEL(!(sig_state = (struct signaling_hipd_state *) lmod_get_state_item(ctx->hadb_entry->hip_modular_state, "signaling_hipd_state")),
             -1, "failed to retrieve state for signaling module\n");
    HIP_IFEL(signaling_init_connection_from_msg(&recv_conn, ctx->input_msg, IN),
             -1, "Could not init connection context from R2/U2 \n");
    HIP_IFEL(!(conn = signaling_hipd_state_get_connection(sig_state, recv_conn.id)),
             -1, "Could not get connection state for connection in R2\n");
    HIP_IFEL(signaling_update_connection_from_msg(conn, ctx->input_msg, IN),
             -1, "Could not update connection state with information from R2\n", IN);
    HIP_DEBUG("HIPD state after receiving R2/U2 \n");
    signaling_hipd_state_print(sig_state);

    /* Try to authenticate the user and set flags accordingly */
    signaling_handle_user_signature(ctx->input_msg, conn, IN);

    /* The initiator and responder hosts are authed,
     * because this packet went through all the default hip checking functions. */
    signaling_flag_set(&conn->ctx_in.flags, HOST_AUTHED);
    signaling_flag_set(&conn->ctx_out.flags, HOST_AUTHED);

    /* Ask the firewall for a decision on the remote connection context */
    HIP_IFEL(signaling_send_second_connection_request(&ctx->hadb_entry->hit_our, &ctx->hadb_entry->hit_peer, conn),
             -1, "Failed to communicate new connection information from R2/U2 to hipfw \n");
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop PERF_HANDLE_R2\n");
    hip_perf_stop_benchmark(perf_set, PERF_HANDLE_R2);
#endif

    /* Send an I3 if connection has not been blocked by the oslayer.
     * otherwise send an error notification with the reason and discard the R2. */
    if (conn->status != SIGNALING_CONN_BLOCKED) {
        if (packet_type == HIP_R2) {
            signaling_send_I3(ctx->hadb_entry, conn);
        } else {
            signaling_send_third_update(ctx->input_msg);
        }
    } else {
        HIP_DEBUG("Firewall has blocked the connection after receipt of R2/U2, sending error notification to responder... \n");
        // todo: send error notification
        return -1;
    }

    /* Check if authentication of initiator user was requested,
     * if yes send certificate chain */
    if (signaling_flag_check(conn->ctx_out.flags, USER_AUTH_REQUEST)) {
        if ((param_usr_auth = hip_get_param(ctx->input_msg, HIP_PARAM_SIGNALING_USER_REQ_S))) {
            signaling_send_user_certificate_chain(ctx->hadb_entry, sig_state->pending_conn, ntohl(param_usr_auth->network_id));
        } else {
            HIP_ERROR("User auth parameter missing \n");
            err = -1;
            goto out_err;
        }
    }

out_err:
    return err;
}

/*
 * Handles an incoming I3 packet.
 *
 * We have to confirm the status of the connection to the firewall.
 */
int signaling_handle_incoming_i3(const uint8_t packet_type, UNUSED const uint32_t ha_state, struct hip_packet_context *ctx)
{
    int wait_auth = 0;
    int err = 0;
    struct signaling_connection conn;
    struct signaling_connection *existing_conn = NULL;
    struct signaling_hipd_state *sig_state = NULL;
    const struct signaling_param_user_auth_request *param_usr_auth = NULL;

    /* sanity checks */
    if (packet_type == HIP_I3) {
        HIP_DEBUG("Handling an R2\n");
    } else if (packet_type == HIP_UPDATE) {
        HIP_DEBUG("Handling a third bex update like I3\n");
    } else {
        HIP_ERROR("Packet is neither I3 nor third bex update.\n");
        err = -1;
        goto out_err;
    }

    /* get connection and update flags */
    HIP_IFEL(signaling_init_connection_from_msg(&conn, ctx->input_msg, IN),
             -1, "Could not init connection context from I3/U3 \n");
    HIP_IFEL(!(sig_state = (struct signaling_hipd_state *) lmod_get_state_item(ctx->hadb_entry->hip_modular_state, "signaling_hipd_state")),
             -1, "failed to retrieve state for signaling ports\n");
    HIP_IFEL(!(existing_conn = signaling_hipd_state_get_connection(sig_state, conn.id)),
             -1, "Could not get state for existing connection\n");
    HIP_IFEL(signaling_update_flags_from_connection_id(ctx->input_msg, existing_conn),
             -1, "Could not update authentication flags from I3/U3 message \n");

    /* Check if we're done with this connection or if we have to wait for addition authentication */
    if (signaling_flag_check(existing_conn->ctx_in.flags, USER_AUTH_REQUEST)){
        HIP_DEBUG("Auth uncompleted after I3/U3, waiting for authentication of remote user.\n");
        wait_auth = 1;
    }
    if (signaling_flag_check(existing_conn->ctx_out.flags, USER_AUTH_REQUEST)) {
        HIP_DEBUG("Auth uncompleted after I3/U3, because authentication of local user has been requested\n");
        if ((param_usr_auth = hip_get_param(ctx->input_msg, HIP_PARAM_SIGNALING_USER_REQ_S))) {
            signaling_send_user_certificate_chain(ctx->hadb_entry, existing_conn, ntohl(param_usr_auth->network_id));
            wait_auth = 1;
        } else {
            HIP_ERROR("User auth parameter missing \n");
            err = -1;
            goto out_err;
        }
    }

    if (!wait_auth) {
        HIP_DEBUG("Auth completed after I3/U3 \n");
        signaling_send_connection_update_request(&ctx->hadb_entry->hit_our, &ctx->hadb_entry->hit_peer, existing_conn);
    }

out_err:
    return err;
}
/**
 * Handle an UPDATE message that contains (parts from) a user certificate chain.
 *
 * @return 0 on success
 */
static int signaling_handle_incoming_certificate_udpate(UNUSED const uint8_t packet_type, UNUSED const uint32_t ha_state, struct hip_packet_context *ctx) {
    int err = 0;
    const struct hip_cert *param_cert = NULL;
    const struct signaling_param_connection_identifier *param_conn_id = NULL;
    X509 *cert = NULL;
    STACK_OF(X509) *cert_chain = NULL;
    struct signaling_hipd_state *sig_state = NULL;
    struct hip_host_id pseudo_ui;
    EVP_PKEY *pkey = NULL;
    X509_NAME *subject_name = NULL;
    uint32_t conn_id;
    struct signaling_connection *conn = NULL;
    const struct hip_seq *param_seq = NULL;
    const struct signaling_param_user_auth_request *param_usr_auth = NULL;

    /* sanity checks */
    HIP_IFEL(!ctx->input_msg,  -1, "Message is NULL\n");

    /* get connection identifier and context */
    HIP_IFEL(!(sig_state = (struct signaling_hipd_state *) lmod_get_state_item(ctx->hadb_entry->hip_modular_state, "signaling_hipd_state")),
             -1, "failed to retrieve state\n");
    HIP_IFEL(!(param_conn_id = hip_get_param(ctx->input_msg, HIP_PARAM_SIGNALING_CONNECTION_ID)),
             -1, "No connection identifier found in the message, cannot handle certificates.\n");
    conn_id = ntohl(param_conn_id->id);
    HIP_IFEL(!(conn = signaling_hipd_state_get_connection(sig_state, conn_id)),
             -1, "No connection context for connection id \n");

    /* process certificates */
    HIP_IFEL(!(param_cert = hip_get_param(ctx->input_msg, HIP_PARAM_CERT)),
             -1, "Message contains no certificate. \n");
    if (!sig_state->user_cert_ctx.cert_chain) {;
        HIP_IFEL(!(sig_state->user_cert_ctx.cert_chain = sk_X509_new_null()),
                 -1, "memory allocation failure\n");
    }
    cert_chain = sig_state->user_cert_ctx.cert_chain;
    while(param_cert != NULL && hip_get_param_type((const struct hip_tlv_common *) param_cert) == HIP_PARAM_CERT) {
        HIP_DEBUG("Got certificate %d from a group of %d certificates \n", param_cert->cert_id, param_cert->cert_count);
        HIP_IFEL(signaling_DER_to_X509((const unsigned char *) (param_cert + 1), ntohs(param_cert->length) - sizeof(struct hip_cert) + sizeof(struct hip_tlv_common), &cert),
                 -1, "Could not decode certificate");
        /* set group if this is the beginning of a cert exchange */
        if (sig_state->user_cert_ctx.group == -1) {
            sig_state->user_cert_ctx.group = param_cert->cert_group;
        }
        /* check cert belongs to the group we're currently receiving */
        if (sig_state->user_cert_ctx.group != param_cert->cert_group) {
            HIP_DEBUG("Received certificate from wrong group, discarding... \n");
            continue;
        }
        sk_X509_push(cert_chain, cert);
        //HIP_DEBUG("Recevied and pushed:\n");
        //X509_print_fp(stderr, cert);

        /* check if we have received the last cert */
        if (sk_X509_num(cert_chain) == param_cert->cert_count) {
            HIP_DEBUG("received complete certificate, now saving %d certs \n", sk_X509_num(cert_chain));
            /* we have to reorder the stack one time... */
            stack_reverse(&cert_chain);

            /* Now verify the user identity with the certificate chain
             * We need to construct a temporary host_id struct since, all key_rr_to_xxx functions take this as argument.
             * However, we need only to fill in hi_length, algorithm and the key rr. */
            pseudo_ui.hi_length       = conn->ctx_in.user.key_rr_len;
            pseudo_ui.rdata.algorithm = conn->ctx_in.user.rdata.algorithm;
            memcpy(pseudo_ui.key,
                   conn->ctx_in.user.pkey,
                   conn->ctx_in.user.key_rr_len - sizeof(struct hip_host_id_key_rdata));
            HIP_IFEL(!(pkey = hip_key_rr_to_evp_key(&pseudo_ui, 0)), -1, "Could not deserialize users public key\n");
            cert = sk_X509_pop(cert_chain);
            HIP_IFEL(signaling_DER_to_X509_NAME(conn->ctx_in.user.subject_name, conn->ctx_in.user.subject_name_len, &subject_name),
                     -1, "Could not get users X509 name");

            HIP_IFEL(signaling_user_api_verify_pubkey(subject_name, pkey, cert, 1),
                     -1, "Could not verify users public key with received certificate chain\n");
            if (!verify_certificate_chain(cert, CERTIFICATE_INDEX_TRUSTED_DIR, NULL, cert_chain)) {
                /* Public key verification was successful, so we save the chain */
                sk_X509_push(cert_chain, cert);
                signaling_add_user_certificate_chain(cert_chain);
                signaling_flag_set(&conn->ctx_in.flags, USER_AUTHED);
                signaling_flag_unset(&conn->ctx_in.flags, USER_AUTH_REQUEST);

                /* We send an ack */
                HIP_IFEL(!(param_usr_auth = hip_get_param(ctx->input_msg, HIP_PARAM_SIGNALING_USER_REQ_S)),
                         -1, "Could not get auth request from certificate update \n");
                HIP_IFEL(!(param_seq = hip_get_param(ctx->input_msg, HIP_PARAM_SEQ)),
                         -1, "Cannot build ack for last certificate update, because corresponding UPDATE has no sequence number \n");
                signaling_send_user_certificate_chain_ack(ctx->hadb_entry, ntohl(param_seq->update_id), conn, ntohl(param_usr_auth->network_id));

                /* We confirm to the firewall*/
                HIP_DEBUG("Confirming user authentication to OSLAYER\n");
                signaling_connection_print(conn, "");
                signaling_send_connection_update_request(&ctx->hadb_entry->hit_our, &ctx->hadb_entry->hit_peer, conn);
            } else {
                HIP_DEBUG("Rejecting certificate chain. Chain will not be saved. \n");
                free(cert);
            }

            /* Reset the certificate context for this HA */
            sig_state->user_cert_ctx.group = -1;
            sig_state->user_cert_ctx.user_certificate_required = 0;
            sig_state->user_cert_ctx.cert_chain = NULL;
            sk_X509_free(cert_chain);
            cert_chain = NULL;
        }

        param_cert = (const struct hip_cert *) hip_get_next_param(ctx->input_msg, (const struct hip_tlv_common *) param_cert);
    }

out_err:
    return err;
}

static int signaling_handle_incoming_certificate_update_ack(UNUSED const uint8_t packet_type, UNUSED const uint32_t ha_state, struct hip_packet_context *ctx) {
    int err = 0;
    const struct signaling_param_connection_identifier *param_conn_id = NULL;
    struct signaling_hipd_state *sig_state = NULL;
    struct signaling_connection *existing_conn = NULL;
    uint32_t conn_id;

    /* sanity checks */
    HIP_IFEL(!ctx->input_msg,  -1, "Message is NULL\n");

    /* get connection identifier and context */
    HIP_IFEL(!(sig_state = (struct signaling_hipd_state *) lmod_get_state_item(ctx->hadb_entry->hip_modular_state, "signaling_hipd_state")),
            -1, "failed to retrieve state\n");
    HIP_IFEL(!(param_conn_id = hip_get_param(ctx->input_msg, HIP_PARAM_SIGNALING_CONNECTION_ID)),
             -1, "No connection identifier found in the message, cannot handle certificates.\n");
    conn_id = ntohl(param_conn_id->id);
    HIP_IFEL(!(existing_conn = signaling_hipd_state_get_connection(sig_state, conn_id)),
             -1, "No connection context for connection id \n");

    /* unflag user authentication flag */
    signaling_flag_unset(&existing_conn->ctx_out.flags, USER_AUTH_REQUEST);

    /* Check if we're done with this connection or if authentication failed or we have to wait for additional authentication */
    if (signaling_flag_check(existing_conn->ctx_in.flags, USER_AUTH_REQUEST)){
        HIP_DEBUG("Auth uncompleted, waiting for authentication of remote user.\n");
    } else {
        HIP_DEBUG("Auth completed after update ack \n");
        signaling_send_connection_update_request(&ctx->hadb_entry->hit_our, &ctx->hadb_entry->hit_peer, existing_conn);
    }

out_err:
    return err;
}

/*
 * Handle a BEX update
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
        /* This can be handled like an I2 */
        HIP_DEBUG("Received FIRST BEX Update... \n");
        HIP_IFEL(signaling_handle_incoming_i2(packet_type, ha_state, ctx),
                 -1, "Could not process first bex update \n");
        HIP_DEBUG("still there xx\n");
        HIP_IFEL(signaling_send_second_update(ctx->input_msg),
                 -1, "failed to trigger second bex update. \n");
        break;
    case SIGNALING_SECOND_BEX_UPDATE:
        /* This can be handled like an R2 */
        HIP_DEBUG("Received SECOND BEX Update... \n");
        HIP_IFEL(signaling_handle_incoming_r2(packet_type, ha_state, ctx),
                 -1, "Could not process second bex update \n");
        break;
    case SIGNALING_THIRD_BEX_UPDATE:
        /* This can be handled like an I3 */
        HIP_DEBUG("Received THIRD BEX Update... \n");
        HIP_IFEL(signaling_handle_incoming_i3(packet_type, ha_state, ctx),
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
    }

out_err:
    return err;
}

int signaling_handle_incoming_notification(UNUSED const uint8_t packet_type, UNUSED const uint32_t ha_state, struct hip_packet_context *ctx) {
    int err                                                     = 0;
    struct signaling_hipd_state *sig_state                      = NULL;
    const struct hip_notification *ntf                          = NULL;
    const struct signaling_ntf_user_auth_failed_data *ntf_data  = NULL;

    HIP_IFEL(!(ntf = hip_get_param(ctx->input_msg, HIP_PARAM_NOTIFICATION)),
             -1, "Could not get notification parameter from NOTIFY msg.\n");
    ntf_data = (const struct signaling_ntf_user_auth_failed_data *) ntf->data;
    HIP_IFEL(!(sig_state = (struct signaling_hipd_state *) lmod_get_state_item(ctx->hadb_entry->hip_modular_state, "signaling_hipd_state")),
            -1, "failed to retrieve state for signaling module \n");
    sig_state->user_cert_ctx.user_certificate_required = 1;

out_err:
    return err;
}

int signaling_i2_add_application_context(UNUSED const uint8_t packet_type, UNUSED const uint32_t ha_state, struct hip_packet_context *ctx)
{
    int err = 0;
    struct signaling_hipd_state *sig_state = NULL;

    HIP_IFEL(!ctx->hadb_entry, -1, "No hadb entry.\n");
    HIP_IFEL(!(sig_state = lmod_get_state_item(ctx->hadb_entry->hip_modular_state, "signaling_hipd_state")),
                 -1, "failed to retrieve state for signaling\n");

    if(!sig_state->pending_conn) {
        HIP_DEBUG("We have no connection context for this host associtaion. \n");
        return 0;
    }

    if(signaling_build_param_connection_identifier(ctx->output_msg, sig_state->pending_conn)) {
        HIP_DEBUG("Building of connection identifier parameter failed\n");
        err = 0;
    }

    if(signaling_build_param_application_context(ctx->output_msg, sig_state->pending_conn->sockets, &sig_state->pending_conn->ctx_out.app)) {
        HIP_DEBUG("Building of application context parameter failed.\n");
        err = 0;
    }

out_err:
    return err;
}

int signaling_i2_add_user_signature(UNUSED const uint8_t packet_type, UNUSED const uint32_t ha_state, struct hip_packet_context *ctx)
{
    int err = 0;
    struct signaling_hipd_state *sig_state;

    HIP_IFEL(!ctx->hadb_entry, -1, "No hadb entry.\n");
    HIP_IFEL(!(sig_state = lmod_get_state_item(ctx->hadb_entry->hip_modular_state, "signaling_hipd_state")),
                 -1, "failed to retrieve state for signaling\n");
    HIP_IFEL(signaling_build_param_user_signature(ctx->output_msg, sig_state->pending_conn->ctx_out.user.uid),
             -1, "User failed to sign packet.\n");
out_err:
    return err;
}

int signaling_i2_add_user_context(UNUSED const uint8_t packet_type, UNUSED const uint32_t ha_state, struct hip_packet_context *ctx)
{
    int err = 0;
    struct signaling_hipd_state *sig_state;

    HIP_IFEL(!ctx->hadb_entry, -1, "No hadb entry.\n");
    HIP_IFEL(!(sig_state = lmod_get_state_item(ctx->hadb_entry->hip_modular_state, "signaling_hipd_state")),
                 -1, "failed to retrieve state for signaling\n");
    HIP_IFEL(signaling_build_param_user_context(ctx->output_msg, &sig_state->pending_conn->ctx_out.user),
            -1, "Building of user context parameter failed.\n");

out_err:
    return err;
}

int signaling_r2_add_application_context(UNUSED const uint8_t packet_type, UNUSED const uint32_t ha_state, struct hip_packet_context *ctx)
{
    return signaling_i2_add_application_context(packet_type, ha_state, ctx);
}

int signaling_r2_add_user_context(UNUSED const uint8_t packet_type, UNUSED const uint32_t ha_state, struct hip_packet_context *ctx) {
    return signaling_i2_add_user_context(packet_type, ha_state, ctx);
}

int signaling_r2_add_user_signature(UNUSED const uint8_t packet_type, UNUSED const uint32_t ha_state, struct hip_packet_context *ctx)
{
    return signaling_i2_add_user_signature(packet_type, ha_state, ctx);
}

int signaling_r2_add_user_auth_resp(UNUSED const uint8_t packet_type, UNUSED const uint32_t ha_state, struct hip_packet_context *ctx)
{
    int err = 0;
    struct signaling_hipd_state *sig_state;

    HIP_IFEL(!ctx->hadb_entry, -1, "No hadb entry.\n");
    HIP_IFEL(!(sig_state = lmod_get_state_item(ctx->hadb_entry->hip_modular_state, "signaling_hipd_state")),
             -1, "failed to retrieve state for signaling\n");
    /* check if we must include a user auth req_s parameter */
    if (signaling_flag_check(sig_state->pending_conn->ctx_in.flags, USER_AUTH_REQUEST)) {
        HIP_IFEL(signaling_build_param_user_auth_req_s(ctx->output_msg, 0),
                     -1, "Building of user context parameter failed.\n");
    }

out_err:
    return err;
}
