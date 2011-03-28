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
#include "lib/tool/pk.h"

#include "hipd/hadb.h"
#include "hipd/user.h"
#include "hipd/output.h"
#include "hipd/close.h"


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
/*
 *   Wrapper for hip_send_close(...).
 *
 *   @param peer_hit    the hit of the peer to close
 *   @return            0 on success, negative on error
 */
static int signaling_close_peer(hip_hit_t *peer_hit) {
    int err                 = 0;
    uint16_t mask           = 0;
    hip_common_t *msg_buf   = NULL;

    /* Allocate and build message */
    HIP_IFEL(!(msg_buf = hip_msg_alloc()),
            -ENOMEM, "Out of memory while allocation memory for the bex update packet\n");
    hip_build_network_hdr(msg_buf, HIP_UPDATE, mask, peer_hit, peer_hit);

    /* Add hit to close, this parameter is critical. */
    HIP_IFEL(hip_build_param_contents(msg_buf, peer_hit, HIP_PARAM_HIT, sizeof(hip_hit_t)),
             -1, "build param contents (dst hit) failed\n");

    HIP_IFEL(hip_send_close(msg_buf, 0),
             -1, "Could not close hip associaton\n");

    return 0;

out_err:
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
        if(signaling_build_param_user_context(msg_buf, &conn->ctx_out.user, conn->ctx_out.userdb_entry)) {
            HIP_DEBUG("Building of user conext parameter failed.\n");
        }
    }

    /* check if we have to include a user auth req_s parameter */
    if (type == SIGNALING_SECOND_BEX_UPDATE || type == SIGNALING_THIRD_BEX_UPDATE) {
        if (signaling_flag_check(conn->ctx_in.flags, USER_AUTH_REQUEST)) {
            HIP_IFEL(signaling_build_param_user_auth_req_s(msg_buf, 0),
                     -1, "Building of user context parameter failed.\n");
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

#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Start PERF_I3_HOST_SIGN\n");
        hip_perf_start_benchmark(perf_set, PERF_I3_HOST_SIGN);
#endif
    HIP_IFEL(ha->sign(ha->our_priv_key, msg_buf),
             -EINVAL, "Could not sign I3. Failing\n");
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Stop PERF_I3_HOST_SIGN\n");
        hip_perf_stop_benchmark(perf_set, PERF_I3_HOST_SIGN);
#endif

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
 * Build and send a notification about failed connection establishment.
 *
 * @param reason    the reason why the authentication failed
 */
int signaling_send_connection_failed_ntf(hip_ha_t *ha,
                                         const int reason,
                                         const struct signaling_connection *conn) {
    int err                 = 0;
    uint16_t mask           = 0;
    hip_common_t *msg_buf   = NULL;

    /* Sanity checks */
    HIP_IFEL(!ha, -1, "Given host association is NULL \n");

    /* Allocate and build message */
    HIP_IFEL(!(msg_buf = hip_msg_alloc()),
            -ENOMEM, "Out of memory while allocation memory for the bex update packet\n");
    hip_build_network_hdr(msg_buf, HIP_NOTIFY, mask, &ha->hit_our, &ha->hit_peer);

    /* Append notification parameter */
    signaling_build_param_connection_fail(msg_buf, reason);

    /* Append connection identifier */
    signaling_build_param_connection_identifier(msg_buf, conn);

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

#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Start PERF_SEND_CERT_CHAIN\n");
        hip_perf_start_benchmark(perf_set, PERF_SEND_CERT_CHAIN);
#endif

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
        HIP_IFEL(signaling_build_param_certificate_chain_identifier(msg_buf, conn->id, network_id),
                 -1, "Could not build certificate chain identifier for certificate update packet \n");

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
    struct userdb_user_entry *db_entry = NULL;

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

    /* add/update user in user db */
    if (!(db_entry = userdb_add_user_from_msg(ctx->input_msg, 0))) {
        HIP_ERROR("Could not add user from message\n");
    }

    /* Since this is a new connection, we have to setup new state as a responder
     * and fill the new state with the information in the I2 */
    HIP_IFEL(!(sig_state = (struct signaling_hipd_state *) lmod_get_state_item(ctx->hadb_entry->hip_modular_state, "signaling_hipd_state")),
             -1, "failed to retrieve state for signaling module\n");
    HIP_IFEL(signaling_init_connection_from_msg(&new_conn, ctx->input_msg, IN),
             -1, "Could not init connection context from I2 \n");
    new_conn.side = RESPONDER;
    new_conn.ctx_in.userdb_entry = db_entry;
    HIP_IFEL(!(conn = signaling_hipd_state_add_connection(sig_state, &new_conn)),
             -1, "Could not add new connection to hipd state. \n");

    /* Try to authenticate the user and set flags accordingly */
    userdb_handle_user_signature(ctx->input_msg, conn, IN);

    /* The host is authed because this packet went through all the default hip checking functions */
    signaling_flag_set(&conn->ctx_in.flags, HOST_AUTHED);

    /* Tell the firewall/oslayer about the new connection and await it's decision */
    HIP_IFEL(signaling_send_first_connection_request(&ctx->input_msg->hits, &ctx->input_msg->hitr, conn),
             -1, "Failed to communicate new connection received in I2 to HIPFW\n");

    /* If connection has been blocked by the oslayer.
     * send an error notification with the reason and discard the i2. */
    if (conn->status == SIGNALING_CONN_BLOCKED) {
        HIP_DEBUG("Firewall has blocked incoming connection from I2, sending error notification to initiator... \n");
        signaling_send_connection_failed_ntf(ctx->hadb_entry, PRIVATE_REASON, conn);
        HIP_DEBUG("Closing HA to peer...\n");
        signaling_close_peer(&ctx->hadb_entry->hit_peer);
        return -1;
    }

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
    struct userdb_user_entry *db_entry = NULL;

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_R2x3\n");
    hip_perf_start_benchmark(perf_set, PERF_R2x3);
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

    /* add/update user in user db */
    if (!(db_entry = userdb_add_user_from_msg(ctx->input_msg, 0))) {
        HIP_ERROR("Could not add user from message\n");
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
    conn->ctx_in.userdb_entry = db_entry;


    /* Try to authenticate the user and set flags accordingly */
    userdb_handle_user_signature(ctx->input_msg, conn, IN);


    /* The initiator and responder hosts are authed,
     * because this packet went through all the default hip checking functions. */
    signaling_flag_set(&conn->ctx_in.flags, HOST_AUTHED);
    signaling_flag_set(&conn->ctx_out.flags, HOST_AUTHED);

    /* Ask the firewall for a decision on the remote connection context */
    HIP_IFEL(signaling_send_second_connection_request(&ctx->hadb_entry->hit_our, &ctx->hadb_entry->hit_peer, conn),
             -1, "Failed to communicate new connection information from R2/U2 to hipfw \n");


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
        signaling_send_connection_failed_ntf(ctx->hadb_entry, PRIVATE_REASON, conn);
        HIP_DEBUG("Closing HA to peer...\n");
        signaling_close_peer(&ctx->hadb_entry->hit_peer);
        return -1;
    }
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop PERF_R2, PERF_R2x3\n");
    hip_perf_stop_benchmark(perf_set, PERF_R2);
    hip_perf_stop_benchmark(perf_set, PERF_R2x3);
#endif

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_CERTIFICATE_EXCHANGE, PERF_RECEIVE_CERT_CHAIN\n");
    hip_perf_start_benchmark(perf_set, PERF_CERTIFICATE_EXCHANGE);
    hip_perf_start_benchmark(perf_set, PERF_RECEIVE_CERT_CHAIN);
#endif

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
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_R2_I3\n");
    hip_perf_start_benchmark(perf_set, PERF_R2_I3);

    /* The packet is on the wire, so write all tests now.. */
    HIP_DEBUG("Write PERF_R2, PERF_USER_COMM, PERF_I2_R2, PERF_HIPD_R2_FINISH, PERF_R2_VERIFY_HOST_SIG, PERF_R2_VERIFY_USER_SIG,"
              " PERF_X509_VERIFY_CERT_CHAIN, PERF_I3_HOST_SIGN, PERF_SEND_CERT_CHAIN\n");
    hip_perf_write_benchmark(perf_set, PERF_R2);
    hip_perf_write_benchmark(perf_set, PERF_R2x1);
    hip_perf_write_benchmark(perf_set, PERF_R2x2);
    hip_perf_write_benchmark(perf_set, PERF_R2x3);
    hip_perf_write_benchmark(perf_set, PERF_USER_COMM);
    hip_perf_write_benchmark(perf_set, PERF_I2_R2);
    hip_perf_write_benchmark(perf_set, PERF_HIPD_R2_FINISH);
    hip_perf_write_benchmark(perf_set, PERF_R2_VERIFY_HOST_SIG);
    hip_perf_write_benchmark(perf_set, PERF_R2_VERIFY_USER_SIG);
    hip_perf_write_benchmark(perf_set, PERF_X509_VERIFY_CERT_CHAIN);
    hip_perf_write_benchmark(perf_set, PERF_I3_HOST_SIGN);
    hip_perf_write_benchmark(perf_set, PERF_SEND_CERT_CHAIN);
    hip_perf_write_benchmark(perf_set, PERF_R2_VERIFY_USER_PUBKEY);
#endif

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

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop PERF_R2_I3\n");
    hip_perf_stop_benchmark(perf_set, PERF_R2_I3);
    HIP_DEBUG("Start PERF_HIPD_I3_FINISH, PERF_I3\n");
    hip_perf_start_benchmark(perf_set, PERF_I3);
    hip_perf_start_benchmark(perf_set, PERF_HIPD_I3_FINISH);
#endif

    /* sanity checks */
    if (packet_type == HIP_I3) {
        HIP_DEBUG("Handling an I3\n");
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

    /* Signature validation */
/* DONT DO THIS in HIPD, this is just for the HIPFW
 * #ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_I3_VERIFY_HOST_SIG\n");
    hip_perf_start_benchmark(perf_set, PERF_I3_VERIFY_HOST_SIG);
#endif
    HIP_IFEL(ctx->hadb_entry->verify(ctx->hadb_entry->peer_pub_key,
                                            ctx->input_msg),
             -EINVAL,
             "I3 signature verification failed.\n");
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop PERF_I3_VERIFY_HOST_SIG\n");
    hip_perf_stop_benchmark(perf_set, PERF_I3_VERIFY_HOST_SIG);
#endif */

    /* Check if we're done with this connection or if we have to wait for addition authentication */
    if (signaling_flag_check(existing_conn->ctx_in.flags, USER_AUTH_REQUEST)){
        HIP_DEBUG("Auth uncompleted after I3/U3, waiting for authentication of remote user.\n");
        wait_auth = 1;
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Stop PERF_I3\n");
        hip_perf_stop_benchmark(perf_set, PERF_I3);
        HIP_DEBUG("Start PERF_CERTIFICATE_EXCHANGE, PERF_RECEIVE_CERT_CHAIN\n");
        hip_perf_start_benchmark(perf_set, PERF_CERTIFICATE_EXCHANGE);
        hip_perf_start_benchmark(perf_set, PERF_RECEIVE_CERT_CHAIN);
#endif
    }
    if (signaling_flag_check(existing_conn->ctx_out.flags, USER_AUTH_REQUEST)) {
        HIP_DEBUG("Auth uncompleted after I3/U3, because authentication of local user has been requested\n");
        if ((param_usr_auth = hip_get_param(ctx->input_msg, HIP_PARAM_SIGNALING_USER_REQ_S))) {
#ifdef CONFIG_HIP_PERFORMANCE
            HIP_DEBUG("Stop PERF_I3\n");
            hip_perf_stop_benchmark(perf_set, PERF_I3);
            HIP_DEBUG("Start PERF_CERTIFICATE_EXCHANGE\n");
            hip_perf_start_benchmark(perf_set, PERF_CERTIFICATE_EXCHANGE);
#endif
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
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Stop PERF_NEW_CONN\n");
        hip_perf_stop_benchmark(perf_set, PERF_NEW_CONN);
#endif
    }

out_err:
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Write PERF_USER_COMM, PERF_R2_I3, PERF_NEW_CONN, PERF_I3_VERIFY_HOST_SIG, PERF_HIPD_I3_FINISH, PERF_I3, PERF_SEND_CERT_CHAIN\n");
    hip_perf_write_benchmark(perf_set, PERF_USER_COMM);
    hip_perf_write_benchmark(perf_set, PERF_R2_I3);
    hip_perf_write_benchmark(perf_set, PERF_NEW_CONN);
    hip_perf_write_benchmark(perf_set, PERF_I3_VERIFY_HOST_SIG);
    hip_perf_write_benchmark(perf_set, PERF_HIPD_I3_FINISH);
    hip_perf_write_benchmark(perf_set, PERF_I3);
    hip_perf_write_benchmark(perf_set, PERF_SEND_CERT_CHAIN);
#endif

    return err;
}
/**
 * Handle an UPDATE message that contains (parts from) a user certificate chain.
 *
 * @return 0 on success
 */
static int signaling_handle_incoming_certificate_udpate(UNUSED const uint8_t packet_type, UNUSED const uint32_t ha_state, struct hip_packet_context *ctx) {
    int err = 0;
    const struct signaling_param_cert_chain_id *param_cert_id = NULL;
    X509 *cert = NULL;
    struct signaling_hipd_state *sig_state = NULL;
    struct signaling_connection *conn = NULL;
    const struct hip_seq *param_seq = NULL;
    struct userdb_certificate_context *cert_ctx = NULL;
    uint32_t network_id;
    uint32_t conn_id;

    /* sanity checks */
    HIP_IFEL(!ctx->input_msg,  -1, "Message is NULL\n");

    /* Get connection identifier and context */
    HIP_IFEL(!(sig_state = (struct signaling_hipd_state *) lmod_get_state_item(ctx->hadb_entry->hip_modular_state, "signaling_hipd_state")),
             -1, "failed to retrieve state\n");
    HIP_IFEL(!(param_cert_id = hip_get_param(ctx->input_msg, HIP_PARAM_SIGNALING_CERT_CHAIN_ID)),
             -1, "No connection identifier found in the message, cannot handle certificates.\n");
    conn_id    =  ntohl(param_cert_id->connection_id);
    network_id = ntohl(param_cert_id->network_id);
    HIP_IFEL(!(conn = signaling_hipd_state_get_connection(sig_state, conn_id)),
             -1, "No connection context for connection id \n");

    /* Process certificates and check completeness*/
    err = userdb_add_certificates_from_msg(ctx->input_msg, conn->ctx_in.userdb_entry);
    if (err < 0) {
        HIP_ERROR("Internal error while processing certificates \n");
        err = -1;
        goto out_err;
    } else if (err > 0) {
        HIP_DEBUG("Waiting for further certificate updates because chain is incomplete. \n");
        userdb_entry_print(conn->ctx_in.userdb_entry);
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
    HIP_IFEL(!(cert_ctx = userdb_get_certificate_context(conn->ctx_in.userdb_entry,
                                                         &ctx->input_msg->hits,
                                                         &ctx->input_msg->hitr,
                                                         network_id)),
             -1, "Could not retrieve users certificate chain\n");
    stack_reverse(&cert_ctx->cert_chain);
    userdb_entry_print(conn->ctx_in.userdb_entry);

    /* Match the public key */
    cert = sk_X509_pop(cert_ctx->cert_chain);
    HIP_IFEL(!match_public_key(cert, conn->ctx_in.userdb_entry->pub_key),
             -1, "Users public key does not match with the key in the received certificate chain\n");

    /* Verify the certificate chain */
    if (!verify_certificate_chain(cert, CERTIFICATE_INDEX_TRUSTED_DIR, NULL, cert_ctx->cert_chain)) {
        /* Public key verification was successful, so we save the chain */
        sk_X509_push(cert_ctx->cert_chain, cert);
        userdb_save_user_certificate_chain(cert_ctx->cert_chain);
        signaling_flag_set(&conn->ctx_in.flags, USER_AUTHED);
        signaling_flag_unset(&conn->ctx_in.flags, USER_AUTH_REQUEST);

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
        if (!signaling_flag_check(conn->ctx_out.flags, USER_AUTH_REQUEST)) {
            signaling_send_connection_update_request(&ctx->hadb_entry->hit_our, &ctx->hadb_entry->hit_peer, conn);
#ifdef CONFIG_HIP_PERFORMANCE
            HIP_DEBUG("Stop and write PERF_NEW_CONN\n");
            hip_perf_stop_benchmark(perf_set, PERF_NEW_CONN);
            hip_perf_write_benchmark(perf_set, PERF_NEW_CONN);
#endif
        }
    } else {
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

static int signaling_handle_incoming_certificate_update_ack(UNUSED const uint8_t packet_type, UNUSED const uint32_t ha_state, struct hip_packet_context *ctx) {
    int err = 0;
    const struct signaling_param_cert_chain_id *param_cert_id = NULL;
    struct signaling_hipd_state *sig_state = NULL;
    struct signaling_connection *existing_conn = NULL;
    uint32_t conn_id;

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
    conn_id    =  ntohl(param_cert_id->connection_id);
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
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Stop and write PERF_NEW_CONN\n");
        hip_perf_stop_benchmark(perf_set, PERF_NEW_CONN);
        hip_perf_write_benchmark(perf_set, PERF_NEW_CONN);
#endif
    }

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Write PERF_CERTIFICATE_EXCHANGE, PERF_CERT_UP_CERT_ACK\n");
    hip_perf_write_benchmark(perf_set, PERF_CERTIFICATE_EXCHANGE);
    hip_perf_write_benchmark(perf_set, PERF_CERT_UP_CERT_ACK);
#endif

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

/*
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_UPDATE_VERIFY_HOST_SIG\n");
    hip_perf_start_benchmark(perf_set, PERF_UPDATE_VERIFY_HOST_SIG);
#endif
    HIP_IFEL(ctx->hadb_entry->verify(ctx->hadb_entry->peer_pub_key,
                                     ctx->input_msg),
                                     -EINVAL,
                                     "Verification of Update signature failed\n");
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop PERF_UPDATE_VERIFY_HOST_SIG\n");
    hip_perf_stop_benchmark(perf_set, PERF_UPDATE_VERIFY_HOST_SIG);
#endif
*/

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

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Write PERF_UPDATE_VERIFY_HOST_SIG\n");
    hip_perf_write_benchmark(perf_set, PERF_UPDATE_VERIFY_HOST_SIG);
#endif


out_err:
    return err;
}

static int signaling_handle_notify_connection_failed(UNUSED const uint8_t packet_type, UNUSED const uint32_t ha_state, struct hip_packet_context *ctx) {
    struct signaling_hipd_state *sig_state                      = NULL;
    struct signaling_connection *conn                           = NULL;
    const struct signaling_param_connection_identifier *conn_id = NULL;
    const struct hip_notification *notification                 = NULL;
    const struct signaling_ntf_connection_failed_data *ntf_data = NULL;
    const struct hip_tlv_common *param                          = NULL;
    const struct hip_cert *param_cert                           = NULL;
    X509 *cert                                                  = NULL;
    EVP_PKEY *pub_key                                           = NULL;
    int reason = 0;
    int err = 1;
    const struct in6_addr *peer_hit = NULL;
    const struct in6_addr *our_hit  = NULL;
    const struct in6_addr *src_hit  = NULL;
    int origin = 0;
    hip_ha_t *ha   = NULL;

    /* Get connection context */
    HIP_IFEL(!(notification = hip_get_param(ctx->input_msg, HIP_PARAM_NOTIFICATION)),
             -1, "Message contains no notification parameter.\n");
    HIP_IFEL(!(conn_id = hip_get_param(ctx->input_msg, HIP_PARAM_SIGNALING_CONNECTION_ID)),
             -1, "Could not find connection identifier in notification. \n");

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
        origin = 1;  // 1 = from middlebox
        our_hit = &ctx->input_msg->hitr;
        src_hit = &ctx->input_msg->hits;
    } else {
        HIP_DEBUG("Notification comes from peer host.\n");
        origin = 0;
        our_hit = &ctx->input_msg->hitr;
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
    HIP_IFEL(!(conn = signaling_hipd_state_get_connection(sig_state, ntohs(conn_id->id))),
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
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_NOTIFY_VERIFY_HOST_SIG\n");
    hip_perf_start_benchmark(perf_set, PERF_NOTIFY_VERIFY_HOST_SIG);
#endif
            err = hip_ecdsa_verify(EVP_PKEY_get1_EC_KEY(pub_key), ctx->input_msg);
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop PERF_NOTIFY_VERIFY_HOST_SIG\n");
    hip_perf_stop_benchmark(perf_set, PERF_NOTIFY_VERIFY_HOST_SIG);
#endif
            if(err) {
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
    reason = ntohs(ntf_data->reason);
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
    conn->status = SIGNALING_CONN_BLOCKED;
    conn->reason_reject = reason;
    signaling_send_connection_update_request(our_hit, peer_hit, conn);

out_err:
    return err;
}

int signaling_handle_incoming_notification(UNUSED const uint8_t packet_type, UNUSED const uint32_t ha_state, struct hip_packet_context *ctx) {
    int err                                                     = 0;
    const struct hip_notification *ntf                          = NULL;


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

int signaling_i2_add_application_context(UNUSED const uint8_t packet_type, UNUSED const uint32_t ha_state, struct hip_packet_context *ctx)
{
    int err = 0;
    struct signaling_hipd_state *sig_state = NULL;

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_R1x3\n");
    hip_perf_start_benchmark(perf_set, PERF_R1x3);
#endif
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
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_R1x4x3\n");
    hip_perf_start_benchmark(perf_set, PERF_R1x4x3);
#endif
    HIP_IFEL(!ctx->hadb_entry, -1, "No hadb entry.\n");
    HIP_IFEL(!(sig_state = lmod_get_state_item(ctx->hadb_entry->hip_modular_state, "signaling_hipd_state")),
                 -1, "failed to retrieve state for signaling\n");
    HIP_IFEL(signaling_build_param_user_signature(ctx->output_msg, sig_state->pending_conn->ctx_out.user.uid),
             -1, "User failed to sign packet.\n");
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop PERF_R1x4, PERF_R1x4x3\n");
    hip_perf_stop_benchmark(perf_set, PERF_R1x4);
    hip_perf_stop_benchmark(perf_set, PERF_R1x4x3);
#endif
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
    HIP_IFEL(signaling_build_param_user_context(ctx->output_msg, &sig_state->pending_conn->ctx_out.user, sig_state->pending_conn->ctx_out.userdb_entry),
            -1, "Building of user context parameter failed.\n");

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop PERF_R1x3\n");
    hip_perf_stop_benchmark(perf_set, PERF_R1x3);
#endif

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

