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
 * Builds a complete update message from scratch.
 * Setting either seq or ack_id to
 *
 */
static struct hip_common *build_update_message(hip_ha_t *ha, const int type, struct signaling_connection_context *ctx, const uint32_t seq) {
    int err                 = 0;
    uint16_t mask           = 0;
    struct hip_common *msg_buf   = NULL;

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

    /* Add connection id, application and user context.
     * These parameters (as well as the user's signature are non-critical */
    if(signaling_build_param_connection_identifier(msg_buf, ctx)) {
        HIP_DEBUG("Building of connection identifier parameter failed\n");
    }
    if(signaling_build_param_application_context(msg_buf, ctx)) {
        HIP_DEBUG("Building of application context parameter failed\n");
    }
    if(signaling_build_param_user_context(msg_buf, &ctx->user_ctx)) {
        HIP_DEBUG("Building of user conext parameter failed.\n");
    }

    /* Add host authentication */
    HIP_IFEL(hip_build_param_hmac_contents(msg_buf, &ha->hip_hmac_out),
            -1, "Building of HMAC failed\n");
    HIP_IFEL(ha->sign(ha->our_priv_key, msg_buf),
            -EINVAL, "Could not sign UPDATE. Failing\n");

    /* Add user authentication */
    if(signaling_build_param_user_signature(msg_buf, ctx->user_ctx.uid)) {
        HIP_DEBUG("User failed to sign UPDATE.\n");
    }

    return msg_buf;

out_err:
    free(msg_buf);
    return NULL;
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
    struct hip_common * update_packet_to_send    = NULL;

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
    struct hip_common * update_packet_to_send            = NULL;
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

/**
 * Send a whole certificate chain, possibly dstributed over multiple messages.
 * TODO: Refactor this and move the building parts to the builder.
 * @param ha the host association for the connection on which to send the certificate chain
 *
 * @return  0 on success, negative on error
 */
int signaling_send_user_certificate_chain(hip_ha_t *ha) {
    int err = 0;
    uint16_t mask           = 0;
    struct hip_common *msg_buf = NULL;
    struct update_state * updatestate       = NULL;
    struct signaling_hipd_state * sig_state = NULL;
    STACK_OF(X509) *cert_chain = NULL;
    X509 *cert = NULL;
    int cert_len;
    unsigned char *buf;
    int count = 0;
    int total_cert_count;
    int free_space;

    /* sanity checks */
    HIP_IFEL(!ha, -1, "Given HA is NULL \n");
    HIP_IFEL(!(updatestate = (struct update_state *) lmod_get_state_item(ha->hip_modular_state, "update")),
             -1, "Could not get update state for host association.\n");

    /* Get the users certificate chain */
    HIP_IFEL(!(sig_state = (struct signaling_hipd_state *) lmod_get_state_item(ha->hip_modular_state, "signaling_hipd_state")),
             -1, "failed to retrieve state for signaling module\n");
    HIP_IFEL(!(cert_chain = signaling_user_api_get_user_certificate_chain(sig_state->ctx.user_ctx.uid)),
             -1, "Could not get certificate for user with id %d\n", sig_state->ctx.user_ctx.uid);
    total_cert_count = sk_X509_num(cert_chain);
    HIP_DEBUG("Sending a total of %d certificates from users chain.\n", total_cert_count);

    while(sk_X509_num(cert_chain) > 0) {
        /* Allocate and build a new message */
        HIP_IFEL(!(msg_buf = hip_msg_alloc()),
                -ENOMEM, "Out of memory while allocation memory for the user cert update packet\n");
        hip_build_network_hdr(msg_buf, HIP_UPDATE, mask, &ha->hit_our, &ha->hit_peer);

        /* Add sequence number */
        updatestate->update_id_out++;
        HIP_IFEL(hip_build_param_seq(msg_buf, hip_update_get_out_id(updatestate)),
                 -1, "Building of SEQ parameter failed\n");
        /* Put as much certificate parameter into the message as possible */
        do {
            cert = sk_X509_value(cert_chain, sk_X509_num(cert_chain)-1);
            HIP_IFEL((cert_len = signaling_X509_to_DER(cert, &buf)) < 0,
                     -1, "Could not get DER encoding of certificate\n");
            free_space = signaling_get_free_message_space(msg_buf, ha);
            if (free_space == -1) {
                err = -1;
                goto out_err;
            } else if(free_space > cert_len + (int) sizeof(struct hip_sig) + 7) {
                count++;
                HIP_IFEL(hip_build_param_cert(msg_buf, 0, total_cert_count, count, HIP_CERT_X509V3, buf, cert_len),
                         -1, "Could not build cert parameter\n");
                cert = sk_X509_pop(cert_chain);
                X509_free(cert);
            }
            free(buf);
            buf = NULL;

            if(free_space <= cert_len) {
                HIP_DEBUG("Free space left in current message is not not enough for next cert: Have %d but need %d\n",
                          free_space, cert_len + (int) sizeof(struct hip_sig) + 7);
                break;
            }
        } while (sk_X509_num(cert_chain) > 0);

        /* Mac and sign the packet */
        HIP_IFEL(hip_build_param_hmac_contents(msg_buf, &ha->hip_hmac_out),
                 -1, "Building of HMAC failed\n");
        HIP_IFEL(ha->sign(ha->our_priv_key, msg_buf),
                 -EINVAL, "Could not sign UPDATE. Failing\n");

        HIP_DEBUG("Sending certificate chain for subject id %d up to certificate %d of %d\n", sig_state->ctx.user_ctx.uid, count, total_cert_count);

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
    free(buf);
    free(msg_buf);
    return err;
}

/*
 * Process application information in an I2 packet.
 * We have to send a request to the firewall for the connection with this context,
 * and expect our own connection context from the hipfw to send it in the R2.
 *
 */
UNUSED static int signaling_handle_i2_app_context(UNUSED const uint8_t packet_type, UNUSED const uint32_t ha_state, struct hip_packet_context *ctx)
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
    const struct signaling_param_user_context *param_usr_ctx = NULL;
    struct signaling_hipd_state * sig_state = NULL;

    err = signaling_verify_user_signature(ctx->input_msg);
    switch (err) {
    case 0:
        HIP_DEBUG("User signature verification successful\n");
        break;
    case -1:
        HIP_DEBUG("Error processing user signature \n");
        break;
    default:
        HIP_DEBUG("Could not verify certifcate chain:\n");
        HIP_DEBUG("Error: %s \n", X509_verify_cert_error_string(err));
        /* cache the user identity */
        HIP_IFEL(!(param_usr_ctx = hip_get_param(ctx->input_msg, HIP_PARAM_SIGNALING_USERINFO)),
                 -1, " error getting user context. \n");
        HIP_IFEL(!(sig_state = (struct signaling_hipd_state *) lmod_get_state_item(ctx->hadb_entry->hip_modular_state, "signaling_hipd_state")),
                 -1, "failed to retrieve state for signaling module\n");
        signaling_build_user_context(param_usr_ctx, &sig_state->user_cert_ctx.user_ctx);
        HIP_DEBUG("Requesting user's certificate chain.\n");
        signaling_send_user_auth_failed_ntf(ctx->hadb_entry, SIGNALING_USER_AUTH_CERTIFICATE_REQUIRED);
    }

out_err:
    return err;
}

/*
 * Process user context information in an R2 packet.
 */
static int signaling_handle_r2_user_context(UNUSED const uint8_t packet_type, UNUSED const uint32_t ha_state, struct hip_packet_context *ctx)
{
    return signaling_handle_i2_user_context(packet_type, ha_state, ctx);
}

/*
 * Handles an incomding I2 packet.
 */
int signaling_handle_incoming_i2(const uint8_t packet_type, UNUSED const uint32_t ha_state, struct hip_packet_context *ctx) {
    int err = 0;
    const struct signaling_param_user_context *param_usr_ctx = NULL;
    struct signaling_hipd_state * sig_state = NULL;
    struct signaling_connection_context conn_ctx;

    /* sanity checks */
    HIP_IFEL(packet_type != HIP_I2, -1, "Not an I2 Packet\n")
    HIP_IFEL(signaling_init_connection_context_from_msg(&conn_ctx, ctx->input_msg),
             -1, "Could not init connection context from R2 \n");

    /* Try to authenticate the user */
    err = signaling_verify_user_signature(ctx->input_msg);
    switch (err) {
    case 0:
        /* In this case we can tell the oslayer to add the connection, if it complies with local policy */
        HIP_DEBUG("User signature verification successful\n");
        conn_ctx.connection_status = SIGNALING_CONN_USER_AUTHED;
        break;
    case -1:
        /* In this case we just assume user auth has failed, we do not request his certificates,
         * since this was an internal error. Here, some retransmission of the received packet would be needed */
        HIP_DEBUG("Error processing user signature \n");
        conn_ctx.connection_status = SIGNALING_CONN_USER_UNAUTHED;
        break;
    default:
        /* In this case, we need to request the user's certificate chain.
         * We tell the firewall, that we haven't authenticated the user,
         * so that it can either block until user is authed or allow if the local policy
         * doesn't care about the user. */
        HIP_DEBUG("Could not verify user's certifcate chain:\n");
        HIP_DEBUG("Error: %s \n", X509_verify_cert_error_string(err));
        conn_ctx.connection_status = SIGNALING_CONN_USER_UNAUTHED;

        /* cache the user identity to able to identify it later on */
        HIP_IFEL(!(param_usr_ctx = hip_get_param(ctx->input_msg, HIP_PARAM_SIGNALING_USERINFO)),
                 -1, " error getting user context. \n");
        HIP_IFEL(!(sig_state = (struct signaling_hipd_state *) lmod_get_state_item(ctx->hadb_entry->hip_modular_state, "signaling_hipd_state")),
                 -1, "failed to retrieve state for signaling module\n");
        signaling_build_user_context(param_usr_ctx, &sig_state->user_cert_ctx.user_ctx);
    }

    /* Tell the firewall/oslayer about the new connection and await it's decision */
    signaling_send_connection_context_request(&ctx->input_msg->hits, &ctx->input_msg->hitr, &conn_ctx);

out_err:
    return err;
}

/*
 * Handles an incoming R2 packet.
 */
int signaling_handle_incoming_r2(const uint8_t packet_type, UNUSED const uint32_t ha_state, struct hip_packet_context *ctx) {
    int err     = 0;
    struct signaling_hipd_state *sig_state = NULL;

    HIP_IFEL(packet_type != HIP_R2, -1, "Not an R2 Packet\n")
    signaling_handle_r2_user_context(packet_type, ha_state, ctx);
    signaling_handle_r2_app_context(packet_type, ha_state, ctx);

    HIP_IFEL(!(sig_state = (struct signaling_hipd_state *) lmod_get_state_item(ctx->hadb_entry->hip_modular_state, "signaling_hipd_state")),
            -1, "failed to retrieve state for signaling ports\n");
    if (sig_state->user_cert_ctx.user_certificate_required) {
        signaling_send_user_certificate_chain(ctx->hadb_entry);
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
    X509 *cert = NULL;
    STACK_OF(X509) *cert_chain = NULL;
    struct signaling_hipd_state *sig_state = NULL;
    struct hip_host_id pseudo_ui;
    EVP_PKEY *pkey = NULL;
    X509_NAME *subject_name = NULL;

    /* sanity checks */
    HIP_IFEL(!ctx->input_msg,  -1, "Message is NULL\n");

    /* process certificates */
    HIP_IFEL(!(param_cert = hip_get_param(ctx->input_msg, HIP_PARAM_CERT)),
             0, "Message contains no certificate (second certificate update (ACK) \n");
    HIP_IFEL(!(sig_state = (struct signaling_hipd_state *) lmod_get_state_item(ctx->hadb_entry->hip_modular_state, "signaling_hipd_state")),
            -1, "failed to retrieve state\n");
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
            pseudo_ui.hi_length = sig_state->user_cert_ctx.user_ctx.key_rr_len;
            pseudo_ui.rdata.algorithm = sig_state->user_cert_ctx.user_ctx.rdata.algorithm;
            // note: the + 1 moves the pointer behind the parameter, where the key rr begins
            memcpy(pseudo_ui.key,
                   sig_state->user_cert_ctx.user_ctx.pkey,
                   sig_state->user_cert_ctx.user_ctx.key_rr_len - sizeof(struct hip_host_id_key_rdata));
            HIP_IFEL(!(pkey = hip_key_rr_to_evp_key(&pseudo_ui, 0)), -1, "Could not deserialize users public key\n");
            PEM_write_PUBKEY(stderr, pkey);
            cert = sk_X509_pop(cert_chain);
            HIP_IFEL(signaling_DER_to_X509_NAME(sig_state->user_cert_ctx.user_ctx.subject_name, sig_state->user_cert_ctx.user_ctx.subject_name_len, &subject_name),
                     -1, "Could not get users X509 name");
            HIP_IFEL(signaling_user_api_verify_pubkey(subject_name, pkey, cert, 1),
                     -1, "Could not verify users public key with received certificate chain\n");
            if (!verify_certificate_chain(cert, CERTIFICATE_INDEX_TRUSTED_DIR, NULL, cert_chain)) {
                /* Public key verification was successful, so we save the chain and confirm to the firewall */
                sk_X509_push(cert_chain, cert);
                signaling_add_user_certificate_chain(cert_chain);
                sig_state->ctx.connection_status = SIGNALING_CONN_USER_AUTHED;
                HIP_DEBUG("Confirming user authentication to OSLAYER\n");
                signaling_connection_context_print(&sig_state->ctx, "");
                signaling_send_connection_confirmation(&ctx->hadb_entry->hit_our, &ctx->hadb_entry->hit_peer, &sig_state->ctx);

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

/*
 * Handle a BEX update
 */
int signaling_handle_incoming_update(UNUSED const uint8_t packet_type, UNUSED const uint32_t ha_state, struct hip_packet_context *ctx)
{
    int err = 0;
    int update_type;
    struct signaling_connection_context conn_ctx;
    struct signaling_hipd_state *sig_state = NULL;
    /* Sanity checks */
    HIP_IFEL((update_type = signaling_get_update_type(ctx->input_msg)) < 0,
             -1, "This is no signaling update packet\n");

    /* Handle the different update types */
    if(update_type == SIGNALING_FIRST_BEX_UPDATE) {
        HIP_DEBUG("Received FIRST BEX Update... \n");
        HIP_IFEL(signaling_verify_user_signature(ctx->input_msg),
                 -1, "Could not verify user's signature in update packet.");
        HIP_DEBUG("Correctly verified user signature in UPDATE \n");
        HIP_IFEL(signaling_send_second_update(ctx->input_msg),
                 -1, "failed to trigger second bex update. \n");
    } else if (update_type == SIGNALING_SECOND_BEX_UPDATE) {
        HIP_DEBUG("Received SECOND BEX Update... \n");
        HIP_IFEL(signaling_init_connection_context_from_msg(&conn_ctx, ctx->input_msg),
                 -1, "Could not init connection context from UPDATE \n");
        conn_ctx.connection_status = SIGNALING_CONN_ALLOWED;
        HIP_IFEL(signaling_send_connection_confirmation(&ctx->input_msg->hits, &ctx->input_msg->hitr, &conn_ctx),
                -1, "failed to notify fw to update scdb\n");
        HIP_IFEL(!(sig_state = lmod_get_state_item(ctx->hadb_entry->hip_modular_state, "signaling_hipd_state")),
                     -1, "failed to retrieve state for signaling\n");
        sig_state->update_in_progress = 0;
    } else if (update_type == SIGNALING_FIRST_USER_CERT_CHAIN_UPDATE) {
        err = signaling_handle_incoming_certificate_udpate(packet_type, ha_state, ctx);
    } else if (update_type == SIGNALING_SECOND_USER_CERT_CHAIN_UPDATE) {
        err = signaling_handle_incoming_certificate_udpate(packet_type, ha_state, ctx);
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
    struct signaling_hipd_state *sig_state;

    HIP_IFEL(!ctx->hadb_entry, -1, "No hadb entry.\n");
    HIP_IFEL(!(sig_state = lmod_get_state_item(ctx->hadb_entry->hip_modular_state, "signaling_hipd_state")),
                 -1, "failed to retrieve state for signaling\n");
    if(signaling_build_param_connection_identifier(ctx->output_msg, &sig_state->ctx)) {
        HIP_DEBUG("Building of connection identifier parameter failed\n");
    }
    HIP_IFEL(signaling_build_param_application_context(ctx->output_msg, &sig_state->ctx),
            -1, "Building of application context parameter failed.\n");

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
    HIP_IFEL(signaling_build_param_user_signature(ctx->output_msg, sig_state->ctx.user_ctx.uid),
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
    HIP_IFEL(signaling_build_param_user_context(ctx->output_msg, &sig_state->ctx.user_ctx),
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
