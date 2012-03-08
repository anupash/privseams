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

#include <string.h>
#include <unistd.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

#include "lib/core/debug.h"
#include "lib/core/builder.h"
#include "lib/core/protodefs.h"
#include "lib/core/common.h"
#include "lib/core/ife.h"
#include "lib/core/prefix.h"
#include "lib/core/hostid.h"

#include "signaling_common_builder.h"
#include "signaling_oslayer.h"
#include "signaling_prot_common.h"
#include "signaling_user_api.h"
#include "signaling_x509_api.h"
#include "signaling_user_management.h"



#define CALLBUF_SIZE            60
#define SYMLINKBUF_SIZE         16


/**
 * Builds a hip_param_connection_identifier parameter into msg,
 * using the values in the connection context .
 *
 * @param ctx the connection context where values are taken from
 * @param msg the message, where the parameter is appended
 *
 * @return zero for success, or non-zero on error
 */
int signaling_build_param_connection_identifier(struct hip_common *msg, const struct signaling_connection *conn)
{
    int                                          err = 0;
    struct signaling_param_connection_identifier conn_id;

    /* Sanity checks */
    HIP_IFEL(msg  == NULL, -1, "Got no msg context. (msg == NULL)\n");
    HIP_IFEL(conn == NULL, -1, "Got no context to built the parameter from.\n");

    hip_set_param_type((struct hip_tlv_common *) &conn_id, HIP_PARAM_SIGNALING_CONNECTION_ID);
    hip_set_param_contents_len((struct hip_tlv_common *) &conn_id,
                               sizeof(struct signaling_param_connection_identifier) - sizeof(struct hip_tlv_common));
    conn_id.id = htonl(conn->id);

    HIP_IFEL(hip_build_param(msg, &conn_id),
             -1, "Failed to append connection identifier parameter to message.\n");

out_err:
    return err;
}

/**
 * Builds a hip_param_signaling_appinfo parameter into msg,
 * using the values in the application context 'app_ctx'.
 * TODO: Define and check for mandatory fields.
 *
 * @param app_ctx the application context where values are taken from
 * @param msg the message, where the parameter is appended
 *
 * @return zero for success, or non-zero on error
 */
int signaling_build_param_application_context(struct hip_common *msg,
                                              const struct signaling_port_pair *port_list,
                                              const struct signaling_application_context *app_ctx)
{
    struct signaling_param_app_context appinfo;
    int                                err          = 0;
    int                                i            = 0;
    int                                len_contents = 0;
    int                                tmp_len;
    uint8_t                           *p_tmp = NULL;
    struct signaling_port_pair        *pp    = NULL;
    char                               param_buf[HIP_MAX_PACKET];

    /* Sanity checks */
    HIP_IFEL(msg == NULL,     -1, "Got no msg context. (msg == NULL)\n");
    HIP_IFEL(app_ctx == NULL, -1, "Got no context to built the parameter from.\n");

    /* BUILD THE PARAMETER CONTENTS */
    appinfo.reserved = htons(0);
    pp               = (struct signaling_port_pair *) param_buf;

    /* Set the ports */
    for (i = 0; i < SIGNALING_MAX_SOCKETS; i++) {
        if (port_list[i].src_port == 0 && port_list[i].dst_port == 0) {
            break;
        }
        pp[i].src_port = htons(port_list[i].src_port);
        pp[i].dst_port = htons(port_list[i].dst_port);
    }
    appinfo.port_count = htons(i);
    len_contents      += i * sizeof(struct signaling_port_pair);
    p_tmp              = (uint8_t *) (pp + i);

    /* Set the application */
    tmp_len = MIN(strlen(app_ctx->application_dn), SIGNALING_APP_DN_MAX_LEN);
    memcpy(p_tmp, app_ctx->application_dn, tmp_len);
    appinfo.app_dn_length = htons(tmp_len);
    len_contents         += tmp_len;
    p_tmp                += tmp_len;

    /* Set the issuer */
    tmp_len = MIN(strlen(app_ctx->issuer_dn), SIGNALING_ISS_DN_MAX_LEN);
    memcpy(p_tmp, app_ctx->issuer_dn, tmp_len);
    appinfo.iss_dn_length = htons(tmp_len);
    len_contents         += tmp_len;
    p_tmp                += tmp_len;

    /* Set the requirements */
    tmp_len = MIN(strlen(app_ctx->requirements), SIGNALING_APP_REQ_MAX_LEN);
    memcpy(p_tmp, app_ctx->requirements, tmp_len);
    appinfo.req_length = htons(tmp_len);
    len_contents      += tmp_len;
    p_tmp             += tmp_len;

    /* Set the group */
    tmp_len = MIN(strlen(app_ctx->groups), SIGNALING_APP_GRP_MAX_LEN);
    memcpy(p_tmp, app_ctx->groups, tmp_len);
    appinfo.grp_length = htons(tmp_len);
    len_contents      += tmp_len;
    p_tmp             += tmp_len;

    /* Set type and length */
    len_contents += sizeof(struct signaling_param_app_context) - sizeof(struct hip_tlv_common);
    hip_set_param_contents_len((struct hip_tlv_common *) &appinfo, len_contents);
    //TODO update the parameter type with the correct ones
    hip_set_param_type((struct hip_tlv_common *) &appinfo, HIP_PARAM_SIGNALING_APP_INFO_NAME);

    /* Append the parameter to the message */
    if (hip_build_generic_param(msg, &appinfo, sizeof(struct signaling_param_app_context), param_buf)) {
        HIP_ERROR("Failed to append appinfo parameter to message.\n");
        return -1;
    }

out_err:
    return err;
}

static int any_key_to_key_rr(EVP_PKEY *key, uint8_t *algorithm, unsigned char **key_rr_out)
{
    int err = 0;
    int type;

    HIP_IFEL(!key,          -1, "Cannot serialize NULL-key \n");
    HIP_IFEL(!algorithm,    -1, "Cannot write algorithm to NULL field \n");
    HIP_IFEL(!key_rr_out,   -1, "Cannot write to NULL-buffer \n");

    type = EVP_PKEY_type(key->type);

    switch (type) {
    case EVP_PKEY_RSA:
        *algorithm = HIP_HI_RSA;
        return rsa_to_dns_key_rr(EVP_PKEY_get1_RSA(key), key_rr_out);
    case EVP_PKEY_DSA:
        *algorithm = HIP_HI_DSA;
        return dsa_to_dns_key_rr(EVP_PKEY_get1_DSA(key), key_rr_out);
    case EVP_PKEY_EC:
        *algorithm = HIP_HI_ECDSA;
        return ecdsa_to_key_rr(EVP_PKEY_get1_EC_KEY(key), key_rr_out);
    default:
        HIP_ERROR("Cannot handle unknown key type %d. \n", type);
        *algorithm  = 0;
        *key_rr_out = NULL;
        err         = -1;
    }

out_err:
    return err;
}

/**
 * Build a user context parameter from the given internal user context into msg.
 *
 * @param msg       the message where to put the parameter
 * @param user_ctx  the user context from which the parameter is built
 *
 * @return          zero for success, or non-zero on error
 */
int signaling_build_param_user_context(struct hip_common *msg,
                                       struct signaling_user_context *user_ctx,
                                       struct userdb_user_entry *db_entry)
{
    struct signaling_param_user_context *param_userinfo = NULL;
    int                                  err            = 0;
    int                                  username_len;
    int                                  header_len;
    int                                  pkey_rr_len;
    int                                  par_contents_len;
    EVP_PKEY                            *user_pkey = NULL;
    unsigned char                       *key_rr;

    /* Sanity checks */
    if (!msg) {
        HIP_ERROR("Got no msg context. (msg == NULL)\n");
        return -1;
    }

    /* Check for users public key.
     *   a) We already have it in the user_ctx (send by the firewall).
     *   b) We need to load it from the users certificate. */
    if (user_ctx->key_rr_len <= 0) {
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Start PERF_I_LOAD_USER_PUBKEY, PERF_R_LOAD_USER_PUBKEY");
        hip_perf_start_benchmark(perf_set, PERF_I_LOAD_USER_PUBKEY);
        hip_perf_start_benchmark(perf_set, PERF_R_LOAD_USER_PUBKEY);
#endif
        HIP_IFEL(!(user_pkey = signaling_user_api_get_user_public_key(user_ctx->uid)),
                 -1, "Could not obtain users public key \n");
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Stop PERF_I_LOAD_USER_PUBKEY, PERF_R_LOAD_USER_PUBKEY");
        hip_perf_stop_benchmark(perf_set, PERF_I_LOAD_USER_PUBKEY);
        hip_perf_stop_benchmark(perf_set, PERF_R_LOAD_USER_PUBKEY);
#endif
        PEM_write_PUBKEY(stdout, user_pkey);
        HIP_IFEL((user_ctx->key_rr_len = any_key_to_key_rr(user_pkey, &user_ctx->rdata.algorithm, &key_rr)) < 0,
                 -1, "Could not serialize key \n");
        HIP_DEBUG("GOT keyy rr of length %d\n", user_ctx->key_rr_len);
        memcpy(user_ctx->pkey, key_rr, user_ctx->key_rr_len);
        // set key in userdb
        db_entry->pub_key = user_pkey;

        // necessary because any_key_to_rr returns only the length of the key rrwithout the header
        user_ctx->key_rr_len += sizeof(struct hip_host_id_key_rdata);
        free(key_rr);
    }

    /* calculate lengths */
    header_len       = sizeof(struct signaling_param_user_context) - sizeof(struct hip_host_id_key_rdata);
    pkey_rr_len      = user_ctx->key_rr_len;
    username_len     = user_ctx->subject_name_len;
    par_contents_len = header_len - sizeof(struct hip_tlv_common) + pkey_rr_len + username_len;

    /* BUILD THE PARAMETER */
    param_userinfo = malloc(sizeof(struct hip_tlv_common) + par_contents_len);
    HIP_IFEL(!param_userinfo, -1, "Could not allocate user signature parameter. \n");

    /* Set user identity (public key) */
    param_userinfo->pkey_rr_length  = htons(pkey_rr_len);
    param_userinfo->rdata.algorithm = user_ctx->rdata.algorithm;
    param_userinfo->rdata.flags     = htons(user_ctx->rdata.flags);
    param_userinfo->rdata.protocol  = user_ctx->rdata.protocol;
    memcpy((uint8_t *) param_userinfo + header_len + sizeof(struct hip_host_id_key_rdata),
           user_ctx->pkey,
           pkey_rr_len - sizeof(struct hip_host_id_key_rdata));

    /* Set user name */
    param_userinfo->un_length = htons(username_len);
    memcpy((uint8_t *) param_userinfo + header_len + pkey_rr_len, user_ctx->subject_name, username_len);

    /* Set type and length */
    hip_set_param_type((struct hip_tlv_common *) param_userinfo, HIP_PARAM_SIGNALING_USER_INFO_ID);
    hip_set_param_contents_len((struct hip_tlv_common *) param_userinfo, par_contents_len);

    HIP_IFEL(hip_build_param(msg, param_userinfo),
             -1, "Failed to append appinfo parameter to message.\n");

out_err:
    return err;
}

/**
 *  Build a user signature from the given user context into the given message.
 *
 *  @param msg  the message, to sign
 *  @param uid  the id of the user, which will be prompted for his signature
 *
 *  @return         0 on success, negative otherwise
 */
int signaling_build_param_user_signature(struct hip_common *msg, const uid_t uid)
{
    int            err = 0;
    struct hip_sig sig;
    unsigned char  signature_buf[HIP_MAX_RSA_KEY_LEN / 8];
    int            in_len;
    int            sig_len  = 0;
    uint8_t        sig_type = HIP_HI_RSA;

    /* sanity checks */
    HIP_IFEL(!msg,       -1, "Cannot sign NULL-message\n");

    /* calculate the signature */
    in_len = hip_get_msg_total_len(msg);
    HIP_IFEL((sig_len = signaling_user_api_sign(uid, msg, in_len, signature_buf, &sig_type)) < 0,
             -1, "Could not get user's signature \n");
    HIP_IFEL(sig_type != HIP_HI_RSA && sig_type != HIP_HI_RSA && sig_type != HIP_HI_ECDSA,
             -1, "Unsupported signature type: %d\n", sig_type);

    /* build the signature parameter */
    hip_set_param_type((struct hip_tlv_common *) &sig, HIP_PARAM_SIGNALING_USER_SIGNATURE);
    hip_calc_generic_param_len((struct hip_tlv_common *) &sig, sizeof(struct hip_sig), sig_len);
    sig.algorithm = sig_type;     // algo is 8 bits, no htons necessary
    HIP_IFEL(hip_build_generic_param(msg, &sig, sizeof(struct hip_sig), signature_buf),
             -1, "Failed to build signature parameter\n");

out_err:
    return err;
}

/**
 * Build a connection failed notification parameter.
 *
 * @param msg       the message to which to append the parameter
 * @param reason    the reason why the connection failed.
 *                  this is used in the notification data field
 *
 * @return          0 on sucess, negative if paramater building failed
 */
int signaling_build_param_connection_fail(struct hip_common *msg, const uint16_t reason)
{
    int                                         err = 0;
    int                                         len;
    struct hip_notification                     ntf;
    struct signaling_ntf_connection_failed_data ntf_data;

    /* first build the notification header */
    hip_set_param_type((struct hip_tlv_common *) &ntf, HIP_PARAM_NOTIFICATION);
    len = sizeof(struct hip_notification) - sizeof(struct hip_tlv_common) + sizeof(struct signaling_ntf_user_auth_failed_data);
    hip_set_param_contents_len((struct hip_tlv_common *) &ntf, len);
    ntf.msgtype = ntohs(SIGNALING_CONNECTION_FAILED);

    /* then build the notification data */
    ntf_data.reason = htons(reason);

    /* finally build the parameter into the message */
    HIP_IFEL(hip_build_generic_param(msg, &ntf, sizeof(struct hip_notification), &ntf_data),
             -1, "Could not build notification parameter into message \n");

out_err:
    return err;
}

/**
 * Build a user authentication failed notification parameter.
 *
 * @param msg       the message to which to append the parameter
 * @param reason    the reason why user authentication failed.
 *                  this is used in the notification data field
 *
 * @return          0 on sucess, negative if paramater building failed
 */
int signaling_build_param_user_auth_fail(struct hip_common *msg, const uint16_t reason)
{
    int                                        err = 0;
    int                                        len;
    struct hip_notification                    ntf;
    struct signaling_ntf_user_auth_failed_data ntf_data;

    /* first build the notification header */
    hip_set_param_type((struct hip_tlv_common *) &ntf, HIP_PARAM_NOTIFICATION);
    len = sizeof(struct hip_notification) - sizeof(struct hip_tlv_common) + sizeof(struct signaling_ntf_user_auth_failed_data);
    hip_set_param_contents_len((struct hip_tlv_common *) &ntf, len);
    ntf.msgtype = ntohs(SIGNALING_USER_AUTH_FAILED);

    /* then build the notification data */
    ntf_data.reason = htons(reason);

    /* finally build the parameter into the message */
    HIP_IFEL(hip_build_generic_param(msg, &ntf, sizeof(struct hip_notification), &ntf_data),
             -1, "Could not build notification parameter into message \n");

out_err:
    return err;
}

/**
 * Build as many hip_cert parameters into the message as possible.
 *
 * @param msg         msg, where the certificates are appended
 * @param cert_chain  the certificate chain
 * @param start       the first certificate included is at position start from the top of the stack
 *                    e.g. use start = 1 to start at the top
 * @param freespace   the number of bytes we can use for the certificate parameter
 *                    (the caller should calculate this number in a way that the remaining parameters
 *                     like signatures, HMAC still fit into the packet)
 *
 * @return          -1 on error, otherwise the number of certificates included in the message
 */
int signaling_build_param_cert_chain(struct hip_common *msg,
                                     STACK_OF(X509) *cert_chain,
                                     int start,
                                     int count,
                                     int freespace)
{
    int            err = 0;
    int            i   = start;
    int            cert_len;
    unsigned char *buf;
    X509          *cert = NULL;

    /* sanity checks */
    HIP_IFEL(!msg, -1, "Cannot build parameters into NULL-message\n");
    if (sk_X509_num(cert_chain) == 0) {
        return 0;
    }
    if (start > sk_X509_num(cert_chain)) {
        HIP_DEBUG("Start index is out of range. \n");
        return -1;
    }

    do {
        cert = sk_X509_value(cert_chain, sk_X509_num(cert_chain) - i);
        HIP_IFEL((cert_len = signaling_X509_to_DER(cert, &buf)) < 0,
                 -1, "Could not get DER encoding of certificate #%d (from top)\n", i);
        if (freespace > cert_len + (int) sizeof(struct hip_sig) + 7) {
            HIP_IFEL(hip_build_param_cert(msg, 0, count, i, HIP_CERT_X509V3, buf, cert_len),
                     -1, "Could not build cert parameter\n");
            freespace -= cert_len;
        } else {
            HIP_DEBUG("Free space left in current message is not not enough for next cert: Have %d but need %d\n",
                      freespace, cert_len + (int) sizeof(struct hip_sig) + 7);
            break;
        }
        free(buf);
        buf = NULL;
        i++;
    } while (sk_X509_num(cert_chain) - i >= 0);

    return i - start;

out_err:
    return err;
}

int signaling_build_param_certificate_chain_identifier(struct hip_common *const msg,
                                                       const uint32_t connection_id,
                                                       const uint32_t network_id)
{
    int                                  err = 0;
    int                                  len;
    struct signaling_param_cert_chain_id ccid;

    /* sanity checks*/
    HIP_IFEL(!msg, -1, "Cannot append cert chain id parameter to NULL message \n");

    /* build and append parameter */
    hip_set_param_type((struct hip_tlv_common *) &ccid, HIP_PARAM_SIGNALING_CERT_CHAIN_ID);
    len = sizeof(struct signaling_param_cert_chain_id) - sizeof(struct hip_tlv_common);
    hip_set_param_contents_len((struct hip_tlv_common *) &ccid, len);
    ccid.connection_id = htonl(connection_id);
    ccid.network_id    = htonl(network_id);
    HIP_IFEL(hip_build_param(msg, &ccid),
             -1, "Could not build cert chain id parameter into message \n");

out_err:
    return err;
}

int signaling_build_param_host_info_response(struct hip_common *msg,
                                             UNUSED struct signaling_connection existing_conn,
                                             struct signaling_connection_context *ctx,
                                             const uint8_t host_info_flag)
{
    int err          = 0;
    int len_contents = 0;
    int tmp_len;
    //uint8_t                                *p_tmp = NULL;
    //char param_buf[HIP_MAX_PACKET];
    //struct signaling_param_host_info_id     host_info_id;
    struct signaling_param_host_info_os     host_info_os;
    struct signaling_param_host_info_kernel host_info_kernel;
    //struct signaling_param_host_info_certs  host_info_certs;

    /*Sanity checks*/
    HIP_IFEL(msg        == NULL,    -1, "Got no msg context. (msg == NULL)\n");

    /*BUILD THE PARAMETER CONTENTS*/
    switch (host_info_flag) {
    case HOST_INFO_KERNEL:
        HIP_DEBUG("Request for Information about Host Kernel found. Building host info kernel parameter.\n");
        tmp_len = (ctx->host.host_kernel_len > MAX_SIZE_HOST_KERNEL) ? MAX_SIZE_HOST_KERNEL : ctx->host.host_kernel_len;
        HIP_DEBUG("Host Kernel Length set to be %d.\n", tmp_len);
        memcpy(host_info_kernel.kernel, ctx->host.host_kernel, tmp_len);
        host_info_kernel.kernel[tmp_len] = '\0';
        HIP_DEBUG("Host Kernel value copied \n");

        hip_set_param_contents_len((struct hip_tlv_common *) &host_info_kernel, tmp_len);
        hip_set_param_type((struct hip_tlv_common *) &host_info_kernel, HIP_PARAM_SIGNALING_HOST_INFO_KERNEL);

        /* Append the parameter to the message */
        if (hip_build_param(msg, &host_info_kernel)) {
            HIP_ERROR("Failed to append host info kernel parameter to message.\n");
            return -1;
        }
        break;
    case HOST_INFO_OS:
        HIP_DEBUG("Request for Information about Host OS found. Building host info os parameter\n");
        tmp_len             = (ctx->host.host_os_len > MAX_SIZE_HOST_OS) ? MAX_SIZE_HOST_OS : ctx->host.host_os_len;
        host_info_os.os_len = htons(tmp_len);
        memcpy(&host_info_os.os_name, &ctx->host.host_os, tmp_len);

        tmp_len                     = (ctx->host.host_os_ver_len > MAX_SIZE_HOST_OS) ? MAX_SIZE_HOST_OS : ctx->host.host_os_ver_len;
        host_info_os.os_version_len = htons(tmp_len);
        memcpy(&host_info_os.os_version, &ctx->host.host_os_version, tmp_len);

        len_contents = sizeof(struct signaling_param_host_info_os) - (sizeof(hip_tlv) + sizeof(hip_tlv_len));
        hip_set_param_contents_len((struct hip_tlv_common *) &host_info_os, len_contents);
        hip_set_param_type((struct hip_tlv_common *) &host_info_os, HIP_PARAM_SIGNALING_HOST_INFO_OS);

        /* Append the parameter to the message */
        if (hip_build_param(msg, &host_info_os)) {
            HIP_ERROR("Failed to append host info os parameter to message.\n");
            return -1;
        }
        break;
    case HOST_INFO_ID:
        //TODO right now the assumption is HOST_ID parameter is sent already in the I2 and R2 packet
        //TODO change the code when blinding occurs

        HIP_DEBUG("Request for Information about Host ID found. Building host info ID parameter\n");

/*
 *       host_info_id.host_id_length = htons(ctx->host.host_name_len);
 *       p_tmp                       = (uint8_t *) param_buf;
 *       memcpy(p_tmp, ctx->host.host_name, ctx->host.host_name_len);
 *       len_contents += ctx->host.host_name_len;
 *
 *       host_info_id.domain_id_length = htons(ctx->host.host_domain_name_len);
 *       p_tmp                         = (uint8_t *) param_buf;
 *       memcpy(p_tmp, ctx->host.host_domain_name, ctx->host.host_domain_name_len);
 *       len_contents += ctx->host.host_domain_name_len;
 *
 *       len_contents += sizeof(struct signaling_param_host_info_id) - -sizeof(struct hip_tlv_common);
 *       hip_set_param_contents_len((struct hip_tlv_common *) &host_info_id, len_contents);
 *       hip_set_param_type((struct hip_tlv_common *) &host_info_id, HIP_PARAM_SIGNALING_HOST_INFO_ID);
 *
 *        Append the parameter to the message
 *       if (hip_build_generic_param(msg, &host_info_kernel, sizeof(struct signaling_param_host_info_id), param_buf)) {
 *           HIP_ERROR("Failed to append host info kernel parameter to message.\n");
 *           return -1;
 *           break;
 *       }
 */
        break;
    case HOST_INFO_CERTS:
        HIP_DEBUG("Request for Information about Host OS found. Building host info context\n");
        //TODO handler for the certificate request of host
        break;
    }

out_err:
    return err;
}

int signaling_build_param_app_info_response(struct hip_common *msg,
                                            UNUSED struct signaling_connection existing_conn,
                                            struct signaling_connection_context *ctx,
                                            const uint8_t app_info_flag)
{
    int                                         len_contents = 0;
    int                                         i            = 0;
    int                                         tmp_len;
    char                                        param_buf[HIP_MAX_PACKET];
    struct signaling_param_app_info_name        app_info_name;
    struct signaling_param_app_info_connections app_info_conn;
    //struct signaling_param_app_info_qos_class    app_info_qos;
    //struct signaling_param_app_info_requirements app_info_req;

    switch (app_info_flag) {
    case APP_INFO_NAME:
        HIP_DEBUG("Adding APP_INFO_NAME response to the Service Offer.\n");
        tmp_len                     = strlen(ctx->app.application_dn);
        app_info_name.app_dn_length = htons(tmp_len);
        memcpy(&app_info_name.application_dn, &ctx->app.application_dn, tmp_len);
        len_contents += tmp_len;

        HIP_DEBUG("Application DN : %s.\n", ctx->app.application_dn);
        tmp_len                        = strlen(ctx->app.issuer_dn);
        app_info_name.issuer_dn_length = htons(tmp_len);
        memcpy(&app_info_name.issuer_dn, &ctx->app.issuer_dn, tmp_len);
        len_contents += tmp_len;

        len_contents += (sizeof(app_info_name.app_dn_length) + sizeof(app_info_name.issuer_dn_length));
        hip_set_param_contents_len((struct hip_tlv_common *) &app_info_name, len_contents);
        hip_set_param_type((struct hip_tlv_common *) &app_info_name, HIP_PARAM_SIGNALING_APP_INFO_NAME);

        HIP_DEBUG("All information about the app_info_name parameteres set. Building the HIP Parameter.\n");
        //TODO do not have the version parameter set. Leaving it to null character.
        /* Append the parameter to the message */
        if (hip_build_param(msg, &app_info_name)) {
            HIP_ERROR("Failed to APP_INFO_NAME parameter to message.\n");
            return -1;
        }
        break;
    case APP_INFO_REQUIREMENTS:
        break;
    case APP_INFO_CONNECTIONS:
        HIP_DEBUG("Adding APP_INFO_CONNECTIONS response to the Service Offer.\n");
        for (i = 0; i < SIGNALING_MAX_SOCKETS; i++) {
            if ((ctx->app.sockets[i].src_port != 0) && (ctx->app.sockets[i].dst_port != 0)) {
                app_info_conn.sockets[2 * i]     = ctx->app.sockets[i].src_port;
                app_info_conn.sockets[2 * i + 1] = ctx->app.sockets[i].dst_port;
                len_contents                    += sizeof(struct signaling_port_pair);
            } else if (i == 0) {
                app_info_conn.port_pair_length = 0;
                len_contents                   = sizeof(app_info_conn.port_pair_length) + sizeof(app_info_conn.connection_count);
                hip_set_param_contents_len((struct hip_tlv_common *) &app_info_conn, len_contents);
                hip_set_param_type((struct hip_tlv_common *) &app_info_conn, HIP_PARAM_SIGNALING_APP_INFO_CONNECTIONS);

                //TODO do not have the version parameter set. Leaving it to null character.
                /* Append the parameter to the message */
                if (hip_build_generic_param(msg, &app_info_conn, sizeof(struct signaling_param_app_info_connections), param_buf)) {
                    HIP_ERROR("Failed to append application info connection parameter to message.\n");
                    return -1;
                }
                return 0;
            } else {
                break;
            }
        }
        app_info_conn.connection_count = htons(i);
        app_info_conn.port_pair_length = htons(i);

        len_contents += sizeof(app_info_conn.port_pair_length) + sizeof(app_info_conn.connection_count);
        hip_set_param_contents_len((struct hip_tlv_common *) &app_info_conn, len_contents);
        hip_set_param_type((struct hip_tlv_common *) &app_info_conn, HIP_PARAM_SIGNALING_APP_INFO_CONNECTIONS);

        /* Append the parameter to the message */
        if (hip_build_param(msg, &app_info_conn)) {
            HIP_ERROR("Failed to append application info connection parameter to message.\n");
            return -1;
        }
        break;
    case APP_INFO_QOS_CLASS:
        break;
    }
    return 0;
}

int signaling_build_param_user_info_response(struct hip_common *msg,
                                             UNUSED struct signaling_connection existing_conn,
                                             struct signaling_connection_context *ctx,
                                             const uint8_t user_info_flag)
{
    int len_contents = 0;
    //uint8_t                            *p_tmp = NULL;
    //char                                param_buf[HIP_MAX_PACKET];
    struct signaling_param_user_info_id user_info_id;
    struct signaling_param_user_info_id temp_param;
    //struct signaling_param_user_info_certs   user_info_name;
    int header_len   = 0;
    int key_len      = 0;
    int sub_name_len = 0;

    //p_tmp = (uint8_t *) param_buf;

    switch (user_info_flag) {
    case USER_INFO_ID:
        /*Dirty Work here to keep the parameter as short as possible in length.*/
        HIP_DEBUG("Adding USER_INFO_ID response to Service Offer.\n");
        /*Sanity checking*/
        if ((ctx->user.subject_name_len > 0) && (ctx->user.key_rr_len > 0)) {
            sub_name_len = (ctx->user.subject_name_len > SIGNALING_USER_ID_MAX_LEN) ? SIGNALING_USER_ID_MAX_LEN : ctx->user.subject_name_len;
            key_len      = ((ctx->user.key_rr_len - sizeof(struct hip_host_id_key_rdata)) > SIGNALING_USER_KEY_MAX_LEN)
                           ? SIGNALING_USER_KEY_MAX_LEN : (ctx->user.key_rr_len - sizeof(struct hip_host_id_key_rdata));
            /*Building header of the USER_INFO_ID parameter*/
            temp_param.user_dn_length  = htons(sub_name_len);
            temp_param.prr_length      = htons(key_len + sizeof(struct hip_host_id_key_rdata));
            temp_param.rdata.flags     = htons(ctx->user.rdata.flags);
            temp_param.rdata.algorithm = ctx->user.rdata.algorithm;
            temp_param.rdata.protocol  = ctx->user.rdata.protocol;

            header_len = sizeof(temp_param.user_dn_length) + sizeof(temp_param.prr_length) + sizeof(struct hip_host_id_key_rdata);
            /*Preparing the USER_INFO_ID parameter to be sent*/
            memcpy(&user_info_id, &temp_param, header_len);
            memcpy(&user_info_id.pkey[0], ctx->user.pkey, key_len);
            memcpy(&user_info_id.pkey[key_len], ctx->user.subject_name, sub_name_len);

            len_contents = header_len + (key_len + sizeof(struct hip_host_id_key_rdata)) + sub_name_len;
            hip_set_param_contents_len((struct hip_tlv_common *) &user_info_id, len_contents);
            hip_set_param_type((struct hip_tlv_common *) &user_info_id, HIP_PARAM_SIGNALING_USER_INFO_ID);

            /* Append the parameter to the message */
            if (hip_build_param(msg, &user_info_id)) {
                HIP_ERROR("Failed to USER_INFO_ID parameter to message.\n");
                return -1;
            }
        } else {
            HIP_DEBUG("No user information available to build USER_INFO_ID");
        }
        break;
    case USER_INFO_CERTS:
        //TODO
        break;
    }
    return 0;
}

static int build_param_user_auth(struct hip_common *msg,
                                 uint32_t network_id,
                                 uint16_t type)
{
    int                                      err = 0;
    int                                      len;
    struct signaling_param_user_auth_request ur;

    /* sanity checks*/
    HIP_IFEL(type != HIP_PARAM_SIGNALING_USER_INFO_CERTS && type != HIP_PARAM_SIGNALING_USER_INFO_ID,
             -1, "Invalid types \n");

    /* build and append parameter */
    hip_set_param_type((struct hip_tlv_common *) &ur, type);
    len = sizeof(struct signaling_param_user_auth_request) - sizeof(struct hip_tlv_common);
    hip_set_param_contents_len((struct hip_tlv_common *) &ur, len);
    ur.network_id = htonl(network_id);
    HIP_IFEL(hip_build_param(msg, &ur),
             -1, "Could not build notification parameter into message \n");

out_err:
    return err;
}

int signaling_build_param_user_auth_req_u(struct hip_common *msg,
                                          uint32_t network_id)
{
    return build_param_user_auth(msg, network_id, HIP_PARAM_SIGNALING_USER_INFO_CERTS);
}

int signaling_build_param_user_auth_req_s(struct hip_common *msg,
                                          uint32_t network_id)
{
    return build_param_user_auth(msg, network_id, HIP_PARAM_SIGNALING_USER_INFO_CERTS);
}

/*
 * int signaling_build_param_host_info_req_u(struct hip_common *msg,
 *                                        uint32_t network_id,
 *                                        struct flags_connection_context flags)
 * {
 *  return build_param_host_info_request(msg, network_id, HIP_PARAM_SIGNALING_HOST_INFO_REQ_U, flags);
 * }
 */
int signaling_add_service_offer_to_msg_u(struct hip_common *msg,
                                         struct signaling_connection_flags *flags,
                                         int service_offer_id,
                                         unsigned char *hash)
{
    int                                    err = 0;
    int                                    len;
    int                                    idx = 0;
    struct signaling_param_service_offer_u param_service_offer_u;

    HIP_DEBUG("Adding service offer parameter according to the policy\n");
    /* build and append parameter */
    hip_set_param_type((struct hip_tlv_common *) &param_service_offer_u, HIP_PARAM_SIGNALING_SERVICE_OFFER);
    param_service_offer_u.service_offer_id = htons(service_offer_id);
    //TODO check for the following values to be assigned to the parameter types
    param_service_offer_u.service_description = htonl(0);
    param_service_offer_u.service_type        = htons(0);

    if (signaling_info_req_flag_check(&flags->flag_info_requests, HOST_INFO_OS)) {
        param_service_offer_u.endpoint_info_req[idx] = htons(HOST_INFO_OS);
        idx++;
    }
    if (signaling_info_req_flag_check(&flags->flag_info_requests, HOST_INFO_KERNEL)) {
        param_service_offer_u.endpoint_info_req[idx] = htons(HOST_INFO_KERNEL);
        idx++;
    }
    if (signaling_info_req_flag_check(&flags->flag_info_requests, HOST_INFO_ID)) {
        param_service_offer_u.endpoint_info_req[idx] = htons(HOST_INFO_ID);
        idx++;
    }
    if (signaling_info_req_flag_check(&flags->flag_info_requests, HOST_INFO_CERTS)) {
        param_service_offer_u.endpoint_info_req[idx] = htons(HOST_INFO_CERTS);
        idx++;
    }
    if (signaling_info_req_flag_check(&flags->flag_info_requests, USER_INFO_ID)) {
        param_service_offer_u.endpoint_info_req[idx] = htons(USER_INFO_ID);
        idx++;
    }
    if (signaling_info_req_flag_check(&flags->flag_info_requests, USER_INFO_CERTS)) {
        param_service_offer_u.endpoint_info_req[idx] = htons(USER_INFO_CERTS);
        idx++;
    }
    if (signaling_info_req_flag_check(&flags->flag_info_requests, APP_INFO_NAME)) {
        param_service_offer_u.endpoint_info_req[idx] = htons(APP_INFO_NAME);
        idx++;
    }
    if (signaling_info_req_flag_check(&flags->flag_info_requests, APP_INFO_CONNECTIONS)) {
        param_service_offer_u.endpoint_info_req[idx] = htons(APP_INFO_CONNECTIONS);
        idx++;
    }
    if (signaling_info_req_flag_check(&flags->flag_info_requests, APP_INFO_QOS_CLASS)) {
        param_service_offer_u.endpoint_info_req[idx] = htons(APP_INFO_QOS_CLASS);
        idx++;
    }
    if (signaling_info_req_flag_check(&flags->flag_info_requests, APP_INFO_REQUIREMENTS)) {
        param_service_offer_u.endpoint_info_req[idx] = htons(APP_INFO_REQUIREMENTS);
        idx++;
    }
    HIP_DEBUG("Number of Info Request Parameters in Service Offer = %d.\n", idx);
    len = sizeof(struct signaling_param_service_offer_u) - (sizeof(struct hip_tlv_common) + sizeof(uint16_t) * (MAX_NUM_INFO_ITEMS - idx));
    //Computing the hash of the service offer and storing it in tuple
    hip_set_param_contents_len((struct hip_tlv_common *) &param_service_offer_u, len);

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_MBOX_R1_HASH_SERVICE_OFFER, PERF_MBOX_I2_HASH_SERVICE_OFFER\n");
    hip_perf_start_benchmark(perf_set, PERF_MBOX_R1_HASH_SERVICE_OFFER);
    hip_perf_start_benchmark(perf_set, PERF_MBOX_I2_HASH_SERVICE_OFFER);
#endif
    HIP_IFEL(hip_build_digest(HIP_DIGEST_SHA1, &param_service_offer_u, len, hash),
             -1, "Could not build hash of the service offer \n");
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop PERF_MBOX_R1_HASH_SERVICE_OFFER, PERF_MBOX_I2_HASH_SERVICE_OFFER\n");
    hip_perf_stop_benchmark(perf_set, PERF_MBOX_R1_HASH_SERVICE_OFFER);
    hip_perf_stop_benchmark(perf_set, PERF_MBOX_I2_HASH_SERVICE_OFFER);
#endif
    //print_hash(hash);

    HIP_IFEL(hip_build_param(msg, &param_service_offer_u),
             -1, "Could not build notification parameter into message \n");


out_err:
    return err;
}

int signaling_add_service_offer_to_msg_s(UNUSED struct hip_common *msg,
                                         UNUSED struct signaling_connection_flags *flags,
                                         UNUSED int service_offer_id,
                                         UNUSED unsigned char *hash)
{
    return 0;
}

int signaling_verify_service_ack(struct hip_common *msg,
                                 unsigned char *stored_hash)
{
    const struct hip_tlv_common        *param;
    const struct signaling_service_ack *ack;

    HIP_DEBUG("Ack received corresponding to the service offer.\n");
    //TODO check for signed and unsigned service offer parameters


    if ((param = hip_get_param(msg, HIP_PARAM_SIGNALING_SERVICE_ACK))) {
        do {
            if (hip_get_param_type(param) == HIP_PARAM_SIGNALING_SERVICE_ACK) {
                ack = (const struct signaling_service_ack *) (param + 1);
                if (!memcmp(stored_hash, ack->service_offer_hash, HIP_AH_SHA_LEN)) {
                    HIP_DEBUG("Hash in the Service ACK matches the hash of Service Offer.\n");
                    return 1;
                } else {
                    HIP_DEBUG("The stored hash and the acked hash do not match.\n");
                    printf("Stored hash: ");
                    print_hash(stored_hash);

                    printf("Acked hash: ");
                    print_hash(ack->service_offer_hash);
                }
            }
        } while ((param = hip_get_next_param(msg, param)));
    } else {
        HIP_DEBUG("No Service Offer from middleboxes. Nothing to do.\n");
    }
    HIP_DEBUG("None of the Service Acks matched.\n");
    return 0;
}

/*
 * Building response to the service offer
 *
 * @return 0 on success
 */
//TODO no different parameter types for signed and unsigned service offers. Need to update
int signaling_build_response_to_service_offer_u(struct hip_common *msg,
                                                struct signaling_connection conn,
                                                struct signaling_connection_context *ctx_out,
                                                const struct signaling_param_service_offer_u *offer,
                                                struct signaling_flags_info_req    *flags)
{
    int      err                = 0;
    int      num_req_info_items = 0;
    int      i                  = 0;
    uint16_t tmp_info;

    /* sanity checks */
    HIP_IFEL(!offer, -1, "Got NULL service offer parameter\n");
    HIP_IFEL((hip_get_param_type(offer) != HIP_PARAM_SIGNALING_SERVICE_OFFER),
             -1, "Parameter has wrong type, Following parameters expected: %d \n", HIP_PARAM_SIGNALING_SERVICE_OFFER);
    HIP_DEBUG("Processing requests in the Service Offer parameter.\n");
    num_req_info_items = (hip_get_param_contents_len(offer) - (sizeof(offer->service_offer_id) +
                                                               sizeof(offer->service_type) +
                                                               sizeof(offer->service_description))) / sizeof(uint16_t);

    /* number of service offers to be accepted, if more than the limit drop it */
    if (num_req_info_items > 0) {
        HIP_DEBUG("Number of parameters received in the Service Offer = %d.\n", num_req_info_items);

#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Start PERF_I2_HANDLE_SERVICE_OFFER, PERF_R2_HANDLE_SERVICE_OFFER\n");
        hip_perf_start_benchmark(perf_set, PERF_I2_HANDLE_SERVICE_OFFER);
        hip_perf_start_benchmark(perf_set, PERF_R2_HANDLE_SERVICE_OFFER);
#endif
        /*Processing the information requests in the service offer*/
        while ((i < num_req_info_items) && ((tmp_info = ntohs(offer->endpoint_info_req[i])) != 0)) {
            switch (tmp_info) {
            case HOST_INFO_OS:
                if (!signaling_info_req_flag_check(flags, HOST_INFO_OS)) {
                    HIP_IFEL(signaling_build_param_host_info_response(msg, conn, ctx_out, HOST_INFO_OS),
                             -1, "Could not add HOST_INFO_OS parameter");
                    signaling_info_req_flag_set(flags, HOST_INFO_OS);
                }
                i++;
                break;
            case HOST_INFO_KERNEL:
                if (!signaling_info_req_flag_check(flags, HOST_INFO_KERNEL)) {
                    HIP_IFEL(signaling_build_param_host_info_response(msg, conn, ctx_out, HOST_INFO_KERNEL),
                             -1, "Could not add HOST_INFO_KERNEL parameter");
                    signaling_info_req_flag_set(flags, HOST_INFO_KERNEL);
                }
                i++;
                break;
            case HOST_INFO_ID:
                if (!signaling_info_req_flag_check(flags, HOST_INFO_ID)) {
                    HIP_IFEL(signaling_build_param_host_info_response(msg, conn, ctx_out, HOST_INFO_ID),
                             -1, "Could not add HOST_INFO_ID parameter");
                    signaling_info_req_flag_set(flags, HOST_INFO_ID);
                }
                i++;
                break;
            case HOST_INFO_CERTS:
                if (!signaling_info_req_flag_check(flags, HOST_INFO_CERTS)) {
                    HIP_IFEL(signaling_build_param_host_info_response(msg, conn, ctx_out, HOST_INFO_CERTS),
                             -1, "Could not add HOST_INFO_CERTS parameter");
                    signaling_info_req_flag_set(flags, HOST_INFO_CERTS);
                }
                i++;
                break;

            case USER_INFO_ID:
                if (!signaling_info_req_flag_check(flags, USER_INFO_ID)) {
                    HIP_IFEL(signaling_build_param_user_info_response(msg, conn, ctx_out, USER_INFO_ID),
                             -1, "Could not add USER_INFO_ID parameter");
                    signaling_info_req_flag_set(flags, USER_INFO_ID);
                }
                i++;
                break;
            case USER_INFO_CERTS:
                if (!signaling_info_req_flag_check(flags, USER_INFO_CERTS)) {
                    HIP_IFEL(signaling_build_param_user_info_response(msg, conn, ctx_out, USER_INFO_CERTS),
                             -1, "Could not add USER_INFO_CERTS parameter");
                    signaling_info_req_flag_set(flags, USER_INFO_CERTS);
                }
                i++;
                break;

            case APP_INFO_NAME:
                if (!signaling_info_req_flag_check(flags, APP_INFO_NAME)) {
                    HIP_IFEL(signaling_build_param_app_info_response(msg, conn, ctx_out, APP_INFO_NAME),
                             -1, "Could not add APP_INFO_NAME parameter");
                    signaling_info_req_flag_set(flags, APP_INFO_NAME);
                }
                i++;
                break;
            case APP_INFO_QOS_CLASS:
                if (!signaling_info_req_flag_check(flags, APP_INFO_QOS_CLASS)) {
                    HIP_IFEL(signaling_build_param_app_info_response(msg, conn, ctx_out, APP_INFO_QOS_CLASS),
                             -1, "Could not add APP_INFO_QOS_CLASS parameter");
                    signaling_info_req_flag_set(flags, APP_INFO_QOS_CLASS);
                }
                i++;
                break;
            case APP_INFO_REQUIREMENTS:
                if (!signaling_info_req_flag_check(flags, APP_INFO_REQUIREMENTS)) {
                    HIP_IFEL(signaling_build_param_app_info_response(msg, conn, ctx_out, APP_INFO_REQUIREMENTS),
                             -1, "Could not add APP_INFO_REQUIREMENTS parameter");
                    signaling_info_req_flag_set(flags, APP_INFO_REQUIREMENTS);
                }
                i++;
                break;
            case APP_INFO_CONNECTIONS:
                if (!signaling_info_req_flag_check(flags, APP_INFO_CONNECTIONS)) {
                    HIP_IFEL(signaling_build_param_app_info_response(msg, conn, ctx_out, APP_INFO_CONNECTIONS),
                             -1, "Could not add APP_INFO_CONNECTIONS parameter");
                    signaling_info_req_flag_set(flags, APP_INFO_CONNECTIONS);
                }
                i++;
                break;
            }
        }

#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Stop PERF_I2_HANDLE_SERVICE_OFFER, PERF_R2_HANDLE_SERVICE_OFFER\n");
        hip_perf_stop_benchmark(perf_set, PERF_I2_HANDLE_SERVICE_OFFER);
        hip_perf_stop_benchmark(perf_set, PERF_R2_HANDLE_SERVICE_OFFER);
#endif
    }

out_err:
    return err;
}

/*
 * Building Acknowledgment
 */
int signaling_build_service_ack(struct hip_common *input_msg,
                                struct hip_common *output_msg)
{
    int                                    err = 0;
    struct signaling_param_service_offer_u param_service_offer;
    const struct hip_tlv_common           *param;
    struct signaling_param_service_ack     ack;
    char                                   param_buf[HIP_MAX_PACKET];

    if ((param = hip_get_param(input_msg, HIP_PARAM_SIGNALING_SERVICE_OFFER))) {
        do {
            if (hip_get_param_type(param) == HIP_PARAM_SIGNALING_SERVICE_OFFER) {
                HIP_IFEL(signaling_copy_service_offer(&param_service_offer, (const struct signaling_param_service_offer_u *) (param)),
                         -1, "Could not copy connection context\n");

                ack.service_offer_id = param_service_offer.service_offer_id;
                ack.service_option   = 0;
                /*Generate the hash of the service offer*/
                HIP_IFEL(hip_build_digest(HIP_DIGEST_SHA1, &param_service_offer, hip_get_param_contents_len(&param_service_offer), ack.service_offer_hash),
                         -1, "Could not build hash of the service offer \n");

                // print_hash(ack.service_offer_hash);
                HIP_DEBUG("Hash calculated for Service Acknowledgement\n");
                int len_contents = sizeof(struct signaling_param_service_ack) - sizeof(struct hip_tlv_common);
                hip_set_param_contents_len((struct hip_tlv_common *) &ack, len_contents);
                hip_set_param_type((struct hip_tlv_common *) &ack, HIP_PARAM_SIGNALING_SERVICE_ACK);

                /* Append the parameter to the message */
                if (hip_build_generic_param(output_msg, &ack, sizeof(struct signaling_param_service_ack), param_buf)) {
                    HIP_ERROR("Failed to acknowledge the service offer to the message.\n");
                    return -1;
                }
            }
        } while ((param = hip_get_next_param(input_msg, param)));
    }
out_err:
    return err;
}

/*
 * Fill the internal application_context struct with data from application_context parameter.
 *
 * @return 0 on success
 */
int signaling_build_application_context(const struct signaling_param_app_context *param_app_ctx,
                                        struct signaling_application_context *app_ctx)
{
    int            err = 0;
    const uint8_t *p_contents;
    uint16_t       tmp_len;

    /* sanity checks */
    HIP_IFEL(!param_app_ctx, -1, "Got NULL application context parameter\n");
    HIP_IFEL(!app_ctx, -1, "Got NULL application context to write to\n");

    /* copy contents and make sure maximum lengths are kept */
    tmp_len    = MIN(ntohs(param_app_ctx->app_dn_length), SIGNALING_APP_DN_MAX_LEN);
    p_contents = (const uint8_t *) param_app_ctx + sizeof(struct signaling_param_app_context)
                 + ntohs(param_app_ctx->port_count) * sizeof(struct signaling_port_pair);
    memcpy(app_ctx->application_dn, p_contents, tmp_len);
    app_ctx->application_dn[tmp_len] = '\0';
    p_contents                      += tmp_len;

    tmp_len = MIN(ntohs(param_app_ctx->iss_dn_length), SIGNALING_ISS_DN_MAX_LEN);
    memcpy(app_ctx->issuer_dn, p_contents, tmp_len);
    app_ctx->issuer_dn[tmp_len - 1] = '\0';
    p_contents                     += tmp_len;

    tmp_len = MIN(ntohs(param_app_ctx->req_length), SIGNALING_APP_REQ_MAX_LEN);
    memcpy(app_ctx->requirements, p_contents, tmp_len);
    app_ctx->requirements[tmp_len - 1] = '\0';
    p_contents                        += tmp_len;

    tmp_len = MIN(ntohs(param_app_ctx->grp_length), SIGNALING_APP_GRP_MAX_LEN);
    memcpy(app_ctx->groups, p_contents, tmp_len);
    app_ctx->groups[tmp_len] = '\0';

out_err:
    return err;
}

/*
 * Fill the internal user_context struct with data from user_context parameter.
 *
 * @return 0 on success
 */
int signaling_build_user_context(const struct signaling_param_user_context *param_usr_ctx,
                                 struct signaling_user_context *usr_ctx)
{
    int err = 0;

    /* sanity checks */
    HIP_IFEL(!param_usr_ctx,    -1, "Got NULL user context parameter\n");
    HIP_IFEL(!usr_ctx,          -1, "Got NULL user context to write to\n");
    HIP_IFEL(hip_get_param_type(param_usr_ctx) != HIP_PARAM_SIGNALING_USER_INFO_ID,
             -1, "Parameter has wrong type, expected %d\n", HIP_PARAM_SIGNALING_USER_INFO_ID);

    /* copy contents and make sure max lengths are kept */
    usr_ctx->key_rr_len = MIN(ntohs(param_usr_ctx->pkey_rr_length), SIGNALING_USER_KEY_MAX_LEN + sizeof(struct hip_host_id_key_rdata));
    memcpy(usr_ctx->pkey,
           (const uint8_t *) param_usr_ctx + sizeof(struct signaling_param_user_context),
           usr_ctx->key_rr_len - sizeof(struct hip_host_id_key_rdata));
    usr_ctx->rdata.algorithm = param_usr_ctx->rdata.algorithm;
    usr_ctx->rdata.protocol  = param_usr_ctx->rdata.protocol;
    usr_ctx->rdata.flags     = ntohs(param_usr_ctx->rdata.flags);

    usr_ctx->subject_name_len = MIN(ntohs(param_usr_ctx->un_length), SIGNALING_USER_ID_MAX_LEN);
    memcpy(usr_ctx->subject_name,
           (const uint8_t *) param_usr_ctx + sizeof(struct signaling_param_user_context) + ntohs(param_usr_ctx->pkey_rr_length) - sizeof(struct hip_host_id_key_rdata),
           usr_ctx->subject_name_len);

out_err:
    return err;
}

int signaling_get_ports_from_param_app_ctx(const struct signaling_param_app_context *const param_app_ctx,
                                           struct signaling_port_pair *const port_list)
{
    int                               err = 0;
    int                               i   = 0;
    const struct signaling_port_pair *pp  = NULL;

    /* sanity checks */
    HIP_IFEL(!param_app_ctx,    -1, "Got NULL application context parameter.\n");
    HIP_IFEL(!port_list,        -1, "Got NULL port list to write to.\n");
    HIP_IFEL(hip_get_param_type(param_app_ctx) != HIP_PARAM_SIGNALING_APP_INFO_CONNECTIONS,
             -1, "Parameter has wrong type, expected %d\n", HIP_PARAM_SIGNALING_APP_INFO_CONNECTIONS);

    /* copy the ports from the message */
    pp = (const struct signaling_port_pair *) (param_app_ctx + 1);
    for (i = 0; i < MIN(ntohs(param_app_ctx->port_count), SIGNALING_MAX_SOCKETS); i++) {
        port_list[i].src_port = ntohs(pp[i].dst_port);
        port_list[i].dst_port = ntohs(pp[i].src_port);
    }

out_err:
    return err;
}

int signaling_get_connection_context(struct signaling_connection *conn,
                                     struct signaling_connection_context *ctx,
                                     uint8_t end_point_role)
{
    int err = 0;
    HIP_ASSERT(ctx);

/*
 * #ifdef CONFIG_HIP_PERFORMANCE
 *  HIP_DEBUG("Start PERF_HOST_INFO_LOOKUP\n");   // test 1.1
 *  hip_perf_start_benchmark(perf_set, PERF_HOST_INFO_LOOKUP);
 * #endif
 *  if (signaling_get_verified_host_context(&ctx->host)) {
 *      HIP_DEBUG("Host lookup/verification failed, assuming ANY HOST.\n");
 *      signaling_init_host_context(&ctx->host);
 *  }
 * #ifdef CONFIG_HIP_PERFORMANCE
 *  HIP_DEBUG("Stop PERF_HOST_INFO_LOOKUP\n");   // test 1.1
 *  hip_perf_stop_benchmark(perf_set, PERF_HOST_INFO_LOOKUP);
 * #endif
 */
    memcpy(&ctx->host, &signaling_persistent_host, sizeof(struct signaling_host_context));
    HIP_IFEL(signaling_get_verified_application_context_by_ports(conn, ctx, end_point_role), -1, "Getting application context failed.\n");
    HIP_IFEL(signaling_get_verified_user_context(ctx) == -1, -1, "Getting user context failed.\n");
    return 0;

out_err:
    HIP_DEBUG("Getting Application and User context failed\n");
    signaling_init_user_context(&ctx->user);
    signaling_init_application_context(&ctx->app);
    return err;
}

void signaling_get_hits_from_msg(const struct hip_common *msg, const hip_hit_t **hits, const hip_hit_t **hitr)
{
    const struct hip_tlv_common *param = NULL;

    param = hip_get_param(msg, HIP_PARAM_HIT);
    if (param && hip_get_param_type(param) == HIP_PARAM_HIT) {
        *hitr = hip_get_param_contents_direct(param);
        if (ipv6_addr_is_null(*hitr)) {
            *hitr = NULL;
            HIP_DEBUG("HITR = NULL \n");
        }
    }

    param = hip_get_next_param(msg, param);
    if (param && hip_get_param_type(param) == HIP_PARAM_HIT) {
        *hits = hip_get_param_contents_direct(param);
        if (ipv6_addr_is_null(*hits)) {
            *hits = NULL;
            HIP_DEBUG("HITS = NULL \n");
        }
    }
}

/**
 * Determine the type of a signaling UPDATE message.
 *
 * @param msg   the UPDATE message
 *
 * @return the signaling update type, or negative if this is no siganling update message
 */
int signaling_get_update_type(const struct hip_common *msg)
{
    int                                       err           = -1;
    const struct signaling_param_app_context *param_app_ctx = NULL;
    const struct hip_seq                     *param_seq     = NULL;
    const struct hip_ack                     *param_ack     = NULL;
    const struct hip_cert                    *param_cert    = NULL;
    //const struct signaling_param_user_auth_request *param_usr_auth_req = NULL;
    const struct signaling_param_cert_chain_id *param_cer_chain_id = NULL;

    //TODO check for the parameters to be put here
    param_app_ctx = hip_get_param(msg, HIP_PARAM_SIGNALING_APP_INFO_NAME);
    param_seq     = hip_get_param(msg, HIP_PARAM_SEQ);
    param_ack     = hip_get_param(msg, HIP_PARAM_ACK);
    param_cert    = hip_get_param(msg, HIP_PARAM_CERT);
    //param_usr_auth_req = hip_get_param(msg, HIP_PARAM_SIGNALING_USER_INFO_CERTS);
    param_cer_chain_id = hip_get_param(msg, HIP_PARAM_SIGNALING_CERT_CHAIN_ID);

    if (param_app_ctx && param_seq && !param_ack) {
        return SIGNALING_FIRST_BEX_UPDATE;
    } else if (param_app_ctx && param_seq && param_ack) {
        return SIGNALING_SECOND_BEX_UPDATE;
    } else if (param_ack && !param_seq && !param_cer_chain_id) {
        return SIGNALING_THIRD_BEX_UPDATE;
    } else if (param_cert && param_seq && !param_ack && param_cer_chain_id) {
        return SIGNALING_FIRST_USER_CERT_CHAIN_UPDATE;
    } else if (param_ack && param_cer_chain_id) {
        return SIGNALING_SECOND_USER_CERT_CHAIN_UPDATE;
    }

    return err;
}

/**
 * Determine the free space left in a message.
 *
 * @param msg   the message for which to compute the free space
 * @param ha    the ha for which the message is sent
 *              (we use the ha to determine the cryptographic algorithms and keys,
 *               in order to estimate the signature size)
 *
 * @return      the free space left in the message, excluding space for
 *              MAC and signature
 */
int signaling_get_free_message_space(const struct hip_common *msg, struct hip_hadb_state *ha)
{
    const uint8_t *dst;
    const uint8_t *max_dst          = ((const uint8_t *) msg) + 1400;
    const int      param_mac_length = 24;
    int            param_signature_length;

    if (!ha || !msg) {
        return -1;
    }

    dst = (const uint8_t *) msg + hip_get_msg_total_len(msg);
    switch (hip_get_host_id_algo(ha->our_pub)) {
    case HIP_HI_ECDSA:
        param_signature_length = ECDSA_size(ha->our_priv_key);
        break;
    case HIP_HI_RSA:
        param_signature_length = RSA_size(ha->our_priv_key);
        break;
    default:
        param_signature_length = 200;
    }
    param_signature_length += sizeof(struct hip_sig) + 7;

    return MAX(max_dst - (dst + param_mac_length + param_signature_length + sizeof(struct signaling_param_connection_identifier)), 0);
}

int signaling_get_verified_user_context(struct signaling_connection_context *ctx)
{
    int            err       = 0;
    EVP_PKEY      *user_pkey = NULL;
    unsigned char *key_rr;

    /* Sanity checks */
    HIP_ASSERT(ctx);

    HIP_DEBUG("Getting User context.\n");
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_I_USER_CTX_LOOKUP, PERF_R_USER_CTX_LOOKUP\n");   // test 1.1
    hip_perf_start_benchmark(perf_set, PERF_I_USER_CTX_LOOKUP);
    hip_perf_start_benchmark(perf_set, PERF_R_USER_CTX_LOOKUP);
#endif

    HIP_IFEL(signaling_user_api_get_uname(ctx->user.uid, &ctx->user), -1, "Could not get user name, assuming ANY USER. \n");
    if (ctx->user.key_rr_len <= 0) {
        HIP_IFEL(!(user_pkey = signaling_user_api_get_user_public_key(ctx->user.uid)),
                 -1, "Could not obtain users public key \n");
        //PEM_write_PUBKEY(stdout, user_pkey);
        HIP_IFEL((ctx->user.key_rr_len = any_key_to_key_rr(user_pkey, &ctx->user.rdata.algorithm, &key_rr)) < 0,
                 -1, "Could not serialize key \n");
        HIP_DEBUG("GOT keyy rr of length %d\n", ctx->user.key_rr_len);
        memcpy(ctx->user.pkey, key_rr, ctx->user.key_rr_len);

        // necessary because any_key_to_rr returns only the length of the key rrwithout the header
        ctx->user.key_rr_len += sizeof(struct hip_host_id_key_rdata);
        free(key_rr);
    }

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop PERF_I_USER_CTX_LOOKUP, PERF_R_USER_CTX_LOOKUP\n");   // test 1.1
    hip_perf_stop_benchmark(perf_set, PERF_I_USER_CTX_LOOKUP);
    hip_perf_stop_benchmark(perf_set, PERF_R_USER_CTX_LOOKUP);
#endif
    return 0;
out_err:
    return err;
}

int signaling_check_if_user_info_req(struct hip_packet_context *ctx)
{
    int                                    err                = 0;
    int                                    num_req_info_items = 0;
    int                                    i                  = 0;
    const struct hip_tlv_common           *param;
    struct signaling_param_service_offer_u param_service_offer;
    uint16_t                               tmp_info;

    if ((param = hip_get_param(ctx->input_msg, HIP_PARAM_SIGNALING_SERVICE_OFFER))) {
        HIP_IFEL(signaling_copy_service_offer(&param_service_offer, (const struct signaling_param_service_offer_u *) (param)),
                 -1, "Could not copy connection context\n");
        num_req_info_items = (hip_get_param_contents_len(&param_service_offer) -
                              (sizeof(param_service_offer.service_offer_id) +
                               sizeof(param_service_offer.service_type) +
                               sizeof(param_service_offer.service_description))) / sizeof(uint16_t);
        while (i < num_req_info_items) {
            tmp_info = ntohs(param_service_offer.endpoint_info_req[i]);
            if (tmp_info == USER_INFO_ID || tmp_info == USER_INFO_CERTS) {
                return 1;
            }
            i++;
        }
    }

    HIP_DEBUG("No need for the user to sign this packet as no USER INFO request\n");
    return 0;

out_err:
    return err;
}

void print_hash(const unsigned char *hash)
{
    int i = 0;
    //Printing hash
    printf("Printing the Generated hash: ");
    for (i = 0; i < HIP_AH_SHA_LEN; i++) {
        printf("%02x ", hash[i]);
    }
    printf("\n");
}
