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
    hip_set_param_type((struct hip_tlv_common *) &appinfo, HIP_PARAM_SIGNALING_APPINFO);

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
        HIP_DEBUG("Start PERF_LOAD_USER_PUBKEY");
        hip_perf_start_benchmark(perf_set, PERF_LOAD_USER_PUBKEY);
#endif
        HIP_IFEL(!(user_pkey = signaling_user_api_get_user_public_key(user_ctx->uid)),
                 -1, "Could not obtain users public key \n");
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Stop PERF_LOAD_USER_PUBKEY");
        hip_perf_stop_benchmark(perf_set, PERF_LOAD_USER_PUBKEY);
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
    hip_set_param_type((struct hip_tlv_common *) param_userinfo, HIP_PARAM_SIGNALING_USERINFO);
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

static int build_param_user_auth(struct hip_common *msg,
                                 uint32_t network_id,
                                 uint16_t type)
{
    int                                      err = 0;
    int                                      len;
    struct signaling_param_user_auth_request ur;

    /* sanity checks*/
    HIP_IFEL(type != HIP_PARAM_SIGNALING_USER_REQ_U && type != HIP_PARAM_SIGNALING_USER_REQ_S,
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
    return build_param_user_auth(msg, network_id, HIP_PARAM_SIGNALING_USER_REQ_U);
}

int signaling_build_param_user_auth_req_s(struct hip_common *msg,
                                          uint32_t network_id)
{
    return build_param_user_auth(msg, network_id, HIP_PARAM_SIGNALING_USER_REQ_S);
}

/*
 * Fill the internal host_context struct with data from host_context parameter.
 *
 * @return 0 on success
 */
int signaling_build_host_context(const struct signaling_param_host_context *param_host_ctx,
                                 struct signaling_host_context *host_ctx)
{
    int            err = 0;
    const uint8_t *p_contents;
    uint16_t       tmp_len;
    uint16_t       profile;
    int            i = 0;
    /* sanity checks */
    HIP_IFEL(!param_host_ctx,    -1, "Got NULL user context parameter\n");
    HIP_IFEL(!host_ctx,          -1, "Got NULL user context to write to\n");
    HIP_IFEL(hip_get_param_type(param_host_ctx) != HIP_PARAM_SIGNALING_HOST_INFO_REQ,
             -1, "Parameter has wrong type, expected %d\n", HIP_PARAM_SIGNALING_HOST_INFO_REQ);

    /* copy contents and make sure max lengths are kept */

    host_ctx->info_profile = ntohs(param_host_ctx->profile);
    host_ctx->num_items    = ntohs(param_host_ctx->num_items);
    p_contents             = (const uint8_t *) param_host_ctx + 2 * sizeof(uint16_t);

    for (i = 0; i < host_ctx->num_items; i++) {
        tmp_len =  SIGNALING_HOST_INFO_PROFILE;
        memcpy(&profile, p_contents, sizeof(uint16_t));
        profile     = ntohs(profile);
        p_contents += tmp_len;

        switch (profile) {
        case INFO_KERNEL:
            memcpy(&host_ctx->host_kernel_len, p_contents, tmp_len);
            host_ctx->host_kernel_len = ntohs(host_ctx->host_kernel_len);
            p_contents               += 2 * tmp_len;
            tmp_len                   = MIN(host_ctx->host_kernel_len, SIGNALING_HOST_INFO_MAX_LEN);
            memcpy(host_ctx->host_kernel, p_contents, tmp_len);
            host_ctx->host_kernel[tmp_len - 1] = '\0';
            p_contents                        += tmp_len;
            break;
        case INFO_OS:
            memcpy(&host_ctx->host_os_len, p_contents, tmp_len);
            host_ctx->host_os_len = ntohs(host_ctx->host_os_len);
            p_contents           += 2 * tmp_len;
            tmp_len               = MIN(host_ctx->host_os_len, SIGNALING_HOST_INFO_MAX_LEN);
            memcpy(host_ctx->host_os, p_contents, tmp_len);
            host_ctx->host_os[tmp_len - 1] = '\0';
            p_contents                    += tmp_len;
            break;
        case INFO_NAME:
            memcpy(&host_ctx->host_name_len, p_contents, tmp_len);
            host_ctx->host_name_len = ntohs(host_ctx->host_name_len);
            p_contents             += 2 * tmp_len;
            tmp_len                 = MIN(host_ctx->host_name_len, SIGNALING_HOST_INFO_MAX_LEN);
            memcpy(host_ctx->host_name, p_contents, tmp_len);
            host_ctx->host_name[tmp_len - 1] = '\0';
            p_contents                      += tmp_len;
            break;
        }
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
    HIP_IFEL(hip_get_param_type(param_usr_ctx) != HIP_PARAM_SIGNALING_USERINFO,
             -1, "Parameter has wrong type, expected %d\n", HIP_PARAM_SIGNALING_USERINFO);

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
    HIP_IFEL(hip_get_param_type(param_app_ctx) != HIP_PARAM_SIGNALING_APPINFO,
             -1, "Parameter has wrong type, expected %d\n", HIP_PARAM_SIGNALING_USERINFO);

    /* copy the ports from the message */
    pp = (const struct signaling_port_pair *) (param_app_ctx + 1);
    for (i = 0; i < MIN(ntohs(param_app_ctx->port_count), SIGNALING_MAX_SOCKETS); i++) {
        port_list[i].src_port = ntohs(pp[i].dst_port);
        port_list[i].dst_port = ntohs(pp[i].src_port);
    }

out_err:
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
    int                                             err                = -1;
    const struct signaling_param_app_context       *param_app_ctx      = NULL;
    const struct hip_seq                           *param_seq          = NULL;
    const struct hip_ack                           *param_ack          = NULL;
    const struct hip_cert                          *param_cert         = NULL;
    const struct signaling_param_user_auth_request *param_usr_auth_req = NULL;
    const struct signaling_param_cert_chain_id     *param_cer_chain_id = NULL;

    param_app_ctx      = hip_get_param(msg, HIP_PARAM_SIGNALING_APPINFO);
    param_seq          = hip_get_param(msg, HIP_PARAM_SEQ);
    param_ack          = hip_get_param(msg, HIP_PARAM_ACK);
    param_cert         = hip_get_param(msg, HIP_PARAM_CERT);
    param_usr_auth_req = hip_get_param(msg, HIP_PARAM_SIGNALING_USER_REQ_S);
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
