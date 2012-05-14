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

#include <string.h>
#include <unistd.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>


#include "lib/core/debug.h"
#include "lib/core/builder.h"
#include "lib/core/protodefs.h"
#include "lib/core/common.h"
#include "lib/core/ife.h"
#include "lib/core/prefix.h"
#include "lib/core/hostid.h"
#include "lib/core/crypto.h"
#include "lib/tool/pk.h"
#include "hipd/hipd.h"
#include "hipd/input.h"

#include "signaling_common_builder.h"
#include "signaling_oslayer.h"
#include "signaling_prot_common.h"
#include "signaling_user_api.h"
#include "signaling_x509_api.h"
#include "signaling_user_management.h"

#include "modules/signaling/hipd/signaling_hipd_msg.h"

#define CALLBUF_SIZE            60
#define SYMLINKBUF_SIZE         16

#define HIP_DEFAULT_HIPFW_ALGO       HIP_HI_RSA
#define SERVICE_RESPONSE_ALGO_DH     1

/**
 * Builds a hip_param_connection_identifier parameter into msg,
 * using the values in the connection context .
 *
 * @param ctx the connection context where values are taken from
 * @param msg the message, where the parameter is appended
 *
 * @return zero for success, or non-zero on error
 */
int signaling_build_param_signaling_connection(struct hip_common *msg, const struct signaling_connection *conn)
{
    int                         err = 0;
    struct signaling_connection tmp_conn;

    /* Sanity checks */
    HIP_IFEL(msg  == NULL, -1, "Got no msg context. (msg == NULL)\n");
    HIP_IFEL(conn == NULL, -1, "Got no context to built the parameter from.\n");

    signaling_copy_connection(&tmp_conn, conn);

    tmp_conn.id       = 0;
    tmp_conn.src_port = htons(conn->src_port);
    tmp_conn.dst_port = htons(conn->dst_port);

    HIP_IFEL(hip_build_param_contents(msg, &tmp_conn, HIP_PARAM_SIGNALING_CONNECTION, sizeof(struct signaling_connection)),
             -1, "build signaling_connection failed \n");

    HIP_DEBUG("Signaling connection added successfully src_port = %u, dst_port = %u \n", conn->src_port, conn->dst_port);

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
int signaling_build_param_user_signature(struct hip_common *msg, const uid_t uid,
                                         uint8_t flag_selective_sign)
{
    int            err = 0;
    struct hip_sig sig;
    unsigned char  signature_buf[HIP_MAX_RSA_KEY_LEN / 8];
    int            in_len;
    int            sig_len  = 0;
    uint8_t        sig_type = HIP_DEFAULT_HI_ALGO;

    /* sanity checks */
    HIP_IFEL(!msg,       -1, "Cannot sign NULL-message\n");

    HIP_IFEL(sig_type != HIP_HI_RSA && sig_type != HIP_HI_ECDSA,
             -1, "Unsupported signature type: %d\n", sig_type);

    /* calculate the signature */
    in_len = hip_get_msg_total_len(msg);
    HIP_IFEL((sig_len = signaling_user_api_sign(uid, msg, in_len, signature_buf, sig_type, flag_selective_sign)) < 0,
             -1, "Could not get user's signature \n");

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
        if (ctx->host.host_kernel_len > 0) {
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
        } else {
            HIP_DEBUG("No information about host kernel available.\n");
        }
        break;
    case HOST_INFO_OS:
        HIP_DEBUG("Request for Information about Host OS found. Building host info os parameter\n");
        if (ctx->host.host_os_len > 0 && ctx->host.host_os_ver_len > 0) {
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
    uint8_t                                    *tmp_ptr = NULL;
    //struct signaling_param_app_info_qos_class    app_info_qos;
    //struct signaling_param_app_info_requirements app_info_req;

    switch (app_info_flag) {
    case APP_INFO_NAME:
        HIP_DEBUG("Adding APP_INFO_NAME response to the Service Offer.\n");
        //HIP_DEBUG("Application DN : %s.\n", ctx->app.application_dn);
        tmp_len                     = strlen(ctx->app.application_dn);
        app_info_name.app_dn_length = htons(tmp_len);
        memcpy(app_info_name.application_dn, ctx->app.application_dn, tmp_len);
        len_contents += tmp_len;

        tmp_ptr                        = (uint8_t *) &app_info_name.application_dn[tmp_len];
        tmp_len                        = strlen(ctx->app.issuer_dn);
        app_info_name.issuer_dn_length = htons(tmp_len);
        memcpy(tmp_ptr, ctx->app.issuer_dn, tmp_len);
        len_contents += tmp_len;
        //HIP_DEBUG("ISSUER DN : %s. length = %d\n", tmp_ptr, tmp_len);

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

            HIP_DEBUG("The algorithm used for the user signature : %u\n", ctx->user.rdata.algorithm);

            header_len = sizeof(struct hip_tlv_common) + sizeof(temp_param.user_dn_length) + sizeof(temp_param.prr_length) + sizeof(struct hip_host_id_key_rdata);
            /*Preparing the USER_INFO_ID parameter to be sent*/
            memcpy(&user_info_id, &temp_param, header_len);
            memcpy(&user_info_id.pkey[0], ctx->user.pkey, key_len);
            memcpy(&user_info_id.pkey[key_len], ctx->user.subject_name, sub_name_len);

            len_contents = header_len + (key_len + sizeof(struct hip_host_id_key_rdata)) + sub_name_len - sizeof(struct hip_tlv_common);
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
int signlaing_insert_service_offer_in_hip_msg(struct hip_common *msg,
                                              struct signaling_param_service_offer *offer)
{
    int                    err      = 0;
    struct hip_tlv_common *param    = NULL;
    uint8_t               *tmp_ptr  = (uint8_t *) msg;
    uint16_t               tmp_len  = 0;
    uint16_t               orig_len = hip_get_msg_total_len(msg);
    uint8_t               *buffer;
    uint16_t               buf_len = 0;

    while ((param = hip_get_next_param_readwrite(msg, param)) && hip_get_param_type(param) != HIP_PARAM_SELECTIVE_HASH_LEAF) {
        ;
    }
    if (param) {
        HIP_IFEL(orig_len + hip_get_param_total_len(offer) > HIP_MAX_PACKET, -1,
                 "Cannot add the service offer as the packet size is already large\n")
        tmp_len = ((uint8_t *) param - (uint8_t *) msg);
        buf_len = orig_len - tmp_len;
        buffer  = malloc(buf_len);
        memcpy(buffer, (uint8_t *) param, buf_len);
        hip_set_msg_total_len(msg, tmp_len);
        HIP_IFEL(hip_build_param(msg, offer), -1,
                 "Could not build service offer to the message\n");
        tmp_ptr += hip_get_msg_total_len(msg);
        memcpy(tmp_ptr, buffer, buf_len);
        hip_set_msg_total_len(msg, hip_get_msg_total_len(msg) + buf_len);
    } else {
        HIP_DEBUG("No need to insert service offer\n");
        HIP_IFEL(hip_build_param(msg, offer), -1,
                 "Could not build service offer to the message\n");
    }
out_err:
    return err;
}

int signaling_add_service_offer_to_msg(struct hip_common *msg,
                                       struct signaling_connection_flags *flags,
                                       int            service_offer_id,
                                       unsigned char *hash,
                                       UNUSED void   *mb_key,
                                       X509          *mb_cert,
                                       uint8_t       flag_sign)
{
    int                                  err = 0;
    int                                  len;
    int                                  idx                 = 0;
    struct signaling_param_service_offer param_service_offer = { 0 };
    uint8_t                             *cert_hint           = NULL;
    unsigned int                         cert_hint_len       = 0;


    HIP_DEBUG("Adding service offer parameter according to the policy\n");
    /* build and append parameter */
    hip_set_param_type((struct hip_tlv_common *) &param_service_offer, HIP_PARAM_SIGNALING_SERVICE_OFFER);
    param_service_offer.service_offer_id    = htons(service_offer_id);
    param_service_offer.service_type        = flag_sign;
    param_service_offer.service_description = htonl(0);

    if (signaling_info_req_flag_check(&flags->flag_info_requests, HOST_INFO_OS)) {
        param_service_offer.endpoint_info_req[idx] = HOST_INFO_OS;
        idx++;
    }
    if (signaling_info_req_flag_check(&flags->flag_info_requests, HOST_INFO_KERNEL)) {
        param_service_offer.endpoint_info_req[idx] = HOST_INFO_KERNEL;
        idx++;
    }
    if (signaling_info_req_flag_check(&flags->flag_info_requests, HOST_INFO_ID)) {
        param_service_offer.endpoint_info_req[idx] = HOST_INFO_ID;
        idx++;
    }
    if (signaling_info_req_flag_check(&flags->flag_info_requests, HOST_INFO_CERTS)) {
        param_service_offer.endpoint_info_req[idx] = HOST_INFO_CERTS;
        idx++;
    }
    if (signaling_info_req_flag_check(&flags->flag_info_requests, USER_INFO_ID)) {
        param_service_offer.endpoint_info_req[idx] = USER_INFO_ID;
        idx++;
    }
    if (signaling_info_req_flag_check(&flags->flag_info_requests, USER_INFO_CERTS)) {
        param_service_offer.endpoint_info_req[idx] = USER_INFO_CERTS;
        idx++;
    }
    if (signaling_info_req_flag_check(&flags->flag_info_requests, APP_INFO_NAME)) {
        param_service_offer.endpoint_info_req[idx] = APP_INFO_NAME;
        idx++;
    }
    if (signaling_info_req_flag_check(&flags->flag_info_requests, APP_INFO_CONNECTIONS)) {
        param_service_offer.endpoint_info_req[idx] = APP_INFO_CONNECTIONS;
        idx++;
    }
    if (signaling_info_req_flag_check(&flags->flag_info_requests, APP_INFO_QOS_CLASS)) {
        param_service_offer.endpoint_info_req[idx] = APP_INFO_QOS_CLASS;
        idx++;
    }
    if (signaling_info_req_flag_check(&flags->flag_info_requests, APP_INFO_REQUIREMENTS)) {
        param_service_offer.endpoint_info_req[idx] = APP_INFO_REQUIREMENTS;
        idx++;
    }

    HIP_DEBUG("Number of Info Request Parameters in Service Offer = %d.\n", idx);
    param_service_offer.service_info_len = idx;

    len = sizeof(param_service_offer.service_offer_id) +
          sizeof(param_service_offer.service_type) + sizeof(param_service_offer.service_info_len) +
          sizeof(param_service_offer.service_description) + idx * sizeof(uint8_t);

    if (flag_sign == OFFER_SIGNED) {
        /* Certificate hint if flag is set to create a signed service offer */
        cert_hint = (uint8_t *) signaling_extract_skey_ident_from_cert(mb_cert, &cert_hint_len);
        memcpy(&param_service_offer.endpoint_info_req[idx], cert_hint, cert_hint_len);
        HIP_DEBUG("Certificate Hint copied\n");
        HIP_HEXDUMP("Certificate hint = ", cert_hint, HIP_AH_SHA_LEN);
        len += HIP_AH_SHA_LEN;
    }

    //Computing the hash of the service offer and storing it in tuple
    hip_set_param_contents_len((struct hip_tlv_common *) &param_service_offer, len);

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_MBOX_R1_HASH_SERVICE_OFFER, PERF_MBOX_I2_HASH_SERVICE_OFFER\n");
    hip_perf_start_benchmark(perf_set, PERF_MBOX_R1_HASH_SERVICE_OFFER);
    hip_perf_start_benchmark(perf_set, PERF_MBOX_I2_HASH_SERVICE_OFFER);
#endif
    HIP_IFEL(hip_build_digest(HIP_DIGEST_SHA1, &param_service_offer, len, hash),
             -1, "Could not build hash of the service offer \n");
    HIP_HEXDUMP("Hash of the service offer = ", hash, HIP_AH_SHA_LEN);
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop PERF_MBOX_R1_HASH_SERVICE_OFFER, PERF_MBOX_I2_HASH_SERVICE_OFFER\n");
    hip_perf_stop_benchmark(perf_set, PERF_MBOX_R1_HASH_SERVICE_OFFER);
    hip_perf_stop_benchmark(perf_set, PERF_MBOX_I2_HASH_SERVICE_OFFER);
#endif
    //print_hash(hash);

    HIP_IFEL(hip_build_param(msg, &param_service_offer),
             -1, "Could not build notification parameter into message \n");

out_err:
    return err;
}

int signaling_add_service_offer_to_msg_s(struct hip_common *msg,
                                         struct signaling_connection_flags *flags,
                                         int service_offer_id,
                                         unsigned char *hash,
                                         void          *mb_key,
                                         X509          *mb_cert,
                                         uint8_t        flag_sign)
{
    int err        = 0;
    int tmp_len    = 0;
    int header_len = 0;
    ;
    int                                  info_len            = 0;
    int                                  skid_len            = 0;
    int                                  idx                 = 0;
    int                                  contents_len        = 0;
    struct signaling_param_service_offer param_service_offer = { 0 };
    struct signaling_param_service_offer tmp_service_offer   = { 0 };
    uint8_t                              sha1_digest[HIP_AH_SHA_LEN];
    uint8_t                             *signature = NULL;
    unsigned int                         sig_len;
    uint8_t                             *cert_hint = NULL;
    unsigned int                         cert_hint_len;
    uint8_t                             *tmp_ptr = (uint8_t *) &param_service_offer;

    HIP_DEBUG("Adding service offer parameter according to the policy\n");
    HIP_ASSERT(flag_sign == OFFER_SELECTIVE_SIGNED);
    /* build and append parameter */
    hip_set_param_type((struct hip_tlv_common *) &tmp_service_offer, HIP_PARAM_SIGNALING_SERVICE_OFFER);
    tmp_service_offer.service_offer_id = htons(service_offer_id);
    //TODO check for the following values to be assigned to the parameter types
    tmp_service_offer.service_type        = flag_sign;
    tmp_service_offer.service_description = htonl(0);
    tmp_service_offer.service_sig_algo    = HIP_DEFAULT_HIPFW_ALGO;

    if (signaling_info_req_flag_check(&flags->flag_info_requests, HOST_INFO_OS)) {
        tmp_service_offer.endpoint_info_req[idx] = HOST_INFO_OS;
        idx++;
    }
    if (signaling_info_req_flag_check(&flags->flag_info_requests, HOST_INFO_KERNEL)) {
        tmp_service_offer.endpoint_info_req[idx] = HOST_INFO_KERNEL;
        idx++;
    }
    if (signaling_info_req_flag_check(&flags->flag_info_requests, HOST_INFO_ID)) {
        tmp_service_offer.endpoint_info_req[idx] = HOST_INFO_ID;
        idx++;
    }
    if (signaling_info_req_flag_check(&flags->flag_info_requests, HOST_INFO_CERTS)) {
        tmp_service_offer.endpoint_info_req[idx] = HOST_INFO_CERTS;
        idx++;
    }
    if (signaling_info_req_flag_check(&flags->flag_info_requests, USER_INFO_ID)) {
        tmp_service_offer.endpoint_info_req[idx] = USER_INFO_ID;
        idx++;
    }
    if (signaling_info_req_flag_check(&flags->flag_info_requests, USER_INFO_CERTS)) {
        tmp_service_offer.endpoint_info_req[idx] = USER_INFO_CERTS;
        idx++;
    }
    if (signaling_info_req_flag_check(&flags->flag_info_requests, APP_INFO_NAME)) {
        tmp_service_offer.endpoint_info_req[idx] = APP_INFO_NAME;
        idx++;
    }
    if (signaling_info_req_flag_check(&flags->flag_info_requests, APP_INFO_CONNECTIONS)) {
        tmp_service_offer.endpoint_info_req[idx] = APP_INFO_CONNECTIONS;
        idx++;
    }
    if (signaling_info_req_flag_check(&flags->flag_info_requests, APP_INFO_QOS_CLASS)) {
        tmp_service_offer.endpoint_info_req[idx] = APP_INFO_QOS_CLASS;
        idx++;
    }
    if (signaling_info_req_flag_check(&flags->flag_info_requests, APP_INFO_REQUIREMENTS)) {
        tmp_service_offer.endpoint_info_req[idx] = APP_INFO_REQUIREMENTS;
        idx++;
    }
    HIP_DEBUG("Number of Info Request Parameters in Service Offer = %d.\n", idx);
    tmp_service_offer.service_info_len = idx;
    //print_hash(hash);

    cert_hint = (uint8_t *) signaling_extract_skey_ident_from_cert(mb_cert, &cert_hint_len);
    memcpy(tmp_service_offer.service_cert_hint, cert_hint, cert_hint_len);
    skid_len = cert_hint_len;
    HIP_DEBUG(" Service cert hint copied successfully \n");

    if (HIP_DEFAULT_HIPFW_ALGO == HIP_HI_RSA) {
        sig_len                            = RSA_size((RSA *) mb_key);
        tmp_service_offer.service_sig_algo = HIP_HI_RSA;
    } else if (HIP_DEFAULT_HIPFW_ALGO == HIP_HI_ECDSA) {
        sig_len                            = ECDSA_size((EC_KEY *) mb_key);
        tmp_service_offer.service_sig_algo = HIP_HI_ECDSA;
    }

    signature = calloc(1, sig_len);
    HIP_IFEL(!signature, -1, "Malloc for signature failed.");
    memset(signature, '\0', sig_len);
    tmp_service_offer.service_sig_len = sig_len;

    header_len = sizeof(struct hip_tlv_common) + sizeof(tmp_service_offer.service_offer_id) +
                 sizeof(tmp_service_offer.service_type) + sizeof(tmp_service_offer.service_info_len) +
                 sizeof(tmp_service_offer.service_description)/* +
                                                               * sizeof(tmp_service_offer.service_sig_algo) + sizeof(tmp_service_offer.service_sig_len)*/;
    info_len = sizeof(uint8_t) * idx;
    tmp_len  = sizeof(tmp_service_offer.service_sig_algo) + sizeof(tmp_service_offer.service_sig_len) + sig_len;

    contents_len =  header_len + info_len + skid_len + tmp_len - sizeof(struct hip_tlv_common);
    hip_set_param_contents_len((struct hip_tlv_common *) &tmp_service_offer, contents_len);
    hip_set_param_type((struct hip_tlv_common *) &tmp_service_offer, HIP_PARAM_SIGNALING_SERVICE_OFFER);

    HIP_DEBUG("Param contents length and type set contents_len = %d\n", contents_len);

    memcpy(&param_service_offer, &tmp_service_offer, header_len);
    HIP_DEBUG("Signed Service Offer header len = %d \n", header_len);
    memcpy(&param_service_offer.endpoint_info_req[0], &tmp_service_offer.endpoint_info_req[0], info_len);
    HIP_DEBUG("Signed Service Offer endpoint info len = %d  \n", info_len);
    memcpy(&param_service_offer.endpoint_info_req[idx], &tmp_service_offer.service_cert_hint[0], skid_len);
    HIP_DEBUG("Signed Service Offer service_cert hint len = %d \n", skid_len);

    HIP_IFEL(hip_build_digest(HIP_DIGEST_SHA1, &param_service_offer, header_len + info_len + skid_len, sha1_digest) < 0,
             -1, "Building of SHA1 digest failed\n");
    tmp_ptr += (header_len + info_len + skid_len);
    memcpy(tmp_ptr, &tmp_service_offer.service_sig_algo, sizeof(uint8_t));
    tmp_ptr += sizeof(uint8_t);
    memcpy(tmp_ptr, &tmp_service_offer.service_sig_len, sizeof(uint8_t));
    tmp_ptr += sizeof(uint8_t);

    if (HIP_DEFAULT_HIPFW_ALGO == HIP_HI_RSA) {
        /* RSA_sign returns 0 on failure */
        HIP_IFEL(!RSA_sign(NID_sha1, sha1_digest, SHA_DIGEST_LENGTH, signature,
                           &sig_len, (RSA *) mb_key), -1, "Signing error\n");
    } else if (HIP_DEFAULT_HIPFW_ALGO == HIP_HI_ECDSA) {
        HIP_IFEL(impl_ecdsa_sign(sha1_digest, (EC_KEY *) mb_key, signature), -1,
                 "Could not sign Service offer using ECDSA key\n");
    }

    HIP_HEXDUMP("Signature = ", signature, sig_len);
    memcpy(tmp_ptr, signature, sig_len);

    HIP_DEBUG("Signature_len = %d\n", sig_len);
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_MBOX_R1_HASH_SERVICE_OFFER, PERF_MBOX_I2_HASH_SERVICE_OFFER\n");
    hip_perf_start_benchmark(perf_set, PERF_MBOX_R1_HASH_SERVICE_OFFER);
    hip_perf_start_benchmark(perf_set, PERF_MBOX_I2_HASH_SERVICE_OFFER);
#endif
    HIP_IFEL(hip_build_digest(HIP_DIGEST_SHA1, &param_service_offer, contents_len, hash),
             -1, "Could not build hash of the service offer \n");
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop PERF_MBOX_R1_HASH_SERVICE_OFFER, PERF_MBOX_I2_HASH_SERVICE_OFFER\n");
    hip_perf_stop_benchmark(perf_set, PERF_MBOX_R1_HASH_SERVICE_OFFER);
    hip_perf_stop_benchmark(perf_set, PERF_MBOX_I2_HASH_SERVICE_OFFER);
#endif

    HIP_DEBUG("Param contents length = %d\n", hip_get_param_contents_len((struct hip_tlv_common *) &param_service_offer));
    HIP_IFEL(signlaing_insert_service_offer_in_hip_msg(msg, &param_service_offer), -1,
             "Could not build notification parameter into message \n");

/*
 *  HIP_IFEL(hip_build_param(msg, &param_service_offer),
 *           -1, "Could not build notification parameter into message \n");
 */

out_err:
    return err;
}

/**
 * Verifies a HMAC.
 *
 * @param buffer    the packet data used in HMAC calculation.
 * @param buf_len   the length of the packet.
 * @param hmac      the HMAC to be verified.
 * @param hmac_key  integrity key used with HMAC.
 * @param hmac_type type of the HMAC digest algorithm.
 * @return          0 if calculated HMAC is same as @c hmac, otherwise < 0. On
 *                  error < 0 is returned.
 * @note            Fix the packet len before calling this function!
 */
static int signaling_verify_hmac(struct hip_common *buffer, uint16_t buf_len,
                                 const uint8_t *hmac, void *hmac_key, int hmac_type)
{
    uint8_t hmac_res[HIP_AH_SHA_LEN];

    HIP_HEXDUMP("HMAC data", buffer, buf_len);

    if (hip_write_hmac(hmac_type, hmac_key, buffer, buf_len, hmac_res)) {
        HIP_ERROR("Could not build hmac\n");
        return -EINVAL;
    }

    HIP_HEXDUMP("HMAC", hmac_res, HIP_AH_SHA_LEN);
    if (memcmp(hmac_res, hmac, HIP_AH_SHA_LEN)) {
        return -EINVAL;
    }

    return 0;
}

/**
 * Verifies Selective HMAC in HIP msg
 *
 * @param msg HIP packet
 * @param crypto_key The crypto key
 * @param parameter_type
 * @return 0 if HMAC was validated successfully, < 0 if HMAC could
 * not be validated.
 */
int signaling_verify_packet_selective_hmac(struct hip_common *msg,
                                           const struct hip_crypto_key *crypto_key,
                                           const hip_tlv parameter_type)
{
    int                    orig_len = 0;
    struct hip_crypto_key  tmpkey;
    const struct hip_hmac *hmac             = NULL;
    uint8_t                orig_checksum    = 0;
    unsigned char         *concat_of_leaves = NULL;
    unsigned int           len_concat_of_leaves;

    HIP_DEBUG("hip_verify_packet_hmac() invoked.\n");

    if (!(hmac = hip_get_param(msg, parameter_type))) {
        HIP_ERROR("No HMAC parameter\n");
        return -ENOMSG;
    }

    /* hmac verification modifies the msg length temporarily, so we have
     * to restore the length */
    orig_len = hip_get_msg_total_len(msg);

    /* hmac verification assumes that checksum is zero */
    orig_checksum = hip_get_msg_checksum(msg);
    hip_zero_msg_checksum(msg);

    signaling_build_hash_tree_from_msg(msg, &concat_of_leaves, &len_concat_of_leaves);

    memcpy(&tmpkey, crypto_key, sizeof(tmpkey));
    if (signaling_verify_hmac((struct hip_common *) concat_of_leaves, len_concat_of_leaves, hmac->hmac_data,
                              tmpkey.key, HIP_DIGEST_SHA1_HMAC)) {
        HIP_ERROR("HMAC validation failed\n");
        return -1;
    }

    /* revert the changes to the packet */
    hip_set_msg_total_len(msg, orig_len);
    hip_set_msg_checksum(msg, orig_checksum);

    return 0;
}

/**
 * calculate and create a HMAC2 parameter that includes also a host id
 * which is not included in the message
 *
 * @param msg a HIP control message from the HMAC should be calculated from
 * @param msg_copy an extra, temporary buffer allocated by the caller
 * @param host_id the host id parameter that should be included in the calculated
 *                HMAC value
 * @return zero for success and negative on failure
 */
static int signaling_hip_create_msg_pseudo_hmac2(const struct hip_common *msg,
                                                 struct hip_common *msg_copy,
                                                 struct hip_host_id *host_id)
{
    const struct hip_tlv_common *param = NULL;
    int                          err   = 0;

    uint8_t *buffer;
    uint16_t buf_len  = 0;
    uint16_t orig_len = hip_get_msg_total_len(msg);
    uint16_t tmp_len  = 0;
    uint8_t *tmp_ptr  = NULL;

    HIP_HEXDUMP("host id", host_id,
                hip_get_param_total_len(host_id));

    memcpy(msg_copy, msg, sizeof(struct hip_common));
    hip_set_msg_total_len(msg_copy, 0);
    hip_zero_msg_checksum(msg_copy);

    /* copy parameters to a temporary buffer to calculate
     * pseudo-hmac (includes the host id) */
    while ((param = hip_get_next_param(msg, param)) &&
           hip_get_param_type(param) < HIP_PARAM_HMAC2) {
        HIP_IFEL(hip_build_param(msg_copy, param),
                 -1,
                 "Failed to build param\n");
    }

    // we need to rebuild the compressed parameter format for host ids
    HIP_IFEL(hip_build_param_host_id(msg_copy, host_id), -1,
             "Failed to append pseudo host id to R2\n");
    tmp_ptr = (uint8_t *) msg_copy + hip_get_msg_total_len(msg_copy);

    if (param) {
        tmp_len = ((const uint8_t *) param - (const uint8_t *) msg);
        buf_len = orig_len - tmp_len;
        buffer  = malloc(buf_len);
        memcpy(buffer, (const uint8_t *) param, buf_len);

        memcpy(tmp_ptr, buffer, buf_len);
        hip_set_msg_total_len(msg_copy, hip_get_msg_total_len(msg_copy) + buf_len);
    }

out_err:
    return err;
}

/**
 * Verifies packet HMAC
 *
 * @param msg HIP packet
 * @param key The crypto key
 * @param host_id The Host Identity
 * @return 0 if HMAC was validated successfully, < 0 if HMAC could
 * not be validated. Assumes that the hmac includes only the header
 * and host id.
 */
int signaling_verify_packet_selective_hmac2(struct hip_common *msg,
                                            struct hip_crypto_key *key,
                                            struct hip_host_id *host_id)
{
    struct hip_crypto_key  tmpkey;
    const struct hip_hmac *hmac;
    struct hip_common     *msg_copy         = NULL;
    int                    err              = 0;
    unsigned char         *concat_of_leaves = NULL;
    unsigned int           len_concat_of_leaves;

    if (!(msg_copy = hip_msg_alloc())) {
        return -ENOMEM;
    }

    HIP_IFEL(signaling_hip_create_msg_pseudo_hmac2(msg, msg_copy, host_id), -1,
             "Pseudo hmac2 pkt failed\n");

    HIP_IFEL(!(hmac = hip_get_param(msg, HIP_PARAM_SIGNALING_SELECTIVE_HMAC)), -ENOMSG,
             "Packet contained no HMAC parameter\n");
    HIP_HEXDUMP("HMAC data", msg_copy, hip_get_msg_total_len(msg_copy));

    memcpy(&tmpkey, key, sizeof(tmpkey));

    HIP_IFEL(signaling_build_hash_tree_from_msg(msg_copy, &concat_of_leaves, &len_concat_of_leaves), -1,
             "Building hash tree from the R2 message failed\n");
    HIP_IFEL(signaling_verify_hmac((struct hip_common *) concat_of_leaves, len_concat_of_leaves,
                                   hmac->hmac_data, tmpkey.key,
                                   HIP_DIGEST_SHA1_HMAC),
             -1, "HMAC validation failed\n");
out_err:
    free(msg_copy);
    return err;
}

int signaling_verify_service_ack_u(struct hip_common *msg,
                                   unsigned char *stored_hash)
{
    const struct hip_tlv_common        *param;
    const struct signaling_service_ack *ack;

    HIP_DEBUG("Ack received corresponding to the service offer.\n");

    if ((param = hip_get_param(msg, HIP_PARAM_SIGNALING_SERVICE_ACK))) {
        do {
            if (hip_get_param_type(param) == HIP_PARAM_SIGNALING_SERVICE_ACK) {
                ack = (const struct signaling_service_ack *) (param + 1);
                /* Check if the service acknowledgment is a signed or an unsgined service ack */
                if (signaling_check_if_service_ack_signed((const struct signaling_param_service_ack *) param)) {
                    HIP_DEBUG("Service Ack in the HIP msg in not an unsigned service ack\n");
                    return 0;
                }
                if (!memcmp(stored_hash, ack->service_offer_hash, HIP_AH_SHA_LEN)) {
                    HIP_DEBUG("Hash in the Service ACK matches the hash of Service Offer. Found unsigned service ack\n");
                    return 1;
                } else {
                    HIP_DEBUG("The stored hash and the acked hash do not match.\n");
                    HIP_HEXDUMP("Stored hash: ", stored_hash, HIP_AH_SHA_LEN);
                    HIP_HEXDUMP("Acked hash: ", ack->service_offer_hash, HIP_AH_SHA_LEN);
                }
            }
        } while ((param = hip_get_next_param(msg, param)));
    } else {
        HIP_DEBUG("No Unsigned Service Offer from middleboxes. Nothing to do.\n");
    }
    HIP_DEBUG("None of the Service Acks matched.\n");
    return 0;
}

int signaling_verify_service_ack_s(struct hip_common *msg,
                                   struct hip_common **msg_buf,
                                   unsigned char *stored_hash,
                                   RSA           *priv_key,
                                   unsigned char *dh_shared_key)
{
    int                          err = 0;
    const struct hip_tlv_common *param;
    struct signaling_service_ack ack = { 0 };
//  struct hip_encrypted_aes_sha1 tmp_enc_param = { 0 };

    int            param_len        = 0;
    uint8_t       *tmp_service_ack  = NULL;
    unsigned char *tmp_info_secrets = NULL;
    unsigned char *dec_output       = NULL;
    uint8_t       *tmp_ptr          = NULL;
    uint8_t       *enc_data         = NULL;
    int            enc_data_len     = 0;
    uint16_t       tmp_len          = 0;
    uint16_t       mask             = 0;
    uint8_t       *iv               = NULL;

    /*------------------ Find out the corresponding service acknowledgment --------------------*/
    if ((param = hip_get_param(msg, HIP_PARAM_SIGNALING_SERVICE_ACK))) {
        HIP_DEBUG("Signed Ack received corresponding to the service offer.\n");
        do {
            if (hip_get_param_type(param) == HIP_PARAM_SIGNALING_SERVICE_ACK) {
                param_len       = hip_get_param_contents_len(param);
                enc_data_len    = param_len - sizeof(struct signaling_service_ack) - 16 * sizeof(uint8_t);
                tmp_service_ack = malloc(param_len + sizeof(struct hip_tlv_common));
                memcpy(tmp_service_ack, param, param_len + sizeof(struct hip_tlv_common));
                /* Check if the service acknowledgment is a signed ack */
                if (!signaling_check_if_service_ack_signed((struct signaling_param_service_ack *) tmp_service_ack)) {
                    HIP_DEBUG("Service Ack in the HIP msg in not a signed service ack\n");
                    return 0;
                }
                tmp_ptr = (uint8_t *) tmp_service_ack;
                memcpy(&ack, (const struct signaling_service_ack *) (param + 1), sizeof(struct signaling_service_ack));
                if (!memcmp(stored_hash, ack.service_offer_hash, HIP_AH_SHA_LEN)) {
                    HIP_DEBUG("Hash in the Service ACK matches the hash of Service Offer. Checking for signed service ack\n");
                    break;
                } else {
                    HIP_DEBUG("The stored hash and the acked hash do not match.\n");
                    HIP_HEXDUMP("Stored hash: ", stored_hash, HIP_AH_SHA_LEN);
                    HIP_HEXDUMP("Acked hash: ", ack.service_offer_hash, HIP_AH_SHA_LEN);
                }
                free(tmp_service_ack);
            }
        } while ((param = hip_get_next_param(msg, param)));

        HIP_DEBUG("Packet content len = %d\n", enc_data_len);
        HIP_HEXDUMP("Encrypted end point info secrets : ", (uint8_t *) (tmp_ptr + sizeof(struct signaling_service_ack) +
                                                                        sizeof(struct hip_tlv_common) +
                                                                        16 * sizeof(uint8_t)), enc_data_len);

        /*--------- Extract the symmetric key information now ---------------*/
        if (SERVICE_RESPONSE_ALGO_DH) {
#ifdef CONFIG_HIP_PERFORMANCE
            HIP_DEBUG("Start PERF_MBOX_I2_DEC_SYMM_KEY_DH, PERF_MBOX_R2_DEC_SYMM_KEY_DH,"
                      "PERF_MBOX_U2_DEC_SYMM_KEY_DH, PERF_MBOX_U3_DEC_SYMM_KEY_DH\n");
            hip_perf_start_benchmark(perf_set, PERF_MBOX_I2_DEC_SYMM_KEY_DH);
            hip_perf_start_benchmark(perf_set, PERF_MBOX_R2_DEC_SYMM_KEY_DH);
            hip_perf_start_benchmark(perf_set, PERF_MBOX_U2_DEC_SYMM_KEY_DH);
            hip_perf_start_benchmark(perf_set, PERF_MBOX_U3_DEC_SYMM_KEY_DH);
#endif

            enc_data = (uint8_t *) (tmp_ptr + sizeof(struct signaling_service_ack) + sizeof(struct hip_tlv_common)
                                    + 16 * sizeof(uint8_t));
            iv         = ((struct signaling_param_service_ack *) tmp_service_ack)->iv;
            dec_output = malloc(enc_data_len);
            memcpy(dec_output, enc_data, enc_data_len);

            HIP_HEXDUMP("Key derived from dh parameters = ", dh_shared_key, 16);
            HIP_IFEL(hip_crypto_encrypted(dec_output, iv, HIP_HIP_AES_SHA1,
                                          enc_data_len, dh_shared_key, HIP_DIRECTION_DECRYPT),
                     -1, "Building of param encrypted failed\n");
            HIP_HEXDUMP("Decrypted data = ", dec_output, enc_data_len);
            tmp_len = enc_data_len;

#ifdef CONFIG_HIP_PERFORMANCE
            HIP_DEBUG("Stop PERF_MBOX_I2_DEC_SYMM_KEY_DH, PERF_MBOX_R2_DEC_SYMM_KEY_DH,"
                      "PERF_MBOX_U2_DEC_SYMM_KEY_DH, PERF_MBOX_U3_DEC_SYMM_KEY_DH\n");
            hip_perf_stop_benchmark(perf_set, PERF_MBOX_I2_DEC_SYMM_KEY_DH);
            hip_perf_stop_benchmark(perf_set, PERF_MBOX_R2_DEC_SYMM_KEY_DH);
            hip_perf_stop_benchmark(perf_set, PERF_MBOX_U2_DEC_SYMM_KEY_DH);
            hip_perf_stop_benchmark(perf_set, PERF_MBOX_U3_DEC_SYMM_KEY_DH);
#endif
        } else {
#ifdef CONFIG_HIP_PERFORMANCE
            HIP_DEBUG("Start PERF_MBOX_I2_DEC_SYMM_KEY_RSA, PERF_MBOX_R2_DEC_SYMM_KEY_RSA,"
                      "PERF_MBOX_U2_DEC_SYMM_KEY_RSA, PERF_MBOX_U3_DEC_SYMM_KEY_RSA\n");
            hip_perf_start_benchmark(perf_set, PERF_MBOX_I2_DEC_SYMM_KEY_RSA);
            hip_perf_start_benchmark(perf_set, PERF_MBOX_R2_DEC_SYMM_KEY_RSA);
            hip_perf_start_benchmark(perf_set, PERF_MBOX_U2_DEC_SYMM_KEY_RSA);
            hip_perf_start_benchmark(perf_set, PERF_MBOX_U3_DEC_SYMM_KEY_RSA);
#endif

            iv = malloc(16 * sizeof(uint8_t));
            memset(iv, 0, 16 * sizeof(uint8_t));
            HIP_IFEL(memcmp(iv, ((struct signaling_param_service_ack *) tmp_service_ack)->iv, 16 * sizeof(uint8_t)), -1,
                     "The initial vector not set to 0 even though DH not used\n");
            free(iv);
            tmp_info_secrets = malloc(RSA_size(priv_key));
            enc_data         = (uint8_t *) (tmp_ptr + sizeof(struct signaling_service_ack) + sizeof(struct hip_tlv_common)
                                            + 16 * sizeof(uint8_t));
            memcpy(tmp_info_secrets, (uint8_t *) enc_data, enc_data_len);
            dec_output = malloc(RSA_size(priv_key));
            tmp_len    = RSA_private_decrypt(enc_data_len, tmp_info_secrets, dec_output, priv_key, RSA_PKCS1_OAEP_PADDING);
            if (tmp_len > 0 && tmp_len < RSA_size(priv_key)) {
                HIP_HEXDUMP("Decrypted end point info secrets : ", dec_output, tmp_len);
            } else {
                HIP_DEBUG("Could not decrypt successfully\n");
                return -1;
            }

#ifdef CONFIG_HIP_PERFORMANCE
            HIP_DEBUG("Stop PERF_MBOX_I2_DEC_SYMM_KEY_RSA, PERF_MBOX_R2_DEC_SYMM_KEY_RSA,"
                      "PERF_MBOX_U2_DEC_SYMM_KEY_RSA, PERF_MBOX_U3_DEC_SYMM_KEY_RSA\n");
            hip_perf_stop_benchmark(perf_set, PERF_MBOX_I2_DEC_SYMM_KEY_RSA);
            hip_perf_stop_benchmark(perf_set, PERF_MBOX_R2_DEC_SYMM_KEY_RSA);
            hip_perf_stop_benchmark(perf_set, PERF_MBOX_U2_DEC_SYMM_KEY_RSA);
            hip_perf_stop_benchmark(perf_set, PERF_MBOX_U3_DEC_SYMM_KEY_RSA);
#endif
        }

#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Start PERF_MBOX_I2_DEC_ENDPOINT_SECRET, PERF_MBOX_R2_DEC_ENDPOINT_SECRET,"
                  "PERF_MBOX_U2_DEC_ENDPOINT_SECRET, PERF_MBOX_U3_DEC_ENDPOINT_SECRET\n");
        hip_perf_start_benchmark(perf_set, PERF_MBOX_I2_DEC_ENDPOINT_SECRET);
        hip_perf_start_benchmark(perf_set, PERF_MBOX_R2_DEC_ENDPOINT_SECRET);
        hip_perf_start_benchmark(perf_set, PERF_MBOX_U2_DEC_ENDPOINT_SECRET);
        hip_perf_start_benchmark(perf_set, PERF_MBOX_U3_DEC_ENDPOINT_SECRET);
#endif

        /*----------------- Allocate and build message buffer ----------------------*/
        HIP_IFEL(!(*msg_buf = hip_msg_alloc()),
                 -ENOMEM, "Out of memory while allocation memory for the notify packet\n");
        hip_build_network_hdr(*msg_buf, HIP_UPDATE, mask, &msg->hits, &msg->hitr); /*Just giving some dummy Packet type*/

        HIP_IFEL(signaling_put_decrypted_secrets_to_msg_buf(msg, msg_buf, dec_output,  tmp_len),
                 -1, "Could not add the decrypted endpoint info to the msg buffer for further processing. \n");

#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Stop PERF_MBOX_I2_DEC_ENDPOINT_SECRET, PERF_MBOX_R2_DEC_ENDPOINT_SECRET,"
                  "PERF_MBOX_U2_DEC_ENDPOINT_SECRET, PERF_MBOX_U3_DEC_ENDPOINT_SECRET\n");
        hip_perf_stop_benchmark(perf_set, PERF_MBOX_I2_DEC_ENDPOINT_SECRET);
        hip_perf_stop_benchmark(perf_set, PERF_MBOX_R2_DEC_ENDPOINT_SECRET);
        hip_perf_stop_benchmark(perf_set, PERF_MBOX_U2_DEC_ENDPOINT_SECRET);
        hip_perf_stop_benchmark(perf_set, PERF_MBOX_U3_DEC_ENDPOINT_SECRET);
#endif

        hip_dump_msg(*msg_buf);
        free(dec_output);
        free(tmp_info_secrets);
        free(tmp_service_ack);
        return 1;
    } else {
        HIP_DEBUG("No Signed Service Offer from middleboxes. Nothing to do.\n");
    }
    HIP_DEBUG("None of the Service Acks matched.\n");
    //return 0;
out_err:
    if (iv != NULL && !SERVICE_RESPONSE_ALGO_DH) {
        free(iv);
    }
    return err;
}

int signaling_verify_service_ack_selective_s(struct hip_common *msg,
                                             UNUSED struct hip_common **msg_buf,
                                             unsigned char *stored_hash,
                                             UNUSED RSA    *priv_key,
                                             int           *offset_list,
                                             int           *offset_list_len)
{
    int                                 err             = 0;
    struct hip_tlv_common              *param           = NULL;
    const struct signaling_service_ack *ack             = NULL;
    const uint8_t                      *tmp_ptr         = NULL;
    uint16_t                            tmp_len         = 0;
    uint8_t                             info_remove[10] = { 0 };
    uint8_t                             info_rem_len    = 0;

    HIP_DEBUG("Inside verification of selectively signed ack\n");
    /*------------------ Find out the corresponding service acknowledgment --------------------*/
    if ((param = hip_get_param_readwrite(msg, HIP_PARAM_SIGNALING_SERVICE_ACK))) {
        HIP_DEBUG("Signed Ack received corresponding to the service offer.\n");
        do {
            if (hip_get_param_type(param) == HIP_PARAM_SIGNALING_SERVICE_ACK) {
                ack = (const struct signaling_service_ack *) (param + 1);
                /* Check if the service acknowledgment is a signed or an unsgined service ack */
                if (signaling_check_if_service_ack_signed((struct signaling_param_service_ack *) param)) {
                    HIP_DEBUG("Service Ack in the HIP msg in not an unsigned service ack\n");
                    err = 0;
                    goto out_err;
                }
                if (!memcmp(stored_hash, ack->service_offer_hash, HIP_AH_SHA_LEN)) {
                    HIP_DEBUG("Hash in the Service ACK matches the hash of Service Offer. Found unsigned service ack\n");

                    tmp_ptr  = (const uint8_t *) ack;
                    tmp_ptr +=  sizeof(ack->service_offer_id) +
                               sizeof(ack->service_option) + sizeof(ack->service_offer_hash);
                    HIP_DEBUG("tmp_ptr set\n");
                    tmp_len = hip_get_param_contents_len(param) - (sizeof(ack->service_offer_id) +
                                                                   sizeof(ack->service_option) + sizeof(ack->service_offer_hash));
                    HIP_DEBUG("tmp_len = %u\n", tmp_len);
                    HIP_HEXDUMP("Info remove list = ", tmp_ptr, tmp_len);
                    info_rem_len = tmp_len;
                    memcpy(info_remove, tmp_ptr, tmp_len);

                    offset_list[tmp_len] = (uint8_t *) param - (uint8_t *) msg;
                    *offset_list_len     = tmp_len + 1;

#ifdef CONFIG_HIP_PERFORMANCE
                    HIP_DEBUG("Start PERF_MBOX_I2_BUILD_PARAM_REM_LIST, PERF_MBOX_R2_BUILD_PARAM_REM_LIST, "
                              "PERF_MBOX_U2_BUILD_PARAM_REM_LIST, PERF_MBOX_U3_BUILD_PARAM_REM_LIST\n");
                    hip_perf_start_benchmark(perf_set, PERF_MBOX_I2_BUILD_PARAM_REM_LIST);
                    hip_perf_start_benchmark(perf_set, PERF_MBOX_R2_BUILD_PARAM_REM_LIST);
                    hip_perf_start_benchmark(perf_set, PERF_MBOX_U2_BUILD_PARAM_REM_LIST);
                    hip_perf_start_benchmark(perf_set, PERF_MBOX_U3_BUILD_PARAM_REM_LIST);
#endif
                    signaling_build_offset_list_to_remove_params(msg, offset_list, offset_list_len,
                                                                 info_remove, &info_rem_len);
#ifdef CONFIG_HIP_PERFORMANCE
                    HIP_DEBUG("Stop PERF_MBOX_I2_BUILD_PARAM_REM_LIST, PERF_MBOX_R2_BUILD_PARAM_REM_LIST, "
                              "PERF_MBOX_U2_BUILD_PARAM_REM_LIST, PERF_MBOX_U3_BUILD_PARAM_REM_LIST\n");
                    hip_perf_stop_benchmark(perf_set, PERF_MBOX_I2_BUILD_PARAM_REM_LIST);
                    hip_perf_stop_benchmark(perf_set, PERF_MBOX_R2_BUILD_PARAM_REM_LIST);
                    hip_perf_stop_benchmark(perf_set, PERF_MBOX_U2_BUILD_PARAM_REM_LIST);
                    hip_perf_stop_benchmark(perf_set, PERF_MBOX_U3_BUILD_PARAM_REM_LIST);
#endif
                    return 1;
                } else {
                    HIP_DEBUG("The stored hash and the acked hash do not match.\n");
                    HIP_HEXDUMP("Stored hash: ", stored_hash, HIP_AH_SHA_LEN);
                    HIP_HEXDUMP("Acked hash: ", ack->service_offer_hash, HIP_AH_SHA_LEN);
                }
            }
        } while ((param = hip_get_next_param_readwrite(msg, param)));

        return 1;
    } else {
        HIP_DEBUG("No Signed Service Offer from middleboxes. Nothing to do.\n");
    }

    HIP_DEBUG("None of the Service Acks matched.\n");
    //return 0;
out_err:
    return err;
}

/*
 * Verify the mbox signature on the signed service offer
 *
 * @return Subject Key Identifier
 */
int signaling_verify_service_signature(X509 *cert, uint8_t *verify_it, uint8_t verify_it_len,
                                       uint8_t *signature, uint8_t sig_len)
{
    int     err = 0;
    uint8_t sha1_digest[HIP_AH_SHA_LEN];
    RSA    *rsa   = NULL;
    EC_KEY *ecdsa = NULL;

    HIP_ASSERT(cert);

    EVP_PKEY *pub_key = X509_get_pubkey(cert);

    HIP_IFEL(hip_build_digest(HIP_DIGEST_SHA1, verify_it, verify_it_len, sha1_digest),
             -1, "Could not build message digest \n");

    switch (EVP_PKEY_type(pub_key->type)) {
    case EVP_PKEY_EC:
        // - 1 is the algorithm field
        HIP_DEBUG("Verifying ECDSA signature\n");
        ecdsa = EVP_PKEY_get1_EC_KEY(pub_key);
        HIP_IFEL(ECDSA_size(ecdsa) != sig_len,
                 -1, "Size of public key does not match signature size. Aborting signature verification: %d / %d.\n",
                 ECDSA_size(ecdsa), sig_len);
        HIP_IFEL(impl_ecdsa_verify(sha1_digest, ecdsa, signature),
                 -1, "ECDSA service signature did not verify correctly\n");
        break;
    case EVP_PKEY_RSA:
        HIP_DEBUG("Verifying RSA signature\n");
        rsa = EVP_PKEY_get1_RSA(pub_key);
        HIP_IFEL(RSA_size(rsa) != sig_len,
                 -1, "Size of public key does not match signature size. Aborting signature verification: %d / %d.\n",
                 RSA_size(rsa), sig_len);
        HIP_IFEL(!RSA_verify(NID_sha1, sha1_digest, SHA_DIGEST_LENGTH, signature, RSA_size(rsa), rsa),
                 -1, "RSA service signature did not verify correctly\n");
        break;
    default:
        HIP_IFEL(1, -1, "Unknown algorithm\n");
        break;
    }
out_err:
    return err;
}

int signaling_verify_mb_sig_selective_s(struct signaling_hipd_state          *sig_state,
                                        struct signaling_param_service_offer *offer)
{
    int           err        = 0;
    EVP_PKEY     *pub_key    = NULL;
    X509         *cert       = NULL;
    int           header_len = 0;
    int           info_len   = 0;
    unsigned char certificate_hint[HIP_AH_SHA_LEN];
    uint16_t      cert_hint_len = 0;
    uint8_t      *signature     = NULL;
    uint8_t       sig_len       = 0;
    uint8_t      *tmp_ptr       = (uint8_t *) offer;
    uint16_t      tmp_offer_id  = 0;

    header_len = sizeof(struct hip_tlv_common) + sizeof(offer->service_offer_id) + sizeof(offer->service_type) +
                 sizeof(offer->service_info_len) + sizeof(offer->service_description);
    info_len      = (offer->service_info_len) * sizeof(uint8_t);
    cert_hint_len = HIP_AH_SHA_LEN;

    tmp_offer_id = ntohs(offer->service_offer_id);
    tmp_ptr     += header_len + info_len;
    memcpy(certificate_hint, tmp_ptr, HIP_AH_SHA_LEN);
    HIP_HEXDUMP("Certificate hint = ", certificate_hint, HIP_AH_SHA_LEN);

    /*---- Fetch the certificate and the public key corresponding to the mbox -----*/
    HIP_IFEL(!(cert = signaling_get_mbox_cert_from_offer_id(sig_state, tmp_offer_id)),
             -1, "Could not find the mbox certificate\n");

    HIP_IFEL(!(pub_key = X509_get_pubkey(cert)), -1,
             "Could not find the mbox public key\n");

    tmp_ptr += cert_hint_len + sizeof(uint8_t);
    memcpy(&sig_len, tmp_ptr, sizeof(uint8_t));
    tmp_ptr  += sizeof(uint8_t);
    signature = malloc(sig_len);
    memcpy(signature, tmp_ptr, sig_len);
    HIP_HEXDUMP("Signature received in the service offer = ", signature, sig_len);

    /*---- Verifying mbox signature  ----*/
    HIP_DEBUG("Verifying mbox signature in the Selectively Signed Service Offer parameter.\n");
    if (!signaling_verify_service_signature(cert, (uint8_t *) offer, header_len + info_len + cert_hint_len,
                                            (uint8_t *) signature, sig_len)) {
        HIP_DEBUG("Service Signature verified Successfully\n");
        err = 1;
        goto out_err;
    } else {
        HIP_DEBUG("Service Signature did not verify Successfully\n");
        err = -1;
        goto out_err;
    }
out_err:
    free(signature);
    return err;
}

int signaling_put_decrypted_secrets_to_msg_buf(struct hip_common *msg,
                                               struct hip_common **msg_buf,
                                               uint8_t *data, uint16_t data_len)
{
    int                          err         = 0;
    const struct hip_tlv_common *param       = NULL;
    uint8_t                     *tmp_ptr     = NULL;
    const uint8_t               *tmp_enc_ptr = NULL;
    uint16_t                     tmp_enc_len = 0;

    unsigned char symm_key[16];
    uint8_t       symm_key_len;
    unsigned char symm_key_hint[4];
    uint8_t       algo;

    tmp_ptr     = data;
    tmp_enc_len = data_len;

    /* sizeof(uint16_t) + sizeof(uint32_t) = 6*/
    while (tmp_enc_len > 6) {
        memcpy(&symm_key_len, tmp_ptr, sizeof(uint8_t));
        tmp_ptr += sizeof(uint8_t);
        memcpy(&algo, tmp_ptr, sizeof(uint8_t));
        tmp_ptr += sizeof(uint8_t);
        memcpy(symm_key_hint, tmp_ptr, sizeof(uint32_t));
        tmp_ptr += sizeof(uint32_t);
        memcpy(symm_key, tmp_ptr, symm_key_len);

        HIP_HEXDUMP("Symmetric key received = ", symm_key, symm_key_len);
        HIP_HEXDUMP("Symmetric key hint received = ", symm_key_hint, 4);

        if ((param = hip_get_param(msg, HIP_PARAM_SIGNALING_ENCRYPTED))) {
            do {
                /* Sanity check */
                if (hip_get_param_type(param) == HIP_PARAM_SIGNALING_ENCRYPTED) {
                    tmp_enc_ptr = (const uint8_t *) (param + 1);
                    HIP_HEXDUMP("Symmetric key hint with this encrypted param = ", tmp_enc_ptr, 4);
                    if (!memcmp(tmp_enc_ptr, symm_key_hint, sizeof(uint32_t))) {
                        HIP_DEBUG("Found the corresponding encrypted param\n");
                        HIP_IFEL(signaling_build_hip_packet_from_hip_encrypted_param(msg, msg_buf,
                                                                                     (const struct hip_encrypted_aes_sha1 *) param,
                                                                                     (unsigned char *) symm_key, &symm_key_len,
                                                                                     (unsigned char *) symm_key_hint, &algo), -1,
                                 "Could not append decrypted endpoint info to the hip msg\n");
                    }
                }
            } while ((param = hip_get_next_param(msg, param)));
        }

        tmp_ptr     += symm_key_len;
        tmp_enc_len -= (sizeof(uint16_t) + sizeof(uint32_t) + symm_key_len);
        HIP_DEBUG("tmp_info_sec_len = %d\n", tmp_enc_len);
    }

out_err:
    return err;
}

/*
 * Get information requested in the service offer unsigned
 *
 * @return 0 on success
 */
int signaling_get_info_req_from_service_offer(const struct signaling_param_service_offer *offer,
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

    num_req_info_items = offer->service_info_len;

    /* number of service offers to be accepted, if more than the limit drop it */
    if (num_req_info_items > 0) {
        HIP_DEBUG("Number of parameters received in the Service Offer = %d.\n", num_req_info_items);
        /*Processing the information requests in the service offer*/
        while ((i < num_req_info_items) && ((tmp_info = offer->endpoint_info_req[i]) != 0)) {
            HIP_DEBUG("Service Offer  = %u\n", tmp_info);
            switch (tmp_info) {
            case HOST_INFO_OS:
                if (!signaling_info_req_flag_check(flags, HOST_INFO_OS)) {
                    signaling_info_req_flag_set(flags, HOST_INFO_OS);
                }
                i++;
                break;
            case HOST_INFO_KERNEL:
                if (!signaling_info_req_flag_check(flags, HOST_INFO_KERNEL)) {
                    signaling_info_req_flag_set(flags, HOST_INFO_KERNEL);
                }
                i++;
                break;
            case HOST_INFO_ID:
                if (!signaling_info_req_flag_check(flags, HOST_INFO_ID)) {
                    signaling_info_req_flag_set(flags, HOST_INFO_ID);
                }
                i++;
                break;
            case HOST_INFO_CERTS:
                if (!signaling_info_req_flag_check(flags, HOST_INFO_CERTS)) {
                    signaling_info_req_flag_set(flags, HOST_INFO_CERTS);
                }
                i++;
                break;

            case USER_INFO_ID:
                if (!signaling_info_req_flag_check(flags, USER_INFO_ID)) {
                    signaling_info_req_flag_set(flags, USER_INFO_ID);
                }
                i++;
                break;
            case USER_INFO_CERTS:
                if (!signaling_info_req_flag_check(flags, USER_INFO_CERTS)) {
                    signaling_info_req_flag_set(flags, USER_INFO_CERTS);
                }
                i++;
                break;

            case APP_INFO_NAME:
                if (!signaling_info_req_flag_check(flags, APP_INFO_NAME)) {
                    signaling_info_req_flag_set(flags, APP_INFO_NAME);
                }
                i++;
                break;
            case APP_INFO_QOS_CLASS:
                if (!signaling_info_req_flag_check(flags, APP_INFO_QOS_CLASS)) {
                    signaling_info_req_flag_set(flags, APP_INFO_QOS_CLASS);
                }
                i++;
                break;
            case APP_INFO_REQUIREMENTS:
                if (!signaling_info_req_flag_check(flags, APP_INFO_REQUIREMENTS)) {
                    signaling_info_req_flag_set(flags, APP_INFO_REQUIREMENTS);
                }
                i++;
                break;
            case APP_INFO_CONNECTIONS:
                if (!signaling_info_req_flag_check(flags, APP_INFO_CONNECTIONS)) {
                    signaling_info_req_flag_set(flags, APP_INFO_CONNECTIONS);
                }
                i++;
                break;
            }
        }
    }

out_err:
    return err;
}

/*
 * Building response to the service offer
 *
 * @return 0 on success
 */
int signaling_build_response_to_service_offer_u(struct hip_common *output_msg,
                                                struct signaling_connection conn,
                                                struct signaling_connection_context *ctx_out,
                                                struct signaling_flags_info_req    *flags)
{
    int err = 0;

    /* sanity checks */
    HIP_ASSERT(flags);
    if (signaling_info_req_flag_check(flags, HOST_INFO_OS)) {
        HIP_IFEL(signaling_build_param_host_info_response(output_msg, conn, ctx_out, HOST_INFO_OS),
                 -1, "Could not add HOST_INFO_OS parameter");
    }
    if (signaling_info_req_flag_check(flags, HOST_INFO_KERNEL)) {
        HIP_IFEL(signaling_build_param_host_info_response(output_msg, conn, ctx_out, HOST_INFO_KERNEL),
                 -1, "Could not add HOST_INFO_KERNEL parameter");
    }
    if (signaling_info_req_flag_check(flags, HOST_INFO_ID)) {
        HIP_IFEL(signaling_build_param_host_info_response(output_msg, conn, ctx_out, HOST_INFO_ID),
                 -1, "Could not add HOST_INFO_ID parameter");
    }
    if (signaling_info_req_flag_check(flags, HOST_INFO_CERTS)) {
        HIP_IFEL(signaling_build_param_host_info_response(output_msg, conn, ctx_out, HOST_INFO_CERTS),
                 -1, "Could not add HOST_INFO_CERTS parameter");
    }
    if (signaling_info_req_flag_check(flags, USER_INFO_ID)) {
        HIP_IFEL(signaling_build_param_user_info_response(output_msg, conn, ctx_out, USER_INFO_ID),
                 -1, "Could not add USER_INFO_ID parameter");
    }
    if (signaling_info_req_flag_check(flags, USER_INFO_CERTS)) {
        HIP_IFEL(signaling_build_param_user_info_response(output_msg, conn, ctx_out, USER_INFO_CERTS),
                 -1, "Could not add USER_INFO_CERTS parameter");
    }
    if (signaling_info_req_flag_check(flags, APP_INFO_NAME)) {
        HIP_IFEL(signaling_build_param_app_info_response(output_msg, conn, ctx_out, APP_INFO_NAME),
                 -1, "Could not add APP_INFO_NAME parameter");
    }
    if (signaling_info_req_flag_check(flags, APP_INFO_QOS_CLASS)) {
        HIP_IFEL(signaling_build_param_app_info_response(output_msg, conn, ctx_out, APP_INFO_QOS_CLASS),
                 -1, "Could not add APP_INFO_QOS_CLASS parameter");
    }
    if (signaling_info_req_flag_check(flags, APP_INFO_REQUIREMENTS)) {
        HIP_IFEL(signaling_build_param_app_info_response(output_msg, conn, ctx_out, APP_INFO_REQUIREMENTS),
                 -1, "Could not add APP_INFO_REQUIREMENTS parameter");
    }
    if (signaling_info_req_flag_check(flags, APP_INFO_CONNECTIONS)) {
        HIP_IFEL(signaling_build_param_app_info_response(output_msg, conn, ctx_out, APP_INFO_CONNECTIONS),
                 -1, "Could not add APP_INFO_CONNECTIONS parameter");
    }
out_err:
    return err;
}

/*
 * Building response to the signed service offer
 *
 * @return 0 on success
 */
int signaling_build_response_to_service_offer_s(struct hip_packet_context          *ctx,
                                                struct signaling_connection         conn,
                                                struct signaling_hipd_state        *sig_state,
                                                struct signaling_flags_info_req    *flags)
{
    int err = 0;
    //int      i                  = 0;
    int                                  tmp_len             = 0;
    uint16_t                             mask                = 0;
    struct hip_common                   *msg_buf             = NULL;   /* It will be used in building the HIP Encrypted param*/
    struct signaling_param_service_offer tmp_service_offer_u = { 0 };
    char                                *enc_in_msg          = NULL, *info_secret_enc = NULL;
    unsigned char                       *iv                  = NULL;
    unsigned char                        key_data[16];
    unsigned char                        key_hint[4];
    int                                  key_data_len = 0;
    //uint16_t tmp_info;
    uint8_t                        *tmp_ptr   = NULL;
    struct signaling_flags_info_req tmp_flags = { 0 };

    /* sanity checks */
    HIP_IFEL(!sig_state, -1, "Got NULL for hipd state\n");
    HIP_IFEL(!ctx, -1, "Got NULL for hip packet ctx\n");

    int i = 0, j = 0;
    for (i = 0; sig_state->offer_groups[i] != NULL; i++) {
        signaling_info_req_flag_init(&tmp_flags);
        signaling_build_service_offer_u_from_offer_groups(&tmp_service_offer_u, sig_state->offer_groups[i]);

        /* Allocate and build message buffer */
        HIP_IFEL(!(msg_buf = hip_msg_alloc()),
                 -ENOMEM, "Out of memory while allocation memory for the notify packet\n");
        hip_build_network_hdr(msg_buf, HIP_UPDATE, mask, &ctx->output_msg->hits, &ctx->output_msg->hitr); /*Just giving some dummy Packet type*/

        /* We use two flags below because one (tmp_flags) is used locally to build the dummy msg_buf for encryption
         * the other flag (flags) just collects all the information request over all service offers
         * Reason: as we set the flag for user signature in hipd_state using the flag (flags) we set here
         */
        HIP_IFEL(signaling_get_info_req_from_service_offer(&tmp_service_offer_u, &tmp_flags),  -1,
                 "Could not get info request from service offer.\n");
        HIP_IFEL(signaling_get_info_req_from_service_offer(&tmp_service_offer_u, flags),  -1,
                 "Could not get info request from service offer.\n");
        HIP_IFEL(signaling_build_response_to_service_offer_u(msg_buf, conn, &sig_state->pending_conn_context,  &tmp_flags), -1,
                 "Could not building responses to the signed service offer\n");
        hip_dump_msg(msg_buf);

#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Start PERF_I2_GEN_SYMM_KEY_SIGNED_OFFER, PERF_R2_GEN_SYMM_KEY_SIGNED_OFFER\n");
        hip_perf_start_benchmark(perf_set, PERF_I2_GEN_SYMM_KEY_SIGNED_OFFER);
        hip_perf_start_benchmark(perf_set, PERF_R2_GEN_SYMM_KEY_SIGNED_OFFER);
#endif
        /* ========== Generate 128 -bit key for encrypting the payload of HIP_ENCRYPTED param ===============*/
        HIP_IFEL(generate_key_for_hip_encrypt(key_data, &key_data_len, key_hint), -1, "Could not generate the random key for HIP Encrypted\n");
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Stop PERF_I2_GEN_SYMM_KEY_SIGNED_OFFER, PERF_R2_GEN_SYMM_KEY_SIGNED_OFFER\n");
        hip_perf_stop_benchmark(perf_set, PERF_I2_GEN_SYMM_KEY_SIGNED_OFFER);
        hip_perf_stop_benchmark(perf_set, PERF_R2_GEN_SYMM_KEY_SIGNED_OFFER);
#endif
        /* ========== Create the HIP_ENCRYPTED param. The payload will not be encrypted here ===============*/
        tmp_ptr = (uint8_t *) msg_buf + sizeof(struct hip_common);
        tmp_len = hip_get_msg_total_len(msg_buf) - sizeof(struct hip_common);
        HIP_IFEL(signaling_build_param_encrypted_aes_sha1(ctx->output_msg, (char *) tmp_ptr, &tmp_len, key_hint), -1,
                 "Could not build the HIP Encrypted parameter\n");
        HIP_HEXDUMP("Unencrypted data = ", tmp_ptr, tmp_len);

        j          = 0;
        enc_in_msg = hip_get_param_readwrite(ctx->output_msg, HIP_PARAM_SIGNALING_ENCRYPTED);
        do {
            if (hip_get_param_type(enc_in_msg) == HIP_PARAM_SIGNALING_ENCRYPTED && j >= i) {
                break;
            }
            j++;
        } while ((enc_in_msg = (char *) hip_get_next_param_readwrite(ctx->output_msg, (struct hip_tlv_common *) enc_in_msg)));

        HIP_ASSERT(enc_in_msg);             /* Builder internal error. */
        iv = ((struct hip_encrypted_aes_sha1 *) enc_in_msg)->iv;
        get_random_bytes(iv, 16);
        info_secret_enc = enc_in_msg + sizeof(struct hip_encrypted_aes_sha1);

        /* ========== Encrypt the payload of HIP_ENCRYPTED param.  ===============*/
        HIP_HEXDUMP("enc key = ", key_data, key_data_len);
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Start PERF_I2_ENCRYPT_ENDPOINT_SECRETS, PERF_R2_ENCRYPT_ENDPOINT_SECRETS\n");
        hip_perf_start_benchmark(perf_set, PERF_I2_ENCRYPT_ENDPOINT_SECRETS);
        hip_perf_start_benchmark(perf_set, PERF_R2_ENCRYPT_ENDPOINT_SECRETS);
#endif
        HIP_IFEL(hip_crypto_encrypted(info_secret_enc, iv, HIP_HIP_AES_SHA1,
                                      tmp_len, key_data, HIP_DIRECTION_ENCRYPT),
                 -1, "Building of param encrypted failed\n");
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Stop PERF_I2_ENCRYPT_ENDPOINT_SECRETS, PERF_R2_ENCRYPT_ENDPOINT_SECRETS\n");
        hip_perf_stop_benchmark(perf_set, PERF_I2_ENCRYPT_ENDPOINT_SECRETS);
        hip_perf_stop_benchmark(perf_set, PERF_R2_ENCRYPT_ENDPOINT_SECRETS);
#endif
        HIP_HEXDUMP("Encrypted data = ", info_secret_enc, tmp_len);

        memcpy(&sig_state->offer_groups[i]->key_data.key_hint, key_hint, 4);
        sig_state->offer_groups[i]->key_data.symm_enc_algo = HIP_HIP_AES_SHA1;
        sig_state->offer_groups[i]->key_data.symm_key_len  = key_data_len;
        memcpy(sig_state->offer_groups[i]->key_data.symm_key, key_data, key_data_len);
        free(msg_buf);
    }

out_err:
    //free(msg_buf);
    //free(signature);
    return err;
}

/*
 * Building Acknowledgment for unsigned signed service offer
 */
int signaling_build_service_ack_u(struct hip_common *input_msg,
                                  struct hip_common *output_msg)
{
    int                                  err = 0;
    struct signaling_param_service_offer param_service_offer;
    const struct hip_tlv_common         *param;
    struct signaling_param_service_ack   ack = { 0 };

    if ((param = hip_get_param(input_msg, HIP_PARAM_SIGNALING_SERVICE_OFFER))) {
        do {
            if (hip_get_param_type(param) == HIP_PARAM_SIGNALING_SERVICE_OFFER) {
                HIP_IFEL(signaling_copy_service_offer(&param_service_offer, (const struct signaling_param_service_offer *) (param)),
                         -1, "Could not copy connection context\n");

                ack.service_offer_id = param_service_offer.service_offer_id;
                ack.service_option   = 0;
#ifdef CONFIG_HIP_PERFORMANCE
                HIP_DEBUG("Start PERF_I2_HASH_SERVICE_OFFER, PERF_R2_HASH_SERVICE_OFFER\n");
                hip_perf_start_benchmark(perf_set, PERF_I2_HASH_SERVICE_OFFER);
                hip_perf_start_benchmark(perf_set, PERF_R2_HASH_SERVICE_OFFER);
#endif
                /*Generate the hash of the service offer*/
                HIP_IFEL(hip_build_digest(HIP_DIGEST_SHA1, &param_service_offer, hip_get_param_contents_len(&param_service_offer), ack.service_offer_hash),
                         -1, "Could not build hash of the service offer \n");
#ifdef CONFIG_HIP_PERFORMANCE
                HIP_DEBUG("Start PERF_I2_HASH_SERVICE_OFFER, PERF_R2_HASH_SERVICE_OFFER\n");
                hip_perf_start_benchmark(perf_set, PERF_I2_HASH_SERVICE_OFFER);
                hip_perf_start_benchmark(perf_set, PERF_R2_HASH_SERVICE_OFFER);
#endif
                // print_hash(ack.service_offer_hash);
                HIP_DEBUG("Hash calculated for Service Acknowledgement\n");
                int len_contents = sizeof(ack.service_offer_id) + sizeof(ack.service_option) + sizeof(ack.service_offer_hash);
                hip_set_param_contents_len((struct hip_tlv_common *) &ack, len_contents);
                hip_set_param_type((struct hip_tlv_common *) &ack, HIP_PARAM_SIGNALING_SERVICE_ACK);

                /* Append the parameter to the message */
                if (hip_build_param(output_msg, (struct hip_tlv_common *) &ack)) {
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
 * Building Acknowledgment for selectively signed service offer
 */
int signaling_build_service_ack_selective_s(struct hip_common *input_msg,
                                            struct hip_common *output_msg,
                                            struct signaling_hipd_state *sig_state)
{
    int                                  err = 0, i = 0;
    struct signaling_param_service_offer param_service_offer;
    const struct hip_tlv_common         *param;
    struct signaling_param_service_ack   ack          = { 0 };
    uint8_t                             *tmp_ptr      = NULL;
    uint16_t                             tmp_len      = 0;
    uint16_t                             tmp_offer_id = 0;

    if ((param = hip_get_param(input_msg, HIP_PARAM_SIGNALING_SERVICE_OFFER))) {
        do {
            if (hip_get_param_type(param) == HIP_PARAM_SIGNALING_SERVICE_OFFER) {
                HIP_IFEL(signaling_copy_service_offer(&param_service_offer, (const struct signaling_param_service_offer *) (param)),
                         -1, "Could not copy connection context\n");

                ack.service_offer_id = param_service_offer.service_offer_id;
                ack.service_option   = htons(0);
#ifdef CONFIG_HIP_PERFORMANCE
                HIP_DEBUG("Start PERF_I2_HASH_SERVICE_OFFER, PERF_R2_HASH_SERVICE_OFFER\n");
                hip_perf_start_benchmark(perf_set, PERF_I2_HASH_SERVICE_OFFER);
                hip_perf_start_benchmark(perf_set, PERF_R2_HASH_SERVICE_OFFER);
#endif
                /*Generate the hash of the service offer*/
                HIP_IFEL(hip_build_digest(HIP_DIGEST_SHA1, &param_service_offer, hip_get_param_contents_len(&param_service_offer), ack.service_offer_hash),
                         -1, "Could not build hash of the service offer \n");
#ifdef CONFIG_HIP_PERFORMANCE
                HIP_DEBUG("Stop PERF_I2_HASH_SERVICE_OFFER, PERF_R2_HASH_SERVICE_OFFER\n");
                hip_perf_stop_benchmark(perf_set, PERF_I2_HASH_SERVICE_OFFER);
                hip_perf_stop_benchmark(perf_set, PERF_R2_HASH_SERVICE_OFFER);
#endif
                tmp_ptr  = (uint8_t *) &ack;
                tmp_ptr +=  sizeof(struct hip_tlv_common) + sizeof(ack.service_offer_id) +
                           sizeof(ack.service_option) + sizeof(ack.service_offer_hash);
                tmp_offer_id = ntohs(param_service_offer.service_offer_id);

                for (i = 0; i < MAX_NUM_OFFER_GROUPS && sig_state->offer_groups[i] != NULL; i++) {
                    if (sig_state->offer_groups[i]->mbox[0] == tmp_offer_id) {
                        tmp_len = sizeof(uint8_t) * (sig_state->offer_groups[i]->num_info_req);
                        memcpy(tmp_ptr, &sig_state->offer_groups[i]->info_requests[0], tmp_len);
                        break;
                    }
                }

                // print_hash(ack.service_offer_hash);
                HIP_DEBUG("Hash calculated for Service Acknowledgement\n");
                int len_contents = sizeof(ack.service_offer_id) + sizeof(ack.service_option) + sizeof(ack.service_offer_hash) + tmp_len;
                hip_set_param_contents_len((struct hip_tlv_common *) &ack, len_contents);
                hip_set_param_type((struct hip_tlv_common *) &ack, HIP_PARAM_SIGNALING_SERVICE_ACK);

                /* Append the parameter to the message */
                if (hip_build_param(output_msg, (struct hip_tlv_common *) &ack)) {
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
 * Building Acknowledgment for signed signed service offer. Slightly tricky.
 */
int signaling_build_service_ack_s(struct signaling_hipd_state *sig_state,
                                  struct hip_packet_context *ctx,
                                  const uint8_t *peer_pub_key,
                                  const int peer_pub_key_len)
{
    int                                  err = 0, i = 0;
    struct signaling_param_service_offer param_service_offer;
    const struct hip_tlv_common         *param;
    struct signaling_param_service_ack   ack                       = { 0 };
    char                                 param_buf[HIP_MAX_PACKET] = { 0 };
    unsigned char                       *tmp_info_secrets          = NULL;
    int                                  tmp_info_sec_len          = 0;
    unsigned char                       *enc_output                = NULL;
    uint8_t                             *tmp_ptr                   = NULL;
    uint16_t                             tmp_len                   = 0;
    int                                  len_contents              = 0;
    RSA                                 *rsa                       = NULL;
    unsigned char                       *dh_shared_key             = NULL;
    int                                  dh_shared_len             = 1024;

//  EC_KEY   *ecdsa        = NULL;
    EVP_PKEY *pub_key      = NULL;
    X509     *cert         = NULL;
    uint16_t  tmp_offer_id = 0;
    uint8_t  *tmp_enc_ptr  = 0;
    uint8_t  *iv           = NULL;

    HIP_IFEL(!ctx->hadb_entry, 0, "No hadb entry.\n");
    HIP_DEBUG("Building the signed service ack \n");

    if ((param = hip_get_param(ctx->input_msg, HIP_PARAM_SIGNALING_SERVICE_OFFER))) {
        do {
            if (hip_get_param_type(param) == HIP_PARAM_SIGNALING_SERVICE_OFFER) {
                HIP_IFEL(signaling_copy_service_offer(&param_service_offer, (const struct signaling_param_service_offer *) (param)),
                         -1, "Could not copy connection context\n");
                tmp_offer_id         = ntohs(param_service_offer.service_offer_id);
                tmp_len              = 0;
                tmp_ptr              = (uint8_t *) param_buf;
                ack.service_offer_id = htons(tmp_offer_id);
                HIP_DEBUG("Building ack for offer_id = %u\n", tmp_offer_id);

#ifdef CONFIG_HIP_PERFORMANCE
                HIP_DEBUG("Start PERF_I2_HASH_SERVICE_OFFER, PERF_R2_HASH_SERVICE_OFFER\n");
                hip_perf_start_benchmark(perf_set, PERF_I2_HASH_SERVICE_OFFER);
                hip_perf_start_benchmark(perf_set, PERF_R2_HASH_SERVICE_OFFER);
#endif
                /*Generate the hash of the service offer*/
                HIP_IFEL(hip_build_digest(HIP_DIGEST_SHA1, &param_service_offer, hip_get_param_contents_len(&param_service_offer), ack.service_offer_hash),
                         -1, "Could not build hash of the service offer \n");
                HIP_HEXDUMP("Service offer hash = ", ack.service_offer_hash, HIP_AH_SHA_LEN);
                HIP_DEBUG("Hash calculated for Service Acknowledgement\n");
#ifdef CONFIG_HIP_PERFORMANCE
                HIP_DEBUG("Stop PERF_I2_HASH_SERVICE_OFFER, PERF_R2_HASH_SERVICE_OFFER\n");
                hip_perf_stop_benchmark(perf_set, PERF_I2_HASH_SERVICE_OFFER);
                hip_perf_stop_benchmark(perf_set, PERF_R2_HASH_SERVICE_OFFER);
#endif
                // print_hash(ack.service_offer_hash);
                if (!signaling_check_if_offer_in_nack_list(sig_state, tmp_offer_id)) {
                    for (i = 0; sig_state->offer_groups[i] != NULL; i++) {
                        int j    = 0;
                        int flag = 0;
                        for (j = 0; j < sig_state->offer_groups[i]->num_mboxes; j++) {
                            if (sig_state->offer_groups[i]->mbox[j] == tmp_offer_id) {
                                flag = 1;
                                break;
                            }
                        }
                        if (flag) {
                            tmp_info_sec_len = sizeof(uint16_t) + sizeof(uint32_t) +
                                               sig_state->offer_groups[i]->key_data.symm_key_len;
                            tmp_info_secrets = malloc(tmp_info_sec_len);

                            tmp_enc_ptr = tmp_info_secrets;
                            memcpy(tmp_enc_ptr, &sig_state->offer_groups[i]->key_data.symm_key_len, sizeof(uint8_t));
                            tmp_enc_ptr += sizeof(uint8_t);
                            memcpy(tmp_enc_ptr, &sig_state->offer_groups[i]->key_data.symm_enc_algo, sizeof(uint8_t));
                            tmp_enc_ptr += sizeof(uint8_t);
                            memcpy(tmp_enc_ptr, &sig_state->offer_groups[i]->key_data.key_hint, sizeof(uint32_t));
                            tmp_enc_ptr += sizeof(uint32_t);
                            memcpy(tmp_enc_ptr, sig_state->offer_groups[i]->key_data.symm_key,
                                   sig_state->offer_groups[i]->key_data.symm_key_len);

                            memcpy(tmp_ptr, tmp_info_secrets, tmp_info_sec_len);
                            tmp_ptr += tmp_info_sec_len;
                            tmp_len += tmp_info_sec_len;
                            free(tmp_info_secrets);
                        }
                    }
                }

                HIP_HEXDUMP("Original end point info secrets : ", param_buf, tmp_len);
                HIP_DEBUG("Length of info secrets before encryption = %d\n", tmp_len);

                tmp_info_secrets = (uint8_t *) param_buf;
                tmp_info_sec_len = tmp_len;

                if (SERVICE_RESPONSE_ALGO_DH) {
#ifdef CONFIG_HIP_PERFORMANCE
                    HIP_DEBUG("Start PERF_I2_ENC_SYMM_KEY_INFO_ACK_DH, PERF_R2_ENC_SYMM_KEY_INFO_ACK_DH\n");
                    hip_perf_start_benchmark(perf_set, PERF_I2_ENC_SYMM_KEY_INFO_ACK_DH);
                    hip_perf_start_benchmark(perf_set, PERF_R2_ENC_SYMM_KEY_INFO_ACK_DH);
#endif
                    HIP_IFEL(!(dh_shared_key = calloc(1, dh_shared_len)), -ENOMEM,
                             "Error on allocating memory for Diffie-Hellman shared key.\n");
                    signaling_generate_shared_key_from_dh_shared_secret(dh_shared_key, &dh_shared_len, peer_pub_key, peer_pub_key_len);
                    iv = ack.iv;
                    get_random_bytes(iv, 16);

                    int rem = tmp_info_sec_len % 16;
                    if (rem) {
                        memset(&param_buf[tmp_info_sec_len], 0, (16 - rem));
                        tmp_info_sec_len += (16 - rem);
                    }
                    HIP_HEXDUMP("Enc key derived from DH = ", dh_shared_key, dh_shared_len);
                    HIP_HEXDUMP("IV  = ", iv, 16 * sizeof(uint8_t));
                    HIP_IFEL(hip_crypto_encrypted(tmp_info_secrets, iv, HIP_HIP_AES_SHA1,
                                                  tmp_info_sec_len, dh_shared_key, HIP_DIRECTION_ENCRYPT),
                             -1, "Building of param encrypted failed\n");
                    ack.service_option = htons(tmp_info_sec_len);
                    len_contents       = tmp_info_sec_len + sizeof(ack.service_offer_id) +
                                         sizeof(ack.service_option) + sizeof(ack.service_offer_hash) +
                                         16 * sizeof(uint8_t);
                    free(dh_shared_key);
                    dh_shared_len = 1024;
#ifdef CONFIG_HIP_PERFORMANCE
                    HIP_DEBUG("Stop PERF_I2_ENC_SYMM_KEY_INFO_ACK_DH, PERF_R2_ENC_SYMM_KEY_INFO_ACK_DH\n");
                    hip_perf_stop_benchmark(perf_set, PERF_I2_ENC_SYMM_KEY_INFO_ACK_DH);
                    hip_perf_stop_benchmark(perf_set, PERF_R2_ENC_SYMM_KEY_INFO_ACK_DH);
#endif
                } else {
#ifdef CONFIG_HIP_PERFORMANCE
                    HIP_DEBUG("Start PERF_I2_ENC_SYMM_KEY_INFO_ACK_RSA, PERF_R2_ENC_SYMM_KEY_INFO_ACK_RSA\n");
                    hip_perf_start_benchmark(perf_set, PERF_I2_ENC_SYMM_KEY_INFO_ACK_RSA);
                    hip_perf_start_benchmark(perf_set, PERF_R2_ENC_SYMM_KEY_INFO_ACK_RSA);
#endif
                    /*---- Fetch the certificate and the public key corresponding to the mbox -----*/
                    HIP_IFEL(!(cert = signaling_get_mbox_cert_from_offer_id(sig_state, tmp_offer_id)),
                             -1, "Could not find the mbox certificate\n");
                    HIP_IFEL(!(pub_key = X509_get_pubkey(cert)), -1,
                             "Could not find the mbox public key\n");

                    /*---- Encrypting the end point info secrets ----*/
                    rsa        = EVP_PKEY_get1_RSA(pub_key);
                    enc_output = malloc(RSA_size(rsa));
                    tmp_len    = RSA_public_encrypt(tmp_info_sec_len, tmp_info_secrets, enc_output, rsa, RSA_PKCS1_OAEP_PADDING);

                    ack.service_option = htons(tmp_info_sec_len);
                    iv                 = ack.iv;
                    memset(iv, 0, 16 * sizeof(uint8_t));
                    HIP_DEBUG("Length of encrypted info secrets after encryption = %d\n", tmp_len);
                    HIP_HEXDUMP("Encrypted end point info secrets : ", enc_output, tmp_len);

                    tmp_ptr = (uint8_t *) param_buf;
                    memset(tmp_ptr, 0, sizeof(param_buf));
                    memcpy(tmp_ptr, enc_output, tmp_len);
                    len_contents = tmp_len + sizeof(ack.service_offer_id) +
                                   sizeof(ack.service_option) + sizeof(ack.service_offer_hash) +
                                   16 * sizeof(uint8_t);
#ifdef CONFIG_HIP_PERFORMANCE
                    HIP_DEBUG("Stop PERF_I2_ENC_SYMM_KEY_INFO_ACK_RSA, PERF_R2_ENC_SYMM_KEY_INFO_ACK_RSA\n");
                    hip_perf_stop_benchmark(perf_set, PERF_I2_ENC_SYMM_KEY_INFO_ACK_RSA);
                    hip_perf_stop_benchmark(perf_set, PERF_R2_ENC_SYMM_KEY_INFO_ACK_RSA);
#endif
                }

                /*---- Building of the HIP PARAM SECVICE ACK Signed ----*/
                HIP_DEBUG("Length of the contents of the service ack = %d\n", len_contents);
                hip_calc_param_len((struct hip_tlv_common *) &ack, len_contents);
                hip_set_param_type((struct hip_tlv_common *) &ack, HIP_PARAM_SIGNALING_SERVICE_ACK);

                /* Append the parameter to the message */
                HIP_IFEL(hip_build_generic_param(ctx->output_msg, &ack, sizeof(ack), param_buf),
                         -1, "Could not build the HIP Encrypted parameter\n");
                free(enc_output);
                RSA_free(rsa);
            }
        } while ((param = hip_get_next_param(ctx->input_msg, param)));
    }

    /* Append the parameter to the  service ack list in the hipd_state. We will build the service_ack to the HIP msg later */
/*
 *  HIP_IFEL(!(sig_state = lmod_get_state_item(ctx->hadb_entry->hip_modular_state, "signaling_hipd_state")),
 *           0, "failed to retrieve state for signaling\n");
 *
 *  for (i = 0; i < 10; i++) {
 *      if (sig_state->service_ack[i] == NULL) {
 *          break;
 *      }
 *  }
 *  tmp_len                   = hip_get_param_contents_len(&ack) + sizeof(struct hip_tlv_common);
 *  sig_state->service_ack[i] = malloc(tmp_len);
 *  memcpy(sig_state->service_ack[i], &ack, tmp_len);
 */

out_err:
    return err;
}

/**
 * build a hip_encrypted parameter
 *
 * @param msg the message where the parameter will be appended
 * @param data the payload which has to be encrypted. It contains inner HIP parameters
 * which are internally padded according to rules in RFC 5201, Section 5.2.15
 *
 * @returns zero on success, or -1 on failure
 *
 * @note This function does not actually encrypt anything, it just builds
 * the parameter. The parameter that will be encapsulated in the hip_encrypted
 * parameter has to be encrypted using a different function call.
 */
int signaling_build_param_encrypted_aes_sha1(struct hip_common *output_msg,
                                             char *data, int *data_len, UNUSED unsigned char *key_hint)
{
    int                           err          = 0;
    struct hip_encrypted_aes_sha1 enc          = { 0 };
    char                         *param_padded = NULL;
    hip_set_param_type((struct hip_tlv_common *) &enc, HIP_PARAM_SIGNALING_ENCRYPTED);

    HIP_ASSERT(data);

    enc.reserved = htonl(0);
    memcpy(&enc.reserved, key_hint, sizeof(enc.reserved));

    /* copy the IV *IF* needed, and then the encrypted data */
    /* AES block size must be multiple of 16 bytes */
    // No need for padding anymore


    int rem = *data_len % 16;
    /* this kind of padding works against Ericsson/OpenSSL
     * (method 4: RFC2630 method) */
    /* http://www.di-mgt.com.au/cryptopad.html#exampleaes */
    if (rem) {
        HIP_DEBUG("Adjusting param size to AES block size by %d bytes \n", rem);

        param_padded = malloc(*data_len + rem);
        if (!param_padded) {
            return -ENOMEM;
        }
        memcpy(param_padded, data, *data_len);
        memset(param_padded + *data_len, 0, rem);
        *data_len += rem;
    } else {
        param_padded = malloc(*data_len);
        if (!param_padded) {
            return -ENOMEM;
        }
        memcpy(param_padded, data, *data_len);
    }


    hip_calc_param_len((struct hip_tlv_common *) &enc, sizeof(enc) -
                       sizeof(struct hip_tlv_common) +
                       *data_len);

    HIP_IFEL(hip_build_generic_param(output_msg, &enc, sizeof(enc), param_padded),
             -1, "Could not build the HIP Encrypted parameter\n");
out_err:
    free(param_padded);
    return err;
}

int signaling_add_param_dh_to_hip_update(struct hip_common *msg)
{
    int      err      = 0;
    uint8_t *dh_data1 = NULL, *dh_data2 = NULL;
    int      dh_size1 = 0, dh_size2 = 0;
    int      written1 = 0;

    /* Allocate memory for writing the first Diffie-Hellman shared secret */
    HIP_IFEL((dh_size1 = hip_get_dh_size(DH_GROUP_ID)) == 0,
             -1, "Could not get dh_size1\n");
    HIP_IFEL(!(dh_data1 = calloc(1, dh_size1)),
             -1, "Failed to alloc memory for dh_data1\n");

    /* Allocate memory for writing the second Diffie-Hellman shared secret */
    HIP_IFEL((dh_size2 = hip_get_dh_size(HIP_SECOND_DH_GROUP_ID)) == 0,
             -1, "Could not get dh_size2\n");
    HIP_IFEL(!(dh_data2 = calloc(1, dh_size2)),
             -1, "Failed to alloc memory for dh_data2\n");

    /* Parameter Diffie-Hellman */
    HIP_IFEL((written1 = hip_insert_dh(dh_data1, dh_size1,
                                       DH_GROUP_ID)) < 0,
             written1, "Could not extract the first DH public key\n");

    /* Only one diffie hellman public value in this parameter */
    HIP_IFEL((err = hip_build_param_diffie_hellman_contents(msg,
                                                            DH_GROUP_ID, dh_data1, written1,
                                                            HIP_MAX_DH_GROUP_ID, dh_data2, 0)),
             err, "Building of DH failed.\n");

out_err:
    return err;
}

/* Create a temporary service offer unsigned param.
 * This will help us to reuse the code for signaling_build_response_to_service_offer_u(..)
 * */
int signaling_build_service_offer_u_from_service_offer_s(struct signaling_param_service_offer *offer_u,
                                                         struct signaling_param_service_offer_s *offer_s,
                                                         int end_point_info_len)
{
    int      tmp_len = 0;
    uint8_t *tmp_ptr = (uint8_t *) offer_s;

    HIP_ASSERT(offer_u);
    HIP_ASSERT(offer_s);

    HIP_DEBUG("Now building the service offer unsigned param\n");
    tmp_len =   sizeof(struct hip_tlv_common) + sizeof(offer_u->service_offer_id) +
              sizeof(offer_u->service_type);
    memcpy(offer_u, tmp_ptr, tmp_len);
    tmp_ptr += tmp_len + sizeof(offer_s->service_cert_hint_len) + sizeof(offer_s->service_sig_algo) +
               sizeof(offer_s->service_sig_len);
    tmp_len = sizeof(offer_u->service_description);
    memcpy(&offer_u->service_description, tmp_ptr, tmp_len);
    tmp_ptr += tmp_len;
    tmp_len  = end_point_info_len;
    memcpy(&offer_u->endpoint_info_req[0], tmp_ptr, tmp_len);

    tmp_len +=  sizeof(offer_u->service_offer_id) + sizeof(offer_u->service_type) +
               sizeof(offer_u->service_description);
    hip_set_param_contents_len((struct hip_tlv_common *) offer_u, tmp_len);
    hip_set_param_type((struct hip_tlv_common *) offer_u, HIP_PARAM_SIGNALING_SERVICE_OFFER);

    return 0;
}

/* Create a temporary service offer unsigned param from the offer groups previously created.
 * This will help us to reuse the code for signaling_build_response_to_service_offer_u(..)
 * */
int signaling_build_service_offer_u_from_offer_groups(struct signaling_param_service_offer *offer_u,
                                                      struct service_offer_groups *group)
{
    int tmp_len = 0, i = 0;

    HIP_ASSERT(offer_u);

    HIP_DEBUG("Now building the service offer unsigned param from the offer groups\n");
    offer_u->service_info_len = group->num_info_req;
    offer_u->service_type     = OFFER_UNSIGNED;
    for (i = 0; i < group->num_info_req; i++) {
        HIP_DEBUG("Info requested added from flag  = %u\n", group->info_requests[i]);
        offer_u->endpoint_info_req[i] = group->info_requests[i];
    }
    tmp_len =  sizeof(offer_u->service_offer_id) + sizeof(offer_u->service_type) +
              sizeof(offer_u->service_info_len) + sizeof(offer_u->service_description) +
              (group->num_info_req) * sizeof(uint8_t) + sizeof(offer_u->service_cert_hint);
    hip_set_param_contents_len((struct hip_tlv_common *) offer_u, tmp_len);
    hip_set_param_type((struct hip_tlv_common *) offer_u, HIP_PARAM_SIGNALING_SERVICE_OFFER);
    return 0;
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

/**
 * build the contents of a HIP signature1 parameter
 * (the type and length fields for the parameter should be set separately)
 *
 * @param msg the message
 * @param contents pointer to the signature contents (the data to be written
 *                 after the signature field)
 * @param contents_size size of the contents of the signature (the data after the
 *                 algorithm field)
 * @param algorithm the algorithm as in the HIP drafts that was used for
 *                 producing the signature
 * @return zero for success, or non-zero on error
 */
int signaling_hip_build_param_selective_sign(struct hip_common *msg,
                                             const void *contents,
                                             hip_tlv_len contents_size,
                                             uint8_t algorithm)
{
    /* note: if you make changes in this function, make them also in
     * build_param_signature_contents2(), because it is almost the same */

    struct hip_sig sig;

    HIP_ASSERT(sizeof(struct hip_sig) >= sizeof(struct hip_tlv_common));

    hip_set_param_type((struct hip_tlv_common *) &sig, HIP_PARAM_SIGNALING_SELECTIVE_SIGNATURE);
    hip_calc_generic_param_len((struct hip_tlv_common *) &sig, sizeof(struct hip_sig),
                               contents_size);
    sig.algorithm = algorithm;     /* algo is 8 bits, no htons */

    return hip_build_generic_param(msg, &sig, sizeof(struct hip_sig), contents);
}

int signaling_build_hash_tree_from_msg(struct hip_common *msg,
                                       unsigned char **concat_of_leaves,
                                       unsigned int   *len_concat_of_leaves)
{
    int                        err                 = 0, i = 0, origlen = 0;
    struct hip_tlv_common     *param               = NULL;
    uint8_t                   *tmp_ptr             = NULL;
    uint16_t                   tmp_len             = 0;
    uint16_t                   tmp_pos             = 0;
    uint16_t                   num_leaf            = 1; /*header of the msg is already counted*/
    struct hip_hash_tree_leaf *leaves              = NULL;
    struct hip_hash_tree_leaf  tmp_leaf            = { 0 };
    uint32_t                   HIP_PARAM_SIG_LIMIT = 0;
    int                        param_rem_total_len = 0;

    HIP_DEBUG("Building hash tree before signing\n");
    /* Getting the number of leaves in the hash tree
     * Range limit for the parameters those will be signed
     * http://tools.ietf.org/html/rfc5201#section-5.2 and
     * http://tools.ietf.org/html/rfc5201#section-5.2.11
     */
    if (hip_get_msg_type(msg) == HIP_R1) {
        HIP_PARAM_SIG_LIMIT = HIP_PARAM_HIP_SIGNATURE2;
    } else {
        HIP_PARAM_SIG_LIMIT = HIP_PARAM_HIP_SIGNATURE;
    }

    origlen = hip_get_msg_total_len(msg);

    while ((param = hip_get_next_param_readwrite(msg, param))) {
        if ((hip_get_param_type((struct hip_tlv_common *) param) < HIP_PARAM_SIG_LIMIT) ||
            (hip_get_param_type((struct hip_tlv_common *) param) == HIP_PARAM_SELECTIVE_HASH_LEAF)) {
            num_leaf++;
        }
    }
    while ((param = hip_get_next_param_readwrite(msg, param))) {
        ;
    }

    HIP_DEBUG("number of leaves of the hash tree : %d\n", num_leaf);
    leaves = malloc(num_leaf * sizeof(struct hip_hash_tree_leaf));
    /* Initialize the leaves of the hash tree. Important to have the leaf_pos
     * in struct hip_hash_tree_leaf to initialized to zero*/
    for (i = 0; i < num_leaf; i++) {
        *(leaves + i) = tmp_leaf;
    }

    hip_set_msg_total_len(msg, 0);
    tmp_ptr          = (uint8_t *) msg;
    tmp_len          = sizeof(struct hip_common);
    leaves->leaf_pos = 0;
    HIP_IFEL(hip_build_digest(HIP_DIGEST_SHA1, tmp_ptr, tmp_len, leaves->leaf_hash) < 0,
             -1, "Building of SHA1 digest failed\n");
    hip_set_msg_total_len(msg, origlen);
    //HIP_DEBUG("Leaves of the hash tree set\n");
    i = 1;

    /*Check the hip msg if some portion has been replaced by the mbox with its hash
     * and insert the hash from the leaf at the correct position*/
    param = NULL;
    while ((param = hip_get_next_param_readwrite(msg, param))) {
        if (hip_get_param_type((const struct hip_tlv_common *) param) == HIP_PARAM_SELECTIVE_HASH_LEAF) {
            tmp_pos                                                      = ntohs(((struct siganling_param_selective_hash_leaf *) param)->leaf_pos);
            ((struct hip_hash_tree_leaf *) (leaves + tmp_pos))->leaf_pos = tmp_pos;

            param_rem_total_len += ntohs(((struct siganling_param_selective_hash_leaf *) param)->len_param_rem);
            memcpy((leaves + tmp_pos)->leaf_hash, ((struct siganling_param_selective_hash_leaf *) param)->leaf_hash, HIP_AH_SHA_LEN);
/*          HIP_DEBUG("Postion of the leaf = %u\n", tmp_pos);
 *          HIP_HEXDUMP("Leaf hash = ", (leaves + tmp_pos)->leaf_hash, HIP_AH_SHA_LEN);*/
        }
    }
    param = NULL;
    while (i < num_leaf) {
        if ((leaves + i)->leaf_pos == 0 && (param = hip_get_next_param_readwrite(msg, param))) {
            (leaves + i)->leaf_pos = i;
            tmp_ptr                = (uint8_t *) param;
            tmp_len                = hip_get_param_total_len((const struct hip_tlv_common *) param);

            HIP_IFEL(hip_build_digest(HIP_DIGEST_SHA1, tmp_ptr, tmp_len, (leaves + i)->leaf_hash) < 0,
                     -1, "Building of SHA1 digest failed\n");
/*          HIP_DEBUG("leaf position where hash leaf to be inserted i = %d ", i);
 *          HIP_HEXDUMP("",(leaves + i)->leaf_hash, HIP_AH_SHA_LEN);*/
        }
        i++;
    }

    // Concatenate the leaves of the HASH Tree
    tmp_len               = num_leaf * HIP_AH_SHA_LEN;
    *concat_of_leaves     = malloc(tmp_len);
    *len_concat_of_leaves = tmp_len;
    memset(*concat_of_leaves, 0, tmp_len);
    tmp_ptr = (uint8_t *) (*concat_of_leaves);
    for (i = 0; i < num_leaf; i++) {
        HIP_IFEL(!memcpy(tmp_ptr, (leaves + i)->leaf_hash, HIP_AH_SHA_LEN), -1, "Error memcpying\n");
        tmp_ptr += HIP_AH_SHA_LEN;
    }
    HIP_HEXDUMP("Concatenation of the leaves of the hash tree : ", *concat_of_leaves, *len_concat_of_leaves);

out_err:
    return err;
}

int signaling_build_hash_tree_and_get_root(struct hip_common *msg,
                                           unsigned char *root_hash_tree)
{
    int            err              = 0;
    unsigned char *concat_of_leaves = NULL;
    unsigned int   len_concat_of_leaves;

    HIP_ASSERT(root_hash_tree);
    HIP_IFEL(signaling_build_hash_tree_from_msg(msg, &concat_of_leaves, &len_concat_of_leaves), -1,
             "Could not build hash tree from message\n");
    //Hash the concatenation of the leaves to form the root node
    HIP_IFEL(hip_build_digest(HIP_DIGEST_SHA1, concat_of_leaves, len_concat_of_leaves, root_hash_tree) < 0,
             -1, "Building of SHA1 digest failed\n");

out_err:
    return err;
}

/**
 * Builds a @c HMAC parameter to the HIP packet @c msg. This function calculates
 * also the hmac value from the whole message as specified in the drafts.
 *
 * @param msg a pointer to the message where the @c HMAC parameter will be
 *            appended.
 * @param key a pointer to a key used for hmac.
 * @param param_type HIP_PARAM_HMAC, HIP_PARAM_RELAY_HMAC or HIP_PARAM_RVS_HMAC accordingly
 * @return    zero on success, or negative error value on error.
 * @see       hip_build_param_hmac2_contents()
 * @see       hip_write_hmac().
 */
int signaling_build_param_selective_hmac(struct hip_common *msg,
                                         const struct hip_crypto_key *key,
                                         hip_tlv param_type)
{
    int             err = 0;
    struct hip_hmac hmac;
    unsigned char  *concat_of_leaves = NULL;
    unsigned int    len_concat_of_leaves;

    HIP_IFEL(signaling_build_hash_tree_from_msg(msg, &concat_of_leaves, &len_concat_of_leaves), -1,
             "Could not build hash tree from message\n");

    hip_set_param_type((struct hip_tlv_common *) &hmac, param_type);
    hip_calc_generic_param_len((struct hip_tlv_common *) &hmac,
                               sizeof(struct hip_hmac),
                               0);

    HIP_IFEL(hip_write_hmac(HIP_DIGEST_SHA1_HMAC, key->key, (struct hip_common *) concat_of_leaves,
                            len_concat_of_leaves,
                            hmac.hmac_data), -EFAULT,
             "Error while building HMAC\n");

    err = hip_build_param(msg, &hmac);
out_err:
    return err;
}

int signaling_build_param_selective_hmac2(struct hip_common *msg,
                                          struct hip_crypto_key *key,
                                          struct hip_host_id *host_id)
{
    struct hip_hmac    hmac2;
    struct hip_common *msg_copy         = NULL;
    int                err              = 0;
    unsigned char     *concat_of_leaves = NULL;
    unsigned int       len_concat_of_leaves;


    HIP_IFEL(!(msg_copy = hip_msg_alloc()), -ENOMEM, "Message alloc\n");

    HIP_IFEL(hip_create_msg_pseudo_hmac2(msg, msg_copy, host_id), -1,
             "pseudo hmac pkt failed\n");
    HIP_IFEL(signaling_build_hash_tree_from_msg(msg_copy, &concat_of_leaves, &len_concat_of_leaves), -1,
             "Could not build hash tree from message\n");

    hip_set_param_type((struct hip_tlv_common *) &hmac2, HIP_PARAM_SIGNALING_SELECTIVE_HMAC);
    hip_calc_generic_param_len((struct hip_tlv_common *) &hmac2,
                               sizeof(struct hip_hmac),
                               0);

    HIP_IFEL(hip_write_hmac(HIP_DIGEST_SHA1_HMAC, key->key, concat_of_leaves,
                            len_concat_of_leaves,
                            hmac2.hmac_data),
             -EFAULT,
             "Error while building HMAC\n");

    err = hip_build_param(msg, &hmac2);
out_err:
    free(msg_copy);
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

int signaling_build_hip_packet_from_hip_encrypted_param(UNUSED struct hip_common *common,
                                                        struct hip_common **msg_buf,
                                                        const struct hip_encrypted_aes_sha1 *param,
                                                        unsigned char *symm_key,
                                                        UNUSED uint8_t *symm_key_len,
                                                        UNUSED unsigned char *symm_key_hint,
                                                        UNUSED uint8_t *algo)
{
    int                            err           = 0;
    const char                    *enc_in_msg    = NULL;
    unsigned char                 *iv            = NULL;
    struct hip_encrypted_aes_sha1 *tmp_enc_param = NULL;
    uint8_t                       *tmp_ptr       = NULL;
    uint16_t                       tmp_len       = 0;
    char                          *data          = NULL;
    int                            data_len      = 0;

    enc_in_msg = (const char *) param;
    HIP_ASSERT(enc_in_msg);
    tmp_enc_param = malloc(hip_get_param_total_len(enc_in_msg));
    memcpy(tmp_enc_param, enc_in_msg, hip_get_param_total_len(enc_in_msg));

    iv      = ((struct hip_encrypted_aes_sha1 *) tmp_enc_param)->iv;
    tmp_ptr = (uint8_t *) tmp_enc_param;
    data    = (char *) (tmp_ptr + sizeof(struct hip_encrypted_aes_sha1));

    /*4 = reserved, 16 = IV*/
    data_len = hip_get_param_contents_len(tmp_enc_param) - 4 - 16;

    HIP_DEBUG("Found HIP suite ID " \
              "'AES-CBC with HMAC-SHA1'.\n");
    HIP_HEXDUMP("Encrypted data = ", data, data_len);

    HIP_IFEL(hip_crypto_encrypted(data, iv, HIP_HIP_AES_SHA1, data_len,
                                  (uint8_t *) symm_key,
                                  HIP_DIRECTION_DECRYPT),
             -1,
             "Failed to decrypt the HOST_ID parameter. Dropping\n");

    HIP_HEXDUMP("Decrypted data = ", data, data_len);

    tmp_len = hip_get_msg_total_len(*msg_buf);
    tmp_ptr = (uint8_t *) *msg_buf;
    HIP_DEBUG("Total message length before adding the decrypted data = %d\n", tmp_len);
    if (tmp_len > sizeof(struct hip_common)) {
        tmp_ptr += tmp_len;
    } else {
        tmp_ptr += sizeof(struct hip_common) + tmp_len;
    }
    hip_set_msg_total_len(*msg_buf, sizeof(struct hip_common) + tmp_len + data_len);
    memcpy(tmp_ptr, data, data_len);

out_err:
    return err;
}

static int signaling_get_param_type_from_info_req(uint8_t info)
{
    HIP_DEBUG("Getting parameter for info type = %u\n", info);
    switch (info) {
    case HOST_INFO_OS:
        return HIP_PARAM_SIGNALING_HOST_INFO_OS;
        break;
    case HOST_INFO_KERNEL:
        return HIP_PARAM_SIGNALING_HOST_INFO_KERNEL;
        break;
    case HOST_INFO_ID:
        return HIP_PARAM_SIGNALING_HOST_INFO_ID;
        break;
    case HOST_INFO_CERTS:
        return HIP_PARAM_SIGNALING_HOST_INFO_CERTS;
        break;

    case USER_INFO_ID:
        return HIP_PARAM_SIGNALING_USER_INFO_ID;
        break;
    case USER_INFO_CERTS:
        return HIP_PARAM_SIGNALING_USER_INFO_CERTS;
        break;

    case APP_INFO_NAME:
        return HIP_PARAM_SIGNALING_APP_INFO_NAME;
        break;
    case APP_INFO_QOS_CLASS:
        return HIP_PARAM_SIGNALING_APP_INFO_QOS_CLASS;
        break;
    case APP_INFO_REQUIREMENTS:
        return HIP_PARAM_SIGNALING_APP_INFO_REQUIREMENTS;
        break;
    case APP_INFO_CONNECTIONS:
        return HIP_PARAM_SIGNALING_APP_INFO_CONNECTIONS;
        break;
    }

    return -1;
}

int signaling_build_offset_list_to_remove_params(struct hip_common *msg,
                                                 int               *offset_list,
                                                 int               *offset_list_len,
                                                 uint8_t           *info_remove,
                                                 UNUSED uint8_t    *info_rem_len)
{
    int                    err        = 0, i = 0;
    int                    j          = *offset_list_len;
    struct hip_tlv_common *param      = NULL;
    uint8_t                tmp_info   = 0;
    uint16_t               param_type = 0;

    HIP_DEBUG("Offest list length = %d\n", j);
    for (i = 0; i < j; i++) {
        tmp_info   = info_remove[i];
        param_type = signaling_get_param_type_from_info_req(tmp_info);
        if ((param = hip_get_param_readwrite(msg, param_type))) {
            HIP_DEBUG("Signed Ack received corresponding to the service offer.\n");
            do {
                if (hip_get_param_type(param) == param_type) {
                    offset_list[i] = (uint8_t *) param - (uint8_t *) msg;
                    HIP_DEBUG("Offset for param = %u is %d\n", signaling_get_param_type_from_info_req(tmp_info), offset_list[i]);
                }
            } while ((param = hip_get_next_param_readwrite(msg, param)));
        }
    }

//out_err:
    return err;
}

int signaling_remove_params_from_hip_msg(struct hip_common *msg,
                                         int               *offset_list,
                                         int               *offset_list_len)
{
    int                    err         = 0;
    struct hip_common     *msg_buf     = NULL;
    struct hip_tlv_common *param       = NULL;
    int                    msg_new_len = hip_get_msg_total_len(msg);
    uint8_t               *tmp_ptr     = NULL;
    uint8_t               *start_ptr   = NULL;
    uint16_t               tmp_len     = 0;
    int                    i           = 0;

    uint8_t params_removed[20] = { 0, 0, 0, 0, 0,
                                   0, 0, 0, 0, 0,
                                   0, 0, 0, 0, 0,
                                   0, 0, 0, 0, 0 };

    if (!(msg_buf = hip_msg_alloc())) {
        HIP_ERROR("Out of memory while allocation memory for the temp hip packet\n");
        return -1;
    }
    //HIP_DEBUG("Inside remove params from hip msg\n");

    memcpy(msg_buf, msg, hip_get_msg_total_len(msg));
    //HIP_DEBUG("Original hip msg copied\n");
    tmp_ptr   = (uint8_t *) msg;
    start_ptr = (uint8_t *) msg_buf;
    tmp_len   = offset_list[0];

    for (i = 0; i <= *offset_list_len; i++) {
        memcpy(tmp_ptr, start_ptr, tmp_len);
        //HIP_DEBUG("i = %d, tmp_len = %u, copied portion of the new message\n", i, tmp_len);
        tmp_ptr   += tmp_len;
        start_ptr += tmp_len;

        if (i < *offset_list_len) {
            param = (struct hip_tlv_common *) ((uint8_t *) msg_buf + offset_list[i]);
            //HIP_DEBUG("parameter correct at this positon\n");
            tmp_len      = hip_get_param_total_len(param);
            msg_new_len -= tmp_len;
            start_ptr   += tmp_len;
            //HIP_DEBUG("Length of the parameter at this position = %d, new hip msg length = %d\n", tmp_len, msg_new_len);
            if (i < *offset_list_len - 1) {
                HIP_DEBUG("next offset = %d\n", offset_list[i + 1]);
                tmp_len = offset_list[i + 1] - (offset_list[i] + tmp_len);
            } else {
                tmp_len = hip_get_msg_total_len(msg_buf) - (offset_list[i] + tmp_len);
            }
            //HIP_DEBUG("Sizeof of the next chunk to be copied = %u\n", tmp_len);
        }
    }
    hip_set_msg_total_len(msg, msg_new_len);
/*
 *  HIP_DEBUG("HIP message after removal of secrets and ack msg_len = %d\n", msg_new_len);
 *  hip_dump_msg(msg);
 */

    param = NULL;
    while ((param = hip_get_next_param_readwrite(msg_buf, param))) {
        if (hip_get_param_type(param) == HIP_PARAM_SELECTIVE_HASH_LEAF) {
            int idx = ntohs(((struct siganling_param_selective_hash_leaf *) param)->leaf_pos);
            params_removed[idx] = 1;
        }
    }

    tmp_ptr = (uint8_t *) msg_buf;
    i       = 1;
    int j = 0;
    param = NULL;
    while (i < 20) {
        if (params_removed[i]) {
            i++;
            continue;
        } else if ((param = hip_get_next_param_readwrite(msg_buf, param)) &&
                   j < *offset_list_len &&
                   ((uint8_t *) param - (uint8_t *) msg_buf) == offset_list[j]) {
            j++;
            HIP_DEBUG("Position of the parameter to be removed i = %d\n", i);
            struct siganling_param_selective_hash_leaf tmp_leaf = { 0 };
            tmp_leaf.leaf_pos      = htons(i);
            tmp_leaf.len_param_rem = htons(hip_get_param_total_len(param));
            HIP_IFEL(hip_build_digest(HIP_DIGEST_SHA1, param, hip_get_param_total_len(param), tmp_leaf.leaf_hash) < 0,
                     -1, "Building of SHA1 digest failed\n");
            hip_set_param_contents_len((struct hip_tlv_common *) &tmp_leaf, sizeof(struct siganling_param_selective_hash_leaf) - sizeof(struct hip_tlv_common));
            hip_set_param_type((struct hip_tlv_common *) &tmp_leaf, HIP_PARAM_SELECTIVE_HASH_LEAF);
            HIP_IFEL(hip_build_param(msg, (struct hip_tlv_common *) &tmp_leaf),
                     -1, "Failed to append appinfo parameter to message.\n");
        }
        i++;
    }
/*
 *  HIP_DEBUG("HIP message after addition of hash leafs\n");
 *  hip_dump_msg(msg);
 *
 */
out_err:
    free(msg_buf);
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
    int                    err        = -1;
    const struct hip_seq  *param_seq  = NULL;
    const struct hip_ack  *param_ack  = NULL;
    const struct hip_cert *param_cert = NULL;
    //const struct signaling_param_user_auth_request *param_usr_auth_req = NULL;
    const struct signaling_param_cert_chain_id *param_cer_chain_id = NULL;

    //TODO check for the parameters to be put here
    param_seq  = hip_get_param(msg, HIP_PARAM_SEQ);
    param_ack  = hip_get_param(msg, HIP_PARAM_ACK);
    param_cert = hip_get_param(msg, HIP_PARAM_CERT);
    //param_usr_auth_req = hip_get_param(msg, HIP_PARAM_SIGNALING_USER_INFO_CERTS);
    param_cer_chain_id = hip_get_param(msg, HIP_PARAM_SIGNALING_CERT_CHAIN_ID);

    if (param_seq && !param_ack) {
        return SIGNALING_FIRST_BEX_UPDATE;
    } else if (param_seq && param_ack) {
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
    HIP_DEBUG("Start PERF_I_USER_CTX_LOOKUP, PERF_R_USER_CTX_LOOKUP, "
              "PERF_CONN_U_I_USER_CTX_LOOKUP, PERF_CONN_U_R_USER_CTX_LOOKUP\n");               // test 1.1
    hip_perf_start_benchmark(perf_set, PERF_I_USER_CTX_LOOKUP);
    hip_perf_start_benchmark(perf_set, PERF_R_USER_CTX_LOOKUP);
    hip_perf_start_benchmark(perf_set, PERF_CONN_U_I_USER_CTX_LOOKUP);
    hip_perf_start_benchmark(perf_set, PERF_CONN_U_R_USER_CTX_LOOKUP);
#endif

    HIP_IFEL(signaling_user_api_get_uname(ctx->user.uid, &ctx->user), -1, "Could not get user name, assuming ANY USER. \n");
    if (ctx->user.key_rr_len <= 0) {
        HIP_IFEL(!(user_pkey = signaling_user_api_get_user_public_key(ctx->user.uid)),
                 -1, "Could not obtain users public key \n");
        //PEM_write_PUBKEY(stdout, user_pkey);
        HIP_IFEL((ctx->user.key_rr_len = any_key_to_key_rr(user_pkey, &ctx->user.rdata.algorithm, &key_rr)) < 0,
                 -1, "Could not serialize key \n");
        HIP_DEBUG("GOT key rr of length %d\n", ctx->user.key_rr_len);
        memcpy(ctx->user.pkey, key_rr, ctx->user.key_rr_len);

        // necessary because any_key_to_rr returns only the length of the key rrwithout the header
        ctx->user.key_rr_len += sizeof(struct hip_host_id_key_rdata);
        free(key_rr);
    }

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop PERF_I_USER_CTX_LOOKUP, PERF_R_USER_CTX_LOOKUP, "
              "PERF_CONN_U_I_USER_CTX_LOOKUP, PERF_CONN_U_R_USER_CTX_LOOKUP\n");              // test 1.1
    hip_perf_stop_benchmark(perf_set, PERF_I_USER_CTX_LOOKUP);
    hip_perf_stop_benchmark(perf_set, PERF_R_USER_CTX_LOOKUP);
    hip_perf_stop_benchmark(perf_set, PERF_CONN_U_I_USER_CTX_LOOKUP);
    hip_perf_stop_benchmark(perf_set, PERF_CONN_U_R_USER_CTX_LOOKUP);
#endif
    return 0;
out_err:
    return err;
}

X509 *signaling_get_mbox_cert_from_offer_id(struct signaling_hipd_state *sig_state, uint16_t service_offer_id)
{
    int i = 0;
    for (i = 0; sig_state->mb_certs[i] != NULL; i++) {
        if (sig_state->mb_certs[i]->service_offer_id == service_offer_id) {
            return sig_state->mb_certs[i]->mb_certificate;
        }
    }
    return NULL;
}

int signaling_check_if_user_info_req(struct hip_packet_context *ctx)
{
    int                                  err                = 0;
    int                                  num_req_info_items = 0;
    int                                  i                  = 0;
    const struct hip_tlv_common         *param;
    struct signaling_param_service_offer param_service_offer_u;
    //struct signaling_param_service_offer_s param_service_offer_s;
    uint16_t tmp_info;

    if ((param = hip_get_param(ctx->input_msg, HIP_PARAM_SIGNALING_SERVICE_OFFER))) {
        do {
            if (hip_get_param_type(param) == HIP_PARAM_SIGNALING_SERVICE_OFFER) {
                HIP_IFEL(signaling_copy_service_offer(&param_service_offer_u, (const struct signaling_param_service_offer *) (param)),
                         -1, "Could not copy connection context\n");
                num_req_info_items = (hip_get_param_contents_len(&param_service_offer_u) -
                                      (sizeof(param_service_offer_u.service_offer_id) +
                                       sizeof(param_service_offer_u.service_type) +
                                       sizeof(param_service_offer_u.service_description))) / sizeof(uint16_t);
                while (i < num_req_info_items) {
                    tmp_info = ntohs(param_service_offer_u.endpoint_info_req[i]);
                    if (tmp_info == USER_INFO_ID || tmp_info == USER_INFO_CERTS) {
                        return 1;
                    }
                    i++;
                }
            }
        } while ((param = hip_get_next_param(ctx->input_msg, param)));
    }
    HIP_DEBUG("No need for the user to sign this packet as no USER INFO request\n");
    return 0;

out_err:
    return err;
}

int signaling_check_if_app_or_user_info_req(struct hip_packet_context *ctx)
{
    int                                  err                = 0;
    int                                  num_req_info_items = 0;
    int                                  i                  = 0;
    const struct hip_tlv_common         *param;
    struct signaling_param_service_offer param_service_offer;
    uint16_t                             tmp_info;

    if ((param = hip_get_param(ctx->input_msg, HIP_PARAM_SIGNALING_SERVICE_OFFER))) {
        do {
            if (hip_get_param_type(param) == HIP_PARAM_SIGNALING_SERVICE_OFFER) {
                HIP_IFEL(signaling_copy_service_offer(&param_service_offer, (const struct signaling_param_service_offer *) (param)),
                         -1, "Could not copy connection context\n");
                num_req_info_items = param_service_offer.service_info_len;
                while (i < num_req_info_items) {
                    tmp_info = param_service_offer.endpoint_info_req[i];
                    if (tmp_info == APP_INFO_NAME || tmp_info == APP_INFO_QOS_CLASS ||
                        tmp_info == APP_INFO_REQUIREMENTS || tmp_info == APP_INFO_CONNECTIONS ||
                        tmp_info == USER_INFO_ID || tmp_info == USER_INFO_CERTS) {
                        return 1;
                    }
                    i++;
                }
            }
        } while ((param = hip_get_next_param(ctx->input_msg, param)));
    }
    return 0;

out_err:
    return err;
}

/* FIXME This check seems too complicated!
 *       It may be worth adding a field to an offer that indicates the type
 *       (unauthed, signature-authed, DH-authed) and use this field here. */
int signaling_check_service_offer_type(const struct signaling_param_service_offer *param_service_offer)
{
    HIP_ASSERT(param_service_offer);
    return param_service_offer->service_type;
}

int signaling_check_if_service_ack_signed(const struct signaling_param_service_ack *param_service_ack)
{
    uint16_t tmp_len;

    tmp_len = (sizeof(param_service_ack->service_offer_id) + sizeof(param_service_ack->service_option) +
               sizeof(param_service_ack->service_offer_hash));

    if (ntohs(param_service_ack->service_option) != 0 &&
        hip_get_param_contents_len((const struct tlv_common *) param_service_ack) > tmp_len) {
        return 1;
    } else {
        return 0;
    }
}

int signaling_check_if_mb_certificate_available(struct signaling_hipd_state *sig_state,
                                                struct signaling_param_service_offer *offer)
{
    int           err        = 0, i = 0;
    int           header_len = 0;
    int           info_len   = 0;
    unsigned char certificate_hint[HIP_AH_SHA_LEN];
    uint16_t      cert_hint_len = 0;
    uint8_t      *tmp_ptr       = (uint8_t *) offer;

    const char *dir_path       = "/usr/local/etc/hip/trusted_mb_certs";
    X509       *mb_certificate = NULL;

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_I2_LOCATE_MBOX_CERT, PERF_R2_LOCATE_MBOX_CERT, "
              "PERF_CONN_U1_LOCATE_MBOX_CERT, PERF_CONN_U2_LOCATE_MBOX_CERT\n");
    hip_perf_start_benchmark(perf_set, PERF_I2_LOCATE_MBOX_CERT);
    hip_perf_start_benchmark(perf_set, PERF_R2_LOCATE_MBOX_CERT);
    hip_perf_start_benchmark(perf_set, PERF_CONN_U1_LOCATE_MBOX_CERT);
    hip_perf_start_benchmark(perf_set, PERF_CONN_U2_LOCATE_MBOX_CERT);
#endif
    header_len = sizeof(struct hip_tlv_common) + sizeof(offer->service_offer_id) +
                 sizeof(offer->service_type) + sizeof(offer->service_info_len) +
                 sizeof(offer->service_description);
    cert_hint_len = HIP_AH_SHA_LEN;
    info_len      = offer->service_info_len * sizeof(uint8_t);


    tmp_ptr += (header_len + info_len);
    memcpy(certificate_hint, tmp_ptr, HIP_AH_SHA_LEN);
    HIP_HEXDUMP("Received certificate hint = ", certificate_hint, HIP_AH_SHA_LEN);
    tmp_ptr += HIP_AH_SHA_LEN;

    /* ========== Locate the mbox certificate from store and load the certificate into memory ===============*/
    HIP_IFEL(signaling_locate_mb_certificate(&mb_certificate, dir_path, certificate_hint, cert_hint_len),
             -1, "Could not locate Middlebox certificate\n");

    for (i = 0; i < 10; i++) {
        if (sig_state->mb_certs[i] == NULL) {
            break;
        }
    }

    if (mb_certificate) {
        sig_state->mb_certs[i]                   = malloc(sizeof(struct mbox_certificates));
        sig_state->mb_certs[i]->mb_certificate   = mb_certificate;
        sig_state->mb_certs[i]->service_offer_id = ntohs(offer->service_offer_id);
        err                                      = 1;
    } else {
        err = 0;
    }
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop PERF_I2_LOCATE_MBOX_CERT, PERF_R2_LOCATE_MBOX_CERT, "
              "PERF_CONN_U1_LOCATE_MBOX_CERT, PERF_CONN_U2_LOCATE_MBOX_CERT\n");
    hip_perf_stop_benchmark(perf_set, PERF_I2_LOCATE_MBOX_CERT);
    hip_perf_stop_benchmark(perf_set, PERF_R2_LOCATE_MBOX_CERT);
    hip_perf_stop_benchmark(perf_set, PERF_CONN_U1_LOCATE_MBOX_CERT);
    hip_perf_stop_benchmark(perf_set, PERF_CONN_U2_LOCATE_MBOX_CERT);
#endif
out_err:
    return err;
}

int signaling_check_if_offer_in_nack_list(struct signaling_hipd_state *sig_state, uint16_t service_offer_id)
{
    int err = 0, i = 0;

    for (i = 0; i < 10; i++) {
        if (sig_state->service_nack[i] == service_offer_id) {
            return 1;
        }
    }

//out_err:
    return err;
}

int signaling_hip_rsa_selective_sign(void *const priv_key, struct hip_common *const msg)
{
    RSA         *rsa = priv_key;
    uint8_t      sha1_digest[HIP_AH_SHA_LEN];
    uint8_t     *signature = NULL;
    int          err       = 0, len;
    unsigned int sig_len;

    len = hip_get_msg_total_len(msg);

    HIP_IFEL(signaling_build_hash_tree_and_get_root(msg, (unsigned char *) sha1_digest), -1,
             "Building of the sha1 digest from hash-tree failed");

    HIP_DEBUG("Build hash from the root of the hash tree\n");
    len       = RSA_size(rsa);
    signature = calloc(1, len);
    HIP_IFEL(!signature, -1, "Malloc for signature failed.");
    /* RSA_sign returns 0 on failure */
    HIP_IFEL(!RSA_sign(NID_sha1, sha1_digest, SHA_DIGEST_LENGTH, signature,
                       &sig_len, rsa), -1, "Signing error\n");

    HIP_IFEL(signaling_hip_build_param_selective_sign(msg, signature, len, HIP_SIG_RSA),
             -1, "Building of signature failed\n");

out_err:
    free(signature);
    return err;
}

/**
 * Sign a HIP control message with a private ECDSA key.
 *
 * @param priv_key the ECDSA private key of the local host
 * @param msg The HIP control message to sign. The signature
 *            is appended as a parameter to the message.
 * @return zero on success and negative on error
 * @note the order of parameters is significant so this function
 *       must be called at the right time of building of the parameters
 */
int signaling_hip_ecdsa_selective_sign(void *const priv_key, struct hip_common *const msg)
{
    EC_KEY *ecdsa = priv_key;
    uint8_t sha1_digest[HIP_AH_SHA_LEN];
    int     siglen = ECDSA_size(ecdsa);
    uint8_t signature[siglen];

    if (!msg) {
        HIP_ERROR("NULL message\n");
        return -1;
    }
    if (!priv_key) {
        HIP_ERROR("NULL signing key\n");
        return -1;
    }

    if (!priv_key) {
        HIP_ERROR("Need key for signing \n");
        return -1;
    }
    if (!msg) {
        HIP_ERROR("Need message to sign \n");
        return -1;
    }

    if (signaling_build_hash_tree_and_get_root(msg, (unsigned char *) sha1_digest) < 0) {
        HIP_ERROR("Building of the sha1 digest from hash-tree failed.\n");
        return -1;
    }

    if (impl_ecdsa_sign(sha1_digest, ecdsa, signature)) {
        HIP_ERROR("Signing error\n");
        return -1;
    }

    HIP_HEXDUMP("ECDSA signature = ", signature, siglen);
    if (signaling_hip_build_param_selective_sign(msg, signature, siglen, HIP_SIG_ECDSA)) {
        HIP_ERROR("Building of signature failed\n");
        return -1;
    }

    return 0;
}

/**
 * sign a HIP control message with a private DSA key
 *
 * @param priv_key the DSA private key of the local host
 * @param msg The HIP control message to sign. The signature
 *            is appended as a parameter to the message.
 * @return zero on success and negative on error
 * @note the order of parameters is significant so this function
 *       must be called at the right time of building of the parameters
 */
int signaling_hip_dsa_selective_sign(void *const priv_key, struct hip_common *const msg)
{
    DSA *const dsa = priv_key;
    uint8_t    sha1_digest[HIP_AH_SHA_LEN];
    uint8_t    signature[HIP_DSA_SIGNATURE_LEN];
    int        err = 0;

    HIP_IFEL(signaling_build_hash_tree_and_get_root(msg, (unsigned char *) sha1_digest), -1,
             "Building of the sha1 digest from hash-tree failed");

    HIP_IFEL(impl_dsa_sign(sha1_digest, dsa, signature),
             -1, "Signing error\n");

    HIP_IFEL(signaling_hip_build_param_selective_sign(msg, signature,
                                                      HIP_DSA_SIGNATURE_LEN,
                                                      HIP_SIG_DSA),
             -1, "Building of signature failed\n");

out_err:
    return err;
}

/**
 * Generic signature verification function for DSA and RSA.
 *
 * @param peer_pub public key of the peer
 * @param msg a HIP control message containing a signature parameter to
 *            be verified
 * @param type HIP_HI_RSA, HIP_HI_DSA or HIP_HI_ECDSA
 * @return zero on success and non-zero on failure
 */
static int verify(void *const peer_pub, struct hip_common *const msg, const int type)
{
    int                err = 0, len, origlen = 0;
    struct hip_sig    *sig;
    uint8_t            sha1_digest[HIP_AH_SHA_LEN];
    struct in6_addr    tmpaddr;
    struct hip_puzzle *pz = NULL;
    uint8_t            opaque[HIP_PUZZLE_OPAQUE_LEN];
    uint8_t            rand_i[PUZZLE_LENGTH];

    HIP_IFEL(!peer_pub, -1, "NULL public key\n");
    HIP_IFEL(!msg, -1, "NULL message\n");

    ipv6_addr_copy(&tmpaddr, &msg->hitr);     /* so update is handled, too */

    origlen = hip_get_msg_total_len(msg);

    HIP_IFEL(!(sig = hip_get_param_readwrite(msg, HIP_PARAM_SIGNALING_SELECTIVE_SIGNATURE)),
             -ENOENT, "Could not find signature\n");

    len = ((uint8_t *) sig) - ((uint8_t *) msg);
    hip_zero_msg_checksum(msg);
    HIP_IFEL(len < 0, -ENOENT, "Invalid signature len\n");
    //hip_set_msg_total_len(msg, len);

    HIP_IFEL(signaling_build_hash_tree_and_get_root(msg, (unsigned char *) sha1_digest), -1,
             "Building of the sha1 digest from hash-tree failed");
    if (type == HIP_HI_RSA) {
        /* RSA_verify returns 0 on failure */
        err = !RSA_verify(NID_sha1, sha1_digest, SHA_DIGEST_LENGTH,
                          sig->signature, RSA_size(peer_pub), peer_pub);
    } else if (type == HIP_HI_ECDSA) {
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Start PERF_ECDSA_VERIFY_IMPL\n");
        hip_perf_start_benchmark(perf_set, PERF_ECDSA_VERIFY_IMPL);
#endif
        err = impl_ecdsa_verify(sha1_digest, peer_pub, sig->signature);
    } else {
        err = impl_dsa_verify(sha1_digest, peer_pub, sig->signature);
    }

    if (hip_get_msg_type(msg) == HIP_R1) {
        memcpy(pz->opaque, opaque, HIP_PUZZLE_OPAQUE_LEN);
        memcpy(pz->I, rand_i, PUZZLE_LENGTH);
    }

    ipv6_addr_copy(&msg->hitr, &tmpaddr);

    if (err) {
        err = -1;
    }

out_err:
    if (msg) {
        hip_set_msg_total_len(msg, origlen);
    }
    return err;
}

/**
 * Verify the ECDSA signature from a message.
 *
 * @param peer_pub public key of the peer
 * @param msg a HIP control message containing a signature parameter to
 *            be verified
 * @return zero on success and non-zero on failure
 */
int signaling_hip_ecdsa_selective_verify(void *const peer_pub, struct hip_common *const msg)
{
    return verify(peer_pub, msg, HIP_HI_ECDSA);
}

/**
 * RSA signature verification function
 *
 * @param peer_pub public key of the peer
 * @param msg a HIP control message containing a signature parameter to
 *            be verified
 * @return zero on success and non-zero on failure
 */
int signaling_hip_rsa_selective_verify(void *const peer_pub, struct hip_common *const msg)
{
    return verify(peer_pub, msg, HIP_HI_RSA);
}

/**
 * DSA signature verification function
 *
 * @param peer_pub public key of the peer
 * @param msg a HIP control message containing a signature parameter to
 *            be verified
 * @return zero on success and non-zero on failure
 */
int signaling_hip_dsa_selective_verify(void *const peer_pub, struct hip_common *const msg)
{
    return verify(peer_pub, msg, HIP_HI_DSA);
}

// For our implementation we will consider all the service offers of same type
// No mixing of service offers
int signaling_hip_msg_contains_signed_service_offer(struct hip_common *msg)
{
    const struct hip_tlv_common *param = NULL;
    if ((param = hip_get_param(msg, HIP_PARAM_SIGNALING_SERVICE_OFFER))) {
        do {
            return signaling_check_service_offer_type((const struct signaling_param_service_offer *) (param));
        } while ((param = hip_get_next_param(msg, param)));
    }
    return -1; // No service offers present
}

int signaling_split_info_req_to_groups(struct signaling_hipd_state *sig_state,
                                       struct service_offer_groups *offer_groups,
                                       struct hip_packet_context *ctx)
{
    int                                  err                = 0, i = 0, idx = 0;
    int                                  j                  = 0;
    int                                  num_req_info_items = 0;
    uint8_t                              tmp_info           = 0;
    const struct hip_tlv_common         *param              = NULL;
    struct signaling_param_service_offer param_service_offer;

    if ((param = hip_get_param(ctx->input_msg, HIP_PARAM_SIGNALING_SERVICE_OFFER))) {
        do {
            if (hip_get_param_type(param) == HIP_PARAM_SIGNALING_SERVICE_OFFER) {
                HIP_IFEL(signaling_copy_service_offer(&param_service_offer, (const struct signaling_param_service_offer *) (param)),
                         -1, "Could not copy connection context\n");
                i = 0;
                if (signaling_check_service_offer_type(&param_service_offer) == OFFER_SIGNED ||
                    signaling_check_service_offer_type(&param_service_offer) == OFFER_SELECTIVE_SIGNED) {
                    if (signaling_check_if_mb_certificate_available(sig_state, &param_service_offer)) {
                        num_req_info_items = param_service_offer.service_info_len;
                        /* number of service offers to be accepted, if more than the limit drop it */
                        if (num_req_info_items > 0) {
                            HIP_DEBUG("Number of parameters received in the Service Offer = %d.\n", num_req_info_items);
                            /*Processing the information requests in the service offer*/
                            while ((i < num_req_info_items) && ((tmp_info = param_service_offer.endpoint_info_req[i]) != 0)) {
                                j = tmp_info;
                                for (idx = 0; idx < MAX_NUM_OFFER_GROUPS; idx++) {
                                    if (offer_groups[j].mbox[idx] ==  0) {
                                        break;
                                    }
                                }
                                offer_groups[j].info_requests[0] = tmp_info;
                                offer_groups[j].num_info_req     = 1;
                                offer_groups[j].mbox[idx]        = ntohs(param_service_offer.service_offer_id);
                                offer_groups[j].num_mboxes       = idx + 1;
                                i++;
                            }
                        }
                    } else {
                        signaling_add_offer_to_nack_list(sig_state, ntohs(param_service_offer.service_offer_id));
                    }
                }
            }
        } while ((param = hip_get_next_param(ctx->input_msg, param)));
    }

out_err:
    return err;
}

int signaling_merge_info_req_to_similar_groups(struct service_offer_groups *offer_groups,
                                               struct signaling_hipd_state *sig_state)
{
    int                         err            = 0, i = 0, idx = 0;
    int                         j              = 0, k = 0;
    struct service_offer_groups temp_offer_grp = { { 0 } };

    uint8_t found                                = 0;
    uint8_t entries_merged[MAX_NUM_OFFER_GROUPS] = {  0, 0, 0, 0, 0,
                                                      0, 0, 0, 0, 0 };

    i = 0;
    int m = 0;
    for (k = 0; k < MAX_NUM_OFFER_GROUPS; k++) {
        if (offer_groups[k].info_requests[0] != 0 && offer_groups[k].num_mboxes > 0 && offer_groups[k].num_info_req > 0 && !entries_merged[k]) {
            idx = 0;
            if (sig_state->offer_groups[i] == NULL) {
                sig_state->offer_groups[i] = malloc(sizeof(struct service_offer_groups));
                memcpy(sig_state->offer_groups[i], &temp_offer_grp, sizeof(struct service_offer_groups));

                sig_state->offer_groups[i]->info_requests[idx] = offer_groups[k].info_requests[idx];
                sig_state->offer_groups[i]->num_info_req       = offer_groups[k].num_info_req;
                for (m = 0; m < offer_groups[k].num_mboxes; m++) {
                    sig_state->offer_groups[i]->mbox[m] = offer_groups[k].mbox[m];
                }
                sig_state->offer_groups[i]->num_mboxes = offer_groups[k].num_mboxes;
                idx++;
            }
            //Assumption here if all goes well then the entries before should already have been merged
            for (j = k; j < MAX_NUM_OFFER_GROUPS; j++) {
                if (j != k && (offer_groups[j].num_mboxes == offer_groups[k].num_mboxes) && !entries_merged[j]) {
                    found = 1;
                    HIP_DEBUG("Finding an entry j = %d, k = %d\n", j, k);
                    /* The underlying assumption for this to work is mboxes are added in the same order as the service offers are received*/
                    for (m = 0; m < offer_groups[k].num_mboxes; m++) {
                        if (offer_groups[j].mbox[m] != offer_groups[k].mbox[m]) {
                            found = 0;
                            break;
                        }
                    }
                    // Now merge
                    if (found) {
                        HIP_DEBUG("Found an entry j = %d\n", j);
                        entries_merged[j] = 1;
                        if (sig_state->offer_groups[i] != NULL) {
                            sig_state->offer_groups[i]->info_requests[idx] = offer_groups[j].info_requests[0];
                            sig_state->offer_groups[i]->num_info_req       = ++idx;
                        }
                    }
                }
            }
            i++;
        }
    }

    return err;
}

int signaling_remove_list_info_req(struct service_offer_groups *offer_groups,
                                   struct signaling_hipd_state *sig_state)
{
    int                         err            = 0, i = 0;
    int                         k              = 0, found = 0;
    struct service_offer_groups temp_offer_grp = { { 0 } };

    for (k = 0; k < MAX_NUM_OFFER_GROUPS; k++) {
        if (offer_groups[k].info_requests[0] != 0 && offer_groups[k].mbox[0] != 0 &&
            offer_groups[k].num_mboxes == 1 && offer_groups[k].num_info_req == 1) {
            found = 0;
            for (i = 0; i < MAX_NUM_OFFER_GROUPS && sig_state->offer_groups[i] != NULL; i++) {
                if (sig_state->offer_groups[i]->mbox[0] == offer_groups[k].mbox[0]) {
                    found                                                                   = 1;
                    sig_state->offer_groups[i]->info_requests[offer_groups[k].num_info_req] = offer_groups[k].info_requests[0];
                    sig_state->offer_groups[i]->num_info_req++;
                    break;
                }
            }
            if (i < MAX_NUM_OFFER_GROUPS && sig_state->offer_groups[i] == NULL && !found) {
                sig_state->offer_groups[i] = malloc(sizeof(struct service_offer_groups));
                memcpy(sig_state->offer_groups[i], &temp_offer_grp, sizeof(struct service_offer_groups));

                sig_state->offer_groups[i]->info_requests[0] = offer_groups[k].info_requests[0];
                sig_state->offer_groups[i]->mbox[0]          = offer_groups[k].mbox[0];
                sig_state->offer_groups[i]->num_info_req     = offer_groups[k].num_info_req;
                sig_state->offer_groups[i]->num_mboxes       = offer_groups[k].num_mboxes;
            }
        }
    }
    return err;
}

int signaling_add_offer_to_nack_list(struct signaling_hipd_state *sig_state, uint16_t service_offer_id)
{
    int err = 0, i = 0;

    for (i = 0; i < 10; i++) {
        if (sig_state->service_nack[i] == 0) {
            break;
        }
    }
    sig_state->service_nack[i] = service_offer_id;

    return err;
}

/*
 * Concatenate two string to form a path
 *
 * @return the concatenated string
 */
char *signaling_concatenate_paths(const char *str1, char *str2)
{
    uint8_t str1_len = strlen(str1);
    uint8_t str2_len = strlen(str2);
    int     i, j;
    char   *result;

    result = malloc((str1_len + str2_len + 2) * sizeof(char));
    strcpy(result, str1);
    result[str1_len] = '/';
    for (i = str1_len + 1, j = 0; ((i < (str1_len + str2_len + 1)) && (j < str2_len)); i++, j++) {
        result[i] = str2[j];
    }
    result[str1_len + str2_len + 1] = '\0';
    return result;
}

/*
 * Get the Subject Key Identifier from the X509 certificate
 *
 * @return Subject Key Identifier
 */
unsigned char *signaling_extract_skey_ident_from_cert(X509 *cert, unsigned int *len)
{
    int                k               = 0;
    X509_EXTENSION    *tmp_x509_ext    = NULL;
    ASN1_OCTET_STRING *data            = NULL;
    unsigned char     *ext_data_buffer = NULL;


    /* The logic to get the subjectKeyIdentifier extension is not perfect */
    k            = X509_get_ext_by_NID(cert, NID_subject_key_identifier, -1);
    tmp_x509_ext = X509_get_ext(cert, k);
    if (tmp_x509_ext != NULL) {
        data =   X509_EXTENSION_get_data(tmp_x509_ext);
        if (data != NULL) {
            ext_data_buffer = ASN1_STRING_data(data);
        }
    }

    /* We have to leave the 2 bytes from the start for the Sub Key Identifier to be correct
     * Still no clue as to how to prevent this ugly hack
     */
    *len = ASN1_STRING_length(data) - 2;
    HIP_HEXDUMP("Extension Data = ", ext_data_buffer + 2, *len);
    return ext_data_buffer + 2;
}

int signaling_generate_shared_key_from_dh_shared_secret(uint8_t *shared_key,
                                                        int     *shared_key_length,
                                                        const uint8_t *peer_key,
                                                        const int peer_key_len)
{
    int     err = 0, tmp_len = 0;
    uint8_t sha1_digest[HIP_AH_SHA_LEN];

    tmp_len            = *shared_key_length;
    *shared_key_length = signaling_generate_shared_secret_from_mbox_dh(DH_GROUP_ID, peer_key, peer_key_len, shared_key, *shared_key_length);

    HIP_IFEL(hip_build_digest(HIP_DIGEST_SHA1, shared_key, *shared_key_length, sha1_digest),
             -1, "Could not build message digest \n");
    *shared_key_length = 16;
    memcpy(shared_key, sha1_digest, *shared_key_length);
    memset((shared_key + *shared_key_length), 0, tmp_len - *shared_key_length);
out_err:
    return err;
}

int signaling_generate_shared_secret_from_mbox_dh(const int groupid, const uint8_t *peer_key, size_t peer_len,
                                                  uint8_t *dh_shared_key, size_t outlen)
{
    return hip_calculate_shared_secret(peer_key, groupid, peer_len, dh_shared_key, outlen);
}

/*
 *  Extract mbox key from
 */
/* Locate the middlebox keys from the trusted mbox certificate store
 *
 */
int signaling_locate_mb_certificate(X509 **mb_certificate, const char *dir_path, unsigned char *certificate_hint, uint16_t cert_hint_len)
{
    struct stat    filestat;
    struct dirent *dirp;
    // enter existing path to directory below
    DIR    *dp    = opendir(dir_path);
    uint8_t found = 0;

    if (dp != NULL) {
        while ((dirp = readdir(dp)) != NULL) {
            char          *filepath;
            unsigned char *tmp_cert_hint;
            unsigned int   tmp_cert_hint_len;
            filepath = signaling_concatenate_paths(dir_path, dirp->d_name);
            if (stat(filepath, &filestat)) {
                continue;
            }
            if (S_ISDIR(filestat.st_mode)) {
                continue;
            }
            //printf("Path %s\n", filepath);
            *mb_certificate = load_x509_certificate(filepath);
            tmp_cert_hint   = (uint8_t *) signaling_extract_skey_ident_from_cert(*mb_certificate, &tmp_cert_hint_len);
            if ((cert_hint_len == tmp_cert_hint_len) && !memcmp(tmp_cert_hint, certificate_hint, cert_hint_len)) {
                HIP_DEBUG("Found certificate in our store %s \n", filepath);
                found = 1;
                free(filepath);
                break;
            }

            free(filepath);
            filepath = NULL;
        }
        closedir(dp);
    }

    if (mb_certificate == NULL || !found) {
        return -1;
    } else {
        return 0;
    }
}

/* This generates a random 256 bit key using /dev/random. This key will used in HIP_ENCRYPTED param for encrypting the payload
 * @param key 256-bit to be stored in this
 * @param key_len length of the key generated
 *
 * @return return 0 on success, -1 otherwise
 */
int generate_key_for_hip_encrypt(unsigned char *key, int *key_len, unsigned char *key_hint)
{
    HIP_DEBUG("Reading 128 random bits for Symmetric key\n");
    get_random_bytes(key, 16);

    HIP_DEBUG("Reading 32 random bits for Key_hint\n");
    get_random_bytes(key_hint, 4);

    *key_len = 16;
    HIP_HEXDUMP("Symmetric Key: ", key, *key_len);
    HIP_HEXDUMP("Key Hint: ", key_hint, 4);
    return 0;
}
