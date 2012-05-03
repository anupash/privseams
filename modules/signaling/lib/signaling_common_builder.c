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
int signaling_build_param_user_signature(struct hip_common *msg, const uid_t uid)
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
    HIP_IFEL((sig_len = signaling_user_api_sign(uid, msg, in_len, signature_buf, sig_type)) < 0,
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
int signaling_add_service_offer_to_msg(struct hip_common *msg,
                                       struct signaling_connection_flags *flags,
                                       int service_offer_id,
                                       unsigned char *hash,
                                       UNUSED void   *mb_key,
                                       X509          *mb_cert,
                                       uint8_t        flag_sign)
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
    param_service_offer.service_offer_id = htons(service_offer_id);
    //TODO check for the following values to be assigned to the parameter types
    param_service_offer.service_description = htonl(0);
    param_service_offer.service_type        = htons(0);

    if (signaling_info_req_flag_check(&flags->flag_info_requests, HOST_INFO_OS)) {
        param_service_offer.endpoint_info_req[idx] = htons(HOST_INFO_OS);
        idx++;
    }
    if (signaling_info_req_flag_check(&flags->flag_info_requests, HOST_INFO_KERNEL)) {
        param_service_offer.endpoint_info_req[idx] = htons(HOST_INFO_KERNEL);
        idx++;
    }
    if (signaling_info_req_flag_check(&flags->flag_info_requests, HOST_INFO_ID)) {
        param_service_offer.endpoint_info_req[idx] = htons(HOST_INFO_ID);
        idx++;
    }
    if (signaling_info_req_flag_check(&flags->flag_info_requests, HOST_INFO_CERTS)) {
        param_service_offer.endpoint_info_req[idx] = htons(HOST_INFO_CERTS);
        idx++;
    }
    if (signaling_info_req_flag_check(&flags->flag_info_requests, USER_INFO_ID)) {
        param_service_offer.endpoint_info_req[idx] = htons(USER_INFO_ID);
        idx++;
    }
    if (signaling_info_req_flag_check(&flags->flag_info_requests, USER_INFO_CERTS)) {
        param_service_offer.endpoint_info_req[idx] = htons(USER_INFO_CERTS);
        idx++;
    }
    if (signaling_info_req_flag_check(&flags->flag_info_requests, APP_INFO_NAME)) {
        param_service_offer.endpoint_info_req[idx] = htons(APP_INFO_NAME);
        idx++;
    }
    if (signaling_info_req_flag_check(&flags->flag_info_requests, APP_INFO_CONNECTIONS)) {
        param_service_offer.endpoint_info_req[idx] = htons(APP_INFO_CONNECTIONS);
        idx++;
    }
    if (signaling_info_req_flag_check(&flags->flag_info_requests, APP_INFO_QOS_CLASS)) {
        param_service_offer.endpoint_info_req[idx] = htons(APP_INFO_QOS_CLASS);
        idx++;
    }
    if (signaling_info_req_flag_check(&flags->flag_info_requests, APP_INFO_REQUIREMENTS)) {
        param_service_offer.endpoint_info_req[idx] = htons(APP_INFO_REQUIREMENTS);
        idx++;
    }

    HIP_DEBUG("Number of Info Request Parameters in Service Offer = %d.\n", idx);

    /* Certificate hint if flag is set to create a signed service offer */
    if (flag_sign) {
        cert_hint = (uint8_t *) signaling_extract_skey_ident_from_cert(mb_cert, &cert_hint_len);
        memcpy(&param_service_offer.endpoint_info_req[idx], cert_hint, cert_hint_len);
        HIP_DEBUG("Certificate Hint copied\n");
        HIP_HEXDUMP("Certificate hint = ", cert_hint, HIP_AH_SHA_LEN);
    }

    len = sizeof(struct signaling_param_service_offer)
          - sizeof(uint16_t) * (MAX_NUM_INFO_ITEMS - idx) - sizeof(struct hip_tlv_common);

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
                                         X509          *mb_cert)
{
    int err        = 0;
    int tmp_len    = 0;
    int header_len = 0;
    ;
    int                                    info_len              = 0;
    int                                    skid_len              = 0;
    int                                    idx                   = 0;
    int                                    contents_len          = 0;
    struct signaling_param_service_offer_s param_service_offer_s = { 0 };
    struct signaling_param_service_offer_s tmp_service_offer_s   = { 0 };
    uint8_t                                sha1_digest[HIP_AH_SHA_LEN];
    uint8_t                               *signature = NULL;
    unsigned int                           sig_len;
    uint8_t                               *cert_hint = NULL;
    unsigned int                           cert_hint_len;
    uint8_t                               *tmp_ptr = (uint8_t *) &param_service_offer_s;

    HIP_DEBUG("Adding service offer parameter according to the policy\n");
    /* build and append parameter */
    hip_set_param_type((struct hip_tlv_common *) &tmp_service_offer_s, HIP_PARAM_SIGNALING_SERVICE_OFFER_S);
    tmp_service_offer_s.service_offer_id = htons(service_offer_id);
    //TODO check for the following values to be assigned to the parameter types
    tmp_service_offer_s.service_type        = htons(0);
    tmp_service_offer_s.service_description = htonl(0);
    tmp_service_offer_s.service_sig_algo    = HIP_DEFAULT_HIPFW_ALGO;

    if (signaling_info_req_flag_check(&flags->flag_info_requests, HOST_INFO_OS)) {
        tmp_service_offer_s.endpoint_info_req[idx] = htons(HOST_INFO_OS);
        idx++;
    }
    if (signaling_info_req_flag_check(&flags->flag_info_requests, HOST_INFO_KERNEL)) {
        tmp_service_offer_s.endpoint_info_req[idx] = htons(HOST_INFO_KERNEL);
        idx++;
    }
    if (signaling_info_req_flag_check(&flags->flag_info_requests, HOST_INFO_ID)) {
        tmp_service_offer_s.endpoint_info_req[idx] = htons(HOST_INFO_ID);
        idx++;
    }
    if (signaling_info_req_flag_check(&flags->flag_info_requests, HOST_INFO_CERTS)) {
        tmp_service_offer_s.endpoint_info_req[idx] = htons(HOST_INFO_CERTS);
        idx++;
    }
    if (signaling_info_req_flag_check(&flags->flag_info_requests, USER_INFO_ID)) {
        tmp_service_offer_s.endpoint_info_req[idx] = htons(USER_INFO_ID);
        idx++;
    }
    if (signaling_info_req_flag_check(&flags->flag_info_requests, USER_INFO_CERTS)) {
        tmp_service_offer_s.endpoint_info_req[idx] = htons(USER_INFO_CERTS);
        idx++;
    }
    if (signaling_info_req_flag_check(&flags->flag_info_requests, APP_INFO_NAME)) {
        tmp_service_offer_s.endpoint_info_req[idx] = htons(APP_INFO_NAME);
        idx++;
    }
    if (signaling_info_req_flag_check(&flags->flag_info_requests, APP_INFO_CONNECTIONS)) {
        tmp_service_offer_s.endpoint_info_req[idx] = htons(APP_INFO_CONNECTIONS);
        idx++;
    }
    if (signaling_info_req_flag_check(&flags->flag_info_requests, APP_INFO_QOS_CLASS)) {
        tmp_service_offer_s.endpoint_info_req[idx] = htons(APP_INFO_QOS_CLASS);
        idx++;
    }
    if (signaling_info_req_flag_check(&flags->flag_info_requests, APP_INFO_REQUIREMENTS)) {
        tmp_service_offer_s.endpoint_info_req[idx] = htons(APP_INFO_REQUIREMENTS);
        idx++;
    }
    HIP_DEBUG("Number of Info Request Parameters in Service Offer = %d.\n", idx);
    //print_hash(hash);

    cert_hint                                 = (uint8_t *) signaling_extract_skey_ident_from_cert(mb_cert, &cert_hint_len);
    tmp_service_offer_s.service_cert_hint_len =  htons(cert_hint_len);
    memcpy(tmp_service_offer_s.service_cert_hint, cert_hint, cert_hint_len);
    skid_len = cert_hint_len;
    HIP_DEBUG(" Service cert hint copied successfully \n");

    if (HIP_DEFAULT_HIPFW_ALGO == HIP_HI_RSA) {
        tmp_len = RSA_size((RSA *) mb_key);
        sig_len = tmp_len;
    } else if (HIP_DEFAULT_HIPFW_ALGO == HIP_HI_ECDSA) {
        tmp_len = ECDSA_size((EC_KEY *) mb_key);
        sig_len = tmp_len;
    }

    signature = calloc(1, tmp_len);
    HIP_IFEL(!signature, -1, "Malloc for signature failed.");
    memset(signature, '\0', tmp_len);
    tmp_service_offer_s.service_sig_len = tmp_len;
    HIP_DEBUG("RSA_size determined to be  %d. This is the probabilistic length of signature \n", tmp_len);

    header_len = sizeof(struct hip_tlv_common) + sizeof(tmp_service_offer_s.service_type) + sizeof(tmp_service_offer_s.service_offer_id) +
                 sizeof(tmp_service_offer_s.service_description) + sizeof(tmp_service_offer_s.service_cert_hint_len) +
                 sizeof(tmp_service_offer_s.service_sig_algo) + sizeof(tmp_service_offer_s.service_sig_len);
    info_len = sizeof(uint16_t) * idx;


    contents_len =  header_len + info_len + skid_len + tmp_len - sizeof(struct hip_tlv_common);
    hip_set_param_contents_len((struct hip_tlv_common *) &tmp_service_offer_s, contents_len);
    hip_set_param_type((struct hip_tlv_common *) &tmp_service_offer_s, HIP_PARAM_SIGNALING_SERVICE_OFFER_S);

    HIP_DEBUG("Param contents length and type set contents_len = %d\n", contents_len);

    memcpy(&param_service_offer_s, &tmp_service_offer_s, header_len);
    HIP_DEBUG("Signed Service Offer header len = %d \n", header_len);
    memcpy(&param_service_offer_s.endpoint_info_req[0], &tmp_service_offer_s.endpoint_info_req[0], info_len);
    HIP_DEBUG("Signed Service Offer endpoint info len = %d  \n", info_len);
    memcpy(&param_service_offer_s.endpoint_info_req[idx], &tmp_service_offer_s.service_cert_hint[0], skid_len);
    HIP_DEBUG("Signed Service Offer service_cert hint len = %d \n", skid_len);

    HIP_IFEL(hip_build_digest(HIP_DIGEST_SHA1, &param_service_offer_s, header_len + info_len + skid_len, sha1_digest) < 0,
             -1, "Building of SHA1 digest failed\n");
    tmp_ptr += (header_len + info_len + skid_len);

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
    HIP_IFEL(hip_build_digest(HIP_DIGEST_SHA1, &param_service_offer_s, contents_len, hash),
             -1, "Could not build hash of the service offer \n");
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop PERF_MBOX_R1_HASH_SERVICE_OFFER, PERF_MBOX_I2_HASH_SERVICE_OFFER\n");
    hip_perf_stop_benchmark(perf_set, PERF_MBOX_R1_HASH_SERVICE_OFFER);
    hip_perf_stop_benchmark(perf_set, PERF_MBOX_I2_HASH_SERVICE_OFFER);
#endif

    HIP_DEBUG("Param contents length = %d\n", hip_get_param_contents_len((struct hip_tlv_common *) &param_service_offer_s));
    HIP_IFEL(hip_build_param(msg, &param_service_offer_s),
             -1, "Could not build notification parameter into message \n");

out_err:
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
    //const uint8_t              *tmp_enc_ptr                 = NULL;
    //uint16_t                    tmp_info_sec_len            = 0;

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
        } else {
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
        }

        /*----------------- Allocate and build message buffer ----------------------*/
        HIP_IFEL(!(*msg_buf = hip_msg_alloc()),
                 -ENOMEM, "Out of memory while allocation memory for the notify packet\n");
        hip_build_network_hdr(*msg_buf, HIP_UPDATE, mask, &msg->hits, &msg->hitr); /*Just giving some dummy Packet type*/

        HIP_IFEL(signaling_put_decrypted_secrets_to_msg_buf(msg, msg_buf, dec_output,  tmp_len),
                 -1, "Could not add the decrypted endpoint info to the msg buffer for further processing. \n");

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
int signaling_get_info_req_from_service_offer_u(const struct signaling_param_service_offer *offer,
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
                                                               sizeof(offer->service_description) +
                                                               HIP_AH_SHA_LEN)) / sizeof(uint16_t);

    /* number of service offers to be accepted, if more than the limit drop it */
    if (num_req_info_items > 0) {
        HIP_DEBUG("Number of parameters received in the Service Offer = %d.\n", num_req_info_items);
        /*Processing the information requests in the service offer*/
        while ((i < num_req_info_items) && ((tmp_info = ntohs(offer->endpoint_info_req[i])) != 0)) {
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
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_I2_HANDLE_SERVICE_OFFER, PERF_R2_HANDLE_SERVICE_OFFER\n");
    hip_perf_start_benchmark(perf_set, PERF_I2_HANDLE_SERVICE_OFFER);
    hip_perf_start_benchmark(perf_set, PERF_R2_HANDLE_SERVICE_OFFER);
#endif
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

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop PERF_I2_HANDLE_SERVICE_OFFER, PERF_R2_HANDLE_SERVICE_OFFER\n");
    hip_perf_stop_benchmark(perf_set, PERF_I2_HANDLE_SERVICE_OFFER);
    hip_perf_stop_benchmark(perf_set, PERF_R2_HANDLE_SERVICE_OFFER);
#endif

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
         *  the other flag (flags) just collects all the information request over all service offers
         *  Reason: as we set the flag for user signature in hipd_state using the flag we set here*/
        HIP_IFEL(signaling_get_info_req_from_service_offer_u(&tmp_service_offer_u, &tmp_flags),  -1,
                 "Could not get info request from service offer.\n");
        HIP_IFEL(signaling_get_info_req_from_service_offer_u(&tmp_service_offer_u, flags),  -1,
                 "Could not get info request from service offer.\n");
        HIP_IFEL(signaling_build_response_to_service_offer_u(msg_buf, conn, &sig_state->pending_conn_context,  &tmp_flags), -1,
                 "Could not building responses to the signed service offer\n");
        hip_dump_msg(msg_buf);

        /* ========== Generate 128 -bit key for encrypting the payload of HIP_ENCRYPTED param ===============*/
        HIP_IFEL(generate_key_for_hip_encrypt(key_data, &key_data_len, key_hint), -1, "Could not generate the random key for HIP Encrypted\n");

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
        HIP_IFEL(hip_crypto_encrypted(info_secret_enc, iv, HIP_HIP_AES_SHA1,
                                      tmp_len, key_data, HIP_DIRECTION_ENCRYPT),
                 -1, "Building of param encrypted failed\n");
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
                /*Generate the hash of the service offer*/
                HIP_IFEL(hip_build_digest(HIP_DIGEST_SHA1, &param_service_offer, hip_get_param_contents_len(&param_service_offer), ack.service_offer_hash),
                         -1, "Could not build hash of the service offer \n");

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
 * Building Acknowledgment for signed signed service offer. Slightly tricky.
 */
int signaling_build_service_ack_s(struct signaling_hipd_state *sig_state,
                                  struct hip_packet_context *ctx)
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
                /*Generate the hash of the service offer*/
                HIP_IFEL(hip_build_digest(HIP_DIGEST_SHA1, &param_service_offer, hip_get_param_contents_len(&param_service_offer), ack.service_offer_hash),
                         -1, "Could not build hash of the service offer \n");
                HIP_HEXDUMP("Service offer hash = ", ack.service_offer_hash, HIP_AH_SHA_LEN);
                HIP_DEBUG("Hash calculated for Service Acknowledgement\n");
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
                    HIP_IFEL(!(dh_shared_key = calloc(1, dh_shared_len)), -ENOMEM,
                             "Error on allocating memory for Diffie-Hellman shared key.\n");
                    signaling_generate_shared_key_from_dh_shared_secret(dh_shared_key, &dh_shared_len, mb_dh_pub_key, mb_dh_pub_key_len);
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
                } else {
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
                    // print_hash(ack.service_offer_hash);
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
    for (i = 0; i < group->num_info_req; i++) {
        HIP_DEBUG("Info requested added from flag  = %u\n", group->info_requests[i]);
        offer_u->endpoint_info_req[i] = htons(group->info_requests[i]);
    }
    tmp_len =  sizeof(offer_u->service_offer_id) + sizeof(offer_u->service_type) +
              sizeof(offer_u->service_description) + (group->num_info_req) * sizeof(uint16_t) +
              sizeof(offer_u->service_cert_hint);
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
        HIP_DEBUG("GOT key rr of length %d\n", ctx->user.key_rr_len);
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
                num_req_info_items = (hip_get_param_contents_len(&param_service_offer) -
                                      (sizeof(param_service_offer.service_offer_id) +
                                       sizeof(param_service_offer.service_type) +
                                       sizeof(param_service_offer.service_description) +
                                       HIP_AH_SHA_LEN)) / sizeof(uint16_t);
                while (i < num_req_info_items) {
                    tmp_info = ntohs(param_service_offer.endpoint_info_req[i]);
                    if (tmp_info == APP_INFO_NAME || tmp_info == APP_INFO_QOS_CLASS || tmp_info == APP_INFO_REQUIREMENTS || tmp_info == APP_INFO_CONNECTIONS ||
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

int signaling_check_if_service_offer_signed(struct signaling_param_service_offer *param_service_offer)
{
    uint8_t      *tmp_ptr = NULL;
    uint16_t      tmp_len = 0;
    unsigned char temp_check[HIP_AH_SHA_LEN];
    HIP_ASSERT(param_service_offer);

    tmp_ptr  = (uint8_t *) param_service_offer;
    tmp_len  = hip_get_param_contents_len(param_service_offer);
    tmp_ptr += (tmp_len + sizeof(struct hip_tlv_common) - HIP_AH_SHA_LEN);

    memset(temp_check, 0, HIP_AH_SHA_LEN);
    return memcmp(temp_check, tmp_ptr, HIP_AH_SHA_LEN) ? 1 : 0;
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


    header_len = sizeof(struct hip_tlv_common) + sizeof(offer->service_offer_id) + sizeof(offer->service_type) +
                 sizeof(offer->service_description);
    cert_hint_len = HIP_AH_SHA_LEN;
    info_len      = (hip_get_param_contents_len(offer) - (header_len + cert_hint_len - sizeof(struct hip_tlv_common)));


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
        return 1;
    } else {
        return 0;
    }

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

int signaling_hip_msg_contains_signed_service_offer(struct hip_common *msg)
{
    int                                  err   = 0;
    int                                  flag  = 0;
    const struct hip_tlv_common         *param = NULL;
    struct signaling_param_service_offer param_service_offer;

    if ((param = hip_get_param(msg, HIP_PARAM_SIGNALING_SERVICE_OFFER))) {
        do {
            HIP_IFEL(signaling_copy_service_offer(&param_service_offer, (const struct signaling_param_service_offer *) (param)),
                     -1, "Could not copy connection context\n");
            flag =  signaling_check_if_service_offer_signed(&param_service_offer);
            if (flag) {
                return 1;
            }
        } while ((param = hip_get_next_param(msg, param)));
    }
out_err:
    return err;
}

int signaling_split_info_req_to_groups(struct signaling_hipd_state *sig_state,
                                       struct service_offer_groups *offer_groups,
                                       struct hip_packet_context *ctx)
{
    int                                  err                = 0, i = 0, idx = 0;
    int                                  j                  = 0;
    int                                  num_req_info_items = 0;
    uint16_t                             tmp_info           = 0;
    const struct hip_tlv_common         *param              = NULL;
    struct signaling_param_service_offer param_service_offer;

    if ((param = hip_get_param(ctx->input_msg, HIP_PARAM_SIGNALING_SERVICE_OFFER))) {
        do {
            HIP_IFEL(signaling_copy_service_offer(&param_service_offer, (const struct signaling_param_service_offer *) (param)),
                     -1, "Could not copy connection context\n");
            i = 0;
            if (signaling_check_if_service_offer_signed(&param_service_offer)) {
                if (signaling_check_if_mb_certificate_available(sig_state, &param_service_offer)) {
                    num_req_info_items = (hip_get_param_contents_len(&param_service_offer) - (sizeof(param_service_offer.service_offer_id) +
                                                                                              sizeof(param_service_offer.service_type) +
                                                                                              sizeof(param_service_offer.service_description) +
                                                                                              HIP_AH_SHA_LEN)) / sizeof(uint16_t);
                    /* number of service offers to be accepted, if more than the limit drop it */
                    if (num_req_info_items > 0) {
                        HIP_DEBUG("Number of parameters received in the Service Offer = %d.\n", num_req_info_items);
                        /*Processing the information requests in the service offer*/
                        while ((i < num_req_info_items) && ((tmp_info = ntohs(param_service_offer.endpoint_info_req[i])) != 0)) {
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
        } while ((param = hip_get_next_param(ctx->input_msg, param)));
    }

out_err:
    return err;
}

int signaling_merge_info_req_to_similar_groups(struct service_offer_groups *offer_groups,
                                               struct signaling_hipd_state *sig_state)
{
    int                         err            = 0, i = 0, idx = 0;
    int                         flag           = 0, j = 0, k = 0;
    struct service_offer_groups temp_offer_grp = { { 0 } };

    uint8_t found                                = 0;
    uint8_t entries_merged[MAX_NUM_OFFER_GROUPS] = {  0, 0, 0, 0, 0,
                                                      0, 0, 0, 0, 0 };

    i    = 0;
    flag = 1;
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

//out_err:
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

//out_err:
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
