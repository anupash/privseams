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

/*
 * Allocate an appinfo parameter and initialize to standard values.
 *
 * @param length The total maximum length of the new parameter (including type and length field).
 */
static struct signaling_param_app_context * signaling_param_appinfo_init(unsigned int length) {
    int err = 0;
    struct signaling_param_app_context *par = NULL;

    /* Size must be at least be enough to accomodate fixed contents and tlv header */
    HIP_IFEL((length < sizeof(struct signaling_param_app_context)),
             -1, "Error allocating memory for appinfo parameter: requested size < MinSize.");
    HIP_IFEL(!(par = (struct signaling_param_app_context *) malloc(length)),
             -1, "Could not allocate memory for new appinfo parameter\n");

    /* Set contents to zero (defined standard values). */
    memset((uint8_t *)par, 0, length);

    /* Set type and length */
    hip_set_param_type((hip_tlv_common_t *) par, HIP_PARAM_SIGNALING_APPINFO);
    hip_set_param_contents_len((hip_tlv_common_t *) par, length-2);

out_err:
    if (err)
        return NULL;

    return par;
}

static int signaling_param_appinfo_get_content_length(const struct signaling_application_context *app_ctx) {
    int res = 0;

    if(app_ctx == NULL) {
        return -1;
    }

    /* Length of length fields = 8 (4 x 2 Bytes) */
    res += 8;

    /* Length of port information = 4 (2 x 2 Bytes) */
    res += 4;

    /* Length of variable input */
    res += strlen(app_ctx->application_dn);
    res += strlen(app_ctx->issuer_dn);
    res += strlen(app_ctx->requirements);
    res += strlen(app_ctx->groups);

    return res;
}

static int siganling_build_param_appinfo_contents(struct signaling_param_app_context *par,
                                                  uint16_t src_port,
                                                  uint16_t dest_port,
                                                  const struct signaling_application_context *app_ctx) {
    int err = 0;
    uint8_t *p_tmp;

    /* Sanity checks */
    HIP_IFEL((par == NULL || app_ctx == NULL), -1, "No parameter or application context given.\n");

    /* Set ports */
    par->src_port   = htons(src_port);
    par->dest_port  = htons(dest_port);

    /* Set length fields and make sure to keep to maximum lengths */
    par->app_dn_length  = htons(MIN(strlen(app_ctx->application_dn), SIGNALING_APP_DN_MAX_LEN));
    par->iss_dn_length  = htons(MIN(strlen(app_ctx->issuer_dn),      SIGNALING_ISS_DN_MAX_LEN));
    par->req_length     = htons(MIN(strlen(app_ctx->requirements),   SIGNALING_APP_REQ_MAX_LEN));
    par->grp_length     = htons(MIN(strlen(app_ctx->groups),         SIGNALING_APP_GRP_MAX_LEN));

    /* Set the contents
     * We dont need to check for NULL pointers since length is then set to 0 */
    p_tmp = (uint8_t *) par + sizeof(struct signaling_param_app_context);
    memcpy(p_tmp, app_ctx->application_dn, ntohs(par->app_dn_length));
    p_tmp += ntohs(par->app_dn_length);
    memcpy(p_tmp, app_ctx->issuer_dn, ntohs(par->iss_dn_length));
    p_tmp += ntohs(par->iss_dn_length);
    memcpy(p_tmp, app_ctx->requirements, ntohs(par->req_length));
    p_tmp += ntohs(par->req_length);
    memcpy(p_tmp, app_ctx->groups, ntohs(par->grp_length));

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

 * @return zero for success, or non-zero on error
 */
int signaling_build_param_application_context(hip_common_t *msg, const struct signaling_connection_context *ctx)
{
    struct signaling_param_app_context *appinfo = NULL;
    int err = 0;
    int length_contents = 0;

    /* Sanity checks */
    HIP_IFEL(msg == NULL,
            -1, "Got no msg context. (msg == NULL)\n");
    HIP_IFEL(ctx == NULL,
            -1, "Got no context to built the parameter from.\n");

    /* BUILD THE PARAMETER */
    length_contents = signaling_param_appinfo_get_content_length(&ctx->app_ctx);
    appinfo = signaling_param_appinfo_init(sizeof(hip_tlv_common_t) + length_contents);

    HIP_IFEL(0 > siganling_build_param_appinfo_contents(appinfo, ctx->src_port, ctx->dest_port, &ctx->app_ctx),
            -1, "Failed to build appinfo parameter.\n");

    HIP_IFEL(0 > hip_build_param(msg, appinfo),
            -1, "Failed to append appinfo parameter to message.\n");

out_err:
    free(appinfo);
    return err;
}


static int any_key_to_key_rr(EVP_PKEY *key, uint8_t *algorithm, unsigned char **key_rr_out) {
    int err = 0;
    int type;

    HIP_IFEL(!key,          -1, "Cannot serialize NULL-key \n");
    HIP_IFEL(!algorithm,    -1, "Cannot write algorithm to NULL field \n");
    HIP_IFEL(!*key_rr_out,  -1, "Cannot write to NULL-buffer \n");

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
        *algorithm = 0;
        *key_rr_out = NULL;
        err = -1;
    }

out_err:
    return err;
}

/**
 * @return zero for success, or non-zero on error
 */
int signaling_build_param_user_context(hip_common_t *msg,
                                       struct signaling_user_context *user_ctx)
{
    struct signaling_param_user_context *param_userinfo = NULL;
    int err = 0;
    int username_len;
    int header_len;
    int pkey_rr_len;
    int par_contents_len;
    EVP_PKEY *user_pkey  = NULL;
    unsigned char *key_rr;
    /* Sanity checks */
    HIP_IFEL(!msg,
             -1, "Got no msg context. (msg == NULL)\n");

    /* Check for users public key */
    if (user_ctx->key_rr_len <= 0) {
        HIP_IFEL(!(user_pkey = signaling_user_api_get_user_public_key(user_ctx->euid)),
                 -1, "Could not obtain users public key \n");
        PEM_write_PUBKEY(stdout, user_pkey);
        HIP_IFEL((user_ctx->key_rr_len = any_key_to_key_rr(user_pkey, &user_ctx->rdata.algorithm, &key_rr)) < 0,
                 -1, "Could not serialize key \n");
        HIP_DEBUG("GOT keyy rr of length %d\n", user_ctx->key_rr_len);
        memcpy(user_ctx->pkey, key_rr, user_ctx->key_rr_len);
        // necessary because any_key_to_rr returns only the length of the key rrwithout the header
        user_ctx->key_rr_len += sizeof(struct hip_host_id_key_rdata);
        free(key_rr);
    }

    HIP_DEBUG("Building user info parameter for: \n");
    signaling_user_context_print(user_ctx, "\t", 1);

    /* calculate lengths */
    header_len        = sizeof(struct signaling_param_user_context) - sizeof(struct hip_host_id_key_rdata);
    pkey_rr_len       = user_ctx->key_rr_len;
    username_len      = user_ctx->subject_name_len;
    par_contents_len  = header_len - sizeof(struct hip_tlv_common) + pkey_rr_len + username_len;

    HIP_DEBUG("Building user info parameter of length %d\n", par_contents_len);

    /* BUILD THE PARAMETER */
    param_userinfo = malloc(sizeof(struct hip_tlv_common) + par_contents_len);
    HIP_IFEL(!param_userinfo,
             -1, "Could not allocate user signature parameter. \n");

    /* Set user identity (public key) */
    param_userinfo->pkey_rr_length   = htons(pkey_rr_len);
    param_userinfo->rdata.algorithm  = user_ctx->rdata.algorithm;
    param_userinfo->rdata.flags      = htons(user_ctx->rdata.flags);
    param_userinfo->rdata.protocol   = user_ctx->rdata.protocol;
    memcpy((uint8_t *)param_userinfo + header_len + sizeof(struct hip_host_id_key_rdata),
           user_ctx->pkey,
           pkey_rr_len - sizeof(struct hip_host_id_key_rdata));

    /* Set user name */
    param_userinfo->un_length = htons(username_len);
    memcpy((uint8_t *)param_userinfo + header_len + pkey_rr_len, user_ctx->subject_name, username_len);

    /* Set type and lenght */
    hip_set_param_type((struct hip_tlv_common *) param_userinfo, HIP_PARAM_SIGNALING_USERINFO);
    hip_set_param_contents_len((struct hip_tlv_common *) param_userinfo, par_contents_len);

    HIP_IFEL(hip_build_param(msg, param_userinfo),
             -1, "Failed to append appinfo parameter to message.\n");

    return err;
}

int signaling_build_param_user_signature(hip_common_t *msg, const struct signaling_user_context *user_ctx) {
    int err = 0;
    struct hip_sig sig;
    unsigned char signature_buf[HIP_MAX_RSA_KEY_LEN / 8];
    int in_len;
    int sig_len = 0;
    uint8_t sig_type = HIP_HI_ECDSA;

    /* sanity checks */
    HIP_IFEL(!msg,       -1, "Cannot sign NULL-message\n");
    HIP_IFEL(!user_ctx,  -1, "Cannot sign without user context\n");

    /* calculate the signature */
    in_len = hip_get_msg_total_len(msg);
    HIP_IFEL((sig_len = signaling_user_api_sign(user_ctx->euid, msg, in_len, signature_buf, &sig_type)) < 0,
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
 * Build a user authentication failed notification parameter.
 *
 * @param msg       the message to which to append the parameter
 * @param reason    the reason why user authentication failed.
 *                  this is used in the notification data field
 *
 * @return          0 on sucess, negative if paramater building failed
 */
int signaling_build_param_user_auth_fail(hip_common_t *msg, const uint16_t reason) {
    int err = 0;
    int len;
    struct hip_notification ntf;
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

/*
 * Fill the internal application_context struct with data from application_context parameter.
 *
 * @return 0 on success
 */
int signaling_build_application_context(const struct signaling_param_app_context *param_app_ctx,
                                        struct signaling_application_context *app_ctx) {
    int err = 0;
    const uint8_t *p_contents;
    uint16_t tmp_len;

    /* sanity checks */
    HIP_IFEL(!param_app_ctx, -1, "Got NULL application context parameter\n");
    HIP_IFEL(!app_ctx, -1, "Got NULL application context to write to\n");

    /* copy contents */
    tmp_len = ntohs(param_app_ctx->app_dn_length);
    p_contents = (const uint8_t *) param_app_ctx + sizeof(struct signaling_param_app_context);
    memcpy(app_ctx->application_dn, p_contents, tmp_len);
    app_ctx->application_dn[tmp_len] = '\0';
    p_contents += tmp_len;

    tmp_len = ntohs(param_app_ctx->iss_dn_length);
    memcpy(app_ctx->issuer_dn, p_contents, tmp_len);
    app_ctx->issuer_dn[tmp_len] = '\0';
    p_contents += tmp_len;

    tmp_len = ntohs(param_app_ctx->req_length);
    memcpy(app_ctx->requirements, p_contents, tmp_len);
    app_ctx->requirements[tmp_len] = '\0';
    p_contents += tmp_len;

    tmp_len = ntohs(param_app_ctx->grp_length);
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
                                 struct signaling_user_context *usr_ctx) {
    int err = 0;

    /* sanity checks */
    HIP_IFEL(!param_usr_ctx,    -1, "Got NULL user context parameter\n");
    HIP_IFEL(!usr_ctx,          -1, "Got NULL user context to write to\n");
    HIP_IFEL(hip_get_param_type(param_usr_ctx) != HIP_PARAM_SIGNALING_USERINFO,
            -1, "Parameter has wrong type, expected %d\n", HIP_PARAM_SIGNALING_USERINFO);

    /* copy contents */
    usr_ctx->key_rr_len = ntohs(param_usr_ctx->pkey_rr_length);
    memcpy(usr_ctx->pkey,
           (const uint8_t *) param_usr_ctx + sizeof(struct signaling_param_user_context),
           ntohs(param_usr_ctx->pkey_rr_length) - sizeof(struct hip_host_id_key_rdata));
    usr_ctx->rdata.algorithm = param_usr_ctx->rdata.algorithm;
    usr_ctx->rdata.protocol = param_usr_ctx->rdata.protocol;
    usr_ctx->rdata.flags = ntohs(param_usr_ctx->rdata.flags);

    usr_ctx->subject_name_len = ntohs(param_usr_ctx->un_length);
    memcpy(usr_ctx->subject_name,
           (const uint8_t *) param_usr_ctx + sizeof(struct signaling_param_user_context) + ntohs(param_usr_ctx->pkey_rr_length) - sizeof(struct hip_host_id_key_rdata),
           ntohs(param_usr_ctx->un_length));

out_err:
    return err;
}

void signaling_get_hits_from_msg(const hip_common_t *msg, const hip_hit_t **hits, const hip_hit_t **hitr)
{
    const hip_tlv_common_t *param = NULL;

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

