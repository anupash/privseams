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

#include "lib/core/debug.h"
#include "lib/core/builder.h"
#include "lib/core/protodefs.h"
#include "lib/core/common.h"
#include "lib/core/ife.h"
#include "lib/core/prefix.h"

#include "signaling_common_builder.h"
#include "signaling_oslayer.h"
#include "signaling_prot_common.h"

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
    HIP_IFEL((par == NULL || app_ctx == NULL),
            -1, "No parameter or application context given.\n");

    /* Set ports */
    par->src_port = htons(src_port);
    par->dest_port = htons(dest_port);

    /* Set length fields */
    par->app_dn_length  = htons(strlen(app_ctx->application_dn));
    par->iss_dn_length  = htons(strlen(app_ctx->issuer_dn));
    par->req_length     = htons(strlen(app_ctx->requirements));
    par->grp_length     = htons(strlen(app_ctx->groups));

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

/**
 * @return zero for success, or non-zero on error
 */
int signaling_build_param_user_context(hip_common_t *msg,
                                    const struct signaling_user_context *user_ctx,
                                    const unsigned char *signature, const int sig_len)
{
    struct signaling_param_user_context *param_userinfo = NULL;
    int err = 0;
    int username_len;
    int header_len;
    int par_len;

    /* Sanity checks */
    HIP_IFEL(!msg,
             -1, "Got no msg context. (msg == NULL)\n");
    HIP_IFEL(!signature,
             -1, "Got no signature to build the parameter from.\n");

    /* calculate lengths */
    header_len      = sizeof(struct signaling_param_user_context);
    username_len     = strlen(user_ctx->username);
    par_len         = header_len - sizeof(struct hip_tlv_common) + username_len + sig_len;

    HIP_DEBUG("Building user info parameter of length %d\n", par_len);

    /* BUILD THE PARAMETER */
    param_userinfo = malloc(sizeof(hip_tlv_common_t) + par_len);
    HIP_IFEL(!param_userinfo,
             -1, "Could not allocate user signature parameter. \n");

    hip_set_param_type((hip_tlv_common_t *) param_userinfo, HIP_PARAM_SIGNALING_USERINFO);
    hip_set_param_contents_len((hip_tlv_common_t *) param_userinfo, par_len);
    param_userinfo->ui_length = htons(username_len);
    memcpy((uint8_t *)param_userinfo + header_len, user_ctx->username, username_len);
    param_userinfo->sig_length = htons(sig_len);
    memcpy((uint8_t *)param_userinfo + header_len + username_len, signature, sig_len);

    HIP_IFEL(hip_build_param(msg, param_userinfo),
             -1, "Failed to append appinfo parameter to message.\n");

out_err:
    free(param_userinfo);
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
    memcpy(usr_ctx->username, (const uint8_t *) param_usr_ctx + sizeof(struct signaling_param_user_context),
           ntohs(param_usr_ctx->ui_length));
    usr_ctx->username[ntohs(param_usr_ctx->ui_length)] = '\0';

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
