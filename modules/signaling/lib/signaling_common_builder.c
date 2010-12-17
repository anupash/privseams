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

#include "signaling_common_builder.h"
#include "signaling_oslayer.h"
#include "signaling_prot_common.h"

/*
 * Allocate an appinfo parameter and initialize to standard values.
 *
 * @param length The total maximum length of the new parameter (including type and length field).
 */
static struct signaling_param_appinfo * signaling_param_appinfo_init(unsigned int length) {
    int err = 0;
    struct signaling_param_appinfo *par = NULL;

    /* Size must be at least be enough to accomodate fixed contents and tlv header */
    HIP_IFEL((length < sizeof(struct signaling_param_appinfo)),
             -1, "Error allocating memory for appinfo parameter: requested size < MinSize.");
    HIP_IFEL(!(par = (struct signaling_param_appinfo *) malloc(length)),
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

static int signaling_param_appinfo_get_content_length(struct signaling_application_context *app_ctx) {
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

static int siganling_build_param_appinfo_contents(struct signaling_param_appinfo *par,
                                                  uint16_t src_port,
                                                  uint16_t dest_port,
                                                  struct signaling_application_context *app_ctx) {
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
    p_tmp = (uint8_t *) par + sizeof(struct signaling_param_appinfo);
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
int signaling_build_param_appinfo(hip_common_t *msg, struct signaling_connection_context *ctx)
{
    struct signaling_param_appinfo *appinfo = NULL;
    int err = 0;
    int length_contents = 0;

    /* Sanity checks */
    HIP_IFEL(msg == NULL,
            -1, "Got no msg context. (msg == NULL)\n");
    HIP_IFEL(ctx == NULL,
            -1, "Got no context to built the parameter from.\n");

    /* BUILD THE PARAMETER */
    length_contents = signaling_param_appinfo_get_content_length(&ctx->app_ctx_out);
    appinfo = signaling_param_appinfo_init(sizeof(hip_tlv_common_t) + length_contents);

    HIP_IFEL(0 > siganling_build_param_appinfo_contents(appinfo, ctx->src_port, ctx->dest_port, &ctx->app_ctx_out),
            -1, "Failed to build appinfo parameter.\n");

    HIP_IFEL(0 > hip_build_param(msg, appinfo),
            -1, "Failed to append appinfo parameter to message.\n");

out_err:
    free(appinfo);
    return err;
}

/*
 * Builds and appends an appinfo parameter to the given message setting only the port fields.
 * This is used for communicating ports between hipfw and hipd. The application's name etc. remains empty,
 * since application lookup and verification is done in HIPD.
 *
 * Comment:
 *      The firewall might do the application lookup and verification, if connection tracking is based on
 *      application instead of ports (as for now). Then the application's name etc. should be filled in,
 *      so that the application does not have to repeat the lookup.
 */
int signaling_build_param_portinfo(hip_common_t *msg, uint16_t src_port, uint16_t dst_port) {
    struct signaling_param_appinfo * par = NULL;
    int err = 0;

    HIP_IFEL(!(src_port || dst_port),
            -1, "No port information given, omitting building of parameter HIP_PARAM_SIGNALING_APPINFO.\n");

    /* TODO: need to free parameter after it has been built */
    par = signaling_param_appinfo_init(sizeof(struct signaling_param_appinfo));
    par->src_port = htons(src_port);
    par->dest_port = htons(dst_port);

    HIP_IFEL(hip_build_param(msg, par),
            -1, "HIP builder failed building appinfo parameter into message.\n");

out_err:
    free(par);
    return err;

}

/**
 * @return zero for success, or non-zero on error
 */
int signaling_build_param_user_info(hip_common_t *msg,
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
