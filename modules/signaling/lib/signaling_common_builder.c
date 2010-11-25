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

static int signaling_param_appinfo_get_content_length(struct signaling_state *ctx) {
    struct signaling_state_application *appctx;
    int res = 0;

    if(ctx == NULL) {
        return -1;
    }

    appctx = &ctx->application;

    /* Length of length fields = 8 (4 x 2 Bytes) */
    res += 8;

    /* Length of port information = 4 (2 x 2 Bytes) */
    res += 4;

    /* Length of variable input */
    res += (appctx->application_dn != NULL ? strlen(appctx->application_dn) : 0);
    res += (appctx->issuer_dn != NULL ? strlen(appctx->issuer_dn) : 0);
    res += (appctx->requirements != NULL ? strlen(appctx->requirements) : 0);
    res += (appctx->groups != NULL ? strlen(appctx->groups) : 0);

    return res;
}

static int siganling_build_param_appinfo_contents(struct signaling_param_appinfo *appinfo, struct signaling_state *ctx) {
    int err = 0;
    uint8_t *p_tmp;

    /* Sanity checks */
    HIP_IFEL((appinfo == NULL || ctx == NULL),
            -1, "No parameter or application context given.\n");

    /* Set ports */
    appinfo->src_port = htons(ctx->application.src_port);
    appinfo->dest_port = htons(ctx->application.dest_port);

    /* Set length fields */
    appinfo->app_dn_length = (ctx->application.application_dn != NULL ? htons(strlen(ctx->application.application_dn)) : 0);
    appinfo->iss_dn_length = (ctx->application.issuer_dn != NULL ? htons(strlen(ctx->application.issuer_dn)) : 0);
    appinfo->req_length = (ctx->application.requirements != NULL ? htons(strlen(ctx->application.requirements)) : 0);
    appinfo->grp_length = (ctx->application.groups != NULL ? htons(strlen(ctx->application.groups)) : 0);

    /* Set the contents
     * We dont need to check for NULL pointers since length is then set to 0 */
    p_tmp = (uint8_t *) appinfo + sizeof(struct signaling_param_appinfo);
    memcpy(p_tmp, ctx->application.application_dn, ntohs(appinfo->app_dn_length));
    p_tmp += ntohs(appinfo->app_dn_length);
    memcpy(p_tmp, ctx->application.issuer_dn, ntohs(appinfo->iss_dn_length));
    p_tmp += ntohs(appinfo->iss_dn_length);
    memcpy(p_tmp, ctx->application.requirements, ntohs(appinfo->req_length));
    p_tmp += ntohs(appinfo->req_length);
    memcpy(p_tmp, ctx->application.groups, ntohs(appinfo->grp_length));

out_err:
    return err;
}

/**
 * Build a SIGNALING APP INFO (= Name, Developer, Serial) parameter
 * TODO: Define and check for mandatory fields.
 *
 *
 * @param msg the message
 * @param type the info type
 * @param info the info (app name, devloper or serial)
 * @param length the length of the info
 * @return zero for success, or non-zero on error
 */
int signaling_build_param_appinfo(hip_common_t *msg, struct signaling_state *sig_state)
{
    struct signaling_param_appinfo *appinfo;
    int err = 0;
    int length_contents = 0;

    /* Sanity checks */
    HIP_IFEL(msg == NULL,
            -1, "Got no msg context. (msg == NULL)\n");
    HIP_IFEL(sig_state == NULL,
            -1, "Got no context to built the parameter from.\n");

    /* BUILD THE APPLICATION CONTEXT */

    /* Dynamically lookup application from port information */
    HIP_IFEL(0 > signaling_netstat_get_application_path(sig_state),
            -1, "Got no path to application. \n");

    /* Verify the application */
    HIP_IFEL(0 > signaling_verify_application(sig_state),
            -1, "Could not verify certificate of application: %s.\n", sig_state->application.path);

    /* Build the application context. */
    HIP_IFEL(0 > signaling_get_application_context(sig_state),
            -1, "Could not build application context for application: %s.\n", sig_state->application.path);

    /* BUILD THE PARAMETER */

    /* Allocate some memory for the param */
    length_contents = signaling_param_appinfo_get_content_length(sig_state);
    appinfo = (struct signaling_param_appinfo *) malloc(sizeof(hip_tlv_common_t) + length_contents);

    /* Set type and lenght */
    hip_set_param_type((hip_tlv_common_t *) appinfo, HIP_PARAM_SIGNALING_APPINFO);
    hip_set_param_contents_len((hip_tlv_common_t *) appinfo, length_contents);

    /* Build the parameter contents */
    HIP_IFEL(0 > siganling_build_param_appinfo_contents(appinfo, sig_state),
            -1, "Failed to build appinfo parameter.\n");

    /* Dump it */
    signaling_param_appinfo_print(appinfo);

    /* Insert parameter into the message */
    HIP_IFEL(0 > hip_build_param(msg, appinfo),
            -1, "Failed to append appinfo parameter to message.\n");

out_err:
    return err;
}

/*
 * Allocate an appinfo parameter and initialize to standard values.
 *
 * @param length The total maximum length of the new parameter (including type and length field).
 */
static struct signaling_param_appinfo * signaling_param_appinfo_init(unsigned int length) {
    int err = 0;
    struct signaling_param_appinfo *appctx = NULL;

    /* Size must be at least be enough to accomodate fixed contents and tlv header */
    HIP_IFEL((length < sizeof(struct signaling_param_appinfo)),
            -1, "Error allocating memory for appinfo parameter: requested size < MinSize.");

    appctx = (struct signaling_param_appinfo *) malloc(length);

    /* Set contents to zero. */
    memset((uint8_t *)appctx, 0, length);

    /* Set type and length */
    hip_set_param_type((hip_tlv_common_t *) appctx, HIP_PARAM_SIGNALING_APPINFO);
    hip_set_param_contents_len((hip_tlv_common_t *) appctx, length-2);

out_err:
    if (err)
        return NULL;

    return appctx;
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
int signaling_build_param_portinfo(struct hip_common *msg, uint16_t src_port, uint16_t dst_port) {
    struct signaling_param_appinfo * appctx;
    int err = 0;

    HIP_IFEL(!(src_port || dst_port),
            -1, "No port information given, omitting building of parameter HIP_PARAM_SIGNALING_APPINFO.\n");

    appctx = signaling_param_appinfo_init(sizeof(struct signaling_param_appinfo));
    appctx->src_port = htons(src_port);
    appctx->dest_port = htons(dst_port);

    HIP_IFEL(hip_build_param(msg, appctx),
            -1, "HIP builder failed building appinfo parameter into message.\n");

out_err:
    return err;

}
