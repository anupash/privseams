/*
 * signaling_prot_common.c
 *
 *  Created on: Nov 11, 2010
 *      Author: ziegeldorf
 */

#include <string.h>
#include <stdlib.h>

#include "lib/core/debug.h"
#include "lib/core/ife.h"
#include "signaling_prot_common.h"

static void signaling_param_print_field(const char *prefix, const uint16_t length, const unsigned char *p_content) {
    char buf[length+1];

    if(length == 0) {
        HIP_DEBUG("%s\t <empty>\n", prefix);
        return;
    }

    memset(buf, 0, length + 1);
    memcpy(buf, p_content, length);
    HIP_DEBUG("%s\t%s\n", prefix, buf);
}

void signaling_param_appinfo_print(const struct signaling_param_appinfo *appinfo) {
    const uint8_t *p_content;

    if(appinfo == NULL) {
        HIP_DEBUG("No appinfo parameter given.\n");
        return;
    }
    HIP_DEBUG("+------------ APP INFO START ----------------------\n");
    HIP_DEBUG("Ports: src %d, dest %d\n", ntohs(appinfo->src_port), ntohs(appinfo->dest_port));
    p_content = (const uint8_t *) appinfo + sizeof(struct signaling_param_appinfo);
    signaling_param_print_field("Application DN:", ntohs(appinfo->app_dn_length), p_content);
    p_content += ntohs(appinfo->app_dn_length);
    signaling_param_print_field("AC Issuer DN:\t", ntohs(appinfo->iss_dn_length), p_content);
    p_content += ntohs(appinfo->iss_dn_length);
    signaling_param_print_field("Requirements:\t", ntohs(appinfo->req_length), p_content);
    p_content += ntohs(appinfo->req_length);
    signaling_param_print_field("Groups:\t", ntohs(appinfo->grp_length), p_content);
    HIP_DEBUG("+------------ APP INFO END   ----------------------\n");
}

void signaling_param_userinfo_print(const struct signaling_param_user_context *userinfo) {
    const uint8_t *p_content;

    if(userinfo == NULL) {
        HIP_DEBUG("No userinfo parameter given.\n");
        return;
    }
    p_content = (const uint8_t *) userinfo + sizeof(struct signaling_param_user_context);
    HIP_DEBUG("+------------ USER INFO START ----------------------\n");
    signaling_param_print_field("User Name:", ntohs(userinfo->ui_length), p_content);
    p_content += ntohs(userinfo->ui_length);
    HIP_HEXDUMP("Signature: ", p_content, ntohs(userinfo->sig_length));
    HIP_DEBUG("+------------ USER INFO END   ----------------------\n");
}

struct signaling_connection_context *signaling_init_connection_context(void) {
    int err = 0;
    struct signaling_connection_context *new_ctx;

    HIP_IFEL(!(new_ctx = malloc(sizeof(struct signaling_connection_context))),
             -1, "Could not allocate memory for new application context\n");
    // TODO: doing something like new_ctx = {0} would be more correct and portable
    memset(new_ctx, 0, sizeof(struct signaling_connection_context));
    new_ctx->app_ctx.pid    = -1;
    new_ctx->user_ctx.euid   = -1;
    new_ctx->connection_status = SIGNALING_CONN_NEW;

out_err:
    if (err) {
        free(new_ctx);
        return NULL;
    }
    return new_ctx;
}

const char *signaling_connection_status_name(int status) {
    switch (status) {
    case SIGNALING_CONN_NEW:
        return "NEW";
    case SIGNALING_CONN_PENDING:
        return "PENDING";
    case SIGNALING_CONN_BLOCKED:
        return "BLOCKED";
    case SIGNALING_CONN_ALLOWED:
        return "ALLOWED";
    default:
        return "UNKOWN";
    }
}

void signaling_connection_context_print(const struct signaling_connection_context *ctx) {
    if(ctx == NULL) {
        HIP_DEBUG("No ctx parameter given.\n");
        return;
    }

    HIP_DEBUG("+------------ CONNECTION CONTEXT START ----------------------\n");
    HIP_DEBUG(" Status:\t\t %s\n", signaling_connection_status_name(ctx->connection_status));
    HIP_DEBUG(" Ports:\t\t src %d, dest %d\n", ctx->src_port, ctx->dest_port);
    HIP_DEBUG(" User context \n");
    HIP_DEBUG(" \tUser Id:\t %d\n", ctx->user_ctx.euid);
    HIP_DEBUG(" \tUser Name:\t %s\n", ctx->user_ctx.user_id);
    HIP_DEBUG(" Application context \n");
    HIP_DEBUG(" \tApplication DN:\t %s\n", ctx->app_ctx.application_dn);
    HIP_DEBUG(" \tAC Issuer DN:\t %s\n", ctx->app_ctx.issuer_dn);
    HIP_DEBUG(" \tRequirements:\t %s\n", ctx->app_ctx.requirements);
    HIP_DEBUG(" \tGroups:\t\t %s\n", ctx->app_ctx.groups);
    HIP_DEBUG("+------------ CONNECTION CONTEXT END   ----------------------\n");
}
