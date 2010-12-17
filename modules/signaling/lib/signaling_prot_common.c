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

void signaling_param_appinfo_print(const struct signaling_param_app_context *appinfo) {
    const uint8_t *p_content;

    if(appinfo == NULL) {
        HIP_DEBUG("No appinfo parameter given.\n");
        return;
    }
    HIP_DEBUG("+------------ APP INFO START ----------------------\n");
    HIP_DEBUG("Ports: src %d, dest %d\n", ntohs(appinfo->src_port), ntohs(appinfo->dest_port));
    p_content = (const uint8_t *) appinfo + sizeof(struct signaling_param_app_context);
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

int signaling_init_application_context(struct signaling_application_context *app_ctx) {
    int err = 0;

    HIP_IFEL(!app_ctx, -1, "Application context has to be allocated before initialization\n");

    app_ctx->pid                = -1;
    app_ctx->application_dn[0]  = '\0';
    app_ctx->issuer_dn[0]       = '\0';
    app_ctx->groups[0]          = '\0';
    app_ctx->requirements[0]    = '\0';
    app_ctx->path[0]            = '\0';

out_err:
    return err;
}

int signaling_init_user_context(struct signaling_user_context *user_ctx) {
    int err = 0;

    HIP_IFEL(!user_ctx, -1, "User context has to be allocated before initialization\n");

    user_ctx->euid = -1;
    user_ctx->username[0] = '\0';

out_err:
    return err;
}

int signaling_init_connection_context(struct signaling_connection_context *ctx) {
    int err = 0;

    HIP_IFEL(!ctx, -1, "Connection context has to be allocated before initialization\n");

    ctx->connection_status  = SIGNALING_CONN_NEW;
    ctx->src_port           = 0;
    ctx->dest_port          = 0;
    HIP_IFEL(signaling_init_application_context(&ctx->app_ctx_out),
             -1, "Could not init outgoing application context\n");
    HIP_IFEL(signaling_init_user_context(&ctx->user_ctx),
             -1, "Could not init user context\n");

out_err:
    return err;
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
    HIP_DEBUG(" \tUser Name:\t %s\n", ctx->user_ctx.username);
    HIP_DEBUG(" Application context \n");
    HIP_DEBUG(" \tApplication DN:\t %s\n", ctx->app_ctx_out.application_dn);
    HIP_DEBUG(" \tAC Issuer DN:\t %s\n", ctx->app_ctx_out.issuer_dn);
    HIP_DEBUG(" \tRequirements:\t %s\n", ctx->app_ctx_out.requirements);
    HIP_DEBUG(" \tGroups:\t\t %s\n", ctx->app_ctx_out.groups);
    HIP_DEBUG("+------------ CONNECTION CONTEXT END   ----------------------\n");
}
