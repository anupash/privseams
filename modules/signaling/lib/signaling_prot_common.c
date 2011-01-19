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
#include "lib/core/builder.h"
#include "signaling_prot_common.h"
#include "signaling_common_builder.h"
#include "signaling_x509_api.h"

static const char *signaling_connection_status_name(int status) {
    switch (status) {
    case SIGNALING_CONN_NEW:
        return "NEW";
    case SIGNALING_CONN_PENDING:
        return "PENDING";
    case SIGNALING_CONN_WAITING:
        return "WAITING";
    case SIGNALING_CONN_BLOCKED:
        return "BLOCKED";
    case SIGNALING_CONN_ALLOWED:
        return "ALLOWED";
    case SIGNALING_CONN_USER_AUTHED:
        return "USER AUTHED";
    case SIGNALING_CONN_USER_UNAUTHED:
        return "USER UNAUTHED";
    default:
        return "UNKOWN";
    }
}

static const char *signaling_user_key_name(int key_type) {
    switch (key_type) {
    case HIP_HI_RSA:
        return "RSA";
    case HIP_HI_DSA:
        return "DSA";
    case HIP_HI_ECDSA:
        return "ECDSA";
    default:
        return "UNKOWN";
    }
}

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

/**
 * Prints the application context parameter.
 *
 * @param app the application context parameter to print
 */
void signaling_param_application_context_print(const struct signaling_param_app_context * const param_app_ctx) {
    const uint8_t *p_content;

    if(param_app_ctx == NULL) {
        HIP_DEBUG("No appinfo parameter given.\n");
        return;
    }
    HIP_DEBUG("+------------ APP INFO START ----------------------\n");
    HIP_DEBUG("Ports: src %d, dest %d\n", ntohs(param_app_ctx->src_port), ntohs(param_app_ctx->dest_port));
    p_content = (const uint8_t *) param_app_ctx + sizeof(struct signaling_param_app_context);
    signaling_param_print_field("Application DN:", ntohs(param_app_ctx->app_dn_length), p_content);
    p_content += ntohs(param_app_ctx->app_dn_length);
    signaling_param_print_field("AC Issuer DN:\t", ntohs(param_app_ctx->iss_dn_length), p_content);
    p_content += ntohs(param_app_ctx->iss_dn_length);
    signaling_param_print_field("Requirements:\t", ntohs(param_app_ctx->req_length), p_content);
    p_content += ntohs(param_app_ctx->req_length);
    signaling_param_print_field("Groups:\t", ntohs(param_app_ctx->grp_length), p_content);
    HIP_DEBUG("+------------ APP INFO END   ----------------------\n");
}

/**
 * Print the internal application context structure.
 *
 * @param app_ctx   the application context to print
 * @param prefix    prefix is prepended to all output of this function
 * @param header    0 for no header, 1 to print a header
 */
void signaling_application_context_print(const struct signaling_application_context * const app_ctx,
                                         const char *prefix, const int header) {
    if(app_ctx == NULL) {
        HIP_DEBUG("%sNo application ctx parameter given.\n", prefix);
        return;
    }
    if (header)
        HIP_DEBUG("%s+------------ APPLICATION CONTEXT START ----------------------\n", prefix);
    HIP_DEBUG("%s  Application context \n", prefix);
    HIP_DEBUG("%s  \tApplication DN:\t %s\n", prefix, app_ctx->application_dn);
    HIP_DEBUG("%s  \tAC Issuer DN:\t %s\n", prefix, app_ctx->issuer_dn);
    HIP_DEBUG("%s  \tRequirements:\t %s\n", prefix, app_ctx->requirements);
    HIP_DEBUG("%s  \tGroups:\t\t %s\n", prefix, app_ctx->groups);
    if (header)
        HIP_DEBUG("%s+------------ APPLICATION CONTEXT END   ----------------------\n", prefix);
}

/**
 * Print the internal user context structure.
 *
 * @param usr_ctx   the user context to print
 * @param prefix    prefix is prepended to all output of this function
 * @param header    0 for no header, 1 to print a header
 */
void signaling_user_context_print(const struct signaling_user_context * const user_ctx,
                                  const char *prefix, const int header) {
    X509_NAME *subj_name;
    char subj_name_string[SIGNALING_USER_ID_MAX_LEN] = { "<decoding error>" };

    if(user_ctx == NULL) {
        HIP_DEBUG("%sNo user ctx parameter given.\n", prefix);
        return;
    }

    /* Decode users name */
    if(!signaling_DER_to_X509_NAME(user_ctx->subject_name, user_ctx->subject_name_len, &subj_name)) {
        X509_NAME_oneline(subj_name, subj_name_string, SIGNALING_USER_ID_MAX_LEN);
    }

    if (header)
        HIP_DEBUG("%s+------------- USER CONTEXT START ----------------------\n", prefix);
    HIP_DEBUG("%s  User context \n", prefix);
    HIP_DEBUG("%s  \tSystem UID:\t %d\n", prefix, user_ctx->uid);
    HIP_DEBUG("%s  \tUser Name:\t %s\n", prefix, subj_name_string);
    HIP_DEBUG("%s  \tUser Key:\t %s\n", prefix, signaling_user_key_name(user_ctx->rdata.algorithm));
    HIP_DEBUG("%s  \tUser Key RR:\t Size %d\n", prefix, user_ctx->key_rr_len == -1 ? 0 : user_ctx->key_rr_len - sizeof(struct hip_host_id_key_rdata));
    //if (user_ctx->key_rr_len > 0)
    //    HIP_HEXDUMP(prefix, user_ctx->pkey, user_ctx->key_rr_len - sizeof(struct hip_host_id_key_rdata));
    if (header)
        HIP_DEBUG("%s+------------ USER CONTEXT END   ----------------------\n", prefix);
}

/**
 * Print the internal connection context structure.
 *
 * @param ctx       the connection context to print
 * @param prefix    prefix is prepended to all output of this function
 */
void signaling_connection_context_print(const struct signaling_connection_context * const ctx, const char *prefix) {
    if(ctx == NULL) {
        HIP_DEBUG("%sNo ctx parameter given.\n", prefix);
        return;
    }

    HIP_DEBUG("%s+------------ CONNECTION CONTEXT START ----------------------\n", prefix);
    HIP_DEBUG("%s  Status:\t\t %s\n", prefix, signaling_connection_status_name(ctx->connection_status));
    HIP_DEBUG("%s  Ports:\t\t src %d, dest %d\n", prefix, ctx->src_port, ctx->dest_port);
    signaling_user_context_print(&ctx->user_ctx, prefix, 0);
    signaling_application_context_print(&ctx->app_ctx, prefix, 0);
    HIP_DEBUG("%s+------------ CONNECTION CONTEXT END   ----------------------\n", prefix);
}



/**
 * Prints the user context parameter.
 *
 * @param app the user context parameter to print
 */
void signaling_param_user_context_print(const struct signaling_param_user_context * const userinfo) {
    const uint8_t *p_content;

    if(userinfo == NULL) {
        HIP_DEBUG("No userinfo parameter given.\n");
        return;
    }
    HIP_DEBUG("+------------ USER INFO START ----------------------\n");
    p_content = (const uint8_t *) userinfo + sizeof(struct signaling_param_user_context)
                + (ntohs(userinfo->pkey_rr_length) - sizeof(struct hip_host_id_key_rdata));
    signaling_param_print_field("User Name:", ntohs(userinfo->un_length), p_content);
    HIP_DEBUG("User Key Type: %s", signaling_user_key_name(userinfo->rdata.algorithm));
    p_content = (const uint8_t *) userinfo + sizeof(struct signaling_param_user_context);
    HIP_HEXDUMP("User Key Data: ", p_content, ntohs(userinfo->pkey_rr_length));
    HIP_DEBUG("+------------ USER INFO END   ----------------------\n");
}

/**
 * Initializes the given application context to default values.
 * Memory for context has to be allocated and freed by the caller.
 *
 * @param app_ctx a pointer to the application context that should be initialized
 *
 * @return negative value on error, 0 on success
 */
int signaling_init_application_context(struct signaling_application_context * const app_ctx) {
    int err = 0;

    HIP_IFEL(!app_ctx, -1, "Application context has to be allocated before initialization\n");

    app_ctx->application_dn[0]  = '\0';
    app_ctx->issuer_dn[0]       = '\0';
    app_ctx->groups[0]          = '\0';
    app_ctx->requirements[0]    = '\0';

out_err:
    return err;
}

/**
 * Initializes the given user context to default values.
 * Memory for context has to be allocated and freed by the caller.
 *
 * @param user_ctx a pointer to the user context that should be initialized
 *
 * @return negative value on error, 0 on success
 */
int signaling_init_user_context(struct signaling_user_context * const user_ctx) {
    int err = 0;

    HIP_IFEL(!user_ctx, -1, "User context has to be allocated before initialization\n");

    user_ctx->uid              = -1;    // no user id
    user_ctx->subject_name_len  = -1;    // no subject name
    user_ctx->key_rr_len        = -1;    // no user public key (but key_rdata still has size 4)
    user_ctx->rdata.algorithm   = 0;     // no user public key algorithm
    user_ctx->rdata.flags       = 0;     // unused
    user_ctx->rdata.protocol    = 0;     // unused
    memset(user_ctx->pkey,          0, sizeof(user_ctx->pkey));
    memset(user_ctx->subject_name,  0, sizeof(user_ctx->subject_name));

out_err:
    return err;
}

/**
 * Initializes the given connection context to default values.
 * Memory for context has to be allocated and freed by the caller.
 *
 * @param ctx a pointer to the connection context that should be initialized
 *
 * @return negative value on error, 0 on success
 */
int signaling_init_connection_context(struct signaling_connection_context * const ctx) {
    int err = 0;

    HIP_IFEL(!ctx, -1, "Connection context has to be allocated before initialization\n");

    ctx->connection_status  = SIGNALING_CONN_NEW;
    ctx->src_port           = 0;
    ctx->dest_port          = 0;
    HIP_IFEL(signaling_init_application_context(&ctx->app_ctx),
             -1, "Could not init outgoing application context\n");
    HIP_IFEL(signaling_init_user_context(&ctx->user_ctx),
             -1, "Could not init user context\n");

out_err:
    return err;
}

/**
 * Initializes the given connection context by stripping all
 * connection context information found in the message.
 * Values that are not given in the  message are initialized to default.
 *
 * @param ctx a pointer to the connection context that should be initialized
 * @param msg a msg that contains connection context information
 *
 * @return negative value on error, 0 on success
 */
int signaling_init_connection_context_from_msg(struct signaling_connection_context * const ctx,
                                               const struct hip_common * const msg) {
    int err                     = 0;
    const hip_tlv_common_t *param     = NULL;

    /* sanity checks */
    HIP_IFEL(!ctx, -1, "Cannot initialize NULL-context\n");

    /* init and fill the connection context */
    HIP_IFEL(signaling_init_connection_context(ctx), -1, "Failed to init connection context\n");
    param = hip_get_param(msg, HIP_PARAM_SIGNALING_APPINFO);
    if (param && hip_get_param_type(param) == HIP_PARAM_SIGNALING_APPINFO) {
        ctx->src_port   = ntohs(((const struct signaling_param_app_context *) param)->src_port);
        ctx->dest_port  = ntohs(((const struct signaling_param_app_context *) param)->dest_port);
        HIP_IFEL(signaling_build_application_context((const struct signaling_param_app_context *) param,
                                                     &ctx->app_ctx),
                 -1, "Could not init application context from app ctx parameter \n");
    }

    param = hip_get_param(msg, HIP_PARAM_SIGNALING_USERINFO);
    if (param && hip_get_param_type(param) == HIP_PARAM_SIGNALING_USERINFO) {
        HIP_IFEL(signaling_build_user_context((const struct signaling_param_user_context *) param,
                                              &ctx->user_ctx),
                 -1, "Could not init user context from user ctx parameter \n");
    }

out_err:
    return err;
}

/**
 * Copies a complete connection context structure from src to dst.
 *
 * @param dst   the destination struct
 * @param src   the source struct
 *
 * @return negative value on error, 0 on success
 */
int signaling_copy_connection_context(struct signaling_connection_context * const dst,
                                      const struct signaling_connection_context * const src) {
    if (!dst || !src) {
        HIP_ERROR("Cannot copy from/to NULL struct \n");
        return -1;
    }
    memcpy(dst, src, sizeof(struct signaling_connection_context));
    return 0;
}
