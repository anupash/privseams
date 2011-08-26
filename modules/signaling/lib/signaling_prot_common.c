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


const char *signaling_connection_status_name(int status) {
    switch (status) {
    case SIGNALING_CONN_NEW:
        return "NEW";
    case SIGNALING_CONN_PROCESSING:
        return "PROCESSING";
    case SIGNALING_CONN_WAITING:
        return "WAITING";
    case SIGNALING_CONN_BLOCKED:
        return "BLOCKED";
    case SIGNALING_CONN_ALLOWED:
        return "ALLOWED";
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
        HIP_DEBUG("%sNo connection context struct given.\n", prefix);
        return;
    }

    HIP_DEBUG("%s+------------ CONNECTION CONTEXT START ----------------------\n", prefix);
    signaling_flags_print(ctx->flags, prefix);
    signaling_user_context_print(&ctx->user, prefix, 0);
    signaling_application_context_print(&ctx->app, prefix, 0);
    HIP_DEBUG("%s+------------ CONNECTION CONTEXT END   ----------------------\n", prefix);
}

/**
 * Print the internal connection structure.
 *
 * @param conn      the connection to print
 * @param prefix    prefix is prepended to all output of this function
 */
void signaling_connection_print(const struct signaling_connection *const conn, const char *const prefix) {
    char prefix_buf[strlen(prefix)+2];

    memset(prefix_buf, 0, strlen(prefix)+2);
    strcat(prefix_buf, prefix);
    strcat(prefix_buf, "\t");

    if(conn == NULL) {
        HIP_DEBUG("%sNo connection struct given.\n", prefix);
        return;
    }

    HIP_DEBUG("%s+------------ CONNECTION START ----------------------\n", prefix);
    HIP_DEBUG("%s  Identifier:\t\t %d\n", prefix, conn->id);
    HIP_DEBUG("%s  Status:\t\t %s\n",   prefix, signaling_connection_status_name(conn->status));
    HIP_DEBUG("%s  Side:\t\t %s\n",   prefix, conn->side == INITIATOR ? "INITIATOR" : "RESPONDER");
    HIP_DEBUG("%s  Ports:\t\t src %d, dest %d\n", prefix, conn->src_port, conn->dst_port);
    HIP_DEBUG("%s  Outgoing connection context:\n",prefix);
    signaling_connection_context_print(&conn->ctx_out, prefix_buf);
    HIP_DEBUG("%s  Incoming connection context:\n",prefix);
    signaling_connection_context_print(&conn->ctx_in, prefix_buf);
    HIP_DEBUG("%s+------------ CONNECTION END   ----------------------\n", prefix);
}


/**
 * Prints the connection identifier parameter.
 *
 * @param conn_id the connection identifier parameter to print
 */
void signaling_param_connection_identifier_print(const struct signaling_param_connection_identifier *const conn_id) {
    if(conn_id == NULL) {
        HIP_DEBUG("No connection identifier parameter given.\n");
        return;
    }
    HIP_DEBUG("+------------ CONNECTION IDENTIFIER START ----------------------\n");
    HIP_DEBUG("Connection ID:\t %d \n", ntohl(conn_id->id));
    HIP_DEBUG("Src Port:\t\t %d \n",    ntohs(conn_id->src_port));
    HIP_DEBUG("Dst Port:\t\t %d \n",    ntohs(conn_id->dst_port));
    HIP_DEBUG("+------------ CONNECTION IDENTIFIER END   ----------------------\n");
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
int signaling_init_connection(struct signaling_connection *const conn) {
    int err = 0;

    HIP_IFEL(!conn, -1, "Connection context has to be allocated before initialization\n");
    conn->id                = 0;
    conn->status            = SIGNALING_CONN_NEW;
    conn->src_port          = 0;
    conn->dst_port          = 0;
    conn->side              = INITIATOR;
    HIP_IFEL(signaling_init_connection_context(&conn->ctx_in, IN),
             -1, "Could not init incoming connection context\n");
    HIP_IFEL(signaling_init_connection_context(&conn->ctx_out, OUT),
             -1, "Could not init outgoing connection context\n");
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
int signaling_init_connection_from_msg(struct signaling_connection *const conn,
                                       const hip_common_t * const msg) {
    int err                     = 0;
    const struct hip_tlv_common *param     = NULL;

    /* sanity checks */
    HIP_IFEL(!conn, -1, "Cannot initialize NULL-context\n");

    /* init and fill the connection context */
    HIP_IFEL(signaling_init_connection(conn), -1, "Failed to init connection context\n");

    param = hip_get_param(msg, HIP_PARAM_SIGNALING_CONNECTION_ID);
    if (param && hip_get_param_type(param) == HIP_PARAM_SIGNALING_CONNECTION_ID) {
        conn->dst_port   = ntohs(((const struct signaling_param_connection_identifier *) param)->src_port);
        conn->src_port   = ntohs(((const struct signaling_param_connection_identifier *) param)->dst_port);
        conn->id         = ntohl(((const struct signaling_param_connection_identifier *) param)->id);
    }

    HIP_IFEL(signaling_init_connection_context_from_msg(&conn->ctx_in, msg),
             -1, "Could not initialize incomeing connection context from message\n");

out_err:
    return err;
}

int signaling_update_connection_from_msg(struct signaling_connection *const conn,
                                         const hip_common_t * const msg)
{
    int err                     = 0;
    const struct hip_tlv_common *param     = NULL;
    const struct signaling_param_connection_identifier *param_conn_id = NULL;

    /* sanity checks */
    HIP_IFEL(!conn, -1, "Cannot initialize NULL-context\n");
    HIP_IFEL(!msg,  -1, "Cannot initialize from NULL-msg\n");
    param = hip_get_param(msg, HIP_PARAM_SIGNALING_CONNECTION_ID);
    if (param && hip_get_param_type(param) == HIP_PARAM_SIGNALING_CONNECTION_ID) {
        param_conn_id = (const struct signaling_param_connection_identifier *) param;
        conn->id         = ntohl(param_conn_id->id);
        conn->dst_port   = ntohs(param_conn_id->src_port);
        conn->src_port   = ntohs(param_conn_id->dst_port);
    }
    HIP_IFEL(signaling_update_flags_from_connection_id(msg, conn),
             -1, "Could not update flags from connection id parameter \n");
    HIP_IFEL(signaling_init_connection_context_from_msg(&conn->ctx_in, msg),
             -1, "Could not initialize incomeing connection context from message\n");
out_err:
    return err;
}


/**
 * Copies a complete connection structure from src to dst.
 *
 * @param dst   the destination struct
 * @param src   the source struct
 *
 * @return negative value on error, 0 on success
 */
int signaling_copy_connection(struct signaling_connection * const dst,
                              const struct signaling_connection * const src) {
    if (!dst || !src) {
        HIP_ERROR("Cannot copy from/to NULL struct \n");
        return -1;
    }
    memcpy(dst, src, sizeof(struct signaling_connection));
    return 0;
}

/**
 * Initializes the given connection context to default values.
 * Memory for context has to be allocated and freed by the caller.
 *
 * @param ctx a pointer to the connection context that should be initialized
 *
 * @return negative value on error, 0 on success
 */
int signaling_init_connection_context(struct signaling_connection_context *const ctx,
                                      enum direction dir) {
    int err = 0;

    HIP_IFEL(!ctx, -1, "Connection context has to be allocated before initialization\n");
    ctx->direction          = dir;
    ctx->flags              = 0;
    HIP_IFEL(signaling_init_application_context(&ctx->app),
             -1, "Could not init outgoing application context\n");
    HIP_IFEL(signaling_init_user_context(&ctx->user),
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
    HIP_IFEL(signaling_init_connection_context(ctx, IN), -1, "Failed to init connection context\n");

    param = hip_get_param(msg, HIP_PARAM_SIGNALING_APPINFO);
    if (param && hip_get_param_type(param) == HIP_PARAM_SIGNALING_APPINFO) {
        HIP_IFEL(signaling_build_application_context((const struct signaling_param_app_context *) param,
                                                     &ctx->app),
                 -1, "Could not init application context from app ctx parameter \n");
    }

    param = hip_get_param(msg, HIP_PARAM_SIGNALING_USERINFO);
    if (param && hip_get_param_type(param) == HIP_PARAM_SIGNALING_USERINFO) {
        HIP_IFEL(signaling_build_user_context((const struct signaling_param_user_context *) param,
                                              &ctx->user),
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

int signaling_update_flags_from_connection_id(const struct hip_common *const msg,
                                              struct signaling_connection *const conn)
{
    int err = 0;
    const struct signaling_param_connection_identifier *param_conn_id = NULL;

    /* sanity checks */
    HIP_IFEL(!conn,           -1, "Cannot update flags of NULL-connection\n");
    HIP_IFEL(!msg,            -1, "Cannot update flags from NULL-msg\n");

    /* Set flags from connection id flags */
    param_conn_id = hip_get_param(msg, HIP_PARAM_SIGNALING_CONNECTION_ID);
    if (param_conn_id && hip_get_param_type(param_conn_id) == HIP_PARAM_SIGNALING_CONNECTION_ID) {
        if (conn->side == INITIATOR) {
            if (signaling_flag_check(param_conn_id->flags, FH1)) {
                signaling_flag_set(&conn->ctx_out.flags, HOST_AUTH_REQUEST);
            }
            if (signaling_flag_check(param_conn_id->flags, FU1)) {
                signaling_flag_set(&conn->ctx_out.flags, USER_AUTH_REQUEST);
            }
            if (signaling_flag_check(param_conn_id->flags, FH2)) {
                signaling_flag_set(&conn->ctx_in.flags, HOST_AUTH_REQUEST);
            }
            if (signaling_flag_check(param_conn_id->flags, FU2)) {
                signaling_flag_set(&conn->ctx_in.flags, USER_AUTH_REQUEST);
            }
        } else {
            if (signaling_flag_check(param_conn_id->flags, FH1)) {
                signaling_flag_set(&conn->ctx_in.flags, HOST_AUTH_REQUEST);
            }
            if (signaling_flag_check(param_conn_id->flags, FU1)) {
                signaling_flag_set(&conn->ctx_in.flags, USER_AUTH_REQUEST);
            }
            if (signaling_flag_check(param_conn_id->flags, FH2)) {
                signaling_flag_set(&conn->ctx_out.flags, HOST_AUTH_REQUEST);
            }
            if (signaling_flag_check(param_conn_id->flags, FU2)) {
                signaling_flag_set(&conn->ctx_out.flags, USER_AUTH_REQUEST);
            }
        }
    }

    /* Set flags from middlebox flags */
    // todo [AUTH] process middlebox flags

out_err:
    return err;
}

/**
 * Print the internal connection structure.
 *
 * @param conn      the connection to print
 * @param prefix    prefix is prepended to all output of this function
 */
void signaling_flags_print(uint8_t flags, const char *const prefix) {
    char buf[100];
    memset(buf, 0, sizeof(buf));

    sprintf(buf + strlen(buf), "HA  = %d | ", signaling_flag_check(flags, HOST_AUTHED));
    sprintf(buf + strlen(buf), "HAR = %d | ", signaling_flag_check(flags, HOST_AUTH_REQUEST));
    sprintf(buf + strlen(buf), "UA  = %d | ", signaling_flag_check(flags, USER_AUTHED));
    sprintf(buf + strlen(buf), "UAR = %d | ", signaling_flag_check(flags, USER_AUTH_REQUEST));



    HIP_DEBUG("%s  Flags: %s int = %d \n", prefix, buf, flags);
}

int signaling_flag_check_auth_complete(uint8_t flags) {
    return (signaling_flag_check(flags, HOST_AUTHED) && !signaling_flag_check(flags, HOST_AUTH_REQUEST) &&
            signaling_flag_check(flags, USER_AUTHED) && !signaling_flag_check(flags, USER_AUTH_REQUEST));
}

/**
 * @return 1 if flag is set, 0 otherwise
 */
int signaling_flag_check(uint8_t flags, int f) {
    return (flags & (1 << f)) > 0;
}

/**
 * Set flag f in flags.
 *
 * @return flags with f set to 1
 */
void signaling_flag_set(uint8_t *flags, int f) {
    *flags |= 1 << (int) f;
}

/**
 * Unset flag f in flags.
 *
 * @return flags with f set to 1
 */
void signaling_flag_unset(uint8_t *flags, int f) {
    *flags &= ~(1 << (int) f);
}

