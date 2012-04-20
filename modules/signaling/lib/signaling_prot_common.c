/*
 * signaling_prot_common.c
 *
 *  Created on: Nov 11, 2010
 *      Author: ziegeldorf
 */

#include <string.h>
#include <stdlib.h>

#include "lib/core/common.h"
#include "lib/core/debug.h"
#include "lib/core/ife.h"
#include "lib/core/builder.h"
#include "signaling_prot_common.h"
#include "signaling_common_builder.h"
#include "signaling_x509_api.h"
#include "signaling_user_management.h"
#include "signaling_user_api.h"


const char *signaling_connection_status_name(int status)
{
    switch (status) {
    case SIGNALING_CONN_PROCESSING:
        return "PROCESSING";
    case SIGNALING_CONN_BLOCKED:
        return "BLOCKED";
    case SIGNALING_CONN_ALLOWED:
        return "ALLOWED";
    default:
        return "UNKOWN";
    }
}

UNUSED static const char *signaling_user_key_name(int key_type)
{
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

static void signaling_param_print_field(UNUSED const char *prefix, const uint16_t length, const unsigned char *p_content)
{
    char buf[length + 1];

    if (length == 0) {
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
void signaling_param_application_context_print(const struct signaling_param_app_context *const param_app_ctx)
{
    const uint8_t                    *p_content;
    const struct signaling_port_pair *pp;
    int                               i;

    if (param_app_ctx == NULL) {
        HIP_DEBUG("No appinfo parameter given.\n");
        return;
    }

    p_content = (const uint8_t *) (param_app_ctx + 1);

    HIP_DEBUG("+------------ APP INFO START ----------------------\n");
    HIP_DEBUG("Sockets: (%d) \t\t", ntohs(param_app_ctx->port_count));
    pp = (const struct signaling_port_pair *) p_content;
    for (i = 0; i < ntohs(param_app_ctx->port_count); i++) {
        if (pp[i].src_port == 0 && pp[i].dst_port == 0 && i > 0) {
            break;
        }
        HIP_DEBUG("[%d: %d -> %d]\n", i, ntohs(pp[i].src_port), ntohs(pp[i].dst_port));
    }

    p_content += ntohs(param_app_ctx->port_count) * sizeof(struct signaling_port_pair);

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
 * @param host_ctx  the host context to print
 * @param prefix    prefix is prepended to all output of this function
 * @param header    0 for no header, 1 to print a header
 */
void signaling_host_context_print(const struct signaling_host_context *const host_ctx,
                                  UNUSED const char *prefix, const int header)
{
    if (host_ctx == NULL) {
        HIP_DEBUG("%sNo host ctx parameter given.\n", prefix);
        return;
    }
    if (header) {
        HIP_DEBUG("%s+------------ HOST CONTEXT START ----------------------\n", prefix);
    }
    HIP_DEBUG("%s  Host context \n", prefix);
    HIP_DEBUG("%s  \tHost Name:\t %s\n", prefix, host_ctx->host_name);
    HIP_DEBUG("%s  \tOperating System:\t %s\n", prefix, host_ctx->host_os);
    HIP_DEBUG("%s  \tKernel:\t %s\n", prefix, host_ctx->host_kernel);
    HIP_DEBUG("%s  \tCertificate:\t\t %s\n", prefix, host_ctx->host_certs);
    if (header) {
        HIP_DEBUG("%s+------------ HOST CONTEXT END   ----------------------\n", prefix);
    }
}

/**
 * Print the internal application context structure.
 *
 * @param app_ctx   the application context to print
 * @param prefix    prefix is prepended to all output of this function
 * @param header    0 for no header, 1 to print a header
 */
void signaling_application_context_print(const struct signaling_application_context *const app_ctx,
                                         UNUSED const char *prefix, const int header)
{
    if (app_ctx == NULL) {
        HIP_DEBUG("%sNo application ctx parameter given.\n", prefix);
        return;
    }
    if (header) {
        HIP_DEBUG("%s+------------ APPLICATION CONTEXT START ----------------------\n", prefix);
    }
    HIP_DEBUG("%s  Application context \n", prefix);
    HIP_DEBUG("%s  \tApplication DN:\t %s\n", prefix, app_ctx->application_dn);
    HIP_DEBUG("%s  \tAC Issuer DN:\t %s\n", prefix, app_ctx->issuer_dn);
    HIP_DEBUG("%s  \tRequirements:\t %s\n", prefix, app_ctx->requirements);
    HIP_DEBUG("%s  \tGroups:\t\t %s\n", prefix, app_ctx->groups);
    if (header) {
        HIP_DEBUG("%s+------------ APPLICATION CONTEXT END   ----------------------\n", prefix);
    }
}

/**
 * Print the internal user context structure.
 *
 * @param usr_ctx   the user context to print
 * @param prefix    prefix is prepended to all output of this function
 * @param header    0 for no header, 1 to print a header
 */
void signaling_user_context_print(const struct signaling_user_context *const user_ctx,
                                  UNUSED const char *prefix, const int header)
{
    X509_NAME *subj_name;
    char       subj_name_string[SIGNALING_USER_ID_MAX_LEN] = { "<decoding error>" };

    if (user_ctx == NULL) {
        HIP_DEBUG("%sNo user ctx parameter given.\n", prefix);
        return;
    }

    /* Decode users name */
    if (!signaling_DER_to_X509_NAME(user_ctx->subject_name, user_ctx->subject_name_len, &subj_name)) {
        X509_NAME_oneline(subj_name, subj_name_string, SIGNALING_USER_ID_MAX_LEN);
    }

    if (header) {
        HIP_DEBUG("%s+------------- USER CONTEXT START ----------------------\n", prefix);
    }
    HIP_DEBUG("%s  User context \n", prefix);
    HIP_DEBUG("%s  \tSystem UID:\t %d\n", prefix, user_ctx->uid);
    HIP_DEBUG("%s  \tUser Name:\t %s\n", prefix, subj_name_string);
    HIP_DEBUG("%s  \tUser Key:\t %s\n", prefix, signaling_user_key_name(user_ctx->rdata.algorithm));
    HIP_DEBUG("%s  \tUser Key RR:\t Size %d\n", prefix, user_ctx->key_rr_len == -1 ? 0 : user_ctx->key_rr_len - sizeof(struct hip_host_id_key_rdata));
    //if (user_ctx->key_rr_len > 0)
    //    HIP_HEXDUMP(prefix, user_ctx->pkey, user_ctx->key_rr_len - sizeof(struct hip_host_id_key_rdata));
    if (header) {
        HIP_DEBUG("%s+------------ USER CONTEXT END   ----------------------\n", prefix);
    }
}

/**
 * Print the internal connection context structure.
 *
 * @param ctx       the connection context to print
 * @param prefix    prefix is prepended to all output of this function
 */
void signaling_connection_context_print(const struct signaling_connection_context *const ctx, UNUSED const char *prefix)
{
    if (ctx == NULL) {
        HIP_DEBUG("%sNo connection context struct given.\n", prefix);
        return;
    }

    HIP_DEBUG("%s+------------ CONNECTION CONTEXT START ----------------------\n", prefix);
    signaling_user_context_print(&ctx->user, prefix, 0);
    HIP_DEBUG("%sUser DB Entry at:\t %p\n", prefix, ctx->userdb_entry);
    signaling_application_context_print(&ctx->app, prefix, 0);
    signaling_host_context_print(&ctx->host, prefix, 0);
    HIP_DEBUG("%s+------------ CONNECTION CONTEXT END   ----------------------\n", prefix);
}

/**
 * Print the internal connection structure.
 *
 * @param conn      the connection to print
 * @param prefix    prefix is prepended to all output of this function
 */
void signaling_connection_print(const struct signaling_connection *const conn, UNUSED const char *const prefix)
{
    char prefix_buf[strlen(prefix) + 2];
    sprintf(prefix_buf, "%s\t", prefix);

    if (conn == NULL) {
        HIP_DEBUG("%sNo connection struct given.\n", prefix);
        return;
    }

    HIP_DEBUG("%s+------------ CONNECTION START ----------------------\n", prefix);
    HIP_DEBUG("%s  Identifier:\t\t %d\n", prefix, conn->id);
    HIP_DEBUG("%s  Src Port  :\t\t %d\n", prefix, conn->src_port);
    HIP_DEBUG("%s  Dst Port  :\t\t %d\n", prefix, conn->dst_port);
    fprintf(stderr, "\n");
    HIP_DEBUG("%s+------------ CONNECTION END   ----------------------\n", prefix);
}

/**
 * Prints the connection identifier parameter.
 *
 * @param conn_id the connection identifier parameter to print
 */
void signaling_param_connection_identifier_print(const struct signaling_param_connection_identifier *const conn_id)
{
    if (conn_id == NULL) {
        HIP_DEBUG("No connection identifier parameter given.\n");
        return;
    }
    HIP_DEBUG("+------------ CONNECTION IDENTIFIER START ----------------------\n");
    HIP_DEBUG("Connection ID:\t %d \n", ntohl(conn_id->id));
    HIP_DEBUG("+------------ CONNECTION IDENTIFIER END   ----------------------\n");
}

/**
 * Prints the user context parameter.
 *
 * @param app the user context parameter to print
 */
void signaling_param_user_context_print(const struct signaling_param_user_context *const userinfo)
{
    const uint8_t *p_content;

    if (userinfo == NULL) {
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
 * Initializes the given host context to default values.
 * Memory for context has to be allocated and freed by the caller.
 *
 * @param host_ctx a pointer to the host context that should be initialized
 *
 * @return negative value on error, 0 on success
 */
int signaling_init_host_context(struct signaling_host_context *const host_ctx)
{
    int err = 0;

    HIP_IFEL(!host_ctx, -1, "Host context has to be allocated before initialization\n");

    host_ctx->host_kernel_len = -1;
    host_ctx->host_name_len   = -1;
    host_ctx->host_os_len     = -1;
    host_ctx->host_certs_len  = -1;

    //host_ctx->host_id[0]     = '\0';
    host_ctx->host_kernel[0] = '\0';
    host_ctx->host_name[0]   = '\0';
    host_ctx->host_os[0]     = '\0';
    host_ctx->host_certs[0]  = '\0';

out_err:
    return err;
}

/**
 * Initializes the given application context to default values.
 * Memory for context has to be allocated and freed by the caller.
 *
 * @param app_ctx a pointer to the application context that should be initialized
 *
 * @return negative value on error, 0 on success
 */
int signaling_init_application_context(struct signaling_application_context *const app_ctx)
{
    int err = 0;
    int i   = 0;
    HIP_IFEL(!app_ctx, -1, "Application context has to be allocated before initialization\n");

    app_ctx->application_dn[0] = '\0';
    app_ctx->issuer_dn[0]      = '\0';
    app_ctx->groups[0]         = '\0';
    app_ctx->requirements[0]   = '\0';
    for (i = 0; i < SIGNALING_MAX_SOCKETS; i++) {
        app_ctx->sockets[i].src_port = 0;
        app_ctx->sockets[i].dst_port = 0;
    }
    app_ctx->connections = 0;
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
int signaling_init_user_context(struct signaling_user_context *const user_ctx)
{
    int err = 0;

    HIP_IFEL(!user_ctx, -1, "User context has to be allocated before initialization\n");

    user_ctx->uid              = -1;    // no user id
    user_ctx->subject_name_len = -1;     // no subject name
    user_ctx->key_rr_len       = -1;     // no user public key (but key_rdata still has size 4)
    user_ctx->rdata.algorithm  = 0;      // no user public key algorithm
    user_ctx->rdata.flags      = 0;      // unused
    user_ctx->rdata.protocol   = 0;      // unused
    user_ctx->pkey[0]          = '\0';
    user_ctx->subject_name[0]  = '\0';

out_err:
    return err;
}

int signaling_init_app_context_from_msg(struct signaling_application_context *const ctx,
                                        const struct hip_common *const msg,
                                        UNUSED enum direction dir)
{
    int                          err     = 0;
    int                          tmp_len = 0;
    int                          i       = 0;
    const uint8_t               *tmp_ptr = NULL;
    const struct hip_tlv_common *param   = NULL;


    HIP_IFEL(!msg,  -1, "Cannot initialize from NULL-msg\n");

    param = hip_get_param(msg, HIP_PARAM_SIGNALING_APP_INFO_NAME);
    if (param && hip_get_param_type(param) == HIP_PARAM_SIGNALING_APP_INFO_NAME) {
        tmp_len = ntohs(((const struct signaling_param_app_info_name *) param)->app_dn_length);
        memcpy(ctx->application_dn, ((const struct signaling_param_app_info_name *) param)->application_dn,
               tmp_len);
        ctx->application_dn[tmp_len] = '\0';

        tmp_ptr = (const uint8_t *) &((const struct signaling_param_app_info_name *) param)->application_dn[tmp_len];
        tmp_len = ntohs(((const struct signaling_param_app_info_name *) param)->issuer_dn_length);
        memcpy(ctx->issuer_dn, tmp_ptr, tmp_len);
        ctx->issuer_dn[tmp_len] = '\0';
    }

    param = hip_get_param(msg, HIP_PARAM_SIGNALING_APP_INFO_CONNECTIONS);
    if (param && hip_get_param_type(param) == HIP_PARAM_SIGNALING_APP_INFO_CONNECTIONS) {
        ctx->connections = ntohs(((const struct signaling_param_app_info_connections *) param)->connection_count);
        tmp_len          = ntohs(((const struct signaling_param_app_info_connections *) param)->port_pair_length);
        for (i = 0; i < tmp_len; i++) {
            ctx->sockets[i].src_port = ntohs(((const struct signaling_param_app_info_connections *) param)->sockets[2 * i]);
            ctx->sockets[i].dst_port = ntohs(((const struct signaling_param_app_info_connections *) param)->sockets[2 * i + 1]);
        }
    }

    param = hip_get_param(msg, HIP_PARAM_SIGNALING_APP_INFO_QOS_CLASS);
    if (param && hip_get_param_type(param) == HIP_PARAM_SIGNALING_APP_INFO_QOS_CLASS) {
        //TODO handler for the packet type APP_INFO_QOS_CLASS
    }

    param = hip_get_param(msg, HIP_PARAM_SIGNALING_APP_INFO_REQUIREMENTS);
    if (param && hip_get_param_type(param) == HIP_PARAM_SIGNALING_APP_INFO_REQUIREMENTS) {
        //TODO handler for the packet type APP_INFO_REQUIREMENTS
        ctx->requirements[0] = '\0';
    }

out_err:
    return err;
}

int signaling_init_host_context_from_msg(struct signaling_host_context *const ctx,
                                         const struct hip_common *const msg,
                                         UNUSED enum direction dir)
{
    int                                        err         = 0;
    const struct hip_tlv_common               *param       = NULL;
    const struct signaling_param_host_info_os *tmp_info_os = NULL;
    //const uint8_t               *p_contents = NULL;

    HIP_IFEL(!msg,  -1, "Cannot initialize from NULL-msg\n");

    // In case of R1 we have to check the policy for the packet from Initiator
    // In case of I2 we have to check the policy for the packet from Responder
    memcpy(&ctx->host_id, &msg->hits, sizeof(struct in6_addr));

    param = hip_get_param(msg, HIP_PARAM_SIGNALING_HOST_INFO_OS);
    if (param && hip_get_param_type(param) == HIP_PARAM_SIGNALING_HOST_INFO_OS) {
        tmp_info_os      = (const struct signaling_param_host_info_os *) param;
        ctx->host_os_len = ntohs(tmp_info_os->os_len);
        memcpy(&ctx->host_os, &tmp_info_os->os_name, ctx->host_os_len);
        ctx->host_os[ctx->host_os_len - 1] = '\0';

        ctx->host_os_ver_len = ntohs(tmp_info_os->os_version_len);
        memcpy(&ctx->host_os_version, &tmp_info_os->os_version, ctx->host_os_ver_len);
        ctx->host_os_version[ctx->host_os_ver_len - 1] = '\0';
    }

    param = hip_get_param(msg, HIP_PARAM_SIGNALING_HOST_INFO_KERNEL);
    if (param && hip_get_param_type(param) == HIP_PARAM_SIGNALING_HOST_INFO_KERNEL) {
        ctx->host_kernel_len = ntohs(param->length);
        memcpy(ctx->host_kernel, ((const struct signaling_param_host_info_kernel *) param)->kernel,
               ctx->host_kernel_len);
        ctx->host_kernel[ctx->host_kernel_len - 1] = '\0';
    }

    param = hip_get_param(msg, HIP_PARAM_SIGNALING_HOST_INFO_ID);
    if (param && hip_get_param_type(param) == HIP_PARAM_SIGNALING_HOST_INFO_ID) {
        //TODO left for now because the case is not trivial. HIP_PARAM_HOST_ID is also the same
    }

    param = hip_get_param(msg, HIP_PARAM_SIGNALING_HOST_INFO_CERTS);
    if (param && hip_get_param_type(param) == HIP_PARAM_SIGNALING_HOST_INFO_CERTS) {
        //TODO handler for this case left for later
    }
out_err:
    return err;
}

int signaling_init_user_context_from_msg(struct signaling_user_context *const ctx,
                                         struct hip_common *msg,
                                         UNUSED enum direction dir)
{
    int                                        err          = 0;
    const struct hip_tlv_common               *param        = NULL;
    const struct signaling_param_user_info_id *user_ctx     = NULL;
    uint16_t                                   header_len   = 0;
    uint16_t                                   key_len      = 0;
    uint16_t                                   sub_name_len = 0;

    HIP_IFEL(!msg,  -1, "Cannot initialize from NULL-msg\n");


    param = hip_get_param(msg, HIP_PARAM_SIGNALING_USER_INFO_ID);
    if (param && hip_get_param_type(param) == HIP_PARAM_SIGNALING_USER_INFO_ID) {
        user_ctx   = (const struct signaling_param_user_info_id *) param;
        header_len = sizeof(struct signaling_param_user_info_id) -
                     sizeof(ctx->pkey) -
                     sizeof(ctx->subject_name);
        key_len = ntohs(user_ctx->prr_length) -
                  sizeof(struct hip_host_id_key_rdata);
        sub_name_len = ntohs(user_ctx->user_dn_length);

        /*Sanity Checking*/
        HIP_IFEL(sub_name_len >= SIGNALING_USER_ID_MAX_LEN,
                 -1, "Got bad length for domain identifier: %d\n", sub_name_len);
        HIP_IFEL(key_len > SIGNALING_USER_KEY_MAX_LEN,
                 -1, "Got bad key length: %d\n", key_len);
        HIP_IFEL(header_len + key_len + sub_name_len > hip_get_param_contents_len(param) + 4,
                 -1, "Header+ Key + Sub Name length exceeds parameter size: %d\n", header_len + key_len + sub_name_len);

        ctx->subject_name_len = ntohs(user_ctx->user_dn_length);
        ctx->key_rr_len       = ntohs(user_ctx->prr_length);

        ctx->rdata.algorithm = user_ctx->rdata.algorithm;
        ctx->rdata.protocol  = user_ctx->rdata.protocol;
        ctx->rdata.flags     = ntohs(user_ctx->rdata.flags);


        memcpy(ctx->pkey, user_ctx->pkey, key_len);
        memcpy(ctx->subject_name, &user_ctx->pkey[key_len], sub_name_len);
    }

    param = hip_get_param(msg, HIP_PARAM_SIGNALING_USER_INFO_CERTS);
    if (param && hip_get_param_type(param) == HIP_PARAM_SIGNALING_USER_INFO_CERTS) {
        //TODO handler for this case
    }

out_err:
    return err;
}

/**
 * Initializes the given signaling connection to default values.
 *
 * @param conn a pointer to the connection context to be initialized
 *
 * @return negative value on error, 0 on success
 */
int signaling_init_connection(struct signaling_connection *const conn)
{
    int err = 0;

    HIP_IFEL(!conn, -1, "Connection context has to be allocated before initialization\n");
    conn->id       = 0;
    conn->src_port = 0;
    conn->dst_port = 0;
out_err:
    return err;
}

/**
 * Initializes the given signaling connection from information found in the message.
 * Values that are not given in the  message are initialized to default.
 *
 * @param ctx   a pointer to the connection context that should be initialized
 * @param msg   a msg that contains connection context information
 * @param dir   init the incoming (dir = IN), the outgoing (dir = OUT)
 *              or the first unassigned (dir = FWD) connection context from this message
 *
 * @return negative value on error, 0 on success
 */
int signaling_init_connection_from_msg(struct signaling_connection *const conn,
                                       const struct hip_common *const msg,
                                       UNUSED enum direction dir)
{
    int err = 0;
    //uint16_t                     tmp_port = 0;
    const struct hip_tlv_common *param = NULL;

    /* init and fill the connection context */
    HIP_IFEL(signaling_init_connection(conn), -1, "Failed to init connection context\n");

    param = hip_get_param(msg, HIP_PARAM_SIGNALING_CONNECTION);
    if (param && hip_get_param_type(param) == HIP_PARAM_SIGNALING_CONNECTION) {
        signaling_copy_connection(conn, (const struct signaling_connection *) (param + 1));
    }
    conn->id       = 0;
    conn->src_port = ntohs(conn->src_port);
    conn->dst_port = ntohs(conn->dst_port);

    return 0;
out_err:
    return err;
}

int signaling_update_connection_from_msg(struct signaling_connection *const conn,
                                         const struct hip_common *const msg,
                                         UNUSED enum direction dir)
{
    int                          err   = 0;
    const struct hip_tlv_common *param = NULL;

    /* sanity checks */
    HIP_IFEL(!conn, -1, "Cannot initialize NULL-context\n");
    HIP_IFEL(!msg,  -1, "Cannot initialize from NULL-msg\n");

    param = hip_get_param(msg, HIP_PARAM_SIGNALING_CONNECTION);
    if (param && hip_get_param_type(param) == HIP_PARAM_SIGNALING_CONNECTION) {
        conn->id       = ntohl(((const struct signaling_connection *) param)->id);
        conn->src_port = ntohl(((const struct signaling_connection *) param)->src_port);
        conn->dst_port = ntohl(((const struct signaling_connection *) param)->dst_port);
    }

    signaling_update_flags_from_connection_id(msg, conn);

out_err:
    return err;
}

int signaling_update_info_flags_from_msg(struct signaling_connection_flags *flags,
                                         const struct hip_common *const msg,
                                         UNUSED enum direction dir)
{
    int                          err   = 0;
    const struct hip_tlv_common *param = NULL;

    /* sanity checks */
    HIP_IFEL(!msg,      -1, "Cannot initialize from NULL-msg\n");
    HIP_IFEL(!flags,    -1, "Cannot initialize NULL flags\n");
    signaling_info_req_flag_init(&flags->flag_info_requests);
    signaling_service_info_flag_init(&flags->flag_services);

    /*paramters for the host information from the end-point*/
    param = hip_get_param(msg, HIP_PARAM_SIGNALING_HOST_INFO_OS);
    if (param && hip_get_param_type(param) == HIP_PARAM_SIGNALING_HOST_INFO_OS) {
        signaling_info_req_flag_set(&flags->flag_info_requests, HOST_INFO_OS);
    }

    param = hip_get_param(msg, HIP_PARAM_SIGNALING_HOST_INFO_ID);
    if (param && hip_get_param_type(param) == HIP_PARAM_SIGNALING_HOST_INFO_ID) {
        signaling_info_req_flag_set(&flags->flag_info_requests, HOST_INFO_ID);
    }

    param = hip_get_param(msg, HIP_PARAM_SIGNALING_HOST_INFO_KERNEL);
    if (param && hip_get_param_type(param) == HIP_PARAM_SIGNALING_HOST_INFO_KERNEL) {
        signaling_info_req_flag_set(&flags->flag_info_requests, HOST_INFO_KERNEL);
    }

    param = hip_get_param(msg, HIP_PARAM_SIGNALING_HOST_INFO_CERTS);
    if (param && hip_get_param_type(param) == HIP_PARAM_SIGNALING_HOST_INFO_CERTS) {
        signaling_info_req_flag_set(&flags->flag_info_requests, HOST_INFO_CERTS);
    }

    /*paramters for the user information from the end-point*/
    param = hip_get_param(msg, HIP_PARAM_SIGNALING_USER_INFO_ID);
    if (param && hip_get_param_type(param) == HIP_PARAM_SIGNALING_USER_INFO_ID) {
        signaling_info_req_flag_set(&flags->flag_info_requests, USER_INFO_ID);
    }

    param = hip_get_param(msg, HIP_PARAM_SIGNALING_USER_INFO_CERTS);
    if (param && hip_get_param_type(param) == HIP_PARAM_SIGNALING_USER_INFO_CERTS) {
        signaling_info_req_flag_set(&flags->flag_info_requests, USER_INFO_CERTS);
    }

    /*paramters for the application information from the end-point*/
    param = hip_get_param(msg, HIP_PARAM_SIGNALING_APP_INFO_NAME);
    if (param && hip_get_param_type(param) == HIP_PARAM_SIGNALING_APP_INFO_NAME) {
        signaling_info_req_flag_set(&flags->flag_info_requests, APP_INFO_NAME);
    }

    param = hip_get_param(msg, HIP_PARAM_SIGNALING_APP_INFO_CONNECTIONS);
    if (param && hip_get_param_type(param) == HIP_PARAM_SIGNALING_APP_INFO_CONNECTIONS) {
        signaling_info_req_flag_set(&flags->flag_info_requests, APP_INFO_CONNECTIONS);
    }

    param = hip_get_param(msg, HIP_PARAM_SIGNALING_APP_INFO_REQUIREMENTS);
    if (param && hip_get_param_type(param) == HIP_PARAM_SIGNALING_APP_INFO_REQUIREMENTS) {
        signaling_info_req_flag_set(&flags->flag_info_requests, APP_INFO_REQUIREMENTS);
    }

    param = hip_get_param(msg, HIP_PARAM_SIGNALING_APP_INFO_QOS_CLASS);
    if (param && hip_get_param_type(param) == HIP_PARAM_SIGNALING_APP_INFO_QOS_CLASS) {
        signaling_info_req_flag_set(&flags->flag_info_requests, APP_INFO_QOS_CLASS);
    }

    /*paramters for the response to service offer information from the end-point*/
    param = hip_get_param(msg, HIP_PARAM_SIGNALING_SERVICE_ACK);
    if (param && hip_get_param_type(param) == HIP_PARAM_SIGNALING_SERVICE_ACK) {
        signaling_service_info_flag_set(&flags->flag_services, SERVICE_ACK_U);
    }

    param = hip_get_param(msg, HIP_PARAM_SIGNALING_SERVICE_NACK);
    if (param && hip_get_param_type(param) == HIP_PARAM_SIGNALING_SERVICE_NACK) {
        signaling_service_info_flag_set(&flags->flag_services, SERVICE_NACK);
    }

    param = hip_get_param(msg, HIP_PARAM_SIGNALING_SERVICE_OFFER);
    if (param && hip_get_param_type(param) == HIP_PARAM_SIGNALING_SERVICE_OFFER) {
        signaling_service_info_flag_set(&flags->flag_services, SERVICE_OFFER);
    }

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
int signaling_copy_connection(struct signaling_connection *const dst,
                              const struct signaling_connection *const src)
{
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
                                      enum direction dir)
{
    int err = 0;

    HIP_IFEL(!ctx, -1, "Connection context has to be allocated before initialization\n");
    ctx->service_offer_id    = 0;
    ctx->service_type        = 0;
    ctx->service_description = 0;
    ctx->service_options     = 0;

    ctx->direction    = dir;
    ctx->userdb_entry = NULL;
    HIP_IFEL(signaling_init_application_context(&ctx->app),
             -1, "Could not init outgoing application context\n");
    HIP_IFEL(signaling_init_user_context(&ctx->user),
             -1, "Could not init user context\n");
    HIP_IFEL(signaling_init_host_context(&ctx->host),
             -1, "Could not init outgoing host context\n");

out_err:
    return err;
}

/**
 * @return -1 if the port list is full, other wise the position where the ports were added
 */
int signaling_connection_add_port_pair(UNUSED uint16_t src_port, UNUSED uint16_t dst_port,
                                       struct signaling_connection *const conn)
{
    int i;
    int err = -1;

    /* sanity checks */
    HIP_IFEL(!conn, -1, "Need connection context to add port pair\n");

    for (i = 0; i < SIGNALING_MAX_SOCKETS; i++) {
    }

out_err:
    return err;
}

/**
 * Copies a port pair from src to dst.
 *
 * @param dst   the destination struct
 * @param src   the source struct
 *
 * @return negative value on error, 0 on success
 */
int signaling_copy_port_pair(struct signaling_port_pair *const dst,
                             const struct signaling_port_pair *const src)
{
    if (!dst || !src) {
        HIP_ERROR("Cannot copy from/to NULL struct \n");
        return -1;
    }
    memcpy(dst, src, sizeof(struct signaling_port_pair));
    return 0;
}

/**
 * Copies a complete service offer parameter of unsigned typefrom src to dst.
 *
 * @param dst   the destination struct
 * @param src   the source struct
 *
 * @return negative value on error, 0 on success
 */
int signaling_copy_service_offer(struct signaling_param_service_offer *const dst,
                                 const struct signaling_param_service_offer *const src)
{
    if (!dst || !src) {
        HIP_ERROR("Cannot copy from/to NULL struct \n");
        return -1;
    }
    memcpy(dst, src, sizeof(struct signaling_param_service_offer));
    return 0;
}

/**
 * Copies a complete service offer parameter of signed type from src to dst.
 *
 * @param dst   the destination struct
 * @param src   the source struct
 *
 * @return negative value on error, 0 on success
 */
int signaling_copy_service_offer_s(struct signaling_param_service_offer_s *const dst,
                                   const struct signaling_param_service_offer_s *const src)
{
    if (!dst || !src) {
        HIP_ERROR("Cannot copy from/to NULL struct \n");
        return -1;
    }
    memcpy(dst, src, sizeof(struct signaling_param_service_offer_s));
    return 0;
}

/**
 * Copies a complete service offer parameter of signed type from src to dst.
 *
 * @param dst   the destination struct
 * @param src   the source struct
 *
 * @return negative value on error, 0 on success
 */
int signaling_copy_service_ack(struct signaling_param_service_ack *const dst,
                               const struct signaling_param_service_ack *const src)
{
    if (!dst || !src) {
        HIP_ERROR("Cannot copy from/to NULL struct \n");
        return -1;
    }
    memcpy(dst, src, sizeof(struct signaling_param_service_ack));
    return 0;
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
int signaling_init_connection_context_from_msg(struct signaling_connection_context *const ctx,
                                               struct hip_common *msg,
                                               enum direction dir)
{
    int err = 0;

    /* sanity checks */
    HIP_IFEL(!ctx, -1, "Cannot initialize NULL-context\n");
    if (dir == FWD) {
        signaling_init_app_context_from_msg(&ctx->app,   msg, dir);
        signaling_init_host_context_from_msg(&ctx->host, msg, dir);
        signaling_init_user_context_from_msg(&ctx->user, msg, dir);
    } else if (dir == OUT) {
        //There should be no information in the channel without requesting for it.
        memcpy(&ctx->host.host_id, &msg->hitr, sizeof(struct in6_addr));
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
int signaling_copy_connection_context(struct signaling_connection_context *const dst,
                                      const struct signaling_connection_context *const src)
{
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
    int err     = 0;
    int tmp_len = 0;
//    const struct signaling_param_user_auth_request *param_usr_auth;
    const struct signaling_param_service_offer *param_service_offer;
    //const uint8_t                                *p_contents;

    /* sanity checks */
    HIP_IFEL(!conn,           -1, "Cannot update flags of NULL-connection\n");
    HIP_IFEL(!msg,            -1, "Cannot update flags from NULL-msg\n");

    /* This flags the local user. */
/*
 *  if ((param_usr_auth = hip_get_param(msg, HIP_PARAM_SIGNALING_USER_REQ_S))) {
 *      signaling_flag_set(&conn->ctx_out.flags, USER_AUTH_REQUEST);
 *  } else {
 *      signaling_flag_unset(&conn->ctx_out.flags, USER_AUTH_REQUEST);
 *    }
 */

    /* This flags the remote user */
/*
 *  if ((param_usr_auth = hip_get_param(msg, HIP_PARAM_SIGNALING_USER_REQ_U))) {
 *      signaling_flag_set(&conn->ctx_in.flags, USER_AUTH_REQUEST);
 *  } //else if (!signaling_flag_check(conn->ctx_in.flags, USER_AUTH_REQUEST)) {
 *    //  signaling_flag_unset(&conn->ctx_in.flags, USER_AUTH_REQUEST);
 *    //}
 */

    if ((param_service_offer = hip_get_param(msg, HIP_PARAM_SIGNALING_SERVICE_OFFER))) {
        tmp_len = param_service_offer->length;
        tmp_len = (tmp_len - (sizeof(param_service_offer->service_offer_id) +
                              sizeof(param_service_offer->service_type) +
                              sizeof(param_service_offer->service_description)))
                  / sizeof(param_service_offer->endpoint_info_req[0]);
        //p_contents = (const uint8_t *) param_service_offer + sizeof(param_service_offer->service_offer_id) +
        //             sizeof(param_service_offer->service_type) +
        //             sizeof(param_service_offer->service_description);

/*        for (i = 0; i < tmp_len; i++) {
 *          memcpy(&tmp_info, p_contents, sizeof(param_service_offer->endpoint_info_req[i]));
 *          switch (tmp_info) {
 *          case HOST_INFO_KERNEL:
 *              signaling_flag_set(&conn->ctx_in.flags, HOST_INFO_KERNEL);
 *              break;
 *          case HOST_INFO_OS:
 *              signaling_flag_set(&conn->ctx_in.flags, HOST_INFO_OS);
 *              break;
 *          case HOST_INFO_ID:
 *              signaling_flag_set(&conn->ctx_in.flags, HOST_INFO_ID);
 *              break;
 *          case HOST_INFO_CERTS:
 *              signaling_flag_set(&conn->ctx_in.flags, HOST_INFO_CERTS);
 *              break;
 *          default:
 *              break;
 *          }
 *      }*/
    }
out_err:
    return err;
}

/**
 * Print the internal connection structure.
 *
 * @param conn      the connection to print
 * @param prefix    prefix is prepended to all output of this function
 */
/*
 * void signaling_flags_print(struct flags_connection_context flags, UNUSED const char *const prefix)
 * {
 *  char buf[100];
 *  memset(buf, 0, sizeof(buf));
 *
 *  sprintf(buf + strlen(buf), "HA  = %d | ", signaling_flag_check(flags, HOST_AUTHED));
 *  sprintf(buf + strlen(buf), "HAR = %d | ", signaling_flag_check(flags, HOST_AUTH_REQUEST));
 *  sprintf(buf + strlen(buf), "UA  = %d | ", signaling_flag_check(flags, USER_AUTHED));
 *  sprintf(buf + strlen(buf), "UAR = %d | ", signaling_flag_check(flags, USER_AUTH_REQUEST));
 *
 *
 *
 *  HIP_DEBUG("%s  Flags: %s int = %d \n", prefix, buf, flags);
 * }
 *
 * int signaling_flag_check_auth_complete(struct flags_connection_context flags)
 * {
 *  return signaling_flag_check(flags, HOST_AUTHED) && !signaling_flag_check(flags, HOST_AUTH_REQUEST) &&
 *         signaling_flag_check(flags, USER_AUTHED) && !signaling_flag_check(flags, USER_AUTH_REQUEST);
 * }
 */

/**
 * @return 1 if flag is set, 0 otherwise
 */
/*int signaling_flag_check(uint8_t flags, int f) {
 *  return (flags & (1 << f)) > 0;
 * }*/
/*
 * int signaling_flag_check(struct flags_connection_context flags, int f)
 * {
 *  switch (f) {
 *  case USER_AUTH_REQUEST:
 *      return (flags.USER_AUTH_REQUEST) ? 1 : 0;
 *      break;
 *  case USER_AUTHED:
 *      return (flags.USER_AUTHED) ? 1 : 0;
 *      break;
 *  case HOST_AUTH_REQUEST:
 *      return (flags.HOST_AUTH_REQUEST) ? 1 : 0;
 *      break;
 *  case HOST_AUTHED:
 *      return (flags.HOST_AUTHED) ? 1 : 0;
 *      break;
 *  default:
 *      return 0;
 *      break;
 *  }
 *  return 0;
 * }
 */

/**
 * Set flag f in flags.
 *
 * @return flags with f set to 1
 */
/*
 * void signaling_flag_set(struct flags_connection_context *flags, int f)
 * {
 *  switch (f) {
 *  case USER_AUTH_REQUEST:
 *      flags->USER_AUTH_REQUEST = 1;
 *      break;
 *  case USER_AUTHED:
 *      flags->USER_AUTHED = 1;
 *      break;
 *  case HOST_AUTH_REQUEST:
 *      flags->HOST_AUTH_REQUEST = 1;
 *      break;
 *  case HOST_AUTHED:
 *      flags->HOST_AUTHED = 1;
 *      break;
 *  default:
 *      break;
 *  }
 * }
 */

/**
 * Unset flag f in flags.
 *
 * @return flags with f set to 1
 */
/*
 * void signaling_flag_unset(uint8_t *flags, int f) {
 * *flags &= ~(1 << (int) f);
 * }
 */
/*
 * void signaling_flag_unset(struct flags_connection_context *flags, int f)
 * {
 *  switch (f) {
 *  case USER_AUTH_REQUEST:
 *      flags->USER_AUTH_REQUEST = 0;
 *      break;
 *  case USER_AUTHED:
 *      flags->USER_AUTHED = 0;
 *      break;
 *  case HOST_AUTH_REQUEST:
 *      flags->HOST_AUTH_REQUEST = 0;
 *      break;
 *  case HOST_AUTHED:
 *      flags->HOST_AUTHED = 0;
 *      break;
 *
 *  default:
 *      break;
 *  }
 * }
 */
void signaling_flag_init(struct flags_connection_context *flags)
{
    flags->USER_AUTH_REQUEST = 0;
    flags->USER_AUTHED       = 0;
    flags->HOST_AUTH_REQUEST = 0;
    flags->HOST_AUTHED       = 0;
}

void signaling_info_req_flags_print(struct signaling_flags_info_req *flags, const char *const prefix)
{
    char buf[100];
    memset(buf, 0, sizeof(buf));

    sprintf(buf + strlen(buf), "SO   = %d | ", signaling_info_req_flag_check(flags, SERVICE_OFFER));
    sprintf(buf + strlen(buf), "SAU  = %d | ", signaling_info_req_flag_check(flags, SERVICE_ACK_U));
    sprintf(buf + strlen(buf), "SAS  = %d | ", signaling_info_req_flag_check(flags, SERVICE_ACK_S));
    sprintf(buf + strlen(buf), "SNA  = %d | ", signaling_info_req_flag_check(flags, SERVICE_NACK));

    sprintf(buf + strlen(buf), "SOR  = %d | ", signaling_info_req_flag_check(flags, SERVICE_OFFER_RECV));
    sprintf(buf + strlen(buf), "SAUR = %d | ", signaling_info_req_flag_check(flags, SERVICE_ACK_U_RECV));
    sprintf(buf + strlen(buf), "SASR = %d | ", signaling_info_req_flag_check(flags, SERVICE_ACK_S_RECV));
    sprintf(buf + strlen(buf), "SNAR = %d | ", signaling_info_req_flag_check(flags, SERVICE_NACK_RECV));

    HIP_DEBUG("%s  Service Flags: %s \n", prefix, buf);
}

int signaling_info_req_flag_check(struct signaling_flags_info_req *flags, int f)
{
    switch (f) {
    case HOST_INFO_OS:
        return (flags->HOST_INFO_OS) ? 1 : 0;
        break;
    case HOST_INFO_KERNEL:
        return (flags->HOST_INFO_KERNEL) ? 1 : 0;
        break;
    case HOST_INFO_ID:
        return (flags->HOST_INFO_ID) ? 1 : 0;
        break;
    case HOST_INFO_CERTS:
        return (flags->HOST_INFO_CERTS) ? 1 : 0;
        break;
    case USER_INFO_ID:
        return (flags->USER_INFO_ID) ? 1 : 0;
        break;
    case USER_INFO_CERTS:
        return (flags->USER_INFO_CERTS) ? 1 : 0;
        break;
    case APP_INFO_NAME:
        return (flags->APP_INFO_NAME) ? 1 : 0;
        break;
    case APP_INFO_QOS_CLASS:
        return (flags->APP_INFO_QOS_CLASS) ? 1 : 0;
        break;
    case APP_INFO_CONNECTIONS:
        return (flags->APP_INFO_CONNECTIONS) ? 1 : 0;
        break;
    case APP_INFO_REQUIREMENTS:
        return (flags->APP_INFO_REQUIREMENTS) ? 1 : 0;
        break;

    case HOST_INFO_OS_RECV:
        return (flags->HOST_INFO_OS_RECV) ? 1 : 0;
        break;
    case HOST_INFO_KERNEL_RECV:
        return (flags->HOST_INFO_KERNEL_RECV) ? 1 : 0;
        break;
    case HOST_INFO_ID_RECV:
        return (flags->HOST_INFO_ID_RECV) ? 1 : 0;
        break;
    case HOST_INFO_CERTS_RECV:
        return (flags->HOST_INFO_CERTS_RECV) ? 1 : 0;
        break;
    case USER_INFO_ID_RECV:
        return (flags->USER_INFO_ID_RECV) ? 1 : 0;
        break;
    case USER_INFO_CERTS_RECV:
        return (flags->USER_INFO_CERTS_RECV) ? 1 : 0;
        break;
    case APP_INFO_NAME_RECV:
        return (flags->APP_INFO_NAME_RECV) ? 1 : 0;
        break;
    case APP_INFO_QOS_CLASS_RECV:
        return (flags->APP_INFO_QOS_CLASS_RECV) ? 1 : 0;
        break;
    case APP_INFO_CONNECTIONS_RECV:
        return (flags->APP_INFO_CONNECTIONS_RECV) ? 1 : 0;
        break;
    case APP_INFO_REQUIREMENTS_RECV:
        return (flags->APP_INFO_REQUIREMENTS_RECV) ? 1 : 0;
        break;
    default:
        return 0;
    }
}

void signaling_info_req_flag_set(struct signaling_flags_info_req *flags, int f)
{
    switch (f) {
    case HOST_INFO_OS:
        flags->HOST_INFO_OS = 1;
        break;
    case HOST_INFO_KERNEL:
        flags->HOST_INFO_KERNEL = 1;
        break;
    case HOST_INFO_ID:
        flags->HOST_INFO_ID = 1;
        break;
    case HOST_INFO_CERTS:
        flags->HOST_INFO_CERTS = 1;
        break;
    case USER_INFO_ID:
        flags->USER_INFO_ID = 1;
        break;
    case USER_INFO_CERTS:
        flags->USER_INFO_CERTS = 1;
        break;
    case APP_INFO_NAME:
        flags->APP_INFO_NAME = 1;
        break;
    case APP_INFO_QOS_CLASS:
        flags->APP_INFO_QOS_CLASS = 1;
        break;
    case APP_INFO_CONNECTIONS:
        flags->APP_INFO_CONNECTIONS = 1;
        break;
    case APP_INFO_REQUIREMENTS:
        flags->APP_INFO_REQUIREMENTS = 1;
        break;

    case HOST_INFO_OS_RECV:
        flags->HOST_INFO_OS_RECV = 1;
        break;
    case HOST_INFO_KERNEL_RECV:
        flags->HOST_INFO_KERNEL_RECV = 1;
        break;
    case HOST_INFO_CERTS_RECV:
        flags->HOST_INFO_CERTS_RECV = 1;
        break;
    case USER_INFO_ID_RECV:
        flags->USER_INFO_ID_RECV = 1;
        break;
    case USER_INFO_CERTS_RECV:
        flags->USER_INFO_CERTS_RECV = 1;
        break;
    case APP_INFO_NAME_RECV:
        flags->APP_INFO_NAME_RECV = 1;
        break;
    case APP_INFO_QOS_CLASS_RECV:
        flags->APP_INFO_QOS_CLASS_RECV = 1;
        break;
    case APP_INFO_CONNECTIONS_RECV:
        flags->APP_INFO_CONNECTIONS_RECV = 1;
        break;
    case APP_INFO_REQUIREMENTS_RECV:
        flags->APP_INFO_REQUIREMENTS_RECV = 1;
        break;
    }
}

void signaling_info_req_flag_unset(struct signaling_flags_info_req *flags, int f)
{
    switch (f) {
    case HOST_INFO_OS:
        flags->HOST_INFO_OS = 0;
        break;
    case HOST_INFO_KERNEL:
        flags->HOST_INFO_KERNEL = 0;
        break;
    case HOST_INFO_ID:
        flags->HOST_INFO_ID = 0;
        break;
    case HOST_INFO_CERTS:
        flags->HOST_INFO_CERTS = 0;
        break;
    case USER_INFO_ID:
        flags->USER_INFO_ID = 0;
        break;
    case USER_INFO_CERTS:
        flags->USER_INFO_CERTS = 0;
        break;
    case APP_INFO_NAME:
        flags->APP_INFO_NAME = 0;
        break;
    case APP_INFO_QOS_CLASS:
        flags->APP_INFO_QOS_CLASS = 0;
        break;
    case APP_INFO_CONNECTIONS:
        flags->APP_INFO_CONNECTIONS = 0;
        break;
    case APP_INFO_REQUIREMENTS:
        flags->APP_INFO_REQUIREMENTS = 0;
        break;

    case HOST_INFO_OS_RECV:
        flags->HOST_INFO_OS_RECV = 0;
        break;
    case HOST_INFO_KERNEL_RECV:
        flags->HOST_INFO_KERNEL_RECV = 0;
        break;
    case HOST_INFO_CERTS_RECV:
        flags->HOST_INFO_CERTS_RECV = 0;
        break;
    case USER_INFO_ID_RECV:
        flags->USER_INFO_ID_RECV = 0;
        break;
    case USER_INFO_CERTS_RECV:
        flags->USER_INFO_CERTS_RECV = 0;
        break;
    case APP_INFO_NAME_RECV:
        flags->APP_INFO_NAME_RECV = 0;
        break;
    case APP_INFO_QOS_CLASS_RECV:
        flags->APP_INFO_QOS_CLASS_RECV = 0;
        break;
    case APP_INFO_CONNECTIONS_RECV:
        flags->APP_INFO_CONNECTIONS_RECV = 0;
        break;
    case APP_INFO_REQUIREMENTS_RECV:
        flags->APP_INFO_REQUIREMENTS_RECV = 0;
        break;
    }
}

void signaling_info_req_flag_init(struct signaling_flags_info_req *flags)
{
    flags->HOST_INFO_OS          = 0;
    flags->HOST_INFO_KERNEL      = 0;
    flags->HOST_INFO_ID          = 0;
    flags->HOST_INFO_CERTS       = 0;
    flags->USER_INFO_ID          = 0;
    flags->USER_INFO_CERTS       = 0;
    flags->APP_INFO_NAME         = 0;
    flags->APP_INFO_QOS_CLASS    = 0;
    flags->APP_INFO_CONNECTIONS  = 0;
    flags->APP_INFO_REQUIREMENTS = 0;

    flags->HOST_INFO_OS_RECV          = 0;
    flags->HOST_INFO_KERNEL_RECV      = 0;
    flags->HOST_INFO_ID_RECV          = 0;
    flags->HOST_INFO_CERTS_RECV       = 0;
    flags->USER_INFO_ID_RECV          = 0;
    flags->USER_INFO_CERTS_RECV       = 0;
    flags->APP_INFO_NAME_RECV         = 0;
    flags->APP_INFO_QOS_CLASS_RECV    = 0;
    flags->APP_INFO_CONNECTIONS_RECV  = 0;
    flags->APP_INFO_REQUIREMENTS_RECV = 0;
}

void signaling_service_info_flags_print(struct signaling_flags_service_info *flags, const char *const prefix)
{
    char buf[100];
    memset(buf, 0, sizeof(buf));

    sprintf(buf + strlen(buf), "SO   = %d | ", signaling_service_info_flag_check(flags, SERVICE_OFFER));
    sprintf(buf + strlen(buf), "SOS  = %d | ", signaling_service_info_flag_check(flags, SERVICE_OFFER_S));
    sprintf(buf + strlen(buf), "SAU  = %d | ", signaling_service_info_flag_check(flags, SERVICE_ACK_U));
    sprintf(buf + strlen(buf), "SAS  = %d | ", signaling_service_info_flag_check(flags, SERVICE_ACK_S));
    sprintf(buf + strlen(buf), "SNA  = %d | ", signaling_service_info_flag_check(flags, SERVICE_NACK));

    sprintf(buf + strlen(buf), "SOR  = %d | ", signaling_service_info_flag_check(flags, SERVICE_OFFER_RECV));
    sprintf(buf + strlen(buf), "SOSR = %d | ", signaling_service_info_flag_check(flags, SERVICE_OFFER_S_RECV));
    sprintf(buf + strlen(buf), "SAUR = %d | ", signaling_service_info_flag_check(flags, SERVICE_ACK_U_RECV));
    sprintf(buf + strlen(buf), "SASR = %d | ", signaling_service_info_flag_check(flags, SERVICE_ACK_S_RECV));
    sprintf(buf + strlen(buf), "SNAR = %d | ", signaling_service_info_flag_check(flags, SERVICE_NACK_RECV));

    HIP_DEBUG("%s  Service Flags: %s int = %d \n", prefix, buf, flags);
}

int signaling_service_info_flag_check(struct signaling_flags_service_info *flags, int f)
{
    switch (f) {
    case SERVICE_OFFER:
        return (flags->SERVICE_OFFER)       ? 1 : 0;
        break;
    case SERVICE_OFFER_S:
        return (flags->SERVICE_OFFER_S)       ? 1 : 0;
        break;
    case SERVICE_ACK_U:
        return flags->SERVICE_ACK_U           ? 1 : 0;
        break;
    case SERVICE_ACK_S:
        return flags->SERVICE_ACK_S           ? 1 : 0;
        break;
    case SERVICE_NACK:
        return (flags->SERVICE_NACK)        ? 1 : 0;
        break;

    case SERVICE_OFFER_RECV:
        return (flags->SERVICE_OFFER_RECV)  ? 1 : 0;
        break;
    case SERVICE_OFFER_S_RECV:
        return (flags->SERVICE_OFFER_S_RECV)  ? 1 : 0;
        break;
    case SERVICE_ACK_U_RECV:
        return (flags->SERVICE_ACK_U_RECV)  ? 1 : 0;
        break;
    case SERVICE_ACK_S_RECV:
        return (flags->SERVICE_ACK_S_RECV)  ? 1 : 0;
        break;
    case SERVICE_NACK_RECV:
        return (flags->SERVICE_NACK_RECV)  ? 1 : 0;
        break;
    default:
        return 0;
    }
}

void signaling_service_info_flag_set(struct signaling_flags_service_info *flags, int f)
{
    switch (f) {
    case SERVICE_OFFER:
        flags->SERVICE_OFFER = 1;
        break;
    case SERVICE_ACK_U:
        flags->SERVICE_ACK_U = 1;
        break;
    case SERVICE_ACK_S:
        flags->SERVICE_ACK_S = 1;
        break;
    case SERVICE_NACK:
        flags->SERVICE_NACK = 1;
        break;

    case SERVICE_OFFER_RECV:
        flags->SERVICE_OFFER_RECV = 1;
        break;
    case SERVICE_ACK_U_RECV:
        flags->SERVICE_ACK_U_RECV = 1;
        break;
    case SERVICE_ACK_S_RECV:
        flags->SERVICE_ACK_S_RECV = 1;
        break;
    case SERVICE_NACK_RECV:
        flags->SERVICE_NACK_RECV = 1;
        break;
    }
}

void signaling_service_info_flag_unset(struct signaling_flags_service_info *flags, int f)
{
    switch (f) {
    case SERVICE_OFFER:
        flags->SERVICE_OFFER = 0;
        break;
    case SERVICE_ACK_U:
        flags->SERVICE_ACK_U = 0;
        break;
    case SERVICE_ACK_S:
        flags->SERVICE_ACK_S = 0;
        break;
    case SERVICE_NACK:
        flags->SERVICE_NACK = 0;
        break;

    case SERVICE_OFFER_RECV:
        flags->SERVICE_OFFER_RECV = 0;
        break;
    case SERVICE_ACK_U_RECV:
        flags->SERVICE_ACK_U_RECV = 0;
        break;
    case SERVICE_ACK_S_RECV:
        flags->SERVICE_ACK_S_RECV = 0;
        break;
    case SERVICE_NACK_RECV:
        flags->SERVICE_NACK_RECV = 0;
        break;
    }
}

void signaling_service_info_flag_init(struct signaling_flags_service_info *flags)
{
    flags->SERVICE_OFFER = 0;
    flags->SERVICE_ACK_U = 0;
    flags->SERVICE_ACK_S = 0;
    flags->SERVICE_NACK  = 0;

    flags->SERVICE_OFFER_RECV = 0;
    flags->SERVICE_ACK_U_RECV = 0;
    flags->SERVICE_ACK_S_RECV = 0;
    flags->SERVICE_NACK_RECV  = 0;
}
