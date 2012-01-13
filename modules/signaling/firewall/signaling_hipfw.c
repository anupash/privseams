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

/* required for IFNAMSIZ in libipq headers */
#define _BSD_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "config.h"

#ifdef HAVE_LIBCONFIG
#include <libconfig.h>
#else
typedef struct {
    // this is just defined to satisfy dependencies
} config_t;
#endif

#include "lib/core/builder.h"
#include "lib/core/ife.h"
#include "lib/core/hostid.h"

#include "firewall/hslist.h"

#include "modules/signaling/lib/signaling_prot_common.h"
#include "modules/signaling/lib/signaling_common_builder.h"
#include "modules/signaling/lib/signaling_user_management.h"
#include "modules/signaling/lib/signaling_x509_api.h"

#include "signaling_policy_engine.h"
#include "signaling_cdb.h"
#include "signaling_hipfw.h"
#include "signaling_hipfw_feedback.h"

/* Set from libconfig.
 * If set to zero, the firewall does only static filtering on basis of the predefined policy.
 * If set to one, the firewall saves the connection contexts it sees to the conntracking table,
 * for later use. */
int do_conntrack = 0;

/* Paths to configuration elements */
const char *default_policy_file = { "/usr/local/etc/hip/signaling_firewall_policy.cfg" };

const char *path_do_conntracking = { "do_conntracking" };
const char *path_key_file = { "/usr/local/etc/hip/mb-key.pem" };
const char *path_cert_file = { "/usr/local/etc/hip/mb-cert.pem" };

/**
 * releases the configuration file and frees the configuration memory
 *
 * @param cfg   parsed configuration parameters
 * @return      always 0
 */
static int signaling_hipfw_release_config(config_t *cfg)
{
    int err = 0;

    if (cfg) {
#ifdef HAVE_LIBCONFIG
        config_destroy(cfg);
        free(cfg);
#endif
    }

    return err;
}

/**
 * Parses the firewall config-file and stores the parameters in memory
 *
 * @return  configuration parameters
 */
static config_t *signaling_hipfw_read_config(const char *config_file)
{
    config_t *cfg = NULL;

/* WORKAROUND in order to not introduce a new dependency for HIPL
 *
 * FIXME this should be removed once we go tiny */
#ifdef HAVE_LIBCONFIG
    int err = 0;

    HIP_IFEL(!(cfg = malloc(sizeof(config_t))), -1,
             "Unable to allocate memory!\n");

    // init context and read file
    config_init(cfg);
    HIP_IFEL(!config_read_file(cfg, config_file),
             -1, "unable to read config file at %s \n", config_file);

out_err:
    if (err) {
        HIP_DEBUG("Config read error: %s \n", config_error_text(cfg));
        signaling_hipfw_release_config(cfg);
        cfg = NULL;
    }
#endif

    return cfg;
}

/**
 * Initialize the middlebox firewall application.
 * This sets up the firewall's policies.
 *
 * @param policy_file   the configuration file (in libconfig format) that specifies
 *                      the firewall's policy. If NULL, a default policy is used.
 *
 * @return              0 on success, negative on error
 */
int signaling_hipfw_init(const char *policy_file)
{
    int       err = 0;
    config_t *cfg = NULL;

    // register I3
    lmod_register_packet_type(HIP_I3, "HIP_I3");

    // init cdb
    HIP_IFEL(signaling_cdb_init(), -1, "Could not initialize conntracking database. \n");
    HIP_IFEL(signaling_user_mgmt_init(), -1, "Could not initialize user database. \n");

    // read and process policy
    if (!policy_file) {
        policy_file = default_policy_file;
    }
    HIP_DEBUG("Starting firewall with policy: %s \n", policy_file);
    HIP_IFEL(!(cfg = signaling_hipfw_read_config(policy_file)),
             -1, "Could not parse policy file.\n");

    /* Set do_conntracking */
    if (CONFIG_FALSE == config_lookup_bool(cfg, path_do_conntracking, &do_conntrack)) {
        HIP_DEBUG("Could not parse setting 'do_conntrack' from configuration, using default value: %d \n", do_conntrack);
        HIP_DEBUG("Config parse error: %s \n", config_error_text(cfg));
    } else {
        HIP_DEBUG("Connection tracking for signaling firewall is set to: %d\n", do_conntrack);
    }

    /* Initialize the policy engine */
    HIP_IFEL(signaling_policy_engine_init(cfg),
             -1, "Failed to start policy engine \n");

    /* Init firewall identity */
    signaling_hipfw_feedback_init(path_key_file, path_cert_file);

out_err:
    return err;
}

/**
 * Uninitialize the middlebox firewall application.
 * So far, there's nothing to be done.
 *
 * @return 0 on success, negative on error
 */
int signaling_hipfw_uninit(void)
{
    HIP_DEBUG("Uninit signaling firewall \n");
    signaling_cdb_uninit();
    signaling_policy_engine_uninit();
    signaling_hipfw_feedback_uninit();

    return 0;
}

/*
 * Add all information about application and user to the connection tracking table.
 *
 * @note This function does not return a verdict. The caller has the responsibility to decide
 *       what to do, when this function fails.
 *
 * @return 0 on success, negative on error
 */
UNUSED static int signaling_hipfw_conntrack(struct tuple *const tuple,
                                            struct signaling_connection_context *const conn_ctx)
{
    int                                  err          = 0;
    struct signaling_connection_context *new_conn_ctx = NULL;

    if (!do_conntrack) {
        return 0;
    }
    HIP_IFEL(!tuple, -1, "Connection tracking tuple is NULL \n");
    HIP_IFEL(!(new_conn_ctx = malloc(sizeof(struct signaling_connection_context))),
             -1, "Could not allocate new connection context \n");
    signaling_copy_connection_context(new_conn_ctx, conn_ctx);
    tuple->connection_contexts = append_to_slist(tuple->connection_contexts, &new_conn_ctx);

    return 0;
out_err:
    free(new_conn_ctx);
    return err;
}

/*
 * Handles an R1 packet observed by the firewall.
 * We have to
 *   a) Build the connection state.
 *   b) Check with local policy, whether to allow the connection context.
 *   c) Append an host_info_req parameter, if the middlebox requests for more specific information process it
 *
 * @param common    the i2 message
 * @param tuple
 * @param ctx
 *
 * @return          the verdict, i.e. 1 for pass, 0 for drop
 */
int signaling_hipfw_handle_r1(struct hip_common *common, UNUSED struct tuple *tuple, UNUSED struct hip_fw_context *ctx)
{
    int                         err = 0;
    struct signaling_connection new_conn;
    struct userdb_user_entry   *db_entry = NULL;

    printf("\033[22;34mReceived R1 packet\033[22;37m\n\033[01;37m");

    /* sanity checks */
    HIP_IFEL(!common, -1, "Message is NULL\n");

    /* Step a) */
    if (signaling_init_connection_from_msg(&new_conn, common, IN)) {
        HIP_ERROR("Could not init connection context from R1 \n");
        return -1;
    }
    new_conn.side = MIDDLEBOX;

    /* add/update user in user db */
    if (!(db_entry = userdb_add_user_from_msg(common, 0))) {
        HIP_ERROR("Could not add user from message\n");
    }

    /* Try to auth the user and set flags accordingly */
    /* The host is authed because this packet went through all the default hip checking functions */

    /* Step b) */
    HIP_DEBUG("Connection after receipt of R1 \n");
    signaling_connection_print(&new_conn, "\t");
/*
 *   if (signaling_policy_engine_check_and_flag(&common->hits, &new_conn.ctx_in)) {
 *       new_conn.status = SIGNALING_CONN_BLOCKED;
 *       signaling_cdb_add(&common->hits, &common->hitr, &new_conn);
 *       signaling_cdb_print();
 *       signaling_hipfw_send_connection_failed_ntf(common, tuple, ctx, PRIVATE_REASON, &new_conn);
 *       return 0;
 *   }
 */

    /* Step c) */
    // TODO Add more handlers for user and application information requests
/*
 *   if (signaling_flag_check(new_conn.ctx_in.flags, USER_AUTH_REQUEST)) {
 *       if (signaling_build_param_user_auth_req_u(common, 0)) {
 *           HIP_ERROR("Could not add unsigned user auth request. Dropping packet.\n");
 *           return 0;
 *       }
 *       ctx->modified = 1;
 *   }
 *   if (signaling_flag_check(new_conn.ctx_in.flags, HOST_INFO_ID) ||
 *       signaling_flag_check(new_conn.ctx_in.flags, HOST_INFO_OS) ||
 *       signaling_flag_check(new_conn.ctx_in.flags, HOST_INFO_KERNEL) ||
 *       signaling_flag_check(new_conn.ctx_in.flags, HOST_INFO_CERTS)) {
 *
 *        if (signaling_build_param_host_info_req_u(common, 0, new_conn.ctx_in.flags)) {
 *           HIP_ERROR("Could not add host info request. Dropping packet.\n");
 *           return 0;
 *       }
 *
 *       ctx->modified = 1;
 *   }
 */

    /* Step d) */
    new_conn.status = SIGNALING_CONN_PROCESSING;
    HIP_IFEL(signaling_cdb_add(&common->hits, &common->hitr, &tuple->src_port, &tuple->dst_port, &new_conn),
             -1, "Could not add new connection to conntracking table\n");
    HIP_DEBUG("Connection tracking table after receipt of R1\n");
    signaling_cdb_print();

    /* Let packet pass */
    printf("\033[22;32mAccepted R1 packet\033[22;37m\n\n\033[01;37m");
    return 1;

out_err:
    return err;
}

/*
 * Handles an I2 packet observed by the firewall.
 * We have to
 *   a) Build the connection state.
 *   b) Check with local policy, whether to allow the connection context.
 *   c) Append an auth_req_u parameter, if the user's certificate chain is missing and required.
 *   d) Add the new connection to the conntracking table.
 *
 * @param common    the i2 message
 * @param tuple
 * @param ctx
 *
 * @return          the verdict, i.e. 1 for pass, 0 for drop
 */
int signaling_hipfw_handle_i2(struct hip_common *common, UNUSED struct tuple *tuple, UNUSED struct hip_fw_context *ctx)
{
    int                         err = 0;
    struct signaling_connection new_conn;
    struct userdb_user_entry   *db_entry = NULL;

    printf("\033[22;34mReceived I2 packet\033[22;37m\n\033[01;37m");

    /* sanity checks */
    HIP_IFEL(!common, -1, "Message is NULL\n");

    /* Step a) */
    if (signaling_init_connection_from_msg(&new_conn, common, IN)) {
        HIP_ERROR("Could not init connection context from I2 \n");
        return -1;
    }
    new_conn.side = MIDDLEBOX;

    /* add/update user in user db */
    if (!(db_entry = userdb_add_user_from_msg(common, 0))) {
        HIP_ERROR("Could not add user from message\n");
    }

    /* Try to auth the user and set flags accordingly */
    userdb_handle_user_signature(common, &new_conn, IN);
    /* The host is authed because this packet went through all the default hip checking functions */

    /* Step b) */
    HIP_DEBUG("Connection after receipt of i2\n");
    signaling_connection_print(&new_conn, "\t");
/*
 *   if (signaling_policy_engine_check_and_flag(&common->hits, &new_conn.ctx_in)) {
 *       new_conn.status = SIGNALING_CONN_BLOCKED;
 *       signaling_cdb_add(&common->hits, &common->hitr, &new_conn);
 *       signaling_cdb_print();
 *       signaling_hipfw_send_connection_failed_ntf(common, tuple, ctx, PRIVATE_REASON, &new_conn);
 *       return 0;
 *   }
 *
 *    Step c)
 *   if (signaling_flag_check(new_conn.ctx_in.flags, USER_AUTH_REQUEST)) {
 *       if (signaling_build_param_user_auth_req_u(common, 0)) {
 *           HIP_ERROR("Could not add unsigned user auth request. Dropping packet.\n");
 *           return 0;
 *       }
 *       ctx->modified = 1;
 *   }
 */

    /* Step d) */
    new_conn.status = SIGNALING_CONN_PROCESSING;
    HIP_IFEL(signaling_cdb_add(&common->hits, &common->hitr, &tuple->src_port, &tuple->dst_port, &new_conn),
             -1, "Could not add new connection to conntracking table\n");
    HIP_DEBUG("Connection tracking table after receipt of I2\n");
    signaling_cdb_print();

    /* Let packet pass */
    printf("\033[22;32mAccepted I2 packet\033[22;37m\n\n\033[01;37m");
    return 1;

out_err:
    return err;
}

/*
 * Handles an R2 packet observed by the firewall.
 * We have to
 *   a) Add the new connection context to the existing entry in the conntracking table.
 *      Drop the connection if there is no such entry (then the FW has not previously seen an I2).
 *   b) If we appended a auth_req_u parameter in I2, check for auth_req_s parameter in this message.
 *   c) Check, whether to allow the connection context.
 *   d) Append an auth_req_u parameter, if the user's certificate chain is requested but missing.
 *
 * @return the verdict, i.e. 1 for pass, 0 for drop
 */
int signaling_hipfw_handle_r2(struct hip_common *common, UNUSED struct tuple *tuple, UNUSED struct hip_fw_context *ctx)
{
    int                          err = 0;
    struct signaling_connection  recv_conn;
    struct signaling_connection *conn = NULL;
    //const struct signaling_param_user_auth_request *auth_req = NULL;
    struct userdb_user_entry *db_entry = NULL;

    printf("\033[22;34mReceived R2 packet\033[22;37m\n\033[22;37m");

    /* sanity checks */
    HIP_IFEL(!common, -1, "Message is NULL\n");

    /* Step a) */
    HIP_IFEL(signaling_init_connection_from_msg(&recv_conn, common, OUT),
             0, "Could not init connection context from R2/U2 \n");
    HIP_IFEL(!(conn = signaling_cdb_entry_get_connection(&common->hits, &common->hitr, &tuple->src_port, &tuple->dst_port, recv_conn.id)),
             0, "Could not get connection state for connection-tracking table\n");
    HIP_IFEL(signaling_update_connection_from_msg(conn, common, OUT),
             0, "Could not update connection state with information from R2\n");
    //conn->ctx_out.direction = FWD;

    /* add/update user in user db */
    if (!(db_entry = userdb_add_user_from_msg(common, 0))) {
        HIP_ERROR("Could not add user from message\n");
    }
    //conn->ctx_out.userdb_entry = db_entry;

    /* Try to auth the user and set flags accordingly */
    userdb_handle_user_signature(common, conn, OUT);
    /* The host is authed because this packet went through all the default hip checking functions */
    //signaling_flag_set(&conn->ctx_out.flags, HOST_AUTHED);



    /* Step b) */
/*
 *  if (signaling_flag_check(conn->ctx_in.flags, USER_AUTH_REQUEST)) {
 *      if (!(auth_req = hip_get_param(common, HIP_PARAM_SIGNALING_USER_REQ_S))) {
 *          HIP_ERROR("Requested authentication in I2, but R2 is missing signed request parameter. \n");
 *          signaling_hipfw_send_connection_failed_ntf(common, tuple, ctx, PRIVATE_REASON, conn);
 *          return 0;
 *      }
 *  }
 *
 *   Step c)
 *  if (signaling_policy_engine_check_and_flag(&common->hits, &conn->ctx_out)) {
 *      conn->status = SIGNALING_CONN_BLOCKED;
 *      signaling_cdb_add(&common->hits, &common->hitr, conn);
 *      signaling_cdb_print();
 *      signaling_hipfw_send_connection_failed_ntf(common, tuple, ctx, PRIVATE_REASON, conn);
 *      return 0;
 *  }
 *
 *   Step d)
 *  if (signaling_flag_check(conn->ctx_out.flags, USER_AUTH_REQUEST)) {
 *      if (signaling_build_param_user_auth_req_u(common, 0)) {
 *          HIP_ERROR("Could not add unsigned user auth request. Dropping packet.\n");
 *          return 0;
 *      }
 *      ctx->modified = 1;
 *  }
 */

    HIP_DEBUG("Connection tracking table after receipt of R2\n");
    signaling_cdb_print();

    /* Let packet pass */
    printf("\033[22;32mAccepted R2 packet\033[22;37m\n\n\033[22;37m");
    return 1;

out_err:
    return err;
}

/*
 * Handles an I3 packet observed by the firewall.
 * We have to
 *   a) Check for a corressponding entry in the conntracking table.
 *   b) If we appended a auth_req_s parameter in R2, check for auth_req_s parameter in this message.
 *   c) Handle certificates contained in this message, if we requested auth of initiator user,
 *   d) Allow connection if no further authentication is required.
 *
 * @return the verdict, i.e. 1 for pass, 0 for drop
 */
int signaling_hipfw_handle_i3(UNUSED struct hip_common *common, UNUSED struct tuple *tuple, UNUSED const struct hip_fw_context *ctx)
{
    int                          err = 0;
    struct signaling_connection  recv_conn;
    struct signaling_connection *existing_conn = NULL;
    //const struct signaling_param_user_auth_request *auth_req      = NULL;
    int wait_auth = 0;

    printf("\033[22;34mReceived I3 packet\033[22;37m\n\033[01;37m");

    /* Step a) */
    HIP_IFEL(signaling_init_connection_from_msg(&recv_conn, common, OUT),
             0, "Could not init connection context from I3 \n");
    HIP_IFEL(!(existing_conn = signaling_cdb_entry_get_connection(&common->hits, &common->hitr, &tuple->src_port, &tuple->dst_port, recv_conn.id)),
             0, "Could not get connection state for connection-tracking table\n");
    HIP_IFEL(signaling_update_flags_from_connection_id(common, existing_conn),
             -1, "Could not update authentication flags from I3/U3 message \n");

    /* Step b) */
/*
 *  if (signaling_flag_check(existing_conn->ctx_out.flags, USER_AUTH_REQUEST)) {
 *      if (!(auth_req = hip_get_param(common, HIP_PARAM_SIGNALING_USER_REQ_S))) {
 *          HIP_ERROR("Requested authentication in R2, but I3 is missing signed request parameter. \n");
 *          // todo: [user auth] send notification
 *          return 0;
 *      }
 *  }
 */

    /* Try to auth the user and set flags accordingly */
    userdb_handle_user_signature(common, existing_conn, IN);

/*
 *   Check if we're done with this connection or if we have to wait for addition authentication
 *  if (signaling_flag_check(existing_conn->ctx_in.flags, USER_AUTH_REQUEST)) {
 *      HIP_DEBUG("Auth uncompleted after I3/U3, waiting for authentication of initiator user.\n");
 *      wait_auth = 1;
 *  }
 *  if (signaling_flag_check(existing_conn->ctx_out.flags, USER_AUTH_REQUEST)) {
 *      HIP_DEBUG("Auth uncompleted after I3/U3, waiting for authentication of responder user.\n");
 *      wait_auth = 1;
 *  }
 */
    if (!wait_auth) {
        HIP_DEBUG("Auth completed after I3/U3 \n");
        existing_conn->status = SIGNALING_CONN_ALLOWED;
    }

    signaling_cdb_print();
    printf("\033[22;32mAccepted I3 packet\033[22;37m\n\n\033[01;37m");
    return 1;

out_err:
    return err;
}

/**
 * Handle an UPDATE message that contains (parts from) a user certificate chain.
 *
 * @return 0 on success
 */
static int signaling_hipfw_handle_incoming_certificate_udpate(const struct hip_common *common,
                                                              UNUSED struct tuple *tuple,
                                                              UNUSED struct hip_fw_context *ctx)
{
    int                                         err           = 0;
    const struct signaling_param_cert_chain_id *param_cert_id = NULL;
    X509                                       *cert          = NULL;
    struct signaling_connection                *conn          = NULL;
    struct userdb_certificate_context          *cert_ctx      = NULL;
    uint32_t                                    network_id;
    uint32_t                                    conn_id;
    const struct hip_cert                      *param_cert = NULL;
    struct signaling_connection_context        *conn_ctx   = NULL;

    /* sanity checks */
    HIP_IFEL(!common,  0, "Message is NULL\n");

    /* get connection identifier and context */
    HIP_IFEL(!(param_cert_id = hip_get_param(common, HIP_PARAM_SIGNALING_CERT_CHAIN_ID)),
             -1, "No connection identifier found in the message, cannot handle certificates.\n");
    conn_id    =  ntohl(param_cert_id->connection_id);
    network_id = ntohl(param_cert_id->network_id);
    HIP_IFEL(!(conn = signaling_cdb_entry_get_connection(&common->hits, &common->hitr, &tuple->src_port, &tuple->dst_port, conn_id)),
             -1, "No connection context for connection id \n");
    HIP_IFEL(!(param_cert = hip_get_param(common, HIP_PARAM_CERT)),
             -1, "Message contains no certificates.\n");
/*
 *  switch (signaling_cdb_direction(&common->hits, &common->hitr)) {
 *  case 0:
 *      conn_ctx = &conn->ctx_in;
 *      break;
 *  case 1:
 *      conn_ctx = &conn->ctx_out;
 *      break;
 *  default:
 *      HIP_DEBUG("Connection is not conntracked \n");
 *      return 0;
 *  }
 */

    /* process certificates and check completeness*/
    err = userdb_add_certificates_from_msg(common, conn_ctx->userdb_entry);
    if (err < 0) {
        HIP_ERROR("Internal error while processing certificates \n");
        return 0;
    } else if (err > 0) {
        HIP_DEBUG("Waiting for further certificate updates because chain is incomplete. \n");
        userdb_entry_print(conn_ctx->userdb_entry);
        return 1;
    }

    /* We have received a complete chain */
    HIP_DEBUG("Received complete certificate chain.\n");
    HIP_IFEL(!(cert_ctx = userdb_get_certificate_context(conn_ctx->userdb_entry,
                                                         &common->hits,
                                                         &common->hitr,
                                                         network_id)),
             -1, "Could not retrieve users certificate chain\n");
    stack_reverse(&cert_ctx->cert_chain);
    userdb_entry_print(conn_ctx->userdb_entry);

    /* Verify the public key */
    cert = sk_X509_pop(cert_ctx->cert_chain);
    HIP_IFEL(!match_public_key(cert, conn_ctx->userdb_entry->pub_key),
             -1, "Users public key does not match with the key in the received certificate chain\n");

    /* Verify the public key and the certificate chain */
    if (!verify_certificate_chain(cert, CERTIFICATE_INDEX_TRUSTED_DIR, NULL, cert_ctx->cert_chain)) {
        /* Public key verification was successful, so we save the chain */
        sk_X509_push(cert_ctx->cert_chain, cert);
        userdb_save_user_certificate_chain(cert_ctx->cert_chain);
        signaling_flag_set(&conn_ctx->flags, USER_AUTHED);
        signaling_flag_unset(&conn_ctx->flags, USER_AUTH_REQUEST);
    } else {
        HIP_DEBUG("Rejecting certificate chain. Chain will not be saved, update will be dropped. \n");
        // todo: send a notification to the peers
        return 0;
    }

    return 1;

out_err:
    return err;
}

static int signaling_hipfw_handle_incoming_certificate_update_ack(const struct hip_common *common,
                                                                  UNUSED struct tuple *tuple,
                                                                  UNUSED struct hip_fw_context *ctx)
{
    int                                         err           = 1;
    const struct signaling_param_cert_chain_id *param_cert_id = NULL;
    struct signaling_connection                *conn          = NULL;
    uint32_t                                    network_id;
    uint32_t                                    conn_id;
    struct signaling_connection_context        *conn_ctx = NULL;

    /* get connection identifier and context */
    HIP_IFEL(!(param_cert_id = hip_get_param(common, HIP_PARAM_SIGNALING_CERT_CHAIN_ID)),
             0, "No connection identifier found in the message, cannot handle certificates.\n");
    conn_id    =  ntohl(param_cert_id->connection_id);
    network_id = ntohl(param_cert_id->network_id);
    HIP_IFEL(!(conn = signaling_cdb_entry_get_connection(&common->hits, &common->hitr, &tuple->src_port, &tuple->dst_port, conn_id)),
             0, "No connection context for connection id \n");
/*
 *  switch (signaling_cdb_direction(&common->hits, &common->hitr)) {
 *  case 0:
 *      conn_ctx = &conn->ctx_in;
 *      break;
 *  case 1:
 *      conn_ctx = &conn->ctx_out;
 *      break;
 *  default:
 *      HIP_DEBUG("Connection is not conntracked \n");
 *      return 0;
 *  }
 */

    /* check if we authed the user too */
    if (!signaling_flag_check(conn_ctx->flags, USER_AUTHED)) {
        HIP_DEBUG("Received auth ack for user auth that hasn't been successful at the firewall \n");
        return 0;
    }

    return 1;
out_err:
    return err;
}

/*
 * Handles an UPDATE packet observed by the firewall.
 * This includes adding connection context information to the conntracking table
 * and speaking a verdict based on the firewalls policy about host, user and application.
 *
 * @return the verdict, i.e. 1 for pass, 0 for drop
 */
int signaling_hipfw_handle_update(const struct hip_common *common, UNUSED struct tuple *tuple, UNUSED struct hip_fw_context *ctx)
{
    int err = 0;
    int update_type;

    /* Sanity checks */
    HIP_IFEL((update_type = signaling_get_update_type(common)) < 0,
             1, "This is no signaling update packet\n");

    /* Handle the different update types */
    switch (update_type) {
    case SIGNALING_FIRST_BEX_UPDATE:
        HIP_DEBUG("Received FIRST BEX Update... \n");
        return 1;
        break;
    case SIGNALING_SECOND_BEX_UPDATE:
        HIP_DEBUG("Received SECOND BEX Update... \n");
        return 1;
        break;
    case SIGNALING_THIRD_BEX_UPDATE:
        HIP_DEBUG("Received THIRD BEX Update... \n");
        return 1;
        break;
    case SIGNALING_FIRST_USER_CERT_CHAIN_UPDATE:
        HIP_DEBUG("Received certificate Update... \n");
        return signaling_hipfw_handle_incoming_certificate_udpate(common, tuple, ctx);
        break;
    case SIGNALING_SECOND_USER_CERT_CHAIN_UPDATE:
        HIP_DEBUG("Received certificate Update Ack... \n");
        return signaling_hipfw_handle_incoming_certificate_update_ack(common, tuple, ctx);
        break;
    default:
        HIP_DEBUG("Received unknown UPDATE type. \n");
        break;
    }

out_err:
    return err;
}

static int signaling_handle_notify_connection_failed(struct hip_common *common, UNUSED struct tuple *tuple, UNUSED struct hip_fw_context *ctx)
{
    struct signaling_connection                        *conn         = NULL;
    const struct signaling_param_connection_identifier *conn_id      = NULL;
    const struct hip_notification                      *notification = NULL;
    const struct signaling_ntf_connection_failed_data  *ntf_data     = NULL;
    int                                                 reason       = 0;
    int                                                 err          = 1;

    /* Get connection context */
    HIP_IFEL(!(notification = hip_get_param(common, HIP_PARAM_NOTIFICATION)),
             1, "Message contains no notification parameter.\n");
    HIP_IFEL(!(conn_id = hip_get_param(common, HIP_PARAM_SIGNALING_CONNECTION_ID)),
             1, "Could not find connection identifier in notification. \n");
    HIP_IFEL(!(conn = signaling_cdb_entry_get_connection(&common->hits, &common->hitr, &tuple->src_port, &tuple->dst_port, ntohs(conn_id->id))),
             1, "Could not get connection state from connection-tracking table\n");

    /* Get notification data */
    ntf_data =  (const struct signaling_ntf_connection_failed_data *) notification->data;
    reason   = ntohs(ntf_data->reason);
    HIP_DEBUG("Received connection failed notification for following reasons:\n");
    if (reason) {
        if (reason & APPLICATION_BLOCKED) {
            HIP_DEBUG("\t -> Application blocked.\n");
        }
        if (reason & USER_BLOCKED) {
            HIP_DEBUG("\t -> User blocked.\n");
        }
        if (reason & HOST_BLOCKED) {
            HIP_DEBUG("\t -> Host blocked.\n");
        }
        if (reason & PRIVATE_REASON) {
            HIP_DEBUG("\t -> Reason is private.\n");
        }
    } else {
        HIP_DEBUG("\t -> Invalid reason.\n");
    }

    /* Adapt connection status */
    HIP_DEBUG("Blocking the following connection:\n");
    conn->status = SIGNALING_CONN_BLOCKED;
    signaling_connection_print(conn, "\t");

out_err:
    return err;
}

/*
 * Handles an NOTIFY packet observed by the firewall.
 *
 * @return the verdict, i.e. 1 for pass, 0 for drop
 */
int signaling_hipfw_handle_notify(struct hip_common *common, UNUSED struct tuple *tuple, UNUSED struct hip_fw_context *ctx)
{
    int                            err          = 1;
    const struct hip_notification *notification = NULL;

    /* Get notification type data */
    HIP_IFEL(!(notification = hip_get_param(common, HIP_PARAM_NOTIFICATION)),
             1, "Message contains no notification parameter.\n");

    /* Handle different types */
    switch (htons(notification->msgtype)) {
    case SIGNALING_CONNECTION_FAILED:
        err = signaling_handle_notify_connection_failed(common, tuple, ctx);
        break;
    default:
        HIP_DEBUG("Unhandled notification type: %d \n", htons(notification->msgtype));
        break;
    }

out_err:
    return err;
}
