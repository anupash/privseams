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
#include "lib/core/crypto.h"
#include "lib/tool/pk.h"

#include "firewall/hslist.h"
#include "firewall/firewall.h"

#include "modules/signaling/lib/signaling_user_management.h"
#include "modules/signaling/lib/signaling_x509_api.h"
#include "firewall/conntrack.h"

#include "signaling_policy_engine.h"
#include "signaling_cdb.h"
#include "signaling_hipfw.h"
#include "signaling_hipfw_feedback.h"

static unsigned char dh_priv_key[] = {
    0x4D, 0xE2, 0xBE, 0x6A, 0x20, 0x45, 0x5C, 0x3B, 0x13, 0x50,
    0x2E, 0xC3, 0x0D, 0xDF, 0x3A, 0xF9, 0xE9, 0xEC, 0x6B, 0x14,
    0x36, 0x81, 0x4D, 0xE2, 0x2B, 0x1E, 0x25, 0x89, 0x4B, 0x5A,
    0x7D, 0x0B, 0xD8, 0x5B, 0x7B, 0x5D, 0xDF, 0x63, 0xEF, 0xFB,
    0xA0, 0x63, 0x1E, 0xCA, 0x4C, 0x18, 0x68, 0x98, 0x3C, 0xB5,
    0x97, 0xD0, 0xA9, 0xA8, 0x6F, 0x95, 0xD1, 0xA1, 0x0F, 0xD1,
    0x93, 0xB9, 0x26, 0xB4, 0xB1, 0x38, 0x19, 0x51, 0x39, 0x3E,
    0xA9, 0x15, 0xD1, 0x0C, 0x47, 0xDE, 0x70, 0x12, 0x10, 0x1B,
    0xF1, 0xD9, 0x2E, 0xA5, 0x79, 0x78, 0x31, 0x57, 0x05, 0xFD,
    0x59, 0xCD, 0xA1, 0x35, 0x6A, 0x58, 0xBA, 0x69, 0xAB, 0x02,
    0x2F, 0xDA, 0x7D, 0x52, 0x6B, 0x51, 0xE3, 0xB9, 0xF1, 0xA1,
    0xEE, 0x4C, 0x8B, 0x8E, 0xDD, 0x48, 0x9C, 0x8D, 0xF0, 0x2E,
    0xEF, 0x69, 0x36, 0x1C, 0xCA, 0x4A, 0xEF, 0xDA, 0xBE, 0xD7,
    0x7E, 0xAF, 0xC8, 0x61, 0x1B, 0x4B, 0xB2, 0x07, 0x66, 0x03,
    0x26, 0x13, 0x6A, 0x77, 0x43, 0x8C, 0x76, 0x3A, 0x60, 0x16,
    0xD9, 0xE5, 0x9A, 0xA5, 0xE9, 0x07, 0x02, 0x8C, 0x0F, 0x83,
    0x80, 0x2C, 0xD7, 0x1D, 0x45, 0xC1, 0x19, 0xF5, 0x21, 0x5D,
    0x58, 0x59, 0x3F, 0x83, 0x2E, 0xFD, 0xF9, 0x7D, 0xAE, 0x97,
    0xF6, 0xCA, 0x1C, 0x3D, 0x9F, 0xD4, 0x6A, 0x68, 0x11, 0x79,
    0x64, 0xAB
};

static uint16_t dh_priv_key_len = 192;
static DH      *dh              = NULL;

#define SERVICE_RESPONSE_ALGO_DH    1
int SERVICE_OFFER_TYPE = OFFER_SELECTIVE_SIGNED;

/* Set from libconfig.
 * If set to zero, the firewall does only static filtering on basis of the predefined policy.
 * If set to one, the firewall saves the connection contexts it sees to the conntracking table,
 * for later use. */
int do_conntrack = 0;

static uint16_t       next_service_offer_id;
static unsigned char *signaling_dh_shared_key_r     = NULL;
static uint16_t       signaling_dh_shared_key_r_len = 1024;

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

    // Information request parameter types
    lmod_register_parameter_type(HIP_PARAM_SIGNALING_HOST_INFO_ID,          "HIP_PARAM_SIGNALING_HOST_INFO_ID");
    lmod_register_parameter_type(HIP_PARAM_SIGNALING_HOST_INFO_OS,          "HIP_PARAM_SIGNALING_HOST_INFO_OS");
    lmod_register_parameter_type(HIP_PARAM_SIGNALING_HOST_INFO_KERNEL,      "HIP_PARAM_SIGNALING_HOST_INFO_KERNEL");
    lmod_register_parameter_type(HIP_PARAM_SIGNALING_HOST_INFO_CERTS,       "HIP_PARAM_SIGNALING_HOST_INFO_CERTS");

    lmod_register_parameter_type(HIP_PARAM_SIGNALING_USER_INFO_ID,          "HIP_PARAM_SIGNALING_USER_INFO_ID");
    lmod_register_parameter_type(HIP_PARAM_SIGNALING_USER_INFO_CERTS,       "HIP_PARAM_SIGNALING_USER_INFO_CERTS");

    lmod_register_parameter_type(HIP_PARAM_SIGNALING_APP_INFO_NAME,         "HIP_PARAM_SIGNALING_APP_INFO_NAME");
    lmod_register_parameter_type(HIP_PARAM_SIGNALING_APP_INFO_QOS_CLASS,    "HIP_PARAM_SIGNALING_APP_INFO_QOS_CLASS");
    lmod_register_parameter_type(HIP_PARAM_SIGNALING_APP_INFO_CONNECTIONS,  "HIP_PARAM_SIGNALING_APP_INFO_CONNECTIONS");
    lmod_register_parameter_type(HIP_PARAM_SIGNALING_APP_INFO_REQUIREMENTS, "HIP_PARAM_SIGNALING_APP_INFO_REQUIREMENTS");

    // register internal parameter types
    lmod_register_parameter_type(HIP_PARAM_SIGNALING_CONNECTION_CONTEXT,    "HIP_PARAM_SIGNALING_CONNECTION_CONTEXT");
    lmod_register_parameter_type(HIP_PARAM_SIGNALING_CONNECTION,            "HIP_PARAM_SIGNALING_CONNECTION");
    lmod_register_parameter_type(HIP_PARAM_SIGNALING_ENCRYPTED,             "HIP_PARAM_SIGNALING_ENCRYPTED");
    lmod_register_parameter_type(HIP_PARAM_SIGNALING_SERVICE_OFFER,         "HIP_PARAM_SIGNALING_SERVICE_OFFER");
    lmod_register_parameter_type(HIP_PARAM_SIGNALING_SERVICE_OFFER_S,       "HIP_PARAM_SIGNALING_SERVICE_OFFER_S");
    lmod_register_parameter_type(HIP_PARAM_SIGNALING_SERVICE_ACK,           "HIP_PARAM_SIGNALING_SERVICE_ACK");
    lmod_register_parameter_type(HIP_PARAM_SIGNALING_SELECTIVE_HMAC,        "HIP_PARAM_SIGNALING_SELECTIVE_HMAC");
    lmod_register_parameter_type(HIP_PARAM_SIGNALING_SELECTIVE_SIGNATURE,   "HIP_PARAM_SIGNALING_SELECTIVE_SIGNATURE");
    lmod_register_parameter_type(HIP_PARAM_SIGNALING_USER_SIGNATURE,        "HIP_PARAM_SIGNALING_USER_SIGNATURE");
    lmod_register_parameter_type(HIP_PARAM_SIGNALING_PORTS,                 "HIP_PARAM_SIGNALING_PORTS");
    lmod_register_parameter_type(HIP_PARAM_SELECTIVE_HASH_LEAF,             "HIP_PARAM_SELECTIVE_HASH_LEAF");

    signaling_cdb_init();
    HIP_IFEL(signaling_user_mgmt_init(), -1, "Could not initialize user database. \n");

    get_random_bytes((unsigned char *) &next_service_offer_id, sizeof(uint16_t));
    //next_service_offer_id = 0;

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

    HIP_DEBUG("Policy Engine started successfully.\n");
    /* Init firewall identity */
    HIP_IFEL(signaling_hipfw_feedback_init(path_key_file, path_cert_file), -1, "Problem installing the middlebox key and certificate.\n");

    signaling_hipfw_generate_mb_dh_key(DH_GROUP_ID, &dh);
    HIP_ASSERT(dh);
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
int signaling_hipfw_handle_r1(struct hip_common *common, UNUSED struct tuple *tuple, struct hip_fw_context *ctx)
{
    int                                 err = 0;
    int                                 ret = 0;
    struct signaling_connection         new_conn;
    struct signaling_connection_context ctx_in;
    struct signaling_connection_context ctx_out;
    struct in6_addr                     hit_i;
    struct in6_addr                     hit_r;
    struct signaling_connection_flags  *ctx_flags     = NULL;
    struct policy_tuple                *matched_tuple = NULL;

    //This tuple is different from above
    struct tuple *other_dir = NULL;

#ifdef DEMO_MODE
    printf("\033[22;34mReceived R1/U1 packet\033[22;37m\n\033[01;37m");
#endif

    if (tuple->direction == ORIGINAL_DIR) {
        other_dir = &tuple->connection->reply;
    } else {
        other_dir = &tuple->connection->original;
    }

    if (common->type_hdr == HIP_R1) {
        hit_i = common->hitr;
        hit_r = common->hits;
    } else if (common->type_hdr == HIP_UPDATE) {
        hit_i = common->hits;
        hit_r = common->hitr;
    }

    signaling_update_info_flags_from_msg(ctx_flags, common, FWD);

    HIP_IFEL(signaling_hipfw_initialize_connection_contexts_and_flags(common, &new_conn, &ctx_in, &ctx_out, &ctx_flags, &ret),
             -1, "Could not initialize the contexts and flags successfully\n");

    HIP_IFEL(signaling_hipfw_get_dh_shared_key(common, dh,
                                               &signaling_dh_shared_key_r,
                                               &signaling_dh_shared_key_r_len), -1,
             "Could not get the mb shared key using DH public value from responder\n");
    /* Step b) */
    HIP_IFEL(signaling_hipfw_check_policy_and_create_service_offer(common, tuple, other_dir, ctx, &ctx_in, &ctx_out,
                                                                   ctx_flags, &new_conn, &hit_i, &hit_r, &ret),
             -1, "Could not check policy and add service offers\n");

#ifdef DEMO_MODE
    if (ret) {
        printf("\033[22;32mAccepted R1/U1 packet\033[22;37m\n\n\033[01;37m");
    }
#endif

    free(ctx_flags);
    free(matched_tuple);
    return ret;

out_err:
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop PERF_MBOX_R1_ADD_INFO_REQ\n");
    hip_perf_stop_benchmark(perf_set, PERF_MBOX_R1_ADD_INFO_REQ);
#endif
    free(ctx_flags);
    free(matched_tuple);
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
    int                                 err = 0;
    int                                 ret = 0;
    struct signaling_connection         new_conn;
    struct signaling_connection_context ctx_in;
    struct signaling_connection_context ctx_out;
    struct in6_addr                     hit_i;
    struct in6_addr                     hit_r;
    struct signaling_connection_flags  *ctx_flags     = NULL;
    struct policy_tuple                *matched_tuple = NULL;
    struct signaling_cdb_entry         *old_conn;
    struct hip_common                  *msg_buf       = NULL; /* It will be used in building the HIP Encrypted param*/
    unsigned char                      *dh_shared_key = NULL;
    uint16_t                            dh_shared_len = 1024;
    int                                 offset_list[10];
    int                                 offset_list_len = 0;

    //This tuple is different
    struct tuple *other_dir = NULL;

#ifdef DEMO_MODE
    printf("\033[22;34mReceived I2/U2 packet\033[22;37m\n\033[01;37m");
#endif

    if (tuple->direction == ORIGINAL_DIR) {
        other_dir = &tuple->connection->reply;
    } else {
        other_dir = &tuple->connection->original;
    }

    if (common->type_hdr == HIP_I2) {
        hit_i = common->hits;
        hit_r = common->hitr;
    } else if (common->type_hdr == HIP_UPDATE) {
        hit_i = common->hitr;
        hit_r = common->hits;
    }

    /* sanity checks */
    HIP_IFEL(!common, -1, "Message is NULL\n");

    /*
     * Handle the incoming response parameters from the Initiator
     */
    /* Step a) */
    HIP_IFEL(signaling_hipfw_initialize_connection_contexts_and_flags(common, &new_conn, &ctx_in, &ctx_out, &ctx_flags, &ret),
             -1, "Could not initialize the contexts and flags successfully\n");

    old_conn = signaling_cdb_get_connection(hit_i, hit_r, new_conn.src_port, new_conn.dst_port);

    if ((old_conn != NULL) && (old_conn->status == SIGNALING_CONN_BLOCKED)) {
        signaling_cdb_print();
        signaling_hipfw_send_connection_failed_ntf(common, tuple, ctx, PRIVATE_REASON, &new_conn);
        ret = 0;
    } else if ((old_conn != NULL) && (old_conn->status == SIGNALING_CONN_ALLOWED)) {
#ifdef DEMO_MODE
        printf("\033[22;32mAccepted I2/U2 packet\033[22;37m\n\n\033[01;37m");
#endif
        ret = 1;
    } else {
        //Check for acknowledgement
        HIP_DEBUG("Verifying Ack to Service Offer.\n");
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Start PERF_MBOX_I2_VERIFY_ACK\n");
        hip_perf_start_benchmark(perf_set, PERF_MBOX_I2_VERIFY_ACK);
#endif
        if (strlen((char *) tuple->offer_hash) > 0) {
            /*Generating the DH shared key*/
            HIP_IFEL(signaling_hipfw_get_dh_shared_key(common, dh,
                                                       &dh_shared_key,
                                                       &dh_shared_len), -1,
                     "Could not get the mb shared key using DH public value from responder\n");

            if (SERVICE_OFFER_TYPE == OFFER_UNSIGNED &&
                signaling_verify_service_ack_u(common, tuple->offer_hash)) {
#ifdef CONFIG_HIP_PERFORMANCE
                HIP_DEBUG("Stop PERF_MBOX_I2_VERIFY_ACK\n");
                hip_perf_stop_benchmark(perf_set, PERF_MBOX_I2_VERIFY_ACK);
#endif
                HIP_IFEL(signaling_init_connection_context_from_msg(&ctx_in, common, FWD), -1,
                         "Could not initialize the connection context from the message\n");
                HIP_IFEL(signaling_hipfw_check_policy_and_verify_info_response(common, tuple, ctx, &ctx_in,
                                                                               ctx_flags, &new_conn, &hit_i, &hit_r, &ret), -1,
                         "Could not check and verify the info in response with the policy\n");
            } else if (SERVICE_OFFER_TYPE == OFFER_SIGNED &&
                       dh_shared_len > 0 && dh_shared_key != NULL &&
                       signaling_verify_service_ack_s(common, &msg_buf, tuple->offer_hash,
                                                      signaling_hipfw_feedback_get_mb_key(),
                                                      dh_shared_key)) {
#ifdef CONFIG_HIP_PERFORMANCE
                HIP_DEBUG("Stop PERF_MBOX_I2_VERIFY_ACK\n");
                hip_perf_stop_benchmark(perf_set, PERF_MBOX_I2_VERIFY_ACK);
#endif
                HIP_DEBUG("Verifying the Signed service ack succeeded\n");
                HIP_IFEL(signaling_init_connection_context_from_msg(&ctx_in, msg_buf, FWD), -1,
                         "Could not initialize the connection context from the message\n");
                HIP_IFEL(signaling_hipfw_check_policy_and_verify_info_response(common, tuple, ctx, &ctx_in,
                                                                               ctx_flags, &new_conn, &hit_i, &hit_r, &ret), -1,
                         "Could not check and verify the info in response with the policy\n");
            } else if (SERVICE_OFFER_TYPE == OFFER_SELECTIVE_SIGNED &&
                       signaling_verify_service_ack_selective_s(common, &msg_buf, tuple->offer_hash,
                                                                signaling_hipfw_feedback_get_mb_key(),
                                                                offset_list, &offset_list_len)) {
#ifdef CONFIG_HIP_PERFORMANCE
                HIP_DEBUG("Stop PERF_MBOX_I2_VERIFY_ACK\n");
                hip_perf_stop_benchmark(perf_set, PERF_MBOX_I2_VERIFY_ACK);
#endif
                HIP_IFEL(signaling_init_connection_context_from_msg(&ctx_in, common, FWD), -1,
                         "Could not initialize the connection context from the message\n");
                HIP_IFEL(signaling_hipfw_check_policy_and_verify_info_response(common, tuple, ctx, &ctx_in,
                                                                               ctx_flags, &new_conn, &hit_i, &hit_r, &ret), -1,
                         "Could not check and verify the info in response with the policy\n");
            } else {
#ifdef CONFIG_HIP_PERFORMANCE
                HIP_DEBUG("Stop PERF_MBOX_I2_VERIFY_ACK\n");
                hip_perf_stop_benchmark(perf_set, PERF_MBOX_I2_VERIFY_ACK);
#endif
                HIP_DEBUG("Service Ack in I2/U2 could not be found or verified. Blocking the connection.\n");
                signaling_cdb_add_connection(hit_i, hit_r, new_conn.src_port, new_conn.dst_port, SIGNALING_CONN_BLOCKED);
                signaling_cdb_print();
                ret = 0;
            }
        } else {
            HIP_DEBUG("No Service Offers added previously \n");
            signaling_cdb_add_connection(hit_i, hit_r, new_conn.src_port, new_conn.dst_port, SIGNALING_CONN_PROCESSING);
            signaling_cdb_print();
            ret = -1;
        }
    }

    free(dh_shared_key);
    memset(tuple->offer_hash, '\0', HIP_AH_SHA_LEN);
    if (!ret) {
        free(matched_tuple);
        free(ctx_flags);
        return ret;
    }

    /* Let packet pass */
#ifdef DEMO_MODE
    printf("\033[22;32mAccepted I2/U2 packet. Checking for information required from Responder\033[22;37m\n\n\033[01;37m");
#endif

    /*
     * Add the info request parameters to the outgoing
     */
    HIP_DEBUG("Policy check for the Responder.\n");
    signaling_info_req_flag_init(&ctx_flags->flag_info_requests);
    signaling_service_info_flag_init(&ctx_flags->flag_services);
    HIP_IFEL(signaling_hipfw_check_policy_and_create_service_offer(common, tuple, other_dir, ctx, &ctx_in, &ctx_out,
                                                                   ctx_flags, &new_conn, &hit_i, &hit_r, &ret),
             -1, "Could not check policy and add service offers\n");

    if (SERVICE_OFFER_TYPE == OFFER_SELECTIVE_SIGNED &&
        !signaling_remove_params_from_hip_msg(common, offset_list, &offset_list_len)) {
        ctx->modified = 1;
    }
#ifdef DEMO_MODE
    printf("\033[22;32mAccepted I2/U2 packet\033[22;37m\n\n\033[01;37m");
#endif

    free(ctx_flags);
    free(matched_tuple);
    free(msg_buf);
    return ret;

out_err:
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop PERF_MBOX_I2_ADD_INFO_REQ\n");
    hip_perf_stop_benchmark(perf_set, PERF_MBOX_I2_ADD_INFO_REQ);
#endif
    free(msg_buf);
    free(ctx_flags);
    free(matched_tuple);
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
    int err = 0;
    int ret = 0;

    struct signaling_connection         new_conn;
    struct signaling_connection_context ctx_in;

    struct signaling_connection_flags *ctx_flags     = NULL;
    struct policy_tuple               *matched_tuple = NULL;
    struct signaling_cdb_entry        *old_conn;
    struct in6_addr                    hit_i;
    struct in6_addr                    hit_r;
    struct hip_common                 *msg_buf = NULL;  /* It will be used in building the HIP Encrypted param*/
    int                                offset_list[10];
    int                                offset_list_len = 0
    ;
#ifdef DEMO_MODE
    printf("\033[22;34mReceived R2/U3 packet\033[22;37m\n\033[22;37m");
#endif

    /* sanity checks */
    HIP_IFEL(!common, -1, "Message is NULL\n");

    if (common->type_hdr == HIP_R2) {
        hit_i = common->hitr;
        hit_r = common->hits;
    } else if (common->type_hdr == HIP_UPDATE) {
        hit_i = common->hits;
        hit_r = common->hitr;
    }

    /* Step a) */
    // Here in because the firewall has to check for the forwarding policies
    // for the message from the responder
    if (signaling_init_connection_context(&ctx_in, FWD)) {
        HIP_ERROR("Could not init connection context for the OUT SIDE \n");
        ret = -1;
    }

    /*
     * Handle the incoming response parameters from the Initiator
     */
    /* Step a) */
    if (signaling_init_connection_from_msg(&new_conn, common, FWD)) {
        HIP_ERROR("Could not init connection context from R2/U3 \n");
        ret = -1;
    }

    ctx_flags = malloc(sizeof(struct signaling_connection_flags));
    signaling_info_req_flag_init(&ctx_flags->flag_info_requests);
    signaling_service_info_flag_init(&ctx_flags->flag_services);


    // Here the ports are in reversed order as the packet is from the Responder
    if ((old_conn = signaling_cdb_get_connection(hit_i, hit_r, new_conn.src_port, new_conn.dst_port))) {
        if (old_conn->status == SIGNALING_CONN_BLOCKED) {
            signaling_cdb_print();
            signaling_hipfw_send_connection_failed_ntf(common, tuple, ctx, PRIVATE_REASON, &new_conn);
            ret = 0;
        } else if (old_conn->status == SIGNALING_CONN_ALLOWED) {
#ifdef DEMO_MODE
            printf("\033[22;32mAccepted R2/U3 packet\033[22;37m\n\n\033[01;37m");
#endif
            ret = 1;
        } else if (old_conn->status == SIGNALING_CONN_PROCESSING) {
            //Check for acknowledgment
#ifdef CONFIG_HIP_PERFORMANCE
            HIP_DEBUG("Start PERF_MBOX_R2_VERIFY_ACK\n");
            hip_perf_start_benchmark(perf_set, PERF_MBOX_R2_VERIFY_ACK);
#endif
            if (strlen((char *) tuple->offer_hash) > 0) {
                if (SERVICE_OFFER_TYPE == OFFER_UNSIGNED &&
                    signaling_verify_service_ack_u(common, tuple->offer_hash)) {
#ifdef CONFIG_HIP_PERFORMANCE
                    HIP_DEBUG("Stop PERF_MBOX_R2_VERIFY_ACK\n");
                    hip_perf_stop_benchmark(perf_set, PERF_MBOX_R2_VERIFY_ACK);
#endif
                    HIP_IFEL(signaling_init_connection_context_from_msg(&ctx_in, common, FWD), -1,
                             "Could not initialize the connection context from the message\n");
                    HIP_IFEL(signaling_hipfw_check_policy_and_verify_info_response(common, tuple, ctx, &ctx_in,
                                                                                   ctx_flags, &new_conn, &hit_i, &hit_r, &ret), -1,
                             "Could not check and verify the info in response with the policy\n");
                } else if (SERVICE_OFFER_TYPE == OFFER_SELECTIVE_SIGNED &&
                           signaling_verify_service_ack_selective_s(common, &msg_buf, tuple->offer_hash,
                                                                    signaling_hipfw_feedback_get_mb_key(),
                                                                    offset_list, &offset_list_len)) {
#ifdef CONFIG_HIP_PERFORMANCE
                    HIP_DEBUG("Stop PERF_MBOX_R2_VERIFY_ACK\n");
                    hip_perf_stop_benchmark(perf_set, PERF_MBOX_R2_VERIFY_ACK);
#endif
                    HIP_IFEL(signaling_init_connection_context_from_msg(&ctx_in, common, FWD), -1,
                             "Could not initialize the connection context from the message\n");
                    HIP_IFEL(signaling_hipfw_check_policy_and_verify_info_response(common, tuple, ctx, &ctx_in,
                                                                                   ctx_flags, &new_conn, &hit_i, &hit_r, &ret), -1,
                             "Could not check and verify the info in response with the policy\n");
                } else if (SERVICE_OFFER_TYPE == OFFER_SIGNED &&
                           signaling_dh_shared_key_r != NULL &&
                           signaling_verify_service_ack_s(common, &msg_buf, tuple->offer_hash,
                                                          signaling_hipfw_feedback_get_mb_key(),
                                                          signaling_dh_shared_key_r)) {
#ifdef CONFIG_HIP_PERFORMANCE
                    HIP_DEBUG("Stop PERF_MBOX_I2_VERIFY_ACK\n");
                    hip_perf_stop_benchmark(perf_set, PERF_MBOX_I2_VERIFY_ACK);
#endif
                    HIP_IFEL(signaling_init_connection_context_from_msg(&ctx_in, msg_buf, FWD), -1,
                             "Could not initialize the connection context from the message\n");
                    HIP_IFEL(signaling_hipfw_check_policy_and_verify_info_response(common, tuple, ctx, &ctx_in,
                                                                                   ctx_flags, &new_conn, &hit_i, &hit_r, &ret), -1,
                             "Could not check and verify the info in response with the policy\n");
                } else {
#ifdef CONFIG_HIP_PERFORMANCE
                    HIP_DEBUG("Stop PERF_MBOX_R2_VERIFY_ACK\n");
                    hip_perf_stop_benchmark(perf_set, PERF_MBOX_R2_VERIFY_ACK);
#endif
                    //Service Acknowledgement didn't veriy correctly.
                    HIP_DEBUG("Service Acknowledgement didn't veriy correctly.\n");
                    signaling_cdb_add_connection(hit_i, hit_r, new_conn.src_port, new_conn.dst_port, SIGNALING_CONN_BLOCKED);
                    signaling_cdb_print();
                    signaling_hipfw_send_connection_failed_ntf(common, tuple, ctx, PRIVATE_REASON, &new_conn);
                    ret = 0;
                }
            } else {
                HIP_DEBUG("No Service Offers added previously\n");
                signaling_cdb_add_connection(hit_i, hit_r, new_conn.src_port, new_conn.dst_port, SIGNALING_CONN_ALLOWED);
                signaling_cdb_print();
                ret = 1;
            }
        }
    }

    if (SERVICE_OFFER_TYPE == OFFER_SELECTIVE_SIGNED &&
        !signaling_remove_params_from_hip_msg(common, offset_list, &offset_list_len)) {
        ctx->modified = 1;
    }

    memset(tuple->offer_hash, '\0', HIP_AH_SHA_LEN);
    free(signaling_dh_shared_key_r);
    signaling_dh_shared_key_r_len = 1024;
    if (!ret) {
        free(ctx_flags);
        free(matched_tuple);
        return ret;
    }

    /* Let packet pass */
#ifdef DEMO_MODE
    printf("\033[22;32mAccepted R2/U3 packet\033[22;37m\n\n\033[22;37m");
#endif

    free(ctx_flags);
    free(matched_tuple);
    free(msg_buf);
    return ret;

out_err:
    free(ctx_flags);
    free(matched_tuple);
    free(msg_buf);
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
    X509                                       *certificate   = NULL;
    struct userdb_certificate_context          *cert_ctx      = NULL;
    uint32_t                                    network_id;
    const struct hip_cert                      *param_cert = NULL;
    struct signaling_connection_context        *conn_ctx   = NULL;

    /* sanity checks */
    HIP_IFEL(!common,  0, "Message is NULL\n");

    /* get connection identifier and context */
    HIP_IFEL(!(param_cert_id = hip_get_param(common, HIP_PARAM_SIGNALING_CERT_CHAIN_ID)),
             -1, "No connection identifier found in the message, cannot handle certificates.\n");
    network_id = ntohl(param_cert_id->network_id);
    /*HIP_IFEL(!(conn = signaling_cdb_entry_get_connection(&common->hits, &common->hitr, &tuple->src_port, &tuple->dst_port, conn_id, &status)),
     *       -1, "No connection context for connection id \n");*/
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
    certificate = sk_X509_pop(cert_ctx->cert_chain);
    HIP_IFEL(!match_public_key(certificate, conn_ctx->userdb_entry->pub_key),
             -1, "Users public key does not match with the key in the received certificate chain\n");

    /* Verify the public key and the certificate chain */
    if (!verify_certificate_chain(certificate, CERTIFICATE_INDEX_TRUSTED_DIR, NULL, cert_ctx->cert_chain)) {
        /* Public key verification was successful, so we save the chain */
        sk_X509_push(cert_ctx->cert_chain, certificate);
        userdb_save_user_certificate_chain(cert_ctx->cert_chain);
        //signaling_flag_set(&conn_ctx->flags, USER_AUTHED);
        //signaling_flag_unset(&conn_ctx->flags, USER_AUTH_REQUEST);
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
    //uint32_t                                    network_id;
    //uint32_t                                    conn_id;

    /* get connection identifier and context */
    HIP_IFEL(!(param_cert_id = hip_get_param(common, HIP_PARAM_SIGNALING_CERT_CHAIN_ID)),
             0, "No connection identifier found in the message, cannot handle certificates.\n");
    //conn_id    =  ntohl(param_cert_id->connection_id);
    //network_id = ntohl(param_cert_id->network_id);
    /*HIP_IFEL(!(conn = signaling_cdb_entry_get_connection(&common->hits, &common->hitr, &tuple->src_port, &tuple->dst_port, &conn_id, &status)),
     *       0, "No connection context for connection id \n");*/
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
/*
 *  if (!signaling_flag_check(conn_ctx->flags, USER_AUTHED)) {
 *      HIP_DEBUG("Received auth ack for user auth that hasn't been successful at the firewall \n");
 *      return 0;
 *  }
 */

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
int signaling_hipfw_handle_update(struct hip_common *common, UNUSED struct tuple *tuple, UNUSED struct hip_fw_context *ctx)
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
        HIP_IFEL(signaling_hipfw_handle_r1(common, tuple, ctx) == 0,
                 -1, "Handling First BEX Update/U1 failed\n");
        return 1;
        break;
    case SIGNALING_SECOND_BEX_UPDATE:
        HIP_DEBUG("Received SECOND BEX Update... \n");
        HIP_IFEL(signaling_hipfw_handle_i2(common, tuple, ctx) == 0,
                 -1, "Handling Second BEX Update/U2 failed\n");
        return 1;
        break;
    case SIGNALING_THIRD_BEX_UPDATE:
        HIP_DEBUG("Received THIRD BEX Update... \n");
        HIP_IFEL(signaling_hipfw_handle_r2(common, tuple, ctx) == 0,
                 -1, "Handling Third BEX Update/U3 failed\n");
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
        HIP_DEBUG("Unimplemented functionality!\n");
        break;
    default:
        HIP_DEBUG("Unhandled notification type: %d \n", htons(notification->msgtype));
        break;
    }

out_err:
    return err;
}

int signaling_hipfw_initialize_connection_contexts_and_flags(struct hip_common *common,
                                                             struct signaling_connection         *new_conn,
                                                             struct signaling_connection_context *ctx_in,
                                                             struct signaling_connection_context *ctx_out,
                                                             struct signaling_connection_flags   **ctx_flags,
                                                             int *ret)
{
    int err = 0;
    /* sanity checks */
    HIP_IFEL(!common, -1, "Message is NULL\n");

    /* Step a) */
    if (signaling_init_connection_from_msg(new_conn, common, FWD)) {
        HIP_ERROR("Could not init connection context for the IN side \n");
        *ret = -1;
    }

    if (signaling_init_connection_context(ctx_in, FWD)) {
        HIP_ERROR("Could not init connection context for the IN side \n");
        *ret = -1;
    }

    if (signaling_init_connection_context(ctx_out, FWD)) {
        HIP_ERROR("Could not init connection context for the IN SIDE \n");
        *ret = -1;
    }

    *ctx_flags = malloc(sizeof(struct signaling_connection_flags));
    signaling_info_req_flag_init(&(*ctx_flags)->flag_info_requests);
    signaling_service_info_flag_init(&(*ctx_flags)->flag_services);

out_err:
    return err;
}

int signaling_hipfw_check_policy_and_create_service_offer(struct hip_common *common,
                                                          struct tuple *tuple,
                                                          struct tuple *other_dir,
                                                          struct hip_fw_context *ctx,
                                                          UNUSED struct signaling_connection_context *ctx_in,
                                                          struct signaling_connection_context *ctx_out,
                                                          struct signaling_connection_flags   *ctx_flags,
                                                          struct signaling_connection         *new_conn,
                                                          struct in6_addr                     *hit_i,
                                                          struct in6_addr                     *hit_r,
                                                          int *ret)
{
    int                  err           = 0;
    int                  policy_check  = -2;
    struct policy_tuple *matched_tuple = NULL;

    HIP_ASSERT(ctx_out);
    HIP_ASSERT(ctx_flags);
    HIP_ASSERT(new_conn);

    if (common->type_hdr == HIP_R1) {
        HIP_DEBUG("Connection after receipt of R1/U1 \n");
    } else if (common->type_hdr == HIP_I2) {
        HIP_DEBUG("Connection after receipt of I2/U2 \n");
    } else if (common->type_hdr == HIP_R2) {
        HIP_DEBUG("Connection after receipt of R2/U3 \n");
    }
    signaling_connection_print(new_conn, "\t");

    //TODO check here if ctx_in or ctx_out should be used
    HIP_IFEL(signaling_init_connection_context_from_msg(ctx_out, common, OUT), -1, "Could not initialize the connection context from the message\n");
#ifdef CONFIG_HIP_PERFORMANCE
    if (common->type_hdr == HIP_R1) {
        HIP_DEBUG("Start PERF_MBOX_R1_VERIFY_WITH_POLICY\n");
        hip_perf_start_benchmark(perf_set, PERF_MBOX_R1_VERIFY_WITH_POLICY);
    } else if (common->type_hdr == HIP_I2) {
        HIP_DEBUG("Start PERF_MBOX_I2_VERIFY_WITH_POLICY\n");
        hip_perf_start_benchmark(perf_set, PERF_MBOX_I2_VERIFY_WITH_POLICY);
    } else if (common->type_hdr == HIP_R2) {
    }
#endif
    if ((matched_tuple = signaling_policy_engine_check_and_flag(hit_i, ctx_out, &ctx_flags, &policy_check))) {
#ifdef CONFIG_HIP_PERFORMANCE
        if (common->type_hdr == HIP_R1) {
            HIP_DEBUG("Stop PERF_MBOX_R1_VERIFY_WITH_POLICY\n");
            hip_perf_stop_benchmark(perf_set, PERF_MBOX_R1_VERIFY_WITH_POLICY);
        } else if (common->type_hdr == HIP_I2) {
            HIP_DEBUG("Stop PERF_MBOX_I2_VERIFY_WITH_POLICY\n");
            hip_perf_stop_benchmark(perf_set, PERF_MBOX_I2_VERIFY_WITH_POLICY);
        } else if (common->type_hdr == HIP_R2) {
        }
#endif
        HIP_DEBUG("Found matching policy tuple\n");
        if (policy_check == 1) {
            HIP_DEBUG("HIP Msg Dump before adding Service Offer.\n");
            hip_dump_msg(common);
#ifdef CONFIG_HIP_PERFORMANCE
            if (common->type_hdr == HIP_R1) {
                HIP_DEBUG("Start PERF_MBOX_R1_ADD_INFO_REQ\n");
                hip_perf_start_benchmark(perf_set, PERF_MBOX_R1_ADD_INFO_REQ);
            } else if (common->type_hdr == HIP_I2) {
                HIP_DEBUG("Start PERF_MBOX_I2_ADD_INFO_REQ\n");
                hip_perf_start_benchmark(perf_set, PERF_MBOX_I2_ADD_INFO_REQ);
            } else if (common->type_hdr == HIP_R2) {
            }
#endif

            if (SERVICE_OFFER_TYPE != OFFER_SELECTIVE_SIGNED) {
                HIP_IFEL(signaling_add_service_offer_to_msg(common, ctx_flags, next_service_offer_id, other_dir->offer_hash,
                                                            signaling_hipfw_feedback_get_mb_key(), signaling_hipfw_feedback_get_mb_cert(),
                                                            SERVICE_OFFER_TYPE), -1,
                         "Could not add service offer to the message\n");
            } else {
                HIP_IFEL(signaling_add_service_offer_to_msg_s(common, ctx_flags, next_service_offer_id, other_dir->offer_hash,
                                                              signaling_hipfw_feedback_get_mb_key(), signaling_hipfw_feedback_get_mb_cert(),
                                                              SERVICE_OFFER_TYPE), -1,
                         "Could not add service offer to the message\n");
            }

/*
 *           HIP_IFEL(signaling_add_service_offer_to_msg_s(common, ctx_flags, next_service_offer_id, other_dir->offer_hash,
 *                                                         signaling_hipfw_feedback_get_mb_key(), signaling_hipfw_feedback_get_mb_cert()), -1, "Could not add service offer to the message\n");
 */

#ifdef CONFIG_HIP_PERFORMANCE
            if (common->type_hdr == HIP_R1) {
                HIP_DEBUG("Stop PERF_MBOX_R1_ADD_INFO_REQ\n");
                hip_perf_stop_benchmark(perf_set, PERF_MBOX_R1_ADD_INFO_REQ);
            } else if (common->type_hdr == HIP_I2) {
                HIP_DEBUG("Stop PERF_MBOX_I2_ADD_INFO_REQ\n");
                hip_perf_stop_benchmark(perf_set, PERF_MBOX_I2_ADD_INFO_REQ);
            } else if (common->type_hdr == HIP_R2) {
            }
#endif
            HIP_DEBUG("HIP Msg Dump after adding Service Offer.\n");
            hip_dump_msg(common);
            ctx->modified = 1;
            signaling_cdb_add_connection(*hit_i, *hit_r, new_conn->src_port, new_conn->dst_port, SIGNALING_CONN_PROCESSING);
            next_service_offer_id++;

            if (common->type_hdr == HIP_R1) {
                HIP_DEBUG("Connection tracking table after receipt of R1\n");
            } else if (common->type_hdr == HIP_I2) {
                HIP_DEBUG("Connection tracking table after receipt of I2\n");
            } else if (common->type_hdr == HIP_R2) {
            }
            signaling_cdb_print();
            /* Let packet pass */
            *ret = -1;
        } else if (policy_check == 0) {
            signaling_cdb_add_connection(*hit_i, *hit_r, new_conn->src_port, new_conn->dst_port, SIGNALING_CONN_ALLOWED);
            memset(other_dir->offer_hash, '\0', HIP_AH_SHA_LEN);
            if (common->type_hdr == HIP_R1) {
                HIP_DEBUG("Connection tracking table after receipt of R1\n");
            } else if (common->type_hdr == HIP_I2) {
                HIP_DEBUG("Connection tracking table after receipt of I2\n");
            } else if (common->type_hdr == HIP_R2) {
            }
            signaling_cdb_print();
            /* Let packet pass */
            *ret = 1;
        }
    } else {
#ifdef CONFIG_HIP_PERFORMANCE
        if (common->type_hdr == HIP_R1) {
            HIP_DEBUG("Stop PERF_MBOX_R1_VERIFY_WITH_POLICY\n");
            hip_perf_stop_benchmark(perf_set, PERF_MBOX_R1_VERIFY_WITH_POLICY);
        } else if (common->type_hdr == HIP_I2) {
            HIP_DEBUG("Stop PERF_MBOX_I2_VERIFY_WITH_POLICY\n");
            hip_perf_stop_benchmark(perf_set, PERF_MBOX_I2_VERIFY_WITH_POLICY);
        } else if (common->type_hdr == HIP_R2) {
        }
#endif
        if (policy_check == -1) {
            signaling_cdb_add_connection(*hit_i, *hit_r, new_conn->src_port, new_conn->dst_port, SIGNALING_CONN_BLOCKED);
            signaling_cdb_print();
            signaling_hipfw_send_connection_failed_ntf(common, tuple, ctx, PRIVATE_REASON, new_conn);
            *ret = 0;
        } else if (policy_check == 0) {
            if (common->type_hdr == HIP_R1) {
                HIP_DEBUG("Connection tracking table after receipt of R1\n");
            } else if (common->type_hdr == HIP_I2) {
                HIP_DEBUG("Connection tracking table after receipt of I2\n");
            } else if (common->type_hdr == HIP_R2) {
            }
            signaling_cdb_add_connection(*hit_i, *hit_r, new_conn->src_port, new_conn->dst_port, SIGNALING_CONN_ALLOWED);
            signaling_cdb_print();
            *ret = 1;
        }
    }

out_err:
    return err;
}

int signaling_hipfw_check_policy_and_verify_info_response(struct hip_common *common,
                                                          struct tuple *tuple,
                                                          struct hip_fw_context *ctx,
                                                          struct signaling_connection_context *ctx_in,
                                                          struct signaling_connection_flags   *ctx_flags,
                                                          struct signaling_connection         *new_conn,
                                                          struct in6_addr                     *hit_i,
                                                          struct in6_addr                     *hit_r,
                                                          int *ret)
{
    int                  err           = 0;
    int                  policy_check  = -2;
    int                  policy_verify = -2;
    struct policy_tuple *matched_tuple = NULL;
    int                  update_type   = -1;

    // Step b)
#ifdef CONFIG_HIP_PERFORMANCE
    if (common->type_hdr == HIP_R1) {
    } else if (common->type_hdr == HIP_I2) {
        HIP_DEBUG("Start PERF_MBOX_I2_VERIFY_INFO_REQ\n");
        hip_perf_start_benchmark(perf_set, PERF_MBOX_I2_VERIFY_INFO_REQ);
    } else if (common->type_hdr == HIP_R2) {
        HIP_DEBUG("Start PERF_MBOX_R2_VERIFY_INFO_REQ\n");
        hip_perf_start_benchmark(perf_set, PERF_MBOX_R2_VERIFY_INFO_REQ);
    }
#endif


    if ((ctx_in->user.subject_name_len > 0) && (ctx_in->user.key_rr_len > 0)) {
        if (!signaling_verify_user_signature_from_msg(common, &ctx_in->user,
                                                      (SERVICE_OFFER_TYPE == OFFER_SELECTIVE_SIGNED ? 1 : 0))) {
            HIP_DEBUG("User Signature Verified.\n");
        } else {
            HIP_ERROR("User Signature Verification failed. Cannot accept the user information as true.\n");
            signaling_cdb_add_connection(*hit_i, *hit_r, new_conn->src_port, new_conn->dst_port, SIGNALING_CONN_BLOCKED);
            signaling_cdb_print();
            //TODO confirm with Rene if we need it or not.
            HIP_IFEL(signaling_hipfw_send_connection_failed_ntf(common, tuple, ctx, PRIVATE_REASON, new_conn),
                     -1, "Could not send connection fail notification to the end-point\n");
            *ret = 0;
            return *ret;
        }
    }

    if (common->type_hdr == HIP_UPDATE) {
        /* Sanity checks */
        HIP_IFEL((update_type = signaling_get_update_type(common)) < 0,
                 1, "This is no signaling update packet\n");
    }
    /*All the above information is not valid without verification of signature*/
    /*Later when we add certificates we should also verify user key with the certificates*/
    if ((matched_tuple = signaling_policy_engine_check_and_flag((hip_hit_t *) hit_i, ctx_in, &ctx_flags, &policy_check))) {
        HIP_DEBUG("Will verify the connection with the policy.\n");
        policy_verify = signaling_hipfw_verify_connection_with_policy(matched_tuple, ctx_in, ctx_flags);

#ifdef CONFIG_HIP_PERFORMANCE
        if (common->type_hdr == HIP_R1) {
        } else if (common->type_hdr == HIP_I2) {
            HIP_DEBUG("Stop PERF_MBOX_I2_VERIFY_INFO_REQ\n");
            hip_perf_stop_benchmark(perf_set, PERF_MBOX_I2_VERIFY_INFO_REQ);
        } else if (common->type_hdr == HIP_R2) {
            HIP_DEBUG("Stop PERF_MBOX_R2_VERIFY_INFO_REQ\n");
            hip_perf_stop_benchmark(perf_set, PERF_MBOX_R2_VERIFY_INFO_REQ);
        }
#endif
        if (policy_verify == -1) {
            signaling_cdb_add_connection(*hit_i, *hit_r, new_conn->src_port, new_conn->dst_port, SIGNALING_CONN_BLOCKED);
            signaling_cdb_print();
            //TODO confirm with Rene if we need it or not.
            HIP_IFEL(signaling_hipfw_send_connection_failed_ntf(common, tuple, ctx, PRIVATE_REASON, new_conn),
                     -1, "Could not send connection fail notification to the end-point\n");
            *ret = 0;
        } else {
            HIP_DEBUG("Connection tracking table after receipt of I2/U2\n");
            signaling_cdb_add_connection(*hit_i, *hit_r, new_conn->src_port, new_conn->dst_port, SIGNALING_CONN_PROCESSING);
            signaling_cdb_print();
            *ret = -1;
        }
    } else {
#ifdef CONFIG_HIP_PERFORMANCE
        if (common->type_hdr == HIP_R1) {
        } else if (common->type_hdr == HIP_I2) {
            HIP_DEBUG("Stop PERF_MBOX_I2_VERIFY_INFO_REQ\n");
            hip_perf_stop_benchmark(perf_set, PERF_MBOX_I2_VERIFY_INFO_REQ);
        } else if (common->type_hdr == HIP_R2) {
            HIP_DEBUG("Stop PERF_MBOX_R2_VERIFY_INFO_REQ\n");
            hip_perf_stop_benchmark(perf_set, PERF_MBOX_R2_VERIFY_INFO_REQ);
        }
#endif
        if (policy_check == -1) {
            // TODO add connection to scdb
            signaling_cdb_add_connection(*hit_i, *hit_r, new_conn->src_port, new_conn->dst_port, SIGNALING_CONN_BLOCKED);
            signaling_cdb_print();
            signaling_hipfw_send_connection_failed_ntf(common, tuple, ctx, PRIVATE_REASON, new_conn);
            *ret = 0;
        } else if (policy_check == 0) {
            // TODO add connection to scdb
            if (common->type_hdr == HIP_R1) {
                HIP_DEBUG("Connection tracking table after receipt of R1/U1\n");
                *ret = -1;
            } else if (common->type_hdr == HIP_I2) {
                HIP_DEBUG("Connection tracking table after receipt of I2\n");
                signaling_cdb_add_connection(*hit_i, *hit_r, new_conn->src_port, new_conn->dst_port, SIGNALING_CONN_PROCESSING);
                *ret = -1;
            } else if (common->type_hdr == HIP_R2) {
                HIP_DEBUG("Connection tracking table after receipt of R2\n");
                signaling_cdb_add_connection(*hit_i, *hit_r, new_conn->src_port, new_conn->dst_port, SIGNALING_CONN_ALLOWED);
                *ret = 1;
            } else if (common->type_hdr == HIP_UPDATE) {
                if (update_type == SIGNALING_SECOND_BEX_UPDATE) {
                    HIP_DEBUG("Connection tracking table after receipt of U2\n");
                    signaling_cdb_add_connection(*hit_i, *hit_r, new_conn->src_port, new_conn->dst_port, SIGNALING_CONN_PROCESSING);
                    *ret = -1;
                } else if (update_type == SIGNALING_THIRD_BEX_UPDATE) {
                    HIP_DEBUG("Connection tracking table after receipt of U3\n");
                    signaling_cdb_add_connection(*hit_i, *hit_r, new_conn->src_port, new_conn->dst_port, SIGNALING_CONN_ALLOWED);
                    *ret = 1;
                }
            }
            signaling_cdb_print();
        }
    }

out_err:
    return err;
}

int signaling_hipfw_generate_mb_dh_key(UNUSED const int group_id, DH **dh_key)
{
    int err;
    DH *temp_dh;

    BIGNUM *priv_key = NULL;

    temp_dh  = hip_generate_dh_key(DH_GROUP_ID);
    priv_key = BN_bin2bn(dh_priv_key, dh_priv_key_len, NULL);

    *dh_key      = DH_new();
    (*dh_key)->g = BN_new();
    (*dh_key)->p = BN_new();

    /* Put generator corresponding to group_id into dh->g */
    BN_copy(dh->p, temp_dh->p);
    BN_copy(dh->g, temp_dh->g);

    /*Setting the private key so that the corresponding public key can be generated*/
    (*dh_key)->priv_key = priv_key;

    if ((err = DH_generate_key(*dh_key)) != 1) {
        HIP_ERROR("DH key generation failed (%d).\n", err);
        exit(1);
    }

    HIP_DEBUG("=========================== Printing Mbox DH key ==============================\n");
    BIO *bio_out;
    bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
    HIP_DEBUG("DH parameters\n");
    DHparams_print(bio_out, *dh_key);
    BIO_free(bio_out);

    uint8_t *buffer  = NULL;
    int      bufsize = 0;
    bufsize = hip_get_dh_size(group_id);
    buffer  = calloc(1, bufsize);
    HIP_DEBUG("Size of the public key : %d\n", bufsize);
    hip_encode_dh_publickey(*dh_key, buffer, bufsize);
    HIP_HEXDUMP("Public Key :", buffer, bufsize);
    free(buffer);

    uint8_t *buffer1  = NULL;
    int      bufsize1 = 0;
    bufsize1 = BN_num_bytes((*dh_key)->priv_key);
    buffer1  = calloc(1, bufsize1);
    HIP_DEBUG("Size of the private key : %d\n", bufsize1);
    err = bn2bin_safe((*dh_key)->priv_key, buffer1, bufsize1);
    HIP_HEXDUMP("Private Key :", buffer1, bufsize1);
    free(buffer1);
    HIP_DEBUG("========================================================================\n");

    DH_free(temp_dh);
    return 1;
}

int signaling_hipfw_get_dh_shared_key(struct hip_common *msg,
                                      DH *dh_key,
                                      unsigned char **dh_shared_key,
                                      uint16_t *dh_shared_len)
{
    int                        err                         = 0;
    struct hip_diffie_hellman *dhf                         = NULL;
    uint8_t                    sha1_digest[HIP_AH_SHA_LEN] = { 0 };
    int                        tmp_len                     = 0;
    HIP_ASSERT(dh_key);
    HIP_IFEL(!(*dh_shared_key = calloc(1, *dh_shared_len)),
             -ENOMEM,
             "Error on allocating memory for Diffie-Hellman shared key.\n");
    HIP_IFEL(!(dhf = hip_get_param_readwrite(msg, HIP_PARAM_DIFFIE_HELLMAN)),
             -ENOENT, "No Diffie-Hellman parameter found.\n");

    /* If the message has two DH keys, select (the stronger, usually) one. */
    const struct hip_dh_public_value *dhpv = hip_dh_select_key(dhf);
    tmp_len = hip_gen_dh_shared_key(dh_key, dhpv->public_value,
                                    ntohs(dhpv->pub_len), (unsigned char *) *dh_shared_key, *dh_shared_len);
    if (tmp_len < 0) {
        HIP_ERROR("Could not create shared secret\n");
        return -1;
    } else {
        *dh_shared_len = tmp_len;
    }
    HIP_IFEL(hip_build_digest(HIP_DIGEST_SHA1, *dh_shared_key, *dh_shared_len, sha1_digest),
             -1, "Could not build message digest \n");

    *dh_shared_len = 16;
    memcpy(*dh_shared_key, sha1_digest, *dh_shared_len);
    memset((*dh_shared_key + *dh_shared_len), 0, 1024 - *dh_shared_len);

    HIP_HEXDUMP("DH Shared key : ", *dh_shared_key, *dh_shared_len);
out_err:
    return err;
}

DH *signaling_hipfw_get_mb_dh_key()
{
    if (dh != NULL) {
        return dh;
    } else {
        return NULL;
    }
}
