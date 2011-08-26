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

#include "firewall/hslist.h"

#include "modules/signaling/lib/signaling_prot_common.h"
#include "modules/signaling/lib/signaling_common_builder.h"
#include "modules/signaling/lib/signaling_user_management.h"

#include "signaling_policy_engine.h"
#include "signaling_hipfw.h"

/* Set from libconfig.
 * If set to zero, the firewall does only static filtering on basis of the predefined policy.
 * If set to one, the firewall saves the connection contexts it sees to the conntracking table,
 * for later use. */
int do_conntrack = 0;

/* Paths to configuration elements */
const char *default_policy_file      = {"/usr/local/etc/hip/signaling_firewall_policy.cfg"};

const char *path_do_conntracking     = {"do_conntracking"};

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
    int err       = 0;

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
int signaling_hipfw_init(const char *policy_file) {
    int err         = 0;
    config_t *cfg   = NULL;

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

    /* Start the policy engine */
    HIP_IFEL(signaling_policy_engine_init(cfg),
             -1, "Failed to start policy engine \n");
out_err:
    return err;
}

/**
 * Uninitialize the middlebox firewall application.
 * So far, there's nothing to be done.
 *
 * @return 0 on success, negative on error
 */
int signaling_hipfw_uninit(void) {
    HIP_DEBUG("Uninit signaling firewall \n");
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
static int signaling_hipfw_conntrack(struct tuple * const tuple,
                                     struct signaling_connection_context * const conn_ctx)
{
    int err = 0;
    struct signaling_connection_context *new_conn_ctx = NULL;

    if(!do_conntrack) {
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
 * Handles an I2 packet observed by the firewall.
 * This includes adding connection context information to the conntracking table
 * and speaking a verdict based on the firewalls policy about host, user and application.
 *
 * @return the verdict, i.e. 1 for pass, 0 for drop
 */
int signaling_hipfw_handle_i2(struct hip_common *common, struct tuple *tuple, UNUSED const hip_fw_context_t *ctx)
{
    struct signaling_connection_context conn_ctx;
    int verdict = 1;
    int err = 0;

    HIP_IFEL(signaling_init_connection_context_from_msg(&conn_ctx, common),
             -1, "Could not init new connection context from message\n");

    /* Verify the user signature in the packet. */
    err = signaling_verify_user_signature(common);
    switch (err) {
    case 0:
        HIP_DEBUG("User signature verification successful\n");
        break;
    case -1:
        HIP_DEBUG("Error processing user signature, assuming \"ANY USER\"\n");
        signaling_init_user_context(&conn_ctx.user);
        break;
    default:
        HIP_DEBUG("Could not verify certifcate chain:\n");
        HIP_DEBUG("Error: %s \n", X509_verify_cert_error_string(err));
        HIP_DEBUG("Requesting user's certificate chain.\n");

        // TODO: send a notification / certificate request
    }

    /* Get a verdict on given hosts, user and application from the policy engine */
    verdict = signaling_policy_check(tuple, &conn_ctx);
    if(!verdict) {
        HIP_DEBUG("Connection has been rejected according to the firewall's policy\n");
    } else {
        HIP_DEBUG("Connection has been accepted according to the firewall's policy\n");
    }

    /* If we allow the connection, save it in conntracking table */
    if (verdict) {
        if (signaling_hipfw_conntrack(tuple, &conn_ctx)) {
            // for now we let pass, if we were very restrictive,
            // we would spread verdict = DROP here
            HIP_DEBUG("Couldn't conntrack connection context\n");
        }
    }

    return verdict;
out_err:
    return 0;
}

/*
 * Handles an R2 packet observed by the firewall.
 * This includes adding connection context information to the conntracking table
 * and speaking a verdict based on the firewalls policy about host, user and application.
 *
 * @return the verdict, i.e. 1 for pass, 0 for drop
 */
int signaling_hipfw_handle_r2(struct hip_common *common, struct tuple *tuple, const hip_fw_context_t *ctx)
{
    return signaling_hipfw_handle_i2(common, tuple, ctx);
}

/*
 * Handles an UPDATE packet observed by the firewall.
 * This includes adding connection context information to the conntracking table
 * and speaking a verdict based on the firewalls policy about host, user and application.
 *
 * @return the verdict, i.e. 1 for pass, 0 for drop
 */
int signaling_hipfw_handle_update(UNUSED const struct hip_common *common, UNUSED struct tuple *tuple, UNUSED const hip_fw_context_t *ctx)
{
    HIP_DEBUG("WARNING: unimplemented function \n");
    return 1;
}

