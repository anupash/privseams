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

#include <arpa/inet.h>
#include <string.h>
#include <openssl/x509.h>

#include "lib/core/debug.h"
#include "lib/core/common.h"
#include "lib/core/ife.h"
#include "lib/core/prefix.h"
#include "lib/core/straddr.h"

#include "firewall/hslist.h"

#include "modules/signaling/lib/signaling_x509_api.h"
#include "signaling_policy_engine.h"

/* Paths to configuration elements */
const char *path_rules_in =   { "rules_in" };
const char *path_rules_out =   { "rules_out" };
const char *path_rules_fwd =   { "rules_fwd" };

/* Cache for the rules set */
struct slist *policy_tuples_in  = NULL;
struct slist *policy_tuples_out = NULL;
struct slist *policy_tuples_fwd = NULL;

/**
 * releases the configuration file and frees the configuration memory
 *
 * @param cfg   parsed configuration parameters
 * @return      always 0
 */
static int release_config(config_t *cfg)
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
static config_t *read_config(const char *config_file)
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
        release_config(cfg);
        cfg = NULL;
    }
#endif

    return cfg;
}

UNUSED static int compare_tuples(const struct policy_tuple *t1, const struct policy_tuple *t2)
{
    if (strncmp(t1->application.app_id, t2->application.app_id, SIGNALING_APP_DN_MAX_LEN)) {
        return -1;
    }
    if (strncmp(t1->user.user_id, t2->user.user_id, SIGNALING_USER_ID_MAX_LEN)) {
        return -1;
    }
    if (IN6_ARE_ADDR_EQUAL(&t1->host.host_id, &t2->host.host_id)) {
        return -1;
    }
    return 0;
}

static void print_policy_tuple(const struct policy_tuple *tuple, UNUSED const char *prefix)
{
    char dst[INET6_ADDRSTRLEN];

    HIP_DEBUG("%s-------------- POLICY TUPLE ----------------\n", prefix);
    if (ipv6_addr_any(&tuple->host.host_id)) {
        HIP_DEBUG("%s  HOST:\t ANY HOST\n", prefix);
    } else {
        hip_in6_ntop(&tuple->host.host_id, dst);
        HIP_DEBUG("%s  HOST:\t %s\n", prefix, dst);
    }
    HIP_DEBUG("%s  USER:\t %s\n", prefix, strlen(tuple->user.user_id) == 0 ? "ANY USER" : tuple->user.user_id);
    HIP_DEBUG("%s  APP:\t %s\n",  prefix, strlen(tuple->application.app_id)  == 0 ? "ANY APPLICATION" : tuple->application.app_id);
    HIP_DEBUG("%s  TRGT:\t %s\n",  prefix, policy_decision_check(tuple->target, POLICY_ACCEPT) ? "ALLOW" : "DROP");
    HIP_DEBUG("%s--------------------------------------------\n", prefix);
}

static void printf_policy_tuple(const struct policy_tuple *tuple, UNUSED const char *prefix)
{
    char dst[INET6_ADDRSTRLEN];

    printf("%s--------------     TUPLE    ----------------\n", prefix);
    if (ipv6_addr_any(&tuple->host.host_id)) {
        printf("%s  HOST:\t ANY HOST\n", prefix);
    } else {
        hip_in6_ntop(&tuple->host.host_id, dst);
        printf("%s  HOST:\t %s\n", prefix, dst);
    }
    printf("%s  USER:\t %s\n", prefix, strlen(tuple->user.user_id) == 0 ? "ANY USER" : tuple->user.user_id);
    printf("%s  APP:\t %s\n",  prefix, strlen(tuple->application.app_id)  == 0 ? "ANY APPLICATION" : tuple->application.app_id);
    printf("%s  TRGT:\t %s\n",  prefix, policy_decision_check(tuple->target, POLICY_ACCEPT) ? "ALLOW" : "DROP");
    printf("%s--------------------------------------------\n", prefix);
}

static int read_tuple(config_setting_t *tuple, struct slist **rulelist)
{
    int                  err           = 0;
    struct policy_tuple *entry         = NULL;
    const char          *host_id       = NULL;
    const char          *host_name     = NULL;
    const char          *host_certs    = NULL;
    const char          *host_kernel   = NULL;
    const char          *host_os       = NULL;
    const char          *user_id       = NULL;
    const char          *app_id        = NULL;
    const char          *target_string = NULL;
    config_setting_t    *temp          = NULL;


    HIP_IFEL(!tuple, -1, "Got NULL-tuple\n");
    HIP_IFEL(!(entry = malloc(sizeof(struct policy_tuple))),
             -1, "Could not allocate memory for new rule\n");

    policy_decision_init(&entry->target);


    if (!(temp = config_setting_get_member(tuple, "host"))) {
        HIP_DEBUG("No HOST information in the policy file \n");
    } else {
        if (CONFIG_FALSE == config_setting_lookup_string(temp, "hit", &host_id)) {
            entry->host.host_id = in6addr_any;
            HIP_DEBUG("No HOST HIT information in the policy file \n");
        } else {
            HIP_IFEL(inet_pton(AF_INET6, host_id, &entry->host.host_id) != 1,
                     -1, "Could not parse host id to in6addr \n");
        }

        if (CONFIG_FALSE == config_setting_lookup_string(temp, "kernel", &host_kernel)) {
            HIP_DEBUG("No HOST Kernel information in the policy file \n");
        } else {
            strncpy(entry->host.host_os, host_kernel, SIGNALING_HOST_INFO_REQ_MAX_LEN - 1);
            entry->host.host_kernel[SIGNALING_HOST_INFO_REQ_MAX_LEN - 1] = '\0';
        }

        if (CONFIG_FALSE == config_setting_lookup_string(temp, "os", &host_os)) {
            HIP_DEBUG("No HOST OS information in the policy file \n");
            entry->host.host_os[0] = '\0';
        } else {
            strncpy(entry->host.host_os, host_name, SIGNALING_HOST_INFO_REQ_MAX_LEN - 1);
            entry->host.host_os[SIGNALING_HOST_INFO_REQ_MAX_LEN - 1] = '\0';
        }

        if (CONFIG_FALSE == config_setting_lookup_string(temp, "name", &host_name)) {
            HIP_DEBUG("No HOST Name information in the policy file \n");
            entry->host.host_name[0] = '\0';
        } else {
            strncpy(entry->host.host_name, host_name, SIGNALING_HOST_INFO_REQ_MAX_LEN - 1);
            entry->host.host_name[SIGNALING_HOST_INFO_REQ_MAX_LEN - 1] = '\0';
        }


        if (CONFIG_FALSE == config_setting_lookup_string(temp, "certs", &host_certs)) {
            HIP_DEBUG("No HOST Name information in the policy file \n");
            entry->host.host_certs[0] = '\0';
        } else {
            strncpy(entry->host.host_certs, host_certs, SIGNALING_HOST_INFO_REQ_MAX_LEN - 1);
            entry->host.host_certs[SIGNALING_HOST_INFO_REQ_MAX_LEN - 1] = '\0';
        }
    }


    /* Lookup and save values */
    if (!(temp = config_setting_get_member(tuple, "user"))) {
        HIP_DEBUG("No USER information in the policy file \n");
        entry->user.user_id[0] = '\0';
    } else {
        if (CONFIG_FALSE == config_setting_lookup_string(temp, "name", &user_id)) {
            HIP_DEBUG("No USER DN information in the policy file \n");
            entry->user.user_id[0] = '\0';
        } else {
            strncpy(entry->user.user_id, user_id, SIGNALING_USER_ID_MAX_LEN - 1);
            entry->user.user_id[SIGNALING_USER_ID_MAX_LEN - 1] = '\0';
            /*Request for USER_INFO_SHORT*/
            policy_decision_set(&entry->target, POLICY_USER_INFO_SHORT);
        }
    }


    if (CONFIG_FALSE == config_setting_lookup_string(tuple, "application", &app_id)) {
        entry->application.app_id[0] = '\0';
    } else {
        strncpy(entry->application.app_id, app_id, SIGNALING_APP_DN_MAX_LEN - 1);
        entry->application.app_id[SIGNALING_APP_DN_MAX_LEN - 1] = '\0';
    }

    if (CONFIG_FALSE == config_setting_lookup_string(tuple, "target", &target_string)) {
        policy_decision_set(&entry->target, POLICY_REJECT);
    } else {
        policy_decision_set(&entry->target, strcmp(target_string, "ALLOW") == 0 ? POLICY_ACCEPT : POLICY_REJECT);
    }
    *rulelist = append_to_slist(*rulelist, entry);

out_err:
    return err;
}

static int read_tuples(config_t *cfg)
{
    int               err   = 0;
    int               i     = 0;
    config_setting_t *rules = NULL;
    config_setting_t *tuple = NULL;

    HIP_IFEL(!(rules = config_lookup(cfg, path_rules_in)),
             -1, "Could not get list of tuples from incoming rule setting \n)");
    while ((tuple = config_setting_get_elem(rules, i))) {
        read_tuple(tuple, &policy_tuples_in);
        i++;
    }
    rules = NULL;
    HIP_DEBUG("Read %d rules for incoming traffic from policy file \n", i);

    HIP_IFEL(!(rules = config_lookup(cfg, path_rules_out)),
             -1, "Could not get list of tuples from outgoing rule setting \n)");
    i = 0;
    while ((tuple = config_setting_get_elem(rules, i))) {
        read_tuple(tuple, &policy_tuples_out);
        i++;
    }
    rules = NULL;
    HIP_DEBUG("Read %d rules for outgoing traffic from policy file \n", i);

    HIP_IFEL(!(rules = config_lookup(cfg, path_rules_fwd)),
             -1, "Could not get list of tuples from outgoing rule setting \n)");
    i = 0;
    while ((tuple = config_setting_get_elem(rules, i))) {
        read_tuple(tuple, &policy_tuples_fwd);
        i++;
    }
    rules = NULL;
    HIP_DEBUG("Read %d rules for forwarding traffic from policy file \n", i);

out_err:
    return err;
}

/**
 * Initialize the policy engine from a given configuration.
 *
 * @param cfg   the configuration object parsed from a policy configuration file
 */
int signaling_policy_engine_init(config_t *cfg)
{
    int err;

    err = read_tuples(cfg);
    signaling_policy_engine_print_rule_set("");

    return err;
}

int signaling_policy_engine_init_from_file(const char *const policy_file)
{
    config_t *cfg = NULL;
    if (!(cfg = read_config(policy_file))) {
        HIP_ERROR("Could not parse policy file for policy engine.\n");
        return -1;
    }
    return signaling_policy_engine_init(cfg);
}

/**
 * Uninitialize the policy engine from a given configuration.
 *
 * @param cfg   the configuration object parsed from a policy configuration file
 */
int signaling_policy_engine_uninit(void)
{
    HIP_DEBUG("Uninitializing the policy engine \n");
    return 0;
}

/**
 * @return 0 if tuples don't match, 1 if they do
 */
static int match_tuples(const struct policy_tuple *tuple_conn, const struct policy_tuple *tuple_rule)
{
    /* Check if hits match or if rule allows any hit */
    if (ipv6_addr_cmp(&tuple_rule->host.host_id, &in6addr_any) != 0) {
        if (ipv6_addr_cmp(&tuple_rule->host.host_id, &tuple_conn->host.host_id) != 0) {
            HIP_DEBUG("Host does not match\n");
            return 0;
        }
    }
    /* Check if host with any kernel version is allowed */
    if (strlen(tuple_rule->host.host_kernel) > 0) {
        if (strcmp(tuple_rule->host.host_kernel, tuple_conn->host.host_kernel) > 0) {
            HIP_DEBUG("Kernel version below %s is not allowed\n", tuple_rule->host.host_kernel);
            return 0;
        }
    }

    /* Check if host with any operating system is allowed */
    if (strlen(tuple_rule->host.host_os) > 0) {
        if (strcmp(tuple_rule->host.host_os, tuple_conn->host.host_os) != 0) {
            HIP_DEBUG("Operating system %s is not allowed\n", tuple_rule->host.host_os);
            return 0;
        }
    }

    /* Check if host with any name is allowed */
    if (strlen(tuple_rule->host.host_name) > 0) {
        if (strcmp(tuple_rule->host.host_name, tuple_conn->host.host_name) != 0) {
            HIP_DEBUG("Hosts with the name %s is not allowed\n", tuple_rule->host.host_name);
            return 0;
        }
    }


    /* Check if user ids match or if rule allows any user */

    if (strlen(tuple_rule->user.user_id) > 0) {
        if (strcmp(tuple_rule->user.user_id, tuple_conn->user.user_id) != 0) {
            HIP_DEBUG("User does not match\n");
            return 0;
        }
    }

    /* Check if app ids match or if rule allows any app */
    if (strlen(tuple_rule->application.app_id) != 0) {
        if (strcmp(tuple_rule->application.app_id, tuple_conn->application.app_id) != 0) {
            HIP_DEBUG("App does not match\n");
            return 0;
        }
    }

    return 1;
}

/**
 * @return the matching tuple or NULL if no tuples matches
 */
static const struct policy_tuple *match_tuple_list(const struct policy_tuple *tuple_conn, const struct slist *const rules)
{
    const struct slist *listentry = rules;
    while (listentry) {
        if (match_tuples(tuple_conn, (struct policy_tuple *) listentry->data)) {
            return listentry->data;
        }
        HIP_DEBUG("Following tuple did not match:\n");
        print_policy_tuple((struct policy_tuple *) listentry->data, "\t");
        listentry = listentry->next;
    }
    return NULL;
}

/**
 * Check with the given policy, whether a connection with given tuple and connection context should be allowed.
 *
 * @param tuple     the conntracking tuple for the connection
 * @param conn_ctx  the connection context with application and user context for this connection
 *
 * @return          0 if the connection complies with the policy,
 *                  if not, a bitmask specifying what parts of the context need to be authed
 *                  in order for the connection to comply
 *                  -1 the connection would not comply even if every entity as given was authenticated
 */
struct policy_tuple signaling_policy_check(const struct in6_addr *const hit,
                                           const struct signaling_connection_context *const conn_ctx)
{
    struct policy_tuple        ret;
    struct policy_tuple        tuple_for_conn_authed;
    struct policy_tuple        tuple_for_conn_unauthed;
    const struct policy_tuple *tuple_match = NULL;
    struct slist              *rule_list   = NULL;
    X509_NAME                 *x509_subj_name;

    policy_decision_init(&ret.target);

    /* Construct the authed and unauthed tuple for the current context.
     * Need to memset-0 because we want to use memcmp later. */
    memset(&tuple_for_conn_authed, 0, sizeof(struct policy_tuple));
    memset(&tuple_for_conn_unauthed, 0, sizeof(struct policy_tuple));
    memcpy(tuple_for_conn_authed.application.app_id,   conn_ctx->app.application_dn, SIGNALING_APP_DN_MAX_LEN);
    memcpy(tuple_for_conn_unauthed.application.app_id, conn_ctx->app.application_dn, SIGNALING_APP_DN_MAX_LEN);
    if (signaling_flag_check(conn_ctx->flags, HOST_AUTHED)) {
        memcpy(&tuple_for_conn_authed.host.host_id, hit, sizeof(struct in6_addr));
        if (conn_ctx->host.host_kernel_len > 0) {
            strncpy(tuple_for_conn_authed.host.host_kernel, conn_ctx->host.host_kernel, SIGNALING_HOST_INFO_REQ_MAX_LEN);
        }
        if (conn_ctx->host.host_os_len > 0) {
            strncpy(tuple_for_conn_authed.host.host_os, conn_ctx->host.host_os, SIGNALING_HOST_INFO_REQ_MAX_LEN);
        }

        if (conn_ctx->host.host_name_len > 0) {
            strncpy(tuple_for_conn_authed.host.host_name, conn_ctx->host.host_name, SIGNALING_HOST_INFO_REQ_MAX_LEN);
        }
    } else {
        memcpy(&tuple_for_conn_authed.host.host_id, &in6addr_any, sizeof(struct in6_addr));
        if (conn_ctx->host.host_kernel_len > 0) {
            strncpy(tuple_for_conn_unauthed.host.host_kernel, conn_ctx->host.host_kernel, SIGNALING_HOST_INFO_REQ_MAX_LEN);
        }
        if (conn_ctx->host.host_os_len > 0) {
            strncpy(tuple_for_conn_unauthed.host.host_os, conn_ctx->host.host_os, SIGNALING_HOST_INFO_REQ_MAX_LEN);
        }
        if (conn_ctx->host.host_name_len > 0) {
            strncpy(tuple_for_conn_unauthed.host.host_name, conn_ctx->host.host_name, SIGNALING_HOST_INFO_REQ_MAX_LEN);
        }
    }

    memcpy(&tuple_for_conn_unauthed.host.host_id, hit,         sizeof(struct in6_addr));
    if (!signaling_DER_to_X509_NAME(conn_ctx->user.subject_name, conn_ctx->user.subject_name_len, &x509_subj_name)) {
        X509_NAME_oneline(x509_subj_name, tuple_for_conn_authed.user.user_id, SIGNALING_USER_ID_MAX_LEN);
        X509_NAME_oneline(x509_subj_name, tuple_for_conn_unauthed.user.user_id, SIGNALING_USER_ID_MAX_LEN);
        tuple_for_conn_authed.user.user_id[SIGNALING_USER_ID_MAX_LEN - 1]   = '\0';
        tuple_for_conn_unauthed.user.user_id[SIGNALING_USER_ID_MAX_LEN - 1] = '\0';
    } else {
        tuple_for_conn_authed.user.user_id[0]   = '\0';
        tuple_for_conn_unauthed.user.user_id[0] = '\0';
    }
    if (!signaling_flag_check(conn_ctx->flags, USER_AUTHED)) {
        tuple_for_conn_authed.user.user_id[0] = '\0';
    }

    HIP_DEBUG("Checking connection context:\n");
    print_policy_tuple(&tuple_for_conn_unauthed, "\t");

    /* Determine which rule set to apply */
    switch (conn_ctx->direction) {
    case IN:
        rule_list = policy_tuples_in;
        break;
    case OUT:
        rule_list = policy_tuples_out;
        break;
    case FWD:
        rule_list = policy_tuples_fwd;
        break;
    }

    /* Find a match for authed tuple */
    if ((tuple_match = match_tuple_list(&tuple_for_conn_authed, rule_list))) {
        printf("\033[22;32mConnection could be matched to firewall rules:\033[22;37m\n");
        printf("Connection tuple:\n");
        printf_policy_tuple(&tuple_for_conn_authed, "\t");
        printf("is matched by rule tuple:\n");
        printf_policy_tuple(tuple_match, "\t");
        return *tuple_match;
    }

    /* If we haven't found a match and the unauthed tuple does not differ from
     * the authed tuple, we can return the result right away. */
    if (!memcmp(&tuple_for_conn_authed, &tuple_for_conn_unauthed, sizeof(struct policy_tuple))) {
        policy_decision_set(&ret.target, POLICY_REJECT);
        return ret;
    }

    /* If we wouldn't have a match for the unauthed tuple, reject. */
    if (!(tuple_match = match_tuple_list(&tuple_for_conn_unauthed, rule_list))) {
        HIP_DEBUG("Rejected because no match for unauthed tuple.\n");
        printf("\033[22;32mRejected because no match for unauthed tuple.\033[22;37m\n\033[22;37m");
        printf("Rejected tuple:\n");
        printf_policy_tuple(&tuple_for_conn_authed, "\t");
        policy_decision_set(&ret.target, POLICY_REJECT);
        return ret;
    }

    /* If we have found a match for the unautehd tuple,
     *  determine which minimum set of the unauthed entities need to be authenticated */

    /* Check if we need host auth,
     * this is the case if the match's host id is not "ANY",
     */
    if (ipv6_addr_cmp(&tuple_match->host.host_id, &in6addr_any)) {
        policy_decision_set(&ret.target, POLICY_HOST_AUTH_REQUIRED);
    }

    /* Check if we really need the user auth,
     * this is the case if the match's user id is not "ANY",
     */
    if (strlen(tuple_match->user.user_id)) {
        policy_decision_set(&ret.target, POLICY_USER_AUTH_REQUIRED);
    }

    /* Check if we really need the app auth,
     * this is the case if the match's app id is not "ANY",
     */
    if (strlen(tuple_match->application.app_id)) {
        policy_decision_set(&ret.target, POLICY_APP_AUTH_REQUIRED);
    }

    /*
     * Check if we need to request for host information
     */
    if (strlen(tuple_match->host.host_kernel) > 0) {
        policy_decision_set(&ret.target, POLICY_HOST_INFO_KERNEL);
    }
    if (strlen(tuple_match->host.host_os) > 0) {
        policy_decision_set(&ret.target, POLICY_HOST_INFO_OS);
    }
    if (strlen(tuple_match->host.host_name) > 0) {
        policy_decision_set(&ret.target, POLICY_HOST_INFO_NAME);
    }
    if (strlen(tuple_match->host.host_certs) > 0) {
        policy_decision_set(&ret.target, POLICY_HOST_INFO_CERTS);
    }

    printf("\033[22;32mConnection could be matched to firewall rules:\n\033[22;37m");
    printf("Connection tuple:\n");
    printf_policy_tuple(&tuple_for_conn_unauthed, "\t");
    printf("is matched by rule tuple:\n");
    printf_policy_tuple(tuple_match, "\t");

    return ret;
}

/**
 * Check a connection context against the local policy and check the flags
 * for those entities that need to be auth'd to comply.
 *
 * @return    0 on success (if the tuple complies, or will comply if auth is complete),
 *           -1 if the context will be rejected no matter what authentication takes place
 */
int signaling_policy_engine_check_and_flag(const hip_hit_t *hit,
                                           struct signaling_connection_context *const conn_ctx)
{
    struct policy_tuple req_auth_tuple = signaling_policy_check(hit, conn_ctx);

    //req_auth_types = signaling_policy_check(hit, conn_ctx);
    if (policy_decision_check(req_auth_tuple.target, POLICY_REJECT)) {
        HIP_DEBUG("Connection request has been rejected by local policy. \n");
        printf("\033[22;31m Connection request has been rejected by local policy.\n\033[22;37m");
        return -1;
    } else if (policy_decision_check(req_auth_tuple.target, POLICY_ACCEPT)) {
        HIP_DEBUG("Connection request has been accepted as is by local policy. \n");
        /* tell the HIPD that it needs not request authentication for the firewall */
        signaling_flag_set(&conn_ctx->flags, HOST_AUTHED);
        signaling_flag_set(&conn_ctx->flags, USER_AUTHED);
        return 0;
    } else {
        HIP_DEBUG("Connection request will be accepted by local policy if further authentication is effectuated: \n");
        /* Set those flags for which we need no user authentication */
        if (!policy_decision_check(req_auth_tuple.target, POLICY_USER_AUTH_REQUIRED)) {
            signaling_flag_set(&conn_ctx->flags, USER_AUTHED);
        } else {
            signaling_flag_set(&conn_ctx->flags, USER_AUTH_REQUEST);
        }
        if (!policy_decision_check(req_auth_tuple.target, POLICY_HOST_AUTH_REQUIRED)) {
            signaling_flag_set(&conn_ctx->flags, HOST_AUTHED);
        } else {
            signaling_flag_set(&conn_ctx->flags, HOST_AUTH_REQUEST);
        }
        if (!policy_decision_check(req_auth_tuple.target, POLICY_HOST_AUTH_REQUIRED)) {
            signaling_flag_set(&conn_ctx->flags, HOST_AUTHED);
        } else {
            signaling_flag_set(&conn_ctx->flags, HOST_AUTH_REQUEST);
        }

        /* Requesting for additional information from host based on the firewall policy*/
        if (policy_decision_check(req_auth_tuple.target, POLICY_HOST_INFO_OS)) {
            signaling_flag_set(&conn_ctx->flags, HOST_INFO_OS);
        } else {
            signaling_flag_set(&conn_ctx->flags, HOST_INFO_OS_RECV);
        }

        if (policy_decision_check(req_auth_tuple.target, POLICY_HOST_INFO_KERNEL)) {
            signaling_flag_set(&conn_ctx->flags, HOST_INFO_KERNEL);
        } else {
            signaling_flag_set(&conn_ctx->flags, HOST_INFO_KERNEL_RECV);
        }

        if (policy_decision_check(req_auth_tuple.target, POLICY_HOST_INFO_NAME)) {
            signaling_flag_set(&conn_ctx->flags, HOST_INFO_NAME);
        } else {
            signaling_flag_set(&conn_ctx->flags, HOST_INFO_NAME_RECV);
        }

        if (policy_decision_check(req_auth_tuple.target, POLICY_HOST_INFO_CERTS)) {
            signaling_flag_set(&conn_ctx->flags, HOST_INFO_CERTS);
        } else {
            signaling_flag_set(&conn_ctx->flags, HOST_INFO_CERTS_RECV);
        }

        return 0;
    }
}

void signaling_policy_engine_print_rule_set(UNUSED const char *prefix)
{
    struct slist        *listentry;
    struct policy_tuple *entry;

    listentry = policy_tuples_in;
    HIP_DEBUG("%s-------------- RULES FOR INCOMING TRAFFIC ----------------\n", prefix);
    while (listentry != NULL) {
        if (listentry->data != NULL) {
            entry = (struct policy_tuple *) listentry->data;
            print_policy_tuple(entry, "\t");
        }
        listentry = listentry->next;
    }
    HIP_DEBUG("%s--------------           END RULES        ----------------\n", prefix);

    listentry = policy_tuples_out;
    HIP_DEBUG("%s-------------- RULES FOR OUTGOING TRAFFIC ----------------\n", prefix);
    while (listentry != NULL) {
        if (listentry->data != NULL) {
            entry = (struct policy_tuple *) listentry->data;
            print_policy_tuple(entry, "\t");
        }
        listentry = listentry->next;
    }
    HIP_DEBUG("%s--------------           END RULES        ----------------\n", prefix);

    listentry = policy_tuples_fwd;
    HIP_DEBUG("%s-------------- RULES FOR FORWARDING TRAFFIC ----------------\n", prefix);
    while (listentry != NULL) {
        if (listentry->data != NULL) {
            entry = (struct policy_tuple *) listentry->data;
            print_policy_tuple(entry, "\t");
        }
        listentry = listentry->next;
    }
    HIP_DEBUG("%s--------------            END RULES         ----------------\n", prefix);
}

void policy_decision_set(struct policy_decision *flags, int f)
{
    switch (f) {
    case POLICY_ACCEPT:
        flags->POLICY_ACCEPT = 1;
        break;
    case POLICY_REJECT:
        flags->POLICY_REJECT = 1;
        break;
    case POLICY_USER_AUTH_REQUIRED:
        flags->POLICY_USER_AUTH_REQUIRED = 1;
        break;
    case POLICY_HOST_AUTH_REQUIRED:
        flags->POLICY_HOST_AUTH_REQUIRED = 1;
        break;
    case POLICY_APP_AUTH_REQUIRED:
        flags->POLICY_APP_AUTH_REQUIRED = 1;
        break;
    case POLICY_HOST_INFO_OS:
        flags->POLICY_HOST_INFO_OS = 1;
        break;
    case POLICY_HOST_INFO_KERNEL:
        flags->POLICY_HOST_INFO_KERNEL = 1;
        break;
    case POLICY_HOST_INFO_NAME:
        flags->POLICY_HOST_INFO_NAME = 1;
        break;
    case POLICY_HOST_INFO_CERTS:
        flags->POLICY_HOST_INFO_CERTS = 1;
        break;
    case POLICY_USER_SIGN:
        flags->POLICY_USER_SIGN = 1;
        break;
    case POLICY_USER_INFO_SHORT:
        flags->POLICY_USER_INFO_SHORT = 1;
        break;
    case POLICY_USER_INFO_LONG:
        flags->POLICY_USER_INFO_LONG = 1;
        break;
    case POLICY_USER_INFO_SHORT_SIGNED:
        flags->POLICY_USER_INFO_SHORT_SIGNED = 1;
        break;
    case POLICY_USER_INFO_LONG_SIGNED:
        flags->POLICY_USER_INFO_LONG_SIGNED = 1;
        break;

    default:
        break;
    }
}

void policy_decision_unset(struct policy_decision *flags, int f)
{
    switch (f) {
    case POLICY_ACCEPT:
        flags->POLICY_ACCEPT = 0;
        break;
    case POLICY_REJECT:
        flags->POLICY_REJECT = 0;
        break;
    case POLICY_USER_AUTH_REQUIRED:
        flags->POLICY_USER_AUTH_REQUIRED = 0;
        break;
    case POLICY_HOST_AUTH_REQUIRED:
        flags->POLICY_HOST_AUTH_REQUIRED = 0;
        break;
    case POLICY_APP_AUTH_REQUIRED:
        flags->POLICY_APP_AUTH_REQUIRED = 0;
        break;
    case POLICY_HOST_INFO_OS:
        flags->POLICY_HOST_INFO_OS = 0;
        break;
    case POLICY_HOST_INFO_KERNEL:
        flags->POLICY_HOST_INFO_KERNEL = 0;
        break;
    case POLICY_HOST_INFO_NAME:
        flags->POLICY_HOST_INFO_NAME = 0;
        break;
    case POLICY_HOST_INFO_CERTS:
        flags->POLICY_HOST_INFO_CERTS = 0;
        break;
    case POLICY_USER_SIGN:
        flags->POLICY_USER_SIGN = 0;
        break;
    case POLICY_USER_INFO_SHORT:
        flags->POLICY_USER_INFO_SHORT = 0;
        break;
    case POLICY_USER_INFO_LONG:
        flags->POLICY_USER_INFO_LONG = 0;
        break;
    case POLICY_USER_INFO_SHORT_SIGNED:
        flags->POLICY_USER_INFO_SHORT_SIGNED = 0;
        break;
    case POLICY_USER_INFO_LONG_SIGNED:
        flags->POLICY_USER_INFO_LONG_SIGNED = 0;
        break;

    default:
        break;
    }
}

void policy_decision_init(struct policy_decision *flags)
{
    flags->POLICY_ACCEPT                 = 0;
    flags->POLICY_REJECT                 = 0;
    flags->POLICY_USER_AUTH_REQUIRED     = 0;
    flags->POLICY_HOST_AUTH_REQUIRED     = 0;
    flags->POLICY_APP_AUTH_REQUIRED      = 0;
    flags->POLICY_HOST_INFO_OS           = 0;
    flags->POLICY_HOST_INFO_KERNEL       = 0;
    flags->POLICY_HOST_INFO_NAME         = 0;
    flags->POLICY_HOST_INFO_CERTS        = 0;
    flags->POLICY_USER_SIGN              = 0;
    flags->POLICY_USER_INFO_SHORT        = 0;
    flags->POLICY_USER_INFO_LONG         = 0;
    flags->POLICY_USER_INFO_CERTS        = 0;
    flags->POLICY_USER_INFO_SHORT_SIGNED = 0;
    flags->POLICY_USER_INFO_LONG_SIGNED  = 0;
}

int policy_decision_check(struct policy_decision flags, int f)
{
    switch (f) {
    case POLICY_ACCEPT:
        return (flags.POLICY_ACCEPT) ? 1 : 0;
        break;
    case POLICY_REJECT:
        return (flags.POLICY_REJECT) ? 1 : 0;
        break;
    case POLICY_USER_AUTH_REQUIRED:
        return (flags.POLICY_USER_AUTH_REQUIRED) ? 1 : 0;
        break;
    case POLICY_HOST_AUTH_REQUIRED:
        return (flags.POLICY_HOST_AUTH_REQUIRED) ? 1 : 0;
        break;
    case POLICY_APP_AUTH_REQUIRED:
        return (flags.POLICY_APP_AUTH_REQUIRED) ? 1 : 0;
        break;
    case POLICY_HOST_INFO_OS:
        return (flags.POLICY_HOST_INFO_OS) ? 1 : 0;
        break;
    case POLICY_HOST_INFO_KERNEL:
        return (flags.POLICY_HOST_INFO_KERNEL) ? 1 : 0;
        break;
    case POLICY_HOST_INFO_NAME:
        return (flags.POLICY_HOST_INFO_NAME) ? 1 : 0;
        break;
    case POLICY_HOST_INFO_CERTS:
        return (flags.POLICY_HOST_INFO_CERTS) ? 1 : 0;
        break;
    case POLICY_USER_SIGN:
        return (flags.POLICY_USER_SIGN) ? 1 : 0;
        break;
    case POLICY_USER_INFO_SHORT:
        return (flags.POLICY_USER_INFO_SHORT) ? 1 : 0;
        break;
    case POLICY_USER_INFO_LONG:
        return (flags.POLICY_USER_INFO_LONG) ? 1 : 0;
        break;
    case POLICY_USER_INFO_SHORT_SIGNED:
        return (flags.POLICY_USER_INFO_SHORT_SIGNED) ? 1 : 0;
        break;
    case POLICY_USER_INFO_LONG_SIGNED:
        return (flags.POLICY_USER_INFO_LONG_SIGNED) ? 1 : 0;
        break;
    default:
        return 0;
        break;
    }
}
