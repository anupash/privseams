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
const char *path_rules_in      = {"rules_in"};
const char *path_rules_out     = {"rules_out"};
const char *path_rules_fwd     = {"rules_fwd"};

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
        release_config(cfg);
        cfg = NULL;
    }
#endif

    return cfg;
}

UNUSED static int compare_tuples(const struct policy_tuple *t1, const struct policy_tuple *t2) {
    if (strncmp(t1->app_id, t2->app_id, SIGNALING_APP_DN_MAX_LEN)) {
        return -1;
    }
    if (strncmp(t1->user_id, t2->user_id, SIGNALING_USER_ID_MAX_LEN)) {
       return -1;
    }
    if (IN6_ARE_ADDR_EQUAL(&t1->host_id, &t2->host_id)) {
        return -1;
    }
    return 0;
}

static void print_policy_tuple(const struct policy_tuple *tuple, const char *prefix) {
    char dst[INET6_ADDRSTRLEN];

    HIP_DEBUG("%s-------------- POLICY TUPLE ----------------\n", prefix);
    if (ipv6_addr_any(&tuple->host_id)) {
        HIP_DEBUG("%s  HOST:\t ANY HOST\n", prefix);
    } else {
        hip_in6_ntop(&tuple->host_id, dst);
        HIP_DEBUG("%s  HOST:\t %s\n", prefix, dst);
    }
    HIP_DEBUG("%s  USER:\t %s\n", prefix, strlen(tuple->user_id) == 0 ? "ANY USER" : tuple->user_id);
    HIP_DEBUG("%s  APP:\t %s\n",  prefix, strlen(tuple->app_id)  == 0 ? "ANY APPLICATION" : tuple->app_id);
    HIP_DEBUG("%s  TRGT:\t %s\n",  prefix, tuple->target  == POLICY_ACCEPT ? "ALLOW" : "DROP");
    HIP_DEBUG("%s--------------------------------------------\n", prefix);
}

static int read_tuple(config_setting_t *tuple, struct slist **rulelist) {
    int err                     = 0;
    struct policy_tuple *entry  = NULL;
    const char *host_id         = NULL;
    const char *user_id         = NULL;
    const char *app_id          = NULL;
    const char *target_string   = NULL;

    HIP_IFEL(!tuple, -1, "Got NULL-tuple\n");
    HIP_IFEL(!(entry = malloc(sizeof(struct policy_tuple))),
             -1, "Could not allocate memory for new rule\n");

    /* Lookup and save values */
    if(CONFIG_FALSE == config_setting_lookup_string(tuple, "host", &host_id)) {
        entry->host_id = in6addr_any;
    } else {
        HIP_IFEL(inet_pton(AF_INET6, host_id, &entry->host_id) != 1,
                 -1, "Could not parse host id to in6addr \n");
    }
    if(CONFIG_FALSE == config_setting_lookup_string(tuple, "user", &user_id)) {
        entry->user_id[0] = '\0';
    } else {
        strncpy(entry->user_id, user_id, SIGNALING_USER_ID_MAX_LEN-1);
        entry->user_id[SIGNALING_USER_ID_MAX_LEN-1] = '\0';
    }
    if(CONFIG_FALSE == config_setting_lookup_string(tuple, "application", &app_id)) {
        entry->app_id[0] = '\0';
    } else {
        strncpy(entry->app_id, user_id, SIGNALING_APP_DN_MAX_LEN - 1);
        entry->app_id[SIGNALING_APP_DN_MAX_LEN - 1] = '\0';
    }
    if(CONFIG_FALSE == config_setting_lookup_string(tuple, "target", &target_string)) {
        entry->target = POLICY_REJECT;
    } else {
        entry->target = strcmp(target_string, "ALLOW") == 0 ? POLICY_ACCEPT : POLICY_REJECT;
    }

    *rulelist = append_to_slist(*rulelist, entry);

out_err:
    return err;
}

static int read_tuples(config_t *cfg) {
    int err                 = 0;
    int i                   = 0;
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
int signaling_policy_engine_init(config_t *cfg) {
    int err;

    err = read_tuples(cfg);
    signaling_policy_engine_print_rule_set("");

    return err;
}

int signaling_policy_engine_init_from_file(const char *const policy_file) {
    config_t *cfg = NULL;
    if (!(cfg = read_config(policy_file))) {
        HIP_ERROR("Could not parse policy file for policy engine.\n");
        return -1;
    }
    return signaling_policy_engine_init(cfg);
}

/**
 * @return 0 if tuples don't match, 1 if they do
 */
static int match_tuples(const struct policy_tuple *tuple_conn, const struct policy_tuple *tuple_rule) {
    /* Check if hits match or if rule allows any hit */
    if(ipv6_addr_cmp(&tuple_rule->host_id, &in6addr_any) != 0) {
        if(ipv6_addr_cmp(&tuple_rule->host_id, &tuple_conn->host_id) != 0) {
            return 0;
        }
    }

    /* Check if user ids match or if rule allows any user */
    if(strlen(tuple_rule->user_id) != 0) {
        if(strcmp(tuple_rule->user_id, tuple_conn->user_id) != 0) {
            return 0;
        }
    }

    /* Check if app ids match or if rule allows any app */
    if(strlen(tuple_rule->app_id) != 0) {
        if(strcmp(tuple_rule->app_id, tuple_conn->app_id) != 0) {
            return 0;
        }
    }

    return 1;
}

/**
 * @return the matching tuple or NULL if no tuples matches
 */
static const struct policy_tuple *match_tuple_list(const struct policy_tuple *tuple_conn, const struct slist *const rules) {
    const struct slist *listentry = rules;
    while (listentry) {
        if(match_tuples(tuple_conn, (struct policy_tuple *) listentry->data)) {
            return listentry->data;
        }
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
int signaling_policy_check(const struct in6_addr *const hit,
                           const struct signaling_connection_context *const conn_ctx)
{
    int ret   = 0;
    struct policy_tuple tuple_for_conn_authed;
    struct policy_tuple tuple_for_conn_unauthed;
    const struct policy_tuple *tuple_match = NULL;
    struct slist *rule_list = NULL;
    X509_NAME *x509_subj_name;

    /* Construct the authed and unauthed tuple for the current context.
     * Need to memset-0 because we want to use memcmp later. */
    memset(&tuple_for_conn_authed, 0, sizeof(struct policy_tuple));
    memset(&tuple_for_conn_authed, 0, sizeof(struct policy_tuple));
    memcpy(tuple_for_conn_authed.app_id,   conn_ctx->app.application_dn, SIGNALING_APP_DN_MAX_LEN);
    memcpy(tuple_for_conn_unauthed.app_id, conn_ctx->app.application_dn, SIGNALING_APP_DN_MAX_LEN);
    if (signaling_flag_check(conn_ctx->flags, HOST_AUTHED)) {
        memcpy(&tuple_for_conn_authed.host_id, hit, sizeof(struct in6_addr));
    } else {
        memcpy(&tuple_for_conn_authed.host_id, &in6addr_any, sizeof(struct in6_addr));
    }
    memcpy(&tuple_for_conn_unauthed.host_id, hit,         sizeof(struct in6_addr));
    if (!signaling_DER_to_X509_NAME(conn_ctx->user.subject_name, conn_ctx->user.subject_name_len, &x509_subj_name)) {
        X509_NAME_oneline(x509_subj_name, tuple_for_conn_authed.user_id, SIGNALING_USER_ID_MAX_LEN);
        X509_NAME_oneline(x509_subj_name, tuple_for_conn_unauthed.user_id, SIGNALING_USER_ID_MAX_LEN);
        tuple_for_conn_authed.user_id[SIGNALING_USER_ID_MAX_LEN-1] = '\0';
        tuple_for_conn_unauthed.user_id[SIGNALING_USER_ID_MAX_LEN-1] = '\0';
    } else {
        tuple_for_conn_authed.user_id[0] = '\0';
        tuple_for_conn_unauthed.user_id[0] = '\0';
    }
    if (!signaling_flag_check(conn_ctx->flags, USER_AUTHED)) {
        tuple_for_conn_authed.user_id[0] = '\0';
    }

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
        HIP_DEBUG("Connection tuple:\n");
        print_policy_tuple(&tuple_for_conn_authed, "\t");
        HIP_DEBUG("is matched by rule tuple:\n");
        print_policy_tuple(tuple_match, "\t");
        return tuple_match->target;
    }

    /* If we haven't found a match and the unauthed tuple does not differ from
     * the authed tuple, we can return the result right away. */
    if (!memcmp(&tuple_for_conn_authed, &tuple_for_conn_unauthed, sizeof(struct policy_tuple))) {
        return POLICY_REJECT;
    }

    /* If we wouldn't have a match for the unauthed tuple, reject. */
    if (!(tuple_match = match_tuple_list(&tuple_for_conn_unauthed, rule_list))) {
        return POLICY_REJECT;
    }

    /* If we have found a match for the unautehd tuple,
     *  determine which minimum set of the unauthed entities need to be authenticated */

    /* Check if we need host auth,
     * this is the case if the match's host id is not "ANY",
     */
    if(ipv6_addr_cmp(&tuple_match->host_id, &in6addr_any)) {
        ret |= POLICY_HOST_AUTH_REQUIRED;
    }

    /* Check if we really need the user auth,
     * this is the case if the match's user id is not "ANY",
     */
    if(strlen(tuple_match->user_id)) {
        ret |= POLICY_USER_AUTH_REQUIRED;
    }

    /* Check if we really need the app auth,
     * this is the case if the match's app id is not "ANY",
     */
    if(strlen(tuple_match->app_id)) {
        ret |= POLICY_APP_AUTH_REQUIRED;
    }

    HIP_DEBUG("Unauthed connection tuple:\n");
    print_policy_tuple(&tuple_for_conn_unauthed, "\t");
    HIP_DEBUG("is matched by rule tuple:\n");
    print_policy_tuple(tuple_match, "\t");

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
    int req_auth_types = 0;

    req_auth_types = signaling_policy_check(hit, conn_ctx);
    if (req_auth_types & POLICY_REJECT) {
        HIP_DEBUG("Connection request has been rejected by local policy. \n");
        return -1;
    } else if (req_auth_types == POLICY_ACCEPT){
        HIP_DEBUG("Connection request has been accepted as is by local policy \n");
        /* tell the HIPD that it needs not request authentication for the firewall */
        signaling_flag_set(&conn_ctx->flags, HOST_AUTHED);
        signaling_flag_set(&conn_ctx->flags, USER_AUTHED);
    } else {
        HIP_DEBUG("Connection request will be accepted by local policy if further authentication is effectuated: \n");
        /* Set those flags for which we need no user authentication */
        if (!(req_auth_types & POLICY_USER_AUTH_REQUIRED)) {
            signaling_flag_set(&conn_ctx->flags, USER_AUTHED);
        }
        if (!(req_auth_types & POLICY_HOST_AUTH_REQUIRED)) {
            signaling_flag_set(&conn_ctx->flags, HOST_AUTHED);
        }
    }

    return 0;
}


void signaling_policy_engine_print_rule_set(const char *prefix) {
    struct slist *listentry;
    struct policy_tuple *entry;

    listentry = policy_tuples_in;
    HIP_DEBUG("%s-------------- RULES FOR INCOMING TRAFFIC ----------------\n", prefix);
    while(listentry != NULL) {
        if(listentry->data != NULL) {
            entry = (struct policy_tuple *) listentry->data;
            print_policy_tuple(entry, "\t");
        }
        listentry = listentry->next;
    }
    HIP_DEBUG("%s--------------           END RULES        ----------------\n", prefix);

    listentry = policy_tuples_out;
    HIP_DEBUG("%s-------------- RULES FOR OUTGOING TRAFFIC ----------------\n", prefix);
    while(listentry != NULL) {
        if(listentry->data != NULL) {
            entry = (struct policy_tuple *) listentry->data;
            print_policy_tuple(entry, "\t");
        }
        listentry = listentry->next;
    }
    HIP_DEBUG("%s--------------           END RULES        ----------------\n", prefix);

    listentry = policy_tuples_fwd;
    HIP_DEBUG("%s-------------- RULES FOR FORWARDING TRAFFIC ----------------\n", prefix);
    while(listentry != NULL) {
        if(listentry->data != NULL) {
            entry = (struct policy_tuple *) listentry->data;
            print_policy_tuple(entry, "\t");
        }
        listentry = listentry->next;
    }
    HIP_DEBUG("%s--------------            END RULES         ----------------\n", prefix);

}
