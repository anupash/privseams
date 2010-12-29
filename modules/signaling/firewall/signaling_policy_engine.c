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

#include "lib/core/debug.h"
#include "lib/core/common.h"
#include "lib/core/ife.h"
#include "lib/core/prefix.h"
#include "lib/core/straddr.h"

#include "firewall/hslist.h"

#include "signaling_policy_engine.h"

const char *path_rules     = {"rules"};

SList *policy_tuples = NULL;

static void print_policy_tuple(const struct policy_tuple *tuple, const char *prefix) {
    char dst[INET6_ADDRSTRLEN];
    hip_in6_ntop(&tuple->host_id, dst);

    HIP_DEBUG("%s-------------- POLICY TUPLE ----------------\n", prefix);
    HIP_DEBUG("%s  HOST:\t %s\n", prefix, dst);
    HIP_DEBUG("%s  USER:\t %s\n", prefix, strlen(tuple->user_id) == 0 ? "ANY USER" : tuple->user_id);
    HIP_DEBUG("%s  APP:\t %s\n",  prefix, strlen(tuple->app_id)  == 0 ? "ANY APPLICATION" : tuple->app_id);
    HIP_DEBUG("%s--------------------------------------------\n", prefix);
}

static int read_tuple(config_setting_t *tuple) {
    int err                     = 0;
    struct policy_tuple *entry  = NULL;
    const char *host_id         = NULL;
    const char *user_id         = NULL;
    const char *app_id          = NULL;

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

    policy_tuples = append_to_slist(policy_tuples, entry);

out_err:
    return err;
}

static int read_tuples(config_t *cfg) {
    int err                 = 0;
    int i                   = 0;
    config_setting_t *rules = NULL;
    config_setting_t *tuple = NULL;

    HIP_IFEL(!(rules = config_lookup(cfg, path_rules)),
             -1, "Could not get list of tuples from rule setting \n)");

    while ((tuple = config_setting_get_elem(rules, i))) {
        read_tuple(tuple);
        i++;
    }

    HIP_DEBUG("Read %d rules from policy file \n", i);
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

    HIP_DEBUG("Connection tuple:\n");
    print_policy_tuple(tuple_conn, "\t");
    HIP_DEBUG("is matched by rule tuple:\n");
    print_policy_tuple(tuple_rule, "\t");

    /* If we made it so far, the connection tuple matches the rule tuple */
    return 1;
}

/**
 * Check with the given policy, whether a connection with given tuple and connection context should be allowed.
 *
 * @param tuple     the conntracking tuple for the connection
 * @param conn_ctx  the connection context with application and user context for this connection
 *
 * @return          1 if the connection complies with the policy, 0 otherwise
 */
int signaling_policy_check(UNUSED const struct tuple *tuple, UNUSED const struct signaling_connection_context *conn_ctx) {
    int match = 0;
    struct policy_tuple tuple_for_conn;
    SList *listentry;

    /* Construct the tuple for the current context */
    memcpy(&tuple_for_conn.app_id, conn_ctx->app_ctx.application_dn, SIGNALING_APP_DN_MAX_LEN);
    memcpy(&tuple_for_conn.user_id, conn_ctx->user_ctx.username, SIGNALING_USER_ID_MAX_LEN);
    memcpy(&tuple_for_conn.host_id, &tuple->hip_tuple->data->src_hit, sizeof(struct in6_addr));

    /* Find a match */
    listentry = policy_tuples;
    while (listentry) {
        match = match_tuples(&tuple_for_conn, (struct policy_tuple *) listentry->data);
        if (match) {
            break;
        }
        listentry = listentry->next;
    }

    return match;
}

void signaling_policy_engine_print_rule_set(const char *prefix) {
    SList *listentry;
    listentry = policy_tuples;
    struct policy_tuple *entry;

    HIP_DEBUG("%s-------------- POLICY RULES START ----------------\n", prefix);
    while(listentry != NULL) {
        if(listentry->data != NULL) {
            entry = (struct policy_tuple *) listentry->data;
            print_policy_tuple(entry, "\t");
        }
        listentry = listentry->next;
    }
    HIP_DEBUG("%s-------------- POLICY RULES END   ----------------\n", prefix);
}
