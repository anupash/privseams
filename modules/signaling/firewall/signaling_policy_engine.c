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
    if (strncmp(t1->application.application_dn, t2->application.application_dn, SIGNALING_APP_DN_MAX_LEN)) {
        return -1;
    }
    if (strncmp(t1->user.user_name, t2->user.user_name, SIGNALING_USER_ID_MAX_LEN)) {
        return -1;
    }
    if (IN6_ARE_ADDR_EQUAL(&t1->host.host_id, &t2->host.host_id)) {
        return -1;
    }
    return 0;
}

static void print_policy_tuple(const struct policy_tuple *tuple, UNUSED const char *prefix,
                               struct signaling_connection_flags *flags)
{
    HIP_DEBUG("%s-------------- POLICY TUPLE ----------------\n", prefix);
    if (ipv6_addr_any(&tuple->host.host_id)) {
        HIP_DEBUG("%s  HOST ID:\t\t ANY HOST\n", prefix);
    } else {
        HIP_DEBUG_HIT("\t  HOST ID\t\t", &tuple->host.host_id);
    }
    HIP_DEBUG("%s  HOST KERNEL:\t\t %s\n", prefix, strlen(tuple->host.host_kernel) == 0 ? "ANY KERNEL" : tuple->host.host_kernel);
    HIP_DEBUG("%s  HOST OS:\t\t %s\n", prefix, strlen(tuple->host.host_os) == 0 ? "ANY OS" : tuple->host.host_os);
    HIP_DEBUG("%s  HOST NAME:\t\t %s\n", prefix, strlen(tuple->host.host_name) == 0 ? "ANY HOST" : tuple->host.host_name);

    HIP_DEBUG("%s  USER:\t\t\t %s\n", prefix, strlen(tuple->user.user_name) == 0 ? "ANY USER" : tuple->user.user_name);
    HIP_DEBUG("%s  APP NAME:\t\t %s\n",  prefix, strlen(tuple->application.application_dn)  == 0 ? "ANY APPLICATION" : tuple->application.application_dn);
    HIP_DEBUG("%s  APP ISS:\t\t %s\n",  prefix, strlen(tuple->application.issuer_dn)  == 0 ? "ANY ISSUER" : tuple->application.issuer_dn);
    HIP_DEBUG("%s  APP CONN:\t\t %d\n",  prefix, tuple->application.connections < 0 ? -1 : tuple->application.connections);

    if (policy_decision_check(tuple->target, POLICY_ACCEPT) || policy_decision_check(tuple->target, POLICY_REJECT)) {
        HIP_DEBUG("%s  TRGT:\t\t\t %s\n",  prefix, policy_decision_check(tuple->target, POLICY_ACCEPT) ? "ALLOW" : "DROP");
    } else if (flags != NULL) {
        HIP_DEBUG("%s  TRGT:\t\t\t\n", prefix);
        if (signaling_info_req_flag_check(&flags->flag_info_requests, HOST_INFO_ID)) {
            HIP_DEBUG("%s      :\t\t\t %s\n",  prefix, signaling_info_req_flag_check(&flags->flag_info_requests, HOST_INFO_ID) ? "HOST_INFO_ID" : "");
        }
        if (signaling_info_req_flag_check(&flags->flag_info_requests, HOST_INFO_KERNEL)) {
            HIP_DEBUG("%s      :\t\t\t %s\n",  prefix, signaling_info_req_flag_check(&flags->flag_info_requests, HOST_INFO_KERNEL) ? "HOST_INFO_KERNEL" : "");
        }
        if (signaling_info_req_flag_check(&flags->flag_info_requests, HOST_INFO_OS)) {
            HIP_DEBUG("%s      :\t\t\t %s\n",  prefix, signaling_info_req_flag_check(&flags->flag_info_requests, HOST_INFO_OS) ? "HOST_INFO_OS" : "");
        }
        if (signaling_info_req_flag_check(&flags->flag_info_requests, HOST_INFO_CERTS)) {
            HIP_DEBUG("%s      :\t\t\t %s\n",  prefix, signaling_info_req_flag_check(&flags->flag_info_requests, HOST_INFO_CERTS) ? "HOST_INFO_CERTS" : "");
        }

        if (signaling_info_req_flag_check(&flags->flag_info_requests, APP_INFO_NAME)) {
            HIP_DEBUG("%s      :\t\t\t %s\n",  prefix, signaling_info_req_flag_check(&flags->flag_info_requests, APP_INFO_NAME) ? "APP_INFO_NAME" : "");
        }
        if (signaling_info_req_flag_check(&flags->flag_info_requests, APP_INFO_QOS_CLASS)) {
            HIP_DEBUG("%s      :\t\t\t %s\n",  prefix, signaling_info_req_flag_check(&flags->flag_info_requests, APP_INFO_QOS_CLASS) ? "APP_INFO_QOS_CLASS" : "");
        }
        if (signaling_info_req_flag_check(&flags->flag_info_requests, APP_INFO_CONNECTIONS)) {
            HIP_DEBUG("%s      :\t\t\t %s\n",  prefix, signaling_info_req_flag_check(&flags->flag_info_requests, APP_INFO_CONNECTIONS) ? "APP_INFO_CONNECTIONS" : "");
        }
        if (signaling_info_req_flag_check(&flags->flag_info_requests, APP_INFO_REQUIREMENTS)) {
            HIP_DEBUG("%s      :\t\t\t %s\n",  prefix, signaling_info_req_flag_check(&flags->flag_info_requests, APP_INFO_REQUIREMENTS) ? "APP_INFO_REQUIREMENTS" : "");
        }

        if (signaling_info_req_flag_check(&flags->flag_info_requests, USER_INFO_ID)) {
            HIP_DEBUG("%s      :\t\t\t %s\n",  prefix, signaling_info_req_flag_check(&flags->flag_info_requests, USER_INFO_ID) ? "USER_INFO_ID" : "");
        }
        if (signaling_info_req_flag_check(&flags->flag_info_requests, USER_INFO_CERTS)) {
            HIP_DEBUG("%s      :\t\t\t %s\n",  prefix, signaling_info_req_flag_check(&flags->flag_info_requests, USER_INFO_CERTS) ? "USER_INFO_CERTS" : "");
        }
    }
    HIP_DEBUG("%s--------------------------------------------\n", prefix);
}

UNUSED static void printf_policy_tuple(const struct policy_tuple *tuple, UNUSED const char *prefix,
                                       struct signaling_connection_flags *flags)
{
    char dst[INET6_ADDRSTRLEN];

    printf("%s--------------     TUPLE    ----------------\n", prefix);
    if (ipv6_addr_any(&tuple->host.host_id)) {
        printf("%s  HOST:\t ANY HOST\n", prefix);
    } else {
        hip_in6_ntop(&tuple->host.host_id, dst);
        printf("%s  HOST:\t %s\n", prefix, dst);
    }
    printf("%s  HOST KERNEL:\t\t %s\n", prefix, strlen(tuple->host.host_kernel) == 0 ? "ANY KERNEL" : tuple->host.host_kernel);
    printf("%s  HOST OS:\t\t %s\n", prefix, strlen(tuple->host.host_os) == 0 ? "ANY OS" : tuple->host.host_os);
    printf("%s  HOST NAME:\t\t %s\n", prefix, strlen(tuple->host.host_name) == 0 ? "ANY HOST" : tuple->host.host_name);

    printf("%s  USER:\t %s\n", prefix, strlen(tuple->user.user_name) == 0 ? "ANY USER" : tuple->user.user_name);
    printf("%s  APP:\t %s\n",  prefix, strlen(tuple->application.application_dn)  == 0 ? "ANY APPLICATION" : tuple->application.application_dn);
    printf("%s  APP ISS:\t\t %s\n",  prefix, strlen(tuple->application.issuer_dn)  == 0 ? "ANY ISSUER" : tuple->application.issuer_dn);
    printf("%s  APP CONN:\t\t %d\n",  prefix, tuple->application.connections < 0 ? -1 : tuple->application.connections);

    if (policy_decision_check(tuple->target, POLICY_ACCEPT) || policy_decision_check(tuple->target, POLICY_REJECT)) {
        printf("%s  TRGT:\t\t\t %s\n",  prefix, policy_decision_check(tuple->target, POLICY_ACCEPT) ? "ALLOW" : "DROP");
    } else {
        printf("%s  TRGT:\t\t\t\n", prefix);
        if (signaling_info_req_flag_check(&flags->flag_info_requests, HOST_INFO_ID)) {
            printf("%s      :\t\t\t %s\n",  prefix, signaling_info_req_flag_check(&flags->flag_info_requests, HOST_INFO_ID) ? "HOST_INFO_ID" : "");
        }
        if (signaling_info_req_flag_check(&flags->flag_info_requests, HOST_INFO_KERNEL)) {
            printf("%s      :\t\t\t %s\n",  prefix, signaling_info_req_flag_check(&flags->flag_info_requests, HOST_INFO_KERNEL) ? "HOST_INFO_KERNEL" : "");
        }
        if (signaling_info_req_flag_check(&flags->flag_info_requests, HOST_INFO_OS)) {
            printf("%s      :\t\t\t %s\n",  prefix, signaling_info_req_flag_check(&flags->flag_info_requests, HOST_INFO_OS) ? "HOST_INFO_OS" : "");
        }
        if (signaling_info_req_flag_check(&flags->flag_info_requests, HOST_INFO_CERTS)) {
            printf("%s      :\t\t\t %s\n",  prefix, signaling_info_req_flag_check(&flags->flag_info_requests, HOST_INFO_CERTS) ? "HOST_INFO_CERTS" : "");
        }

        if (signaling_info_req_flag_check(&flags->flag_info_requests, APP_INFO_NAME)) {
            printf("%s      :\t\t\t %s\n",  prefix, signaling_info_req_flag_check(&flags->flag_info_requests, APP_INFO_NAME) ? "APP_INFO_NAME" : "");
        }
        if (signaling_info_req_flag_check(&flags->flag_info_requests, APP_INFO_QOS_CLASS)) {
            printf("%s      :\t\t\t %s\n",  prefix, signaling_info_req_flag_check(&flags->flag_info_requests, APP_INFO_QOS_CLASS) ? "APP_INFO_QOS_CLASS" : "");
        }
        if (signaling_info_req_flag_check(&flags->flag_info_requests, APP_INFO_CONNECTIONS)) {
            printf("%s      :\t\t\t %s\n",  prefix, signaling_info_req_flag_check(&flags->flag_info_requests, APP_INFO_CONNECTIONS) ? "APP_INFO_CONNECTIONS" : "");
        }
        if (signaling_info_req_flag_check(&flags->flag_info_requests, APP_INFO_REQUIREMENTS)) {
            printf("%s      :\t\t\t %s\n",  prefix, signaling_info_req_flag_check(&flags->flag_info_requests, APP_INFO_REQUIREMENTS) ? "APP_INFO_REQUIREMENTS" : "");
        }

        if (signaling_info_req_flag_check(&flags->flag_info_requests, USER_INFO_ID)) {
            printf("%s      :\t\t\t %s\n",  prefix, signaling_info_req_flag_check(&flags->flag_info_requests, USER_INFO_ID) ? "USER_INFO_ID" : "");
        }
        if (signaling_info_req_flag_check(&flags->flag_info_requests, USER_INFO_CERTS)) {
            printf("%s      :\t\t\t %s\n",  prefix, signaling_info_req_flag_check(&flags->flag_info_requests, USER_INFO_CERTS) ? "USER_INFO_CERTS" : "");
        }
    }
    printf("%s--------------------------------------------\n", prefix);
}

static int read_tuple(config_setting_t *tuple, struct slist **rulelist)
{
    int                  err     = 0;
    struct policy_tuple *entry   = NULL;
    const char          *host_id = NULL;
    //const char          *host_name   = NULL;
    const char *host_certs  = NULL;
    const char *host_kernel = NULL;
    const char *host_os     = NULL;
    const char *user_id     = NULL;
    const char *app_name    = NULL;
    const char *app_issuer  = NULL;
    long  int   app_conn    = -1;
    //const char          *app_requirements = NULL;
    const char       *target_string = NULL;
    config_setting_t *temp          = NULL;


    HIP_IFEL(!tuple, -1, "Got NULL-tuple\n");
    HIP_IFEL(!(entry = malloc(sizeof(struct policy_tuple))),
             -1, "Could not allocate memory for new rule\n");

    policy_decision_init(&entry->target);


    if (!(temp = config_setting_get_member(tuple, "host"))) {
        HIP_DEBUG("No HOST information in the policy file \n");
        entry->host.host_id        = in6addr_any;
        entry->host.host_os[0]     = '\0';
        entry->host.host_kernel[0] = '\0';
        entry->host.host_name[0]   = '\0';
        entry->host.host_certs[0]  = '\0';
    } else {
        if (CONFIG_FALSE == config_setting_lookup_string(temp, "hit", &host_id)) {
            entry->host.host_id = in6addr_any;
            HIP_DEBUG("No HOST HIT information in the policy file \n");
        } else {
            HIP_IFEL(inet_pton(AF_INET6, host_id, &entry->host.host_id) != 1,
                     -1, "Could not parse host id to in6addr \n");
            policy_decision_set(&entry->target, POLICY_HOST_INFO_ID);
        }

        if (CONFIG_FALSE == config_setting_lookup_string(temp, "kernel", &host_kernel)) {
            HIP_DEBUG("No HOST Kernel information in the policy file \n");
            entry->host.host_kernel[0] = '\0';
        } else {
            strncpy(entry->host.host_kernel, host_kernel, SIGNALING_HOST_INFO_REQ_MAX_LEN - 1);
            entry->host.host_kernel[SIGNALING_HOST_INFO_REQ_MAX_LEN - 1] = '\0';
            policy_decision_set(&entry->target, POLICY_HOST_INFO_KERNEL);
        }

        if (CONFIG_FALSE == config_setting_lookup_string(temp, "os", &host_os)) {
            HIP_DEBUG("No HOST OS information in the policy file \n");
            entry->host.host_os[0] = '\0';
        } else {
            strncpy(entry->host.host_os, host_os, SIGNALING_HOST_INFO_REQ_MAX_LEN - 1);
            entry->host.host_os[SIGNALING_HOST_INFO_REQ_MAX_LEN - 1] = '\0';
            policy_decision_set(&entry->target, POLICY_HOST_INFO_OS);
        }

        if (CONFIG_FALSE == config_setting_lookup_string(temp, "certs", &host_certs)) {
            HIP_DEBUG("No HOST Name information in the policy file \n");
            entry->host.host_certs[0] = '\0';
        } else {
            strncpy(entry->host.host_certs, host_certs, SIGNALING_HOST_INFO_REQ_MAX_LEN - 1);
            entry->host.host_certs[SIGNALING_HOST_INFO_REQ_MAX_LEN - 1] = '\0';
            policy_decision_set(&entry->target, POLICY_HOST_INFO_CERTS);
        }
        entry->host.host_name[0] = '\0';
    }


    /* Lookup and save values */
    if (!(temp = config_setting_get_member(tuple, "user"))) {
        HIP_DEBUG("No USER information in the policy file \n");
        entry->user.user_name[0] = '\0';
    } else {
        if (CONFIG_FALSE == config_setting_lookup_string(temp, "name", &user_id)) {
            HIP_DEBUG("No USER DN information in the policy file \n");
            entry->user.user_name[0] = '\0';
        } else {
            strncpy(entry->user.user_name, user_id, SIGNALING_USER_ID_MAX_LEN - 1);
            entry->user.user_name[SIGNALING_USER_ID_MAX_LEN - 1] = '\0';
            policy_decision_set(&entry->target, POLICY_USER_INFO_ID);
        }
        if (CONFIG_FALSE == config_setting_lookup_string(temp, "certs", &user_id)) {
            HIP_DEBUG("No USER DN information in the policy file \n");
        } else {
            policy_decision_set(&entry->target, POLICY_USER_INFO_CERTS);
        }
    }

    if (!(temp = config_setting_get_member(tuple, "application"))) {
        HIP_DEBUG("No APP information in the policy file \n");
        entry->application.application_dn[0] = '\0';
        entry->application.issuer_dn[0]      = '\0';
        entry->application.requirements[0]   = '\0';
        entry->application.connections       = -1;
    } else {
        if (CONFIG_FALSE == config_setting_lookup_string(temp, "name", &app_name)) {
            HIP_DEBUG("No Information about Application DN in the policy file \n");
            entry->application.application_dn[0] = '\0';
        } else {
            strncpy(entry->application.application_dn, app_name, SIGNALING_APP_DN_MAX_LEN - 1);
            entry->application.application_dn[SIGNALING_APP_DN_MAX_LEN - 1] = '\0';
            policy_decision_set(&entry->target, POLICY_APP_INFO_NAME);
        }

        if (CONFIG_FALSE == config_setting_lookup_string(temp, "issuer", &app_issuer)) {
            HIP_DEBUG("No Information about Issuer DN in the policy file \n");
            entry->application.issuer_dn[0] = '\0';
        } else {
            strncpy(entry->application.issuer_dn, app_issuer, SIGNALING_ISS_DN_MAX_LEN - 1);
            entry->application.issuer_dn[SIGNALING_APP_DN_MAX_LEN - 1] = '\0';
            policy_decision_set(&entry->target, POLICY_APP_INFO_NAME);
        }

        //TODO Still to add logic for setting of app req in policy configuration
        entry->application.requirements[0] = '\0';

        if (CONFIG_FALSE == config_setting_lookup_int(temp, "connections", &app_conn)) {
            HIP_DEBUG("No Information about Application Connections in the policy file \n");
            entry->application.connections = -1;
        } else {
            entry->application.connections = app_conn;
            HIP_DEBUG("Max Application connections allowed = %d \n ", entry->application.connections);
            policy_decision_set(&entry->target, POLICY_APP_INFO_CONNECTIONS);
        }
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
    signaling_policy_engine_print_rule_set("", NULL);

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
 * @return 0 if tuples don't match, 1 if they do, -1 if some request has to be made
 */
static int match_tuples(struct policy_tuple                 *tuple_conn,
                        const struct policy_tuple           *tuple_rule,
                        struct signaling_connection_flags   *flags)
{
    /* Check if hits match or if rule allows any hit */
    int ret     = 1;
    int tmp_len = 0;
    if (ipv6_addr_cmp(&tuple_rule->host.host_id, &in6addr_any) != 0) {
        if (ipv6_addr_cmp(&tuple_rule->host.host_id, &tuple_conn->host.host_id) != 0) {
            HIP_DEBUG("Host does not match\n");
            ret = 0;
        }
    }

    /* Check if host with any name is allowed */
    if (ret && strlen(tuple_rule->host.host_name) > 0) {
        tmp_len = strlen(tuple_conn->host.host_name);
        if (tmp_len <= 0) {
            signaling_info_req_flag_set(&flags->flag_info_requests, HOST_INFO_ID);
            ret = -1;
        } else if (strncmp(tuple_rule->host.host_name, tuple_conn->host.host_name, tmp_len) != 0) {
            HIP_DEBUG("Hosts with the name %s is not allowed\n", tuple_rule->host.host_name);
            ret = 0;
        }
    }

    /* Check if host with any kernel version is allowed */
    if (ret && strlen(tuple_rule->host.host_kernel) > 0) {
        tmp_len = strlen(tuple_conn->host.host_kernel);
        if (tmp_len <= 0) {
            signaling_info_req_flag_set(&flags->flag_info_requests, HOST_INFO_KERNEL);
            ret = -1;
        } else if (strncmp(tuple_rule->host.host_kernel, tuple_conn->host.host_kernel, tmp_len) > 0) {
            HIP_DEBUG("Kernel version below %s is not allowed\n", tuple_rule->host.host_kernel);
            ret = 0;
        }
    }

    /* Check if host with any operating system is allowed */
    if (ret && strlen(tuple_rule->host.host_os) > 0) {
        tmp_len = strlen(tuple_conn->host.host_os);
        if (tmp_len <= 0) {
            signaling_info_req_flag_set(&flags->flag_info_requests, HOST_INFO_OS);
            ret = -1;
        } else if (strncmp(tuple_rule->host.host_os, tuple_conn->host.host_os, tmp_len) != 0) {
            HIP_DEBUG("Operating system %s is not allowed\n", tuple_rule->host.host_os);
            ret = 0;
        }
    }

    /* Check if user ids match or if rule allows any user */
    if (ret && strlen(tuple_rule->user.user_name) > 0) {
        tmp_len = strlen(tuple_conn->user.user_name);
        if (tmp_len <= 0) {
            signaling_info_req_flag_set(&flags->flag_info_requests, USER_INFO_ID);
            ret = -1;
        } else if (strncmp(tuple_rule->user.user_name, tuple_conn->user.user_name, tmp_len) != 0) {
            HIP_DEBUG("User does not match\n");
            ret = 0;
        }
    }

    /* Check if app ids match or if rule allows any app */
    if (ret && strlen(tuple_rule->application.application_dn) != 0) {
        tmp_len = strlen(tuple_conn->application.application_dn);
        if (tmp_len <= 0) {
            signaling_info_req_flag_set(&flags->flag_info_requests, APP_INFO_NAME);
            ret = -1;
        } else if (strncmp(tuple_rule->application.application_dn, tuple_conn->application.application_dn, tmp_len) != 0) {
            HIP_DEBUG("Application Name does not match\n");
            ret = 0;
        }
    }

    if (ret && strlen(tuple_rule->application.issuer_dn) != 0) {
        tmp_len = strlen(tuple_conn->application.issuer_dn);
        if (tmp_len <= 0) {
            signaling_info_req_flag_set(&flags->flag_info_requests, APP_INFO_NAME);
            ret = -1;
        } else if (strncmp(tuple_rule->application.issuer_dn, tuple_conn->application.issuer_dn, tmp_len) != 0) {
            HIP_DEBUG("App Issued DN does not match\n");
            ret = 0;
        }
    }

    if (ret && strlen(tuple_rule->application.requirements) != 0) {
        tmp_len = strlen(tuple_conn->application.requirements);
        if (tmp_len <= 0) {
            signaling_info_req_flag_set(&flags->flag_info_requests, APP_INFO_REQUIREMENTS);
            ret = -1;
        } else if (strncmp(tuple_rule->application.requirements, tuple_conn->application.requirements, tmp_len) != 0) {
            HIP_DEBUG("Application Requirements not match\n");
            ret = 0;
        }
    }

    if (ret && tuple_rule->application.connections >= 0) {
        if (tuple_conn->application.connections < 0) {
            signaling_info_req_flag_set(&flags->flag_info_requests, APP_INFO_CONNECTIONS);
            ret = -1;
        } else if (tuple_rule->application.connections < tuple_conn->application.connections) {
            HIP_DEBUG("Number of connections for the application exceeds the allowed limit.\n");
            ret = 0;
        }
    }
    return ret;
}

/**
 * @return the matching tuple or NULL if no tuples matches
 */
static const struct policy_tuple *match_tuple_list(struct policy_tuple                  *tuple_conn,
                                                   const struct slist                   *const rules,
                                                   struct signaling_connection_flags    *flags)
{
    HIP_ASSERT(tuple_conn);
    const struct slist *listentry = rules;
    int                 decision  = 0;
    while (listentry) {
        decision = match_tuples(tuple_conn, (struct policy_tuple *) listentry->data, flags);
        if (decision == 1) {
            return listentry->data;
        } else if (decision == -1) {
            // Copying only the info data from the rule tuple but leaving the policy decision targets intact
            memcpy(&tuple_conn->host,        &((struct policy_tuple *) listentry->data)->host,         sizeof(struct host_info));
            memcpy(&tuple_conn->application, &((struct policy_tuple *) listentry->data)->application,  sizeof(struct app_info));
            memcpy(&tuple_conn->user,        &((struct policy_tuple *) listentry->data)->user,         sizeof(struct user_info));
            return tuple_conn;
        } else {
            HIP_DEBUG("Following tuple did not match:\n");
            print_policy_tuple((struct policy_tuple *) listentry->data, "\t", flags);
            listentry = listentry->next;
        }
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
struct policy_tuple *signaling_policy_check(UNUSED const struct in6_addr *const hit,
                                            const struct signaling_connection_context *const conn_ctx,
                                            struct signaling_connection_flags         *ctx_flags)
{
    struct policy_tuple       *tuple_conn;
    const struct policy_tuple *tuple_match = NULL;
    struct slist              *rule_list   = NULL;

    tuple_conn = malloc(sizeof(struct policy_tuple));
    policy_decision_init(&tuple_conn->target);

    /* Construct the authed and unauthed tuple for the current context.
     * Need to memset-0 because we want to use memcmp later. */
    //TODO do not know what the following line does
    signaling_copy_connection_ctx_to_policy_tuple(conn_ctx, tuple_conn);
    print_policy_tuple(tuple_conn, "\t", ctx_flags);
    HIP_DEBUG("Checking connection context:\n");

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
    if ((tuple_match = match_tuple_list(tuple_conn, rule_list, ctx_flags))) {
        printf("\033[22;32mConnection could be matched to firewall rules:\033[22;37m\n");
        //printf("Connection tuple:\n");
        //print_policy_tuple(tuple_match, "\t", ctx_flags);
        printf("is matched by rule tuple:\n");
        print_policy_tuple(tuple_match, "\t", ctx_flags);
        policy_tuple_copy(tuple_match, tuple_conn);
        return tuple_conn;
    } else {
        policy_decision_set(&tuple_conn->target, POLICY_REJECT);
    }
    return tuple_conn;
}

/**
 * Check a connection context against the local policy and check the flags
 * for those entities that need to be auth'd to comply.
 *
 * @return    0 on success (if the tuple complies, or will comply if auth is complete),
 *           -1 if the context will be rejected no matter what authentication takes place
 */
// TODO previously only two values .. have to make compatible with mutiple return values
struct policy_tuple *signaling_policy_engine_check_and_flag(const hip_hit_t *hit,
                                                            struct signaling_connection_context *const conn_ctx,
                                                            struct signaling_connection_flags  **ctx_flags,
                                                            int                                 *ret)
{
    struct policy_tuple *tuple_match = signaling_policy_check(hit, conn_ctx, *ctx_flags);

    //req_auth_types = signaling_policy_check(hit, conn_ctx);
    if (policy_decision_check(tuple_match->target, POLICY_REJECT)) {
        HIP_DEBUG("Connection request has been rejected by local policy. \n");
        printf("\033[22;31m Connection request has been rejected by local policy.\n\033[22;37m");
        *ret = -1;
        free(tuple_match);
        return NULL;
    } else if (policy_decision_check(tuple_match->target, POLICY_ACCEPT)) {
        HIP_DEBUG("Connection request has been accepted as is by local policy. \n");
        /* tell the HIPD that it needs not request for any end-point information*/
        *ret = 0;
        free(tuple_match);
        return NULL;
    } else {
        *ret = 1;
        HIP_DEBUG("Connection request will be accepted by local policy if further the host responds to the service offer: \n");
        return tuple_match;
    }
}

void signaling_copy_connection_ctx_to_policy_tuple(const struct signaling_connection_context *const ctx,
                                                   struct policy_tuple *tuple)
{
    X509_NAME *x509_subj_name;
    //int        i = 0;

    /*Sanity check*/
    HIP_ASSERT(tuple);
    HIP_ASSERT(ctx);

    policy_decision_init(&tuple->target);
    memcpy(&tuple->host.host_id, &ctx->host.host_id, sizeof(struct in6_addr));

    /*Copying/Initialize the host information in the policy tuple*/
    if (strlen(ctx->host.host_kernel) > 0) {
        strcpy(tuple->host.host_kernel, ctx->host.host_kernel);
    } else {
        tuple->host.host_kernel[0] = '\0';
    }

    if (strlen(ctx->host.host_os) > 0) {
        strcpy(tuple->host.host_os,     ctx->host.host_os);
    } else {
        tuple->host.host_os[0] = '\0';
    }

    if (strlen(ctx->host.host_name) > 0) {
        strcpy(tuple->host.host_name,   ctx->host.host_name);
    } else {
        tuple->host.host_name[0] = '\0';
    }

    if (strlen(ctx->host.host_name) > 0) {
        strcpy(tuple->host.host_certs,  ctx->host.host_certs);
    } else {
        tuple->host.host_certs[0] = '\0';
    }


    /*Copying/Initialize the application information in the policy tuple*/
    if (strlen(ctx->app.application_dn) > 0) {
        strcpy(tuple->application.application_dn, ctx->app.application_dn);
    } else {
        tuple->application.application_dn[0] = '\0';
    }

    if (strlen(ctx->app.issuer_dn) > 0) {
        strcpy(tuple->application.issuer_dn, ctx->app.issuer_dn);
    } else {
        tuple->application.issuer_dn[0] = '\0';
    }

    if (strlen(ctx->app.requirements) > 0) {
        strcpy(tuple->application.requirements, ctx->app.requirements);
    } else {
        tuple->application.requirements[0] = '\0';
    }


    if (ctx->app.connections > 0) {
        tuple->application.connections = ctx->app.connections;
    } else {
        tuple->application.connections = -1;
        ;
    }
/*
 *  HIP_DEBUG("============Printing Sockets===============\n");
 *  for (i = 0; i < SIGNALING_MAX_SOCKETS; i++) {
 *      if ((ctx->app.sockets[i].src_port == 0) || (ctx->app.sockets[i].dst_port == 0)) {
 *          break;
 *      }
 *      HIP_DEBUG("Src port = %u, Dst port = %u\n", ctx->app.sockets[i].src_port, ctx->app.sockets[i].dst_port);
 *  }*/


    /*Copying/Initialize the user information in the policy tuple*/
    if (!signaling_DER_to_X509_NAME(ctx->user.subject_name, ctx->user.subject_name_len, &x509_subj_name)) {
        X509_NAME_oneline(x509_subj_name, tuple->user.user_name, SIGNALING_USER_ID_MAX_LEN);
        tuple->user.user_name[SIGNALING_USER_ID_MAX_LEN - 1] = '\0';
        //HIP_DEBUG("USER Distinguished Name found in the context : %s \n", tuple->user.user_name);
    } else {
        tuple->user.user_name[0] = '\0';
    }
}

void signaling_policy_engine_print_rule_set(UNUSED const char *prefix,
                                            struct signaling_connection_flags *flags)
{
    struct slist        *listentry;
    struct policy_tuple *entry;

    listentry = policy_tuples_in;
    HIP_DEBUG("%s-------------- RULES FOR INCOMING TRAFFIC ----------------\n", prefix);
    while (listentry != NULL) {
        if (listentry->data != NULL) {
            entry = (struct policy_tuple *) listentry->data;
            print_policy_tuple(entry, "\t", flags);
        }
        listentry = listentry->next;
    }
    HIP_DEBUG("%s--------------           END RULES        ----------------\n", prefix);

    listentry = policy_tuples_out;
    HIP_DEBUG("%s-------------- RULES FOR OUTGOING TRAFFIC ----------------\n", prefix);
    while (listentry != NULL) {
        if (listentry->data != NULL) {
            entry = (struct policy_tuple *) listentry->data;
            print_policy_tuple(entry, "\t", flags);
        }
        listentry = listentry->next;
    }
    HIP_DEBUG("%s--------------           END RULES        ----------------\n", prefix);

    listentry = policy_tuples_fwd;
    HIP_DEBUG("%s-------------- RULES FOR FORWARDING TRAFFIC ----------------\n", prefix);
    while (listentry != NULL) {
        if (listentry->data != NULL) {
            entry = (struct policy_tuple *) listentry->data;
            print_policy_tuple(entry, "\t", flags);
        }
        listentry = listentry->next;
    }
    HIP_DEBUG("%s--------------            END RULES         ----------------\n", prefix);
}

int policy_tuple_copy(const struct policy_tuple *src, struct policy_tuple *dst)
{
    if (!dst || !src) {
        HIP_ERROR("Cannot copy from/to NULL struct \n");
        return -1;
    }
    memcpy(dst, src, sizeof(struct policy_tuple));
    return 0;
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
    case POLICY_HOST_INFO_OS:
        flags->POLICY_HOST_INFO_OS = 1;
        break;
    case POLICY_HOST_INFO_KERNEL:
        flags->POLICY_HOST_INFO_KERNEL = 1;
        break;
    case POLICY_HOST_INFO_ID:
        flags->POLICY_HOST_INFO_ID = 1;
        break;
    case POLICY_HOST_INFO_CERTS:
        flags->POLICY_HOST_INFO_CERTS = 1;
        break;
    case POLICY_USER_INFO_ID:
        flags->POLICY_USER_INFO_ID = 1;
        break;
    case POLICY_USER_INFO_CERTS:
        flags->POLICY_USER_INFO_CERTS = 1;
        break;
    case POLICY_APP_INFO_NAME:
        flags->POLICY_APP_INFO_NAME = 1;
        break;
    case POLICY_APP_INFO_QOS_CLASS:
        flags->POLICY_APP_INFO_QOS_CLASS = 1;
        break;
    case POLICY_APP_INFO_CONNECTIONS:
        flags->POLICY_APP_INFO_CONNECTIONS = 1;
        break;
    case POLICY_APP_INFO_REQUIREMENTS:
        flags->POLICY_APP_INFO_REQUIREMENTS = 1;
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
    case POLICY_HOST_INFO_OS:
        flags->POLICY_HOST_INFO_OS = 0;
        break;
    case POLICY_HOST_INFO_KERNEL:
        flags->POLICY_HOST_INFO_KERNEL = 0;
        break;
    case POLICY_HOST_INFO_ID:
        flags->POLICY_HOST_INFO_ID = 1;
        break;
    case POLICY_HOST_INFO_CERTS:
        flags->POLICY_HOST_INFO_CERTS = 0;
        break;
    case POLICY_USER_INFO_ID:
        flags->POLICY_USER_INFO_ID = 0;
        break;
    case POLICY_USER_INFO_CERTS:
        flags->POLICY_USER_INFO_CERTS = 0;
        break;
    case POLICY_APP_INFO_NAME:
        flags->POLICY_APP_INFO_NAME = 0;
        break;
    case POLICY_APP_INFO_QOS_CLASS:
        flags->POLICY_APP_INFO_QOS_CLASS = 0;
        break;
    case POLICY_APP_INFO_CONNECTIONS:
        flags->POLICY_APP_INFO_CONNECTIONS = 0;
        break;
    case POLICY_APP_INFO_REQUIREMENTS:
        flags->POLICY_APP_INFO_REQUIREMENTS = 0;
        break;
    default:
        break;
    }
}

void policy_decision_init(struct policy_decision *flags)
{
    flags->POLICY_ACCEPT                = 0;
    flags->POLICY_REJECT                = 0;
    flags->POLICY_HOST_INFO_OS          = 0;
    flags->POLICY_HOST_INFO_KERNEL      = 0;
    flags->POLICY_HOST_INFO_ID          = 0;
    flags->POLICY_HOST_INFO_CERTS       = 0;
    flags->POLICY_USER_INFO_ID          = 0;
    flags->POLICY_USER_INFO_CERTS       = 0;
    flags->POLICY_APP_INFO_NAME         = 0;
    flags->POLICY_APP_INFO_QOS_CLASS    = 0;
    flags->POLICY_APP_INFO_CONNECTIONS  = 0;
    flags->POLICY_APP_INFO_REQUIREMENTS = 0;
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
    case POLICY_HOST_INFO_OS:
        return (flags.POLICY_HOST_INFO_OS) ? 1 : 0;
        break;
    case POLICY_HOST_INFO_KERNEL:
        return (flags.POLICY_HOST_INFO_KERNEL) ? 1 : 0;
        break;
    case POLICY_HOST_INFO_ID:
        return (flags.POLICY_HOST_INFO_ID) ? 1 : 0;
        break;
    case POLICY_HOST_INFO_CERTS:
        return (flags.POLICY_HOST_INFO_CERTS) ? 1 : 0;
        break;
    case POLICY_USER_INFO_ID:
        return (flags.POLICY_USER_INFO_ID) ? 1 : 0;
        break;
    case POLICY_USER_INFO_CERTS:
        return (flags.POLICY_USER_INFO_CERTS) ? 1 : 0;
        break;
    case POLICY_APP_INFO_NAME:
        return (flags.POLICY_APP_INFO_NAME) ? 1 : 0;
        break;
    case POLICY_APP_INFO_QOS_CLASS:
        return (flags.POLICY_APP_INFO_QOS_CLASS) ? 1 : 0;
        break;
    case POLICY_APP_INFO_CONNECTIONS:
        return (flags.POLICY_APP_INFO_CONNECTIONS) ? 1 : 0;
        break;
    case POLICY_APP_INFO_REQUIREMENTS:
        return (flags.POLICY_APP_INFO_REQUIREMENTS) ? 1 : 0;
        break;
    default:
        return 0;
        break;
    }
    return 0;
}

/*
 * Verify the connection context with the policy. Request for information accordingly
 *
 */
int signaling_hipfw_verify_connection_with_policy(struct policy_tuple *tuple,
                                                  struct signaling_connection_context *ctx,
                                                  struct signaling_connection_flags *flags)
{
    struct policy_tuple tuple_conn;
    policy_decision_init(&tuple_conn.target);

    signaling_copy_connection_ctx_to_policy_tuple(ctx, &tuple_conn);

    HIP_DEBUG("Verifying for the requested parameters with the firewall policy rule.\n");
    //HIP_DEBUG("Connection tuple.\n");
    //print_policy_tuple(&tuple_conn, "\t", flags);

    //HIP_DEBUG("Matching with policy rule tuple.\n");
    //print_policy_tuple(tuple, "\t", flags);

    /* Check if hits match or if rule allows any hit */
    if (signaling_info_req_flag_check(&flags->flag_info_requests, HOST_INFO_ID)) {
        if (ipv6_addr_cmp(&tuple->host.host_id, &in6addr_any) != 0) {
            if (ipv6_addr_cmp(&tuple->host.host_id, &tuple_conn.host.host_id) != 0) {
                HIP_DEBUG("Host does not match\n");
                return -1;
            }
        }

        /* Check if host with any name is allowed */
        if (strcmp(tuple->host.host_name, tuple_conn.host.host_name) != 0) {
            HIP_DEBUG("Hosts with the name %s is not allowed\n", tuple->host.host_name);
            return -1;
        }
    }

    if (signaling_info_req_flag_check(&flags->flag_info_requests, HOST_INFO_KERNEL)) {
        /* Check if host with any kernel version is allowed */
        if ((strlen(tuple->host.host_kernel) > 0) && (strlen(tuple_conn.host.host_kernel) > 0)) {
            if (strcmp(tuple->host.host_kernel, tuple_conn.host.host_kernel) != 0) {
                HIP_DEBUG("Kernel version below %s is not allowed\n", tuple->host.host_kernel);
                return -1;
            } else {
                HIP_DEBUG("Kernel version %s is allowed by the policy\n", tuple_conn.host.host_kernel);
            }
        }
    }

    if (signaling_info_req_flag_check(&flags->flag_info_requests, HOST_INFO_OS)) {
        /* Check if host with any operating system is allowed */
        if ((strlen(tuple->host.host_os) > 0) && (strlen(tuple_conn.host.host_os) > 0)) {
            if (strcmp(tuple->host.host_os, tuple_conn.host.host_os) != 0) {
                HIP_DEBUG("Operating system %s is not allowed\n", tuple->host.host_os);
                return -1;
            } else {
                HIP_DEBUG("OS version %s is allowed by the policy\n", tuple_conn.host.host_os);
            }
        }
    }

    if (signaling_info_req_flag_check(&flags->flag_info_requests, USER_INFO_ID)) {
        /* Check if user ids match or if rule allows any user */
        if ((strlen(tuple->user.user_name) > 0) && (strlen(tuple_conn.user.user_name) > 0)) {
            if (strcmp(tuple->user.user_name, tuple_conn.user.user_name) != 0) {
                HIP_DEBUG("User does not match\n");
                return -1;
            }
        }
    }

    if (signaling_info_req_flag_check(&flags->flag_info_requests, APP_INFO_NAME)) {
        /* Check if app ids match or if rule allows any app */
        if ((strlen(tuple->application.application_dn) != 0) && (strlen(tuple->application.application_dn) != 0)) {
            if (strcmp(tuple->application.application_dn, tuple_conn.application.application_dn) != 0) {
                HIP_DEBUG("Application Name does not match\n");
                return -1;
            } else {
                HIP_DEBUG("Application %s is allowed by the policy\n", tuple_conn.application.application_dn);
            }
        }

        if ((strlen(tuple->application.issuer_dn) != 0) && (strlen(tuple_conn.application.issuer_dn) != 0)) {
            if (strcmp(tuple->application.issuer_dn, tuple_conn.application.issuer_dn) != 0) {
                HIP_DEBUG("App Issued DN does not match\n");
                return -1;
            }
        }
    }

    if (signaling_info_req_flag_check(&flags->flag_info_requests, APP_INFO_CONNECTIONS)) {
        if ((tuple->application.connections >= 0) && (tuple_conn.application.connections >= 0)) {
            if (tuple->application.connections < tuple_conn.application.connections) {
                HIP_DEBUG("Num of connections more than the allowed number of connections\n");
                return -1;
            }
        }
    }

    if (signaling_info_req_flag_check(&flags->flag_info_requests, APP_INFO_REQUIREMENTS)) {
        if ((strlen(tuple->application.requirements) != 0) && (strlen(tuple_conn.application.requirements) != 0)) {
            if (strcmp(tuple->application.requirements, tuple_conn.application.requirements) != 0) {
                HIP_DEBUG("Application Requirements not match\n");
                return -1;
            }
        }
    }

    return 0;
}
