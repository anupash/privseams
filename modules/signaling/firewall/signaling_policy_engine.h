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
 */

#ifndef HIP_HIPFW_SIGNALING_POLICY_ENGINE_H
#define HIP_HIPFW_SIGNALING_POLICY_ENGINE_H

#include <libconfig.h>

#include "firewall/firewall_defines.h"
#include "lib/core/protodefs.h"

#include "modules/signaling/lib/signaling_prot_common.h"

/* Definition of return values for signaling_policy_check.
 */
enum policy_all {
    POLICY_ACCEPT =  0,
    POLICY_REJECT =  1,

    POLICY_HOST_INFO_OS     =  2,
    POLICY_HOST_INFO_KERNEL =  3,
    POLICY_HOST_INFO_ID     =  4,
    POLICY_HOST_INFO_CERTS  =  5,

    POLICY_USER_INFO_ID    =  6,
    POLICY_USER_INFO_CERTS =  7,

    POLICY_APP_INFO_NAME         =  8,
    POLICY_APP_INFO_QOS_CLASS    =  9,
    POLICY_APP_INFO_CONNECTIONS  = 10,
    POLICY_APP_INFO_REQUIREMENTS = 11
};

struct policy_decision {
    uint8_t POLICY_ACCEPT;
    uint8_t POLICY_REJECT;

    uint8_t POLICY_HOST_INFO_OS;
    uint8_t POLICY_HOST_INFO_KERNEL;
    uint8_t POLICY_HOST_INFO_ID;
    uint8_t POLICY_HOST_INFO_CERTS;

    uint8_t POLICY_USER_INFO_ID;
    uint8_t POLICY_USER_INFO_CERTS;

    uint8_t POLICY_APP_INFO_NAME;
    uint8_t POLICY_APP_INFO_QOS_CLASS;
    uint8_t POLICY_APP_INFO_CONNECTIONS;
    uint8_t POLICY_APP_INFO_REQUIREMENTS;
};


struct host_info {
    struct in6_addr host_id;
    char            host_kernel[SIGNALING_HOST_INFO_REQ_MAX_LEN];
    char            host_os[SIGNALING_HOST_INFO_REQ_MAX_LEN];
    char            host_name[SIGNALING_HOST_INFO_REQ_MAX_LEN];
    char            host_certs[2 * SIGNALING_HOST_INFO_REQ_MAX_LEN];
};

struct user_info {
    char user_name[SIGNALING_USER_ID_MAX_LEN];
};


struct app_info {
    char application_dn[SIGNALING_APP_DN_MAX_LEN];
    char issuer_dn[SIGNALING_ISS_DN_MAX_LEN];
    char requirements[SIGNALING_APP_REQ_MAX_LEN];
};

//TODO modify all the info parameters according protocol design
struct policy_tuple {
    struct host_info       host;
    struct user_info       user;
    struct app_info        application;
    struct policy_decision target;
};


int signaling_policy_engine_init(config_t *cfg);
int signaling_policy_engine_init_from_file(const char *const policy_file);
int signaling_policy_engine_uninit(void);

void signaling_policy_engine_print_rule_set(const char *prefix);

struct policy_tuple signaling_policy_check(const struct in6_addr *const hit,
                                           const struct signaling_connection_context *const conn_ctx);

int signaling_policy_engine_check_and_flag(const hip_hit_t *hit,
                                           struct signaling_connection_context *const conn_ctx,
                                           struct signaling_connection_flags   *ctx_flags,
                                           struct policy_tuple                 *ret);

void policy_decision_set(struct policy_decision *flags, int f);
void policy_decision_unset(struct policy_decision *flags, int f);
void policy_decision_init(struct policy_decision *flags);
int policy_decision_check(struct policy_decision flags, int f);

int policy_tuple_init(struct policy_tuple *tuple);

int signaling_hipfw_verify_connection_with_policy(struct policy_tuple *tuple, struct signaling_connection_context *ctx);
#endif /* HIP_HIPFW_SIGNALING_POLICY_ENGINE_H */
