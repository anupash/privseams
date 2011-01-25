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
enum policy_decision {
    POLICY_ACCEPT              = 0,
    POLICY_REJECT              = 1,
    POLICY_USER_AUTH_REQUIRED  = 2,
    POLICY_HOST_AUTH_REQUIRED  = 4,
    POLICY_APP_AUTH_REQUIRED   = 8,
};


struct policy_tuple {
    struct in6_addr host_id;
    char user_id[SIGNALING_USER_ID_MAX_LEN];
    char app_id[SIGNALING_APP_DN_MAX_LEN];
    int target;
};

int signaling_policy_engine_init(config_t *cfg);
int signaling_policy_engine_init_from_file(const char *const policy_file);

void signaling_policy_engine_print_rule_set(const char *prefix);

int signaling_policy_check(const struct in6_addr *const hit,
                                                const struct signaling_connection_context *const conn_ctx);

#endif /* HIP_HIPFW_SIGNALING_POLICY_ENGINE_H */
