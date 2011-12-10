/*
 * Copyright (c) 2010 Aalto University and RWTH Aachen University.
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
 */

#ifndef HIP_FIREWALL_FIREWALL_H
#define HIP_FIREWALL_FIREWALL_H

#include <stdbool.h>

#include "lib/core/protodefs.h"

enum {NONE, ENDPOINT, MIDDLEBOX};

/** globally used variables defined in firewall.c */
extern int accept_normal_traffic_by_default;
extern int accept_hip_esp_traffic_by_default;
extern int log_level;
extern int hip_userspace_ipsec;
extern int restore_filter_traffic;
extern int restore_accept_hip_esp_traffic;
extern int filter_traffic;
extern int hip_kernel_ipsec_fallback;
extern int hip_lsi_support;
extern int esp_relay;
extern int hip_esp_protection;
extern int use_midauth;
extern int hip_fw_sock;
extern int system_based_opp_mode;
extern int esp_speedup;
extern int ep_signaling;

int hipfw_main(const char *const rule_file,
               const bool        kill_old,
               const bool        limit_capabilities);
int hip_fw_init_esp_relay(void);
void hip_fw_uninit_esp_relay(void);
hip_hit_t *hip_fw_get_default_hit(void);
hip_lsi_t *hip_fw_get_default_lsi(void);

#endif /* HIP_FIREWALL_FIREWALL_H */
