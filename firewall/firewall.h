/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 */

#ifndef HIP_FIREWALL_FIREWALL_H
#define HIP_FIREWALL_FIREWALL_H

#include "lib/core/protodefs.h"

/** globally used variables defined in firewall.c */
extern int filter_traffic;
extern int hip_kernel_ipsec_fallback;
extern int hip_lsi_support;
extern int esp_relay;
extern int use_midauth;
extern int hip_fw_sock;
extern int hip_fw_async_sock;
extern int system_based_opp_mode;

int hip_fw_init_esp_relay(void);
void hip_fw_uninit_esp_relay(void);
int hip_fw_init_opptcp(void);
int hip_fw_uninit_opptcp(void);
int hip_fw_init_proxy(void);
int hip_fw_uninit_proxy(void);
void set_stateful_filtering(void);
hip_hit_t *hip_fw_get_default_hit(void);
hip_lsi_t *hip_fw_get_default_lsi(void);

#endif /* HIP_FIREWALL_FIREWALL_H */
