/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 */
#ifndef HIP_FIREWALL_FIREWALL_H
#define HIP_FIREWALL_FIREWALL_H

#include "config.h"
#include "lib/core/protodefs.h"

/** globally used variables defined in firewall.c */
extern int filter_traffic;
extern int system_based_opp_mode;
extern int hip_datapacket_mode;
extern int hip_proxy_status;
extern int hip_opptcp;
extern int hip_kernel_ipsec_fallback;
extern int hip_lsi_support;
extern int esp_relay;
#ifdef CONFIG_HIP_MIDAUTH
extern int use_midauth;
#endif

extern int hip_fw_sock;
extern int hip_fw_async_sock;

int hip_fw_init_esp_relay(void);
void hip_fw_uninit_esp_relay(void);
int hip_fw_init_opptcp(void);
int hip_fw_uninit_opptcp(void);
int hip_fw_init_proxy(void);
int hip_fw_uninit_proxy(void);
void set_stateful_filtering(const int active);
hip_hit_t *hip_fw_get_default_hit(void);
hip_lsi_t *hip_fw_get_default_lsi(void);

#endif
