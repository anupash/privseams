#ifndef USER_IPSEC_API_H_
#define USER_IPSEC_API_H_

#include "firewall.h"
#include "user_ipsec_sadb.h"
#include "user_ipsec_esp.h"
#include "user_ipsec_fw_msg.h"
#include "esp_prot_api.h"

int userspace_ipsec_init(void);
int userspace_ipsec_uninit(void);
int hip_firewall_userspace_ipsec_input(hip_fw_context_t *ctx);
int hip_firewall_userspace_ipsec_output(hip_fw_context_t *ctx);

#endif /* USER_IPSEC_API_H_ */
