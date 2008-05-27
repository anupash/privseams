#ifndef HIP_USERIPSEC_H_
#define HIP_USERIPSEC_H_

#include "firewall.h"

int hip_firewall_userspace_ipsec_input(hip_fw_context_t *ctx);
int hip_firewall_userspace_ipsec_output(hip_fw_context_t *ctx);
hip_hit_t *hip_fw_get_default_hit(void);

#endif /* HIP_USERIPSEC_H_ */
