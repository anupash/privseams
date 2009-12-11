#ifndef HIP_SYSOPP_H_
#define HIP_SYSOPP_H_

#include "firewall_defines.h"
#include "libhipcore/protodefs.h"

int hip_fw_handle_outgoing_system_based_opp(const hip_fw_context_t *ctx, const int default_verdict);
int hip_fw_sys_opp_set_peer_hit(const struct hip_common *msg);

#endif /* HIP_SYSOPP_H_ */
