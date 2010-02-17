#ifndef HIP_FIREWALL_SYSOPP_H
#define HIP_FIREWALL_SYSOPP_H

#include "firewall_defines.h"
#include "lib/core/protodefs.h"

int hip_fw_handle_outgoing_system_based_opp(const hip_fw_context_t *ctx,
                                            const int default_verdict);
int hip_fw_sys_opp_set_peer_hit(const struct hip_common *msg);
void hip_fw_flush_system_based_opp_chains(void);

#endif /* HIP_FIREWALL_SYSOPP_H */
