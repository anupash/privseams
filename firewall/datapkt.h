#ifndef HIP_DATAPKT_H
#define HIP_DATAPKT_H

#include "firewall_defines.h"

int hip_datapacket_mode_init(void);
int hip_datapacket_mode_uninit(void);
int hip_fw_userspace_datapacket_input(const hip_fw_context_t *ctx);
int hip_fw_userspace_datapacket_output(const hip_fw_context_t *ctx);
int hip_handle_data_signature(struct hip_common * common);

#endif /* HIP_DATAPKT_H */
