#ifndef HIP_DATAPKT_H
#define HIP_DATAPKT_H

#include "firewall_defines.h"

int datapacket_mode_init(void);
int datapacket_mode_uninit(void);
int hip_fw_userspace_datapacket_input(const hip_fw_context_t *ctx);
int hip_fw_userspace_datapacket_output(const hip_fw_context_t *ctx);
int handle_hip_data(struct hip_common * common);

#endif /* HIP_DATAPKT_H */
