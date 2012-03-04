#ifndef HIP_HIPD_SIGNALING_H
#define HIP_HIPD_SIGNALING_H

#include "modules/signaling/lib/signaling_prot_common.h"

struct signaling_host_context signaling_persistent_host;

int Load_host_info_on_boot_strap(void);
int hip_signaling_init(void);

#endif /* HIP_HIPD_SIGNALING_H */
