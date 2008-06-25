#ifndef HIP_HI3_H
#define HIP_HI3_H
#ifdef CONFIG_HIP_HI3

#include "user.h"
#include "hipd.h"
#include "protodefs.h"
#include "i3_client_api.h"

extern char* hip_i3_config_file;

int hip_i3_init();
int hip_i3_clean();
int hip_hi3_add_pub_trigger_id(struct hip_host_id_entry *entry, int* count);

#endif /* CONFIG_HIP_HI3 */
#endif /* HIP_HI3_H */
