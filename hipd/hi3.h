#ifndef HIP_HI3_H
#define HIP_HI3_H
#ifdef CONFIG_HIP_HI3

#include "user.h"
#include "hipd.h"
#include "protodefs.h"
#include "i3_client_api.h"

extern char* hip_i3_config_file;

int hip_i3_init(hip_hit_t*);

#endif /* CONFIG_HIP_HI3 */
#endif /* HIP_HI3_H */
