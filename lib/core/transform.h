#ifndef HIP_LIB_CORE_TRANSFORM_H
#define HIP_LIB_CORE_TRANSFORM_H

#include "protodefs.h"

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

hip_transform_suite_t hip_select_esp_transform(struct hip_esp_transform *ht);
hip_transform_suite_t hip_select_hip_transform(struct hip_hip_transform *ht);
int hip_transform_key_length(int tid);

#endif /* HIP_LIB_CORE_TRANSFORM_H */
