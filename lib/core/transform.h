/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 */

#ifndef HIP_LIB_CORE_TRANSFORM_H
#define HIP_LIB_CORE_TRANSFORM_H

#include "config.h"
#include "protodefs.h"

hip_transform_suite_t hip_select_esp_transform(struct hip_esp_transform *ht);
hip_transform_suite_t hip_select_hip_transform(struct hip_hip_transform *ht);
int hip_transform_key_length(int tid);

#endif /* HIP_LIB_CORE_TRANSFORM_H */
