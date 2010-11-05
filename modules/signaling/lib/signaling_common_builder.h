/*
 * signaling_common_builder.h
 *
 *  Created on: Nov 5, 2010
 *      Author: ziegeldorf
 */

#ifndef MODULES_SIGNALING_LIB_SIGNALING_COMMON_BUILDER_H_
#define MODULES_SIGNALING_LIB_SIGNALING_COMMON_BUILDER_H_

#include "signaling_prot_common.h"

/* Build port info parameter for user messages. */
int signaling_build_param_portinfo(struct hip_common *msg, uint16_t src_port, uint16_t dest_port);

#endif // MODULES_SIGNALING_LIB_SIGNALING_COMMON_BUILDER_H_
