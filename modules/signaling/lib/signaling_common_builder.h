/*
 * signaling_common_builder.h
 *
 *  Created on: Nov 5, 2010
 *      Author: ziegeldorf
 */

#ifndef MODULES_SIGNALING_LIB_SIGNALING_COMMON_BUILDER_H_
#define MODULES_SIGNALING_LIB_SIGNALING_COMMON_BUILDER_H_

#include "signaling_prot_common.h"
#include "modules/signaling/hipd/signaling_state.h"

/* Build port info parameter for user messages. */
int signaling_build_param_portinfo(struct hip_common *msg, uint16_t src_port, uint16_t dest_port);

/* Build an appinfo parameter. */
int signaling_build_param_appinfo(hip_common_t *ctx, struct signaling_state *sig_state);

#endif // MODULES_SIGNALING_LIB_SIGNALING_COMMON_BUILDER_H_
