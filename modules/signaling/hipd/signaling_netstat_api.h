/*
 * signaling_hipd_user_msg.h
 *
 *  Created on: Nov 5, 2010
 *      Author: ziegeldorf
 */


#ifndef HIP_HIPD_SIGNALING_NETSTAT_WRAPPER_H
#define HIP_HIPD_SIGNALING_NETSTAT_WRAPPER_H

#include "lib/core/protodefs.h"
#include "signaling_state.h"

int signaling_netstat_get_application_context(uint16_t srcport, uint16_t destport);


#endif /* HIP_HIPD_SIGNALING_NETSTAT_WRAPPER_H */
