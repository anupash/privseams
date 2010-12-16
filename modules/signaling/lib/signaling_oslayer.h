/*
 * signaling_hipd_user_msg.h
 *
 *  Created on: Nov 5, 2010
 *      Author: ziegeldorf
 */


#ifndef HIP_HIPD_SIGNALING_NETSTAT_WRAPPER_H
#define HIP_HIPD_SIGNALING_NETSTAT_WRAPPER_H

#include "modules/signaling/lib/signaling_prot_common.h"


int signaling_verify_application(const char *app_path);

int signaling_netstat_get_application_by_ports(const uint16_t src_port, const uint16_t dst_port, struct signaling_connection_context *ctx);

int signaling_get_application_context_from_certificate(char *app_path, struct signaling_application_context *app_ctx);

int signaling_get_verified_application_context_by_ports(uint16_t src_port, uint16_t dst_port, struct signaling_connection_context *ctx);

#endif /* HIP_HIPD_SIGNALING_NETSTAT_WRAPPER_H */
