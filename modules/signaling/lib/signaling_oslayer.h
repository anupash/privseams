/*
 * signaling_hipd_user_msg.h
 *
 *  Created on: Nov 5, 2010
 *      Author: ziegeldorf
 */


#ifndef HIP_HIPD_SIGNALING_NETSTAT_WRAPPER_H
#define HIP_HIPD_SIGNALING_NETSTAT_WRAPPER_H

#include "modules/signaling/lib/signaling_prot_common.h"

/* MAX = ? */
#define PATHBUF_SIZE            200

char *signaling_netstat_get_application_path_by_ports(const uint16_t src_port, uint16_t dst_port);

int signaling_verify_application(const char *app_path);

int signaling_get_application_context(char *app_path, struct signaling_application_context *app_ctx);

#endif /* HIP_HIPD_SIGNALING_NETSTAT_WRAPPER_H */
