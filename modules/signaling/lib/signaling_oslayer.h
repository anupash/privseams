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

int signaling_netstat_get_application_path(struct signaling_application_context *app_ctx);

int signaling_verify_application(struct signaling_application_context *app_ctx);

int signaling_get_application_context(struct signaling_application_context *app_ctx);

#endif /* HIP_HIPD_SIGNALING_NETSTAT_WRAPPER_H */
