/*
 * signaling_hipd_user_msg.h
 *
 *  Created on: Nov 5, 2010
 *      Author: ziegeldorf
 */


#ifndef HIP_HIPD_SIGNALING_USER_API_H
#define HIP_HIPD_SIGNALING_USER_API_H

#include <sys/types.h>

int signaling_user_api_get_uname(uid_t uid, struct signaling_user_context *user_ctx);
int signaling_user_api_get_signature(uid_t uid, const void *data, int in_len, unsigned char *outbuf);

#endif /* HIP_HIPD_SIGNALING_USER_API_H */
