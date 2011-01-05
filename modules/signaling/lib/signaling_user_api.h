/*
 * signaling_hipd_user_msg.h
 *
 *  Created on: Nov 5, 2010
 *      Author: ziegeldorf
 */


#ifndef HIP_HIPD_SIGNALING_USER_API_H
#define HIP_HIPD_SIGNALING_USER_API_H

#include <sys/types.h>

int signaling_X509_to_DER(X509 *cert, unsigned char **buf);
X509 *signaling_user_api_get_user_certificate(const uid_t uid);
int signaling_user_api_get_uname(uid_t uid, struct signaling_user_context *user_ctx);
int signaling_user_api_get_signature(uid_t uid, const void *data, int in_len, unsigned char *outbuf);
int signaling_user_api_verify(const struct signaling_user_context *usr_ctx, const unsigned char *signature, uint16_t sig_len);

#endif /* HIP_HIPD_SIGNALING_USER_API_H */
