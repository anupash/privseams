/*
 * signaling_hipd_user_msg.h
 *
 *  Created on: Nov 5, 2010
 *      Author: ziegeldorf
 */


#ifndef HIP_HIPD_SIGNALING_USER_API_H
#define HIP_HIPD_SIGNALING_USER_API_H

#include <sys/types.h>

int signaling_X509_to_DER(X509 *const cert, unsigned char **buf);
int signaling_DER_to_X509(const unsigned char *const buf, const int len, X509 **cert);
X509 *signaling_user_api_get_user_certificate(const uid_t uid);
int signaling_user_api_get_uname(const uid_t uid, struct signaling_user_context *const user_ctx);
int signaling_user_api_get_signature(const uid_t uid, const void *const data, const int in_len, unsigned char *const outbuf);
int signaling_user_api_verify(const struct signaling_user_context *usr_ctx, const unsigned char *signature, uint16_t sig_len);

#endif /* HIP_HIPD_SIGNALING_USER_API_H */
