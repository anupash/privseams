/*
 * signaling_hipd_user_msg.h
 *
 *  Created on: Nov 5, 2010
 *      Author: ziegeldorf
 */


#ifndef HIP_HIPD_SIGNALING_USER_API_H
#define HIP_HIPD_SIGNALING_USER_API_H

#include <sys/types.h>

/* Utility functions to convert X509 certificates/names to DER encoding and back */
int signaling_X509_NAME_to_DER(X509_NAME *const name, unsigned char **buf);
int signaling_X509_to_DER(X509 *const cert, unsigned char **buf);
int signaling_DER_to_X509_NAME(const unsigned char *const buf, const int len, X509_NAME **name);
int signaling_DER_to_X509(const unsigned char *const buf, const int len, X509 **cert);

/* Getters for different user context information */
int signaling_user_api_get_uname(const uid_t uid, struct signaling_user_context *const user_ctx);
X509 *signaling_user_api_get_user_certificate(const uid_t uid);
EVP_PKEY *signaling_user_api_get_user_public_key(const uid_t uid);

/* Every user supplied cryptography module should implement this function.
 * The HIPD calls this function to build the user's signature. */
int signaling_user_api_sign(const uid_t uid, const void *const data, const int in_len, unsigned char *out_buf, uint8_t *const sig_type);

#endif /* HIP_HIPD_SIGNALING_USER_API_H */
