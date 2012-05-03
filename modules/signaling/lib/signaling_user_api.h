/*
 * signaling_hipd_user_msg.h
 *
 *  Created on: Nov 5, 2010
 *      Author: ziegeldorf
 */


#ifndef HIP_HIPD_SIGNALING_USER_API_H
#define HIP_HIPD_SIGNALING_USER_API_H

#include <sys/types.h>

#include "signaling_prot_common.h"

/* Getters for different user context information */
int signaling_user_api_get_uname(const uid_t uid, struct signaling_user_context *const user_ctx);
STACK_OF(X509) * signaling_user_api_get_user_certificate_chain(const uid_t uid);
EVP_PKEY *signaling_user_api_get_user_public_key(const uid_t uid);

/* Every user supplied cryptography module should implement this function.
 * The HIPD calls this function to build the user's signature. */
int signaling_user_api_sign(const uid_t uid, void *data, const int in_len,
                            unsigned char *out_buf, const uint8_t sig_type,
                            uint8_t flag_selective_sign);

#endif /* HIP_HIPD_SIGNALING_USER_API_H */
