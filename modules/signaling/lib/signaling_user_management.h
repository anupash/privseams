/*
 * signaling_hipd_user_msg.h
 *
 *  Created on: Nov 5, 2010
 *      Author: ziegeldorf
 */


#ifndef HIP_HIPD_SIGNALING_USER_MANAGEMENT_H
#define HIP_HIPD_SIGNALING_USER_MANAGEMENT_H

#include <sys/types.h>

#define SIGNALING_USER_CERT_DIR HIPL_SYSCONFDIR "/user_certchains"

/* Verify that a public key belongs to a specific subject. */
int signaling_user_api_verify_pubkey(X509_NAME *subject, const EVP_PKEY *const pub_key, X509 **user_cert);

#endif /* HIP_HIPD_SIGNALING_USER_MANAGEMENT_H */
