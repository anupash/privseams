/*
 * signaling_hipd_user_msg.h
 *
 *  Created on: Nov 5, 2010
 *      Author: ziegeldorf
 */


#ifndef HIP_HIPD_SIGNALING_USER_MANAGEMENT_H
#define HIP_HIPD_SIGNALING_USER_MANAGEMENT_H

#include <sys/types.h>

/* Util functions */
STACK_OF(X509) *signaling_load_certificate_chain(char *certfile);

/* Verify that a public key belongs to a specific subject. */
int signaling_user_api_verify_pubkey(X509_NAME *subject, const EVP_PKEY *const pub_key, X509 **user_cert);

/* Verify a certificate chain */
int verify_certificate_chain(X509 *leaf_cert, const char *trusted_lookup_dir, STACK_OF(X509) *trusted_chain, STACK_OF(X509) *untrusted_chain);

/* Verify a user signature */
int signaling_verify_user_signature(struct hip_common *msg);

#endif /* HIP_HIPD_SIGNALING_USER_MANAGEMENT_H */
