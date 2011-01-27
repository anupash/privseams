/*
 * signaling_hipd_user_msg.h
 *
 *  Created on: Nov 5, 2010
 *      Author: ziegeldorf
 */


#ifndef HIP_HIPD_SIGNALING_USER_MANAGEMENT_H
#define HIP_HIPD_SIGNALING_USER_MANAGEMENT_H

#include <sys/types.h>

#include "signaling_prot_common.h"

#define CERTIFICATE_INDEX_HASH_LENGTH   8
#define CERTIFICATE_INDEX_SUFFIX_LENGTH 4

#define CERTIFICATE_INDEX_USER_DIR      HIPL_SYSCONFDIR "/user_certchains/"
#define CERTIFICATE_INDEX_TRUSTED_DIR   HIPL_SYSCONFDIR "/trusted_certs/"
#define CERTIFICATE_INDEX_CERT_SUFFIX   ".0"

/* User certificate management functions */
int signaling_add_user_certificate_chain(STACK_OF(X509) *cert_chain);

/* Verify that a public key belongs to a specific subject. */
int signaling_user_api_verify_pubkey(X509_NAME *subject, const EVP_PKEY *const pub_key, X509 *user_cert, int no_chain);

/* Verify a user signature */
int signaling_verify_user_signature(struct hip_common *msg);

/* Wrapper for handling a user signature in a message. */
int signaling_handle_user_signature(struct hip_common *const msg,
                                    struct signaling_connection *const conn,
                                    enum direction dir);

#endif /* HIP_HIPD_SIGNALING_USER_MANAGEMENT_H */
