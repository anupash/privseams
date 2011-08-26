/*
 * signaling_hipd_user_msg.h
 *
 *  Created on: Nov 5, 2010
 *      Author: ziegeldorf
 */


#ifndef HIP_HIPD_SIGNALING_X509_API_H
#define HIP_HIPD_SIGNALING_X509_API_H

#include <sys/types.h>
#include <openssl/x509.h>
#include <x509ac.h>

#include "signaling_prot_common.h"

/* Utility functions to convert X509 certificates/names to DER encoding and back */
int signaling_X509_NAME_to_DER(X509_NAME *const name, unsigned char **buf);
int signaling_X509_to_DER(X509 *const cert, unsigned char **buf);
int signaling_DER_to_X509_NAME(const unsigned char *const buf, const int len, X509_NAME **name);
int signaling_DER_to_X509(const unsigned char *const buf, const int len, X509 **cert);

/* Load and save certificate chains */
STACK_OF(X509) *signaling_load_certificate_chain(char *certfile);
int signaling_save_certificate_chain(STACK_OF(X509) *cert_chain, const char *filename);

/* Verifiers */
int match_public_key(X509 *cert, const EVP_PKEY *pkey);
int verify_certificate_chain(X509 *leaf_cert, const char *trusted_lookup_dir, STACK_OF(X509) *trusted_chain, STACK_OF(X509) *untrusted_chain);
int verify_ac_certificate_chain(X509AC *leaf_cert, const char *trusted_lookup_dir, STACK_OF(X509) *trusted_chain, STACK_OF(X509) *untrusted_chain);

/* Other utility functions */
void stack_reverse(STACK_OF(X509) **cert_chain);
int certificate_chain_cmp(STACK_OF(X509) *c1, STACK_OF(X509) *c2);

#endif /* HIP_HIPD_SIGNALING_X509_API_H */
