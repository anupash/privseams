/*
 * signaling_user_api.c
 *
 *  Created on: Nov 26, 2010
 *      Author: ziegeldorf
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>

#include "lib/core/debug.h"
#include "lib/core/ife.h"
#include "lib/core/builder.h"
#include "lib/core/common.h"
#include "lib/core/crypto.h"
#include "lib/tool/pk.h"

#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include "signaling_prot_common.h"
#include "signaling_user_management.h"

#define CERTIFICATE_INDEX_HASH_LENGTH   8
#define CERTIFICATE_INDEX_SUFFIX_LENGTH 4

#define CERTIFICATE_INDEX_BASE_DIR      HIPL_SYSCONFDIR "/user_certchains"

/**
 * Get the short hash of a X509 name.
 * This equals the output of 'openssl x509 -in some-cert.pem -hash'
 *
 * @param subject   the X509 name of the subject
 * @param out_buf   the output buffer, where the subject hash strint is written
 * @return          the number of characters written to out_buf, or negative on error
 *
 * @note            see sprintf() for return values
 */
static int subject_hash(X509_NAME *subject, char *const out_buf) {
    return sprintf(out_buf, "%08lx", X509_NAME_hash(subject));
}

/**
 * Load a chain of certificates from a file.
 * Certificates need to be pasted one after another into the file.
 *
 * @param certfile  the file which contains the certificate chain
 *
 * @return          a stack of x509 certificates
 *
 * @note            Code is adapted from openssl's load_untrusted function.
 * */
STACK_OF(X509) *signaling_load_certificate_chain(char *certfile)
{
    int err = 0;
    STACK_OF(X509_INFO) *sk=NULL;
    STACK_OF(X509) *stack=NULL;
    FILE *fp=NULL;
    X509_INFO *xi;

    HIP_IFEL(!(stack = sk_X509_new_null()),
             -1, "memory allocation failure\n");
    HIP_IFEL(!(fp=fopen(certfile, "r")),
             -1, "error opening the file, %s\n", certfile);

    /* This loads from a file, a stack of x509/crl/pkey sets */
    HIP_IFEL(!(sk = PEM_X509_INFO_read(fp,NULL,NULL,NULL)),
             -1, "error reading the file, %s\n", certfile);
    fclose(fp);

    /* scan over it and pull out the certs */
    while (sk_X509_INFO_num(sk)) {
        xi=sk_X509_INFO_shift(sk);
        if (xi->x509 != NULL) {
            HIP_DEBUG("Found and pushed certificate: \n");
            X509_print_fp(stderr, xi->x509);
            sk_X509_push(stack,xi->x509);
            xi->x509=NULL;
        }
        X509_INFO_free(xi);
    }

    HIP_IFEL(!sk_X509_num(stack),
             -1, "no certificates in file, %s\n",certfile);

    HIP_DEBUG("Loaded certificate chain of length %d \n", sk_X509_num(stack));

out_err:
    sk_X509_INFO_free(sk);
    if (err) {
        sk_X509_free(stack);
        return NULL;
    }
    return stack;
}

/**
 * Try to verify the public key of given user.
 *
 * @param user_ctx  the user context containing the user name
 *
 * @return 0 on success, negative on error
 */
int signaling_user_api_verify_pubkey(X509_NAME *subject, UNUSED const EVP_PKEY *const pub_key, UNUSED X509 **user_cert)
{
    char name[SIGNALING_USER_ID_MAX_LEN];
    char hash_filename[sizeof(CERTIFICATE_INDEX_BASE_DIR) + CERTIFICATE_INDEX_HASH_LENGTH + CERTIFICATE_INDEX_SUFFIX_LENGTH];
    FILE *fp;

    X509_NAME_oneline(subject, name, SIGNALING_USER_ID_MAX_LEN);
    subject_hash(subject, &hash_filename[sizeof(CERTIFICATE_INDEX_BASE_DIR)]);
    hash_filename[sizeof(CERTIFICATE_INDEX_BASE_DIR) + CERTIFICATE_INDEX_HASH_LENGTH] = '.';
    hash_filename[sizeof(CERTIFICATE_INDEX_BASE_DIR) + CERTIFICATE_INDEX_HASH_LENGTH + 1] = '0';
    hash_filename[sizeof(CERTIFICATE_INDEX_BASE_DIR) + CERTIFICATE_INDEX_HASH_LENGTH + 2] = '\0';
    HIP_DEBUG("Verifying public key of subject: %s \n", name);
    HIP_DEBUG("Looking up certificates index at: %s\n", hash_filename);

    /* Go through the certificate index */
    while ((fp = fopen(hash_filename, "r")) != NULL) {

    }

    return SIGNALING_USER_AUTH_CERTIFICATE_REQUIRED;
}
