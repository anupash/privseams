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

#define CERTIFICATE_INDEX_USER_DIR      HIPL_SYSCONFDIR "/user_certchains/"
#define CERTIFICATE_INDEX_TRUSTED_DIR   HIPL_SYSCONFDIR "/trusted_certs/"
#define CERTIFICATE_INDEX_CERT_SUFFIX   ".0"

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
    X509_INFO *xi =NULL;

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
 * Build and verify a certificate chain.
 *
 * @param leaf_cert             the certificate to verify
 * @param trusted_lookup_dir    certificates in this directory are used as root certificates
 * @param trusted_chain         a certificate stack, that can containt additional trusted certificate
 * @param untruste_chain        a chain of untrusted certificates, that can be used to build a complete certificate chain
 *
 * @return                      0 if a certificate chain could be build and verified, negative if not
 */
int verify_certificate_chain(X509 *leaf_cert, const char *trusted_lookup_dir, STACK_OF(X509) *trusted_chain, STACK_OF(X509) *untrusted_chain) {
    int err                         = 0;
    X509_LOOKUP *lookup             = NULL;
    X509_STORE *verify_ctx_store    = NULL;
    X509_STORE_CTX *verify_ctx      = NULL;

    /* Build the verify context */
    HIP_IFEL(!(verify_ctx_store = X509_STORE_new()),
             -1, "Could not set up certificate store \n");
    HIP_IFEL(!(lookup = X509_STORE_add_lookup(verify_ctx_store, X509_LOOKUP_hash_dir())),
             -1, "Failed to init lookup directory \n");
    if (trusted_lookup_dir) {
        HIP_IFEL(!X509_LOOKUP_add_dir(lookup, trusted_lookup_dir, X509_FILETYPE_PEM),
                 -1, "Could not add directory %s to trusted lookup resources \n", trusted_lookup_dir);
    } else {
        X509_LOOKUP_add_dir(lookup,NULL,X509_FILETYPE_DEFAULT);
    }

    HIP_IFEL(!(verify_ctx = X509_STORE_CTX_new()),
             -1, "Could not allocate new verify context \n");
    HIP_IFEL(!X509_STORE_CTX_init(verify_ctx, verify_ctx_store, leaf_cert, untrusted_chain),
             -1, "Could not setup verify context\n");
    if(trusted_chain) {
        X509_STORE_CTX_trusted_stack(verify_ctx, trusted_chain);
    }

    /* Finally do the verification and output some info */
     err = X509_verify_cert(verify_ctx) == 1 ? 0 : -1;

out_err:
    X509_STORE_CTX_free(verify_ctx);
    return err;
}

/**
 * Try to verify the public key of given user.
 *
 * @param user_ctx  the user context containing the user name
 *
 * @return 0 on success, negative on error
 */
int signaling_user_api_verify_pubkey(X509_NAME *subject, const EVP_PKEY *const pub_key, UNUSED X509 **user_cert)
{
    int err = 0;
    int i = 0;
    char name[SIGNALING_USER_ID_MAX_LEN];
    //char hash_filename[sizeof(CERTIFICATE_INDEX_BASE_DIR) + CERTIFICATE_INDEX_HASH_LENGTH + CERTIFICATE_INDEX_SUFFIX_LENGTH];
    char hash_filename[PATH_MAX];
    STACK_OF(X509) *cert_chain;
    X509 *leaf_cert = NULL;
    EVP_PKEY *cert_pub_key = NULL;

    /* sanity checks */
    HIP_IFEL(!pub_key,      -1, "Cannot verify NULL-pubkey.\n");
    HIP_IFEL(!subject,      -1, "Need X509 subject name for certificate lookup\n");

    /* Print some info and prepare filenames */
    X509_NAME_oneline(subject, name, SIGNALING_USER_ID_MAX_LEN);
    strcat(hash_filename, CERTIFICATE_INDEX_USER_DIR);
    subject_hash(subject, &hash_filename[sizeof(CERTIFICATE_INDEX_USER_DIR)-1]);
    /* We need the -1 because sizeof, unlike strlen, counts the 0-terminator. However, we prefer sizeof for performance reasons */
    strcat(&hash_filename[sizeof(CERTIFICATE_INDEX_USER_DIR) -1 + CERTIFICATE_INDEX_HASH_LENGTH], CERTIFICATE_INDEX_CERT_SUFFIX);
    HIP_DEBUG("Verifying public key of subject: %s \n", name);
    HIP_DEBUG("Looking up certificates index at: %s\n", hash_filename);

    /* Go through the certificate index */
    while ((cert_chain = signaling_load_certificate_chain(hash_filename)) != NULL) {
        leaf_cert = sk_X509_value(cert_chain, 0);
        cert_pub_key = X509_get_pubkey(leaf_cert);
        if (EVP_PKEY_cmp(cert_pub_key, pub_key) == 1) {
            break;
        }
        HIP_DEBUG("Rejecting certificate %s, because public keys did not match\n", hash_filename);
        leaf_cert = NULL;
        free(cert_chain);

        /* move to next possible certificate */
        i++;
        hash_filename[sizeof(CERTIFICATE_INDEX_USER_DIR) + CERTIFICATE_INDEX_HASH_LENGTH] = (char) i;
        HIP_DEBUG("Looking up certificates index at: %s\n", hash_filename);
    }

    if (!leaf_cert) {
        return SIGNALING_USER_AUTH_CERTIFICATE_REQUIRED;
    }

    HIP_DEBUG("Found matching certificate, now verifying certificate chain.\n");

    err = verify_certificate_chain(leaf_cert, CERTIFICATE_INDEX_TRUSTED_DIR, NULL, cert_chain);
    if(err) {
        ERR_print_errors_fp(stderr);
    } else {
        HIP_DEBUG("Successfully verified certificate chain. \n");
    }

out_err:
    return err;
}
