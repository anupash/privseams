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

#include <x509ac-supp.h>

#include "lib/core/debug.h"
#include "lib/core/ife.h"
#include "lib/core/builder.h"
#include "lib/core/common.h"
#include "lib/core/crypto.h"
#include "lib/core/prefix.h"
#include "lib/tool/pk.h"

#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include "signaling_user_management.h"
#include "signaling_prot_common.h"
#include "signaling_x509_api.h"

int signaling_X509_NAME_to_DER(X509_NAME *const name, unsigned char **buf) {
    int len;
    int err = 0;

    HIP_IFEL(!name, -1, "Cannot encode NULL-certificate\n");
    *buf = NULL;
    len = i2d_X509_NAME(name, buf);
    HIP_IFEL(len < 0, -1, "Could not DER-encode the given X509 name.\n");
    HIP_IFEL(len > SIGNALING_USER_ID_MAX_LEN,
             -1, "DER Encoding exceeds user id max size\n");
    return len;

out_err:
    return err;
}

int signaling_X509_to_DER(X509 *const cert, unsigned char **buf) {
    int len;
    int err = 0;

    HIP_IFEL(!cert, -1, "Cannot encode NULL-certificate\n");
    *buf = NULL;
    len = i2d_X509(cert, buf);
    HIP_IFEL(len < 0, -1, "Could not DER-encode the given certificate.\n");
    return len;

out_err:
    return err;
}

int signaling_DER_to_X509_NAME(const unsigned char *const buf, const int len, X509_NAME **name) {
    int err = 0;
    const unsigned char *p;

    HIP_IFEL(!buf,      -1, "Cannot decode from NULL-buffer\n");
    HIP_IFEL(len <= 0,  -1, "Cannot decode x509 name of length <= 0\n");
    p = buf;
    *name = d2i_X509_NAME(NULL, (const unsigned char **)  &p, len);

out_err:
    return err;
}


int signaling_DER_to_X509(const unsigned char *const buf, const int len, X509 **cert) {
    int err = 0;
    const unsigned char *p;

    HIP_IFEL(!buf, -1, "Cannot decode from NULL-buffer\n");
    HIP_IFEL(len <= 0, -1, "Cannot decode certificate of length <= 0\n");
    p = buf;
    *cert = d2i_X509(NULL, (const unsigned char **)  &p, len);

out_err:
    return err;
}

UNUSED static X509 *load_x509_certificate(const char *const file) {
    int err     = 0;
    FILE *fp    = NULL;
    X509 *cert  = NULL;

    HIP_IFEL(!file, -ENOENT, "NULL filename\n");

    fp   = fopen(file, "rb");
    HIP_IFEL(!fp, -ENOMEM,
             "Could not open certificate key file %s for reading\n", file);

    cert = PEM_read_X509(fp, NULL, NULL, NULL);
    if ((err = fclose(fp))) {
        HIP_ERROR("Error closing file\n");
        goto out_err;
    }

out_err:
    if (err) {
        X509_free(cert);
        return NULL;
    }
    return cert;
}

/**
 * Load a chain of certificates from a file.
 * Certificates need to be pasted one after another into the file.
 *
 *
 * @param certfile  the file which contains the certificate chain
 *
 * @return          a stack of x509 certificates, where the certificate
                    at the bottom of the file will be at the top of the returned stack
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
             -1, "No certificate chain at file, %s\n", certfile);

    /* This loads from a file, a stack of x509/crl/pkey sets */
    HIP_IFEL(!(sk = PEM_X509_INFO_read(fp,NULL,NULL,NULL)),
             -1, "error reading the file, %s\n", certfile);
    fclose(fp);

    /* scan over it and pull out the certs */
    while (sk_X509_INFO_num(sk)) {
        xi=sk_X509_INFO_shift(sk);
        if (xi->x509 != NULL) {
            sk_X509_push(stack,xi->x509);
            xi->x509=NULL;
        }
        X509_INFO_free(xi);
    }

    HIP_IFEL(!sk_X509_num(stack),
             -1, "no certificates in file, %s\n",certfile);

out_err:
    sk_X509_INFO_free(sk);
    if (err) {
        sk_X509_free(stack);
        return NULL;
    }
    return stack;
}

/**
 * Save a stack of certificates to a file.
 * The order in which certificates are saved is the order in which they come from the stack,
 * i.e. the certificate at the top of the stack will be at the bottom of the file.
 *
 * @cert_chain  the certificate chain, which is saved
 * @filename    the file to which the certificate chain is written
 * @return      0 on success, negative if there was an error opening the destination file for writing
 */
int signaling_save_certificate_chain(STACK_OF(X509) *cert_chain, const char *filename) {
    int err = 0;
    int i = 0;
    FILE *fp = NULL;

    HIP_IFEL(!(fp = fopen(filename, "w")), -1, "Could not open file %s for writing \n", filename);
    for (i = 0; i < sk_X509_num(cert_chain); i++) {
        PEM_write_X509(fp, sk_X509_value(cert_chain, i));
    }
    HIP_DEBUG("Saved certificate chain of size %d to: %s \n", i, filename);

out_err:
    fclose(fp);
    return err;
}

void stack_reverse(STACK_OF(X509) **cert_chain) {
    int i = 0;
    STACK_OF(X509) *ret = NULL;
    ret = sk_X509_new_null();

    for (i = sk_X509_num(*cert_chain)-1; i>=0; i--) {
        sk_X509_push(ret, sk_X509_pop(*cert_chain));
    }
    sk_X509_free(*cert_chain);
    *cert_chain = ret;
}

/**
 * Compare two certificate chains.
 *
 * @return 0 if they match, -1 otherwise
 */
int certificate_chain_cmp(STACK_OF(X509) *c1, STACK_OF(X509) *c2) {
    int i = 0;
    const X509 *cert1 = NULL;
    const X509 *cert2 = NULL;

    if (!c1 || !c2) {
        return -1;
    }

    for (i = 0; i < MIN(sk_X509_num(c1), sk_X509_num(c2)); i++) {
        cert1 = sk_X509_value(c1, i);
        cert2 = sk_X509_value(c2, i);
        if (X509_cmp(cert1, cert2)) {
            return -1;
        }
    }

    return 0;
}

/**
 * @return 1 if match, 0 otherwise
 */
int match_public_key(X509 *cert, const EVP_PKEY *pkey)
{
    EVP_PKEY *pkey2 = NULL;

    if (!cert) {
        return 0;
    }
    pkey2 = X509_get_pubkey(cert);
    return EVP_PKEY_cmp(pkey2, pkey);
}

/**
 * Build and verify a certificate chain.
 *
 * @param leaf_cert             the certificate to verify
 * @param trusted_lookup_dir    certificates in this directory are used as root certificates
 * @param trusted_chain         a certificate stack, that can containt additional trusted certificate
 * @param untruste_chain        a chain of untrusted certificates, that can be used to build a complete certificate chain
 *
 * @return                      0 if a certificate chain could be build and verified, a non-zero error code otherwise
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
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Start PERF_X509_VERIFY_CERT_CHAIN\n");
        hip_perf_start_benchmark(perf_set, PERF_X509_VERIFY_CERT_CHAIN);
#endif
     err = X509_verify_cert(verify_ctx);
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Stop PERF_X509_VERIFY_CERT_CHAIN\n");
        hip_perf_stop_benchmark(perf_set, PERF_I2_VERIFY_USER_SIG);
#endif
     if (err != 1) {
         err = X509_STORE_CTX_get_error(verify_ctx);
     } else {
         err = 0;
     }

out_err:
    X509_STORE_CTX_free(verify_ctx);
    return err;
}

/**
 * Build and verify a certificate chain with an x509 attribute certificate as leaf.
 *
 * @param leaf_cert             the attribute certificate to verify
 * @param trusted_lookup_dir    certificates in this directory are used as root certificates
 * @param trusted_chain         a certificate stack, that can containt additional trusted certificate
 * @param untruste_chain        a chain of untrusted certificates, that can be used to build a complete certificate chain
 *
 * @return                      0 if a certificate chain could be build and verified, a non-zero error code otherwise
 */
int verify_ac_certificate_chain(X509AC *leaf_cert, const char *trusted_lookup_dir, STACK_OF(X509) *trusted_chain, STACK_OF(X509) *untrusted_chain)
{
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
        X509_LOOKUP_add_dir(lookup, NULL, X509_FILETYPE_DEFAULT);
    }

    HIP_IFEL(!(verify_ctx = X509_STORE_CTX_new()),
             -1, "Could not allocate new verify context \n");
    HIP_IFEL(!X509_STORE_CTX_init(verify_ctx, verify_ctx_store, NULL, untrusted_chain),
             -1, "Could not setup verify context\n");
    if(trusted_chain) {
        X509_STORE_CTX_trusted_stack(verify_ctx, trusted_chain);
    }

    OpenSSL_add_all_algorithms();

    /* Finally do the verification and output some info */
    err = X509AC_verify_cert(verify_ctx, leaf_cert);
    if (err) {
        HIP_ERROR("Attribute certificate did not verify correctly, error %d.\n", err);
        return 1;
    } else {
        HIP_ERROR("Attribute certificate verified!\n");
        err = 0;
    }

out_err:
    X509_STORE_CTX_free(verify_ctx);
    return err;
}
