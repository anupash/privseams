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
#include "lib/core/hostid.h"
#include "lib/tool/pk.h"

#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include "signaling_prot_common.h"
#include "signaling_user_management.h"
#include "signaling_user_api.h"

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
     err = X509_verify_cert(verify_ctx);
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
 * Try to verify the public key of given user.
 *
 * @return 0 if a certificate chain could be build and verified, a non-zero error code otherwise
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

out_err:
    return err;
}

int signaling_verify_user_signature(struct hip_common *msg) {
    int err = 0;
    int hash_range_len;
    int orig_len;
    const struct signaling_param_user_context *param_usr_ctx = NULL;
    struct hip_sig *param_user_signature = NULL;
    unsigned char sha1_digest[HIP_AH_SHA_LEN];
    EVP_PKEY *pkey = NULL;
    X509_NAME *subject_name = NULL;
    RSA *rsa = NULL;
    EC_KEY *ecdsa = NULL;
    struct hip_host_id pseudo_ui;

    orig_len = hip_get_msg_total_len(msg);

    /* We need to construct a temporary host_id struct since, all key_rr_to_xxx functions take this as argument.
     * However, we need only to fill in hi_length, algorithm and the key rr. */
    HIP_IFEL(!(param_usr_ctx = hip_get_param(msg, HIP_PARAM_SIGNALING_USERINFO)),
             -1, "Need user context to verify his signature \n");
    pseudo_ui.hi_length = htons(param_usr_ctx->pkey_rr_length);
    pseudo_ui.rdata.algorithm = param_usr_ctx->rdata.algorithm;
    // note: the + 1 moves the pointer behind the parameter, where the key rr begins
    memcpy(pseudo_ui.key, param_usr_ctx + 1, pseudo_ui.hi_length - sizeof(struct hip_host_id_key_rdata));
    HIP_IFEL(!(pkey = hip_key_rr_to_evp_key(&pseudo_ui, 0)), -1, "Could not deserialize users public key\n");
    HIP_DEBUG("Verifying signature using following public key: \n");
    PEM_write_PUBKEY(stderr, pkey);

    /* No modify the packet to verify signature */
    HIP_IFEL(!(param_user_signature = hip_get_param_readwrite(msg, HIP_PARAM_SIGNALING_USER_SIGNATURE)),
             -1, "Packet contains no user signature\n");
    hash_range_len = ((const uint8_t *) param_user_signature) - ((const uint8_t *) msg);
    hip_zero_msg_checksum(msg);
    HIP_IFEL(hash_range_len < 0, -ENOENT, "Invalid signature len\n");
    hip_set_msg_total_len(msg, hash_range_len);
    HIP_IFEL(hip_build_digest(HIP_DIGEST_SHA1, msg, hash_range_len, sha1_digest),
             -1, "Could not build message digest \n");

    switch (pseudo_ui.rdata.algorithm) {
    case HIP_HI_ECDSA:
        // - 1 is the algorithm field
        ecdsa = EVP_PKEY_get1_EC_KEY(pkey);
        HIP_IFEL(ECDSA_size(ecdsa) != ntohs(param_user_signature->length) - 1,
                 -1, "Size of public key does not match signature size. Aborting signature verification: %d / %d.\n", ECDSA_size(ecdsa), ntohs(param_user_signature->length));
        HIP_IFEL(impl_ecdsa_verify(sha1_digest, ecdsa, param_user_signature->signature),
                     -1, "ECDSA user signature did not verify correctly\n");
        break;
    case HIP_HI_RSA:
        rsa = EVP_PKEY_get1_RSA(pkey);
        HIP_IFEL(RSA_size(rsa) != ntohs(param_user_signature->length) - 1,
                 -1, "Size of public key does not match signature size. Aborting signature verification: %d / %d.\n", RSA_size(rsa), ntohs(param_user_signature->length));
        HIP_IFEL(!RSA_verify(NID_sha1, sha1_digest, SHA_DIGEST_LENGTH, param_user_signature->signature, RSA_size(rsa), rsa),
                 -1, "RSA user signature did not verify correctly\n");
        break;
    default:
        HIP_IFEL(1, -1, "Unknown algorithm\n");
    }

    /* Now verify users public key against his certificate.
     * User Subject Name (in DER) begins directly after the key resource record. */
    HIP_IFEL(signaling_DER_to_X509_NAME((const unsigned char *) (param_usr_ctx + 1) + ntohs(param_usr_ctx->pkey_rr_length) - sizeof(struct hip_host_id_key_rdata),
                                        ntohs(param_usr_ctx->un_length),
                                        &subject_name),
             -1, "Could not decode to x509 name.");

    /* Request the user to send his certificate chain if there was an error */
    err = signaling_user_api_verify_pubkey(subject_name, pkey, NULL);

out_err:
    hip_set_msg_total_len(msg, orig_len);
    RSA_free(rsa);
    EC_KEY_free(ecdsa);
    X509_NAME_free(subject_name);
    return err;
}
