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
#include <sys/stat.h>

#include "lib/core/debug.h"
#include "lib/core/ife.h"
#include "lib/core/builder.h"
#include "lib/core/common.h"
#include "lib/core/crypto.h"
#include "lib/core/hostid.h"
#include "lib/core/prefix.h"
#include "lib/tool/pk.h"

#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include "signaling_common_builder.h"
#include "signaling_prot_common.h"
#include "signaling_user_management.h"
#include "signaling_user_api.h"
#include "signaling_x509_api.h"

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

static void get_user_certchain_hash_path(X509_NAME *subject, char *const buf) {
    strcat(buf, CERTIFICATE_INDEX_USER_DIR);
    subject_hash(subject, buf + sizeof(CERTIFICATE_INDEX_USER_DIR) - 1);
    /* We need the -1 because sizeof, unlike strlen, counts the 0-terminator. However, we prefer sizeof for performance reasons */
    strcat(buf, ".0");
}

static void get_free_user_certchain_hash_path(X509_NAME *subject, char *const buf) {
    struct stat buf_stat;
    int i = 0;
    get_user_certchain_hash_path(subject, buf);
    while (!stat(buf, &buf_stat) && i < 10) {
        i++;
        sprintf(buf + sizeof(CERTIFICATE_INDEX_USER_DIR) + CERTIFICATE_INDEX_HASH_LENGTH - 1, ".%d", i);
    }
}


/*
 * TODO: beautify this
 */
static void get_free_user_certchain_name_path(X509_NAME *subject, char *const buf) {
    char name_buf[128];
    int name_len;
    int i = 0;
    struct stat stat_buf;

    strcat(buf, CERTIFICATE_INDEX_USER_DIR);
    memset(name_buf, 0, 128);
    X509_NAME_get_text_by_NID(subject, NID_commonName, name_buf, 127);
    name_buf[127] = '\0';
    name_len = strlen(name_buf);
    if (name_len == 0) {
        X509_NAME_get_text_by_NID(subject, NID_organizationName, name_buf, 127);
        name_buf[127] = '\0';
        name_len = strlen(name_buf);
    }
    strcat(buf, name_buf);
    strcat(buf, ".cert.0");

    HIP_DEBUG("Path: %s \n", buf);
    while (!stat(buf, &stat_buf) && i < 10) {
        i++;
        sprintf(buf + sizeof(CERTIFICATE_INDEX_USER_DIR) + name_len - 1, ".cert.%d", i);
    }
}

/**
 * Compare if two certificate chains are equal.
 * We consider two chains as equal if all certificates from the shorter chain,
 * match with the certificates from the other chain.
 *
 * @note    The given certificate chain should have the leaf certificate at the bottom
 *          of the stack.
 *
 * TODO: update if we got a matching longer certificate chain
 * @return 1 if we have a matching certificate chain, 0 if not
 */
static int signaling_have_user_cert_chain(STACK_OF(X509) *cert_chain) {
    int i = 0;
    char path_buf[PATH_MAX];
    X509 *cert = NULL;
    X509_NAME *x509_subj_name = NULL;
    STACK_OF(X509) *local_chain = NULL;

    if (sk_X509_num(cert_chain) <= 0) {
        return 1;
    }

    cert = sk_X509_value(cert_chain, sk_X509_num(cert_chain)-1);
    x509_subj_name = X509_get_subject_name(cert);
    memset(path_buf, 0, PATH_MAX);
    get_user_certchain_hash_path(x509_subj_name, path_buf);

    while ((local_chain = signaling_load_certificate_chain(path_buf)) != NULL) {
        if(!certificate_chain_cmp(local_chain, cert_chain)) {
            return 1;
        }
        free(local_chain);
        i++;
        path_buf[sizeof(CERTIFICATE_INDEX_USER_DIR) + CERTIFICATE_INDEX_HASH_LENGTH] = (char) i;
    }
    return 0;
}

/**
 * @return 0 if the certificate chain has been added or if we have it already
 *         negative if an error occurs
 */
int signaling_add_user_certificate_chain(STACK_OF(X509) *cert_chain) {
    int err = 0;
    X509 *cert = NULL;
    X509_NAME *x509_subj_name = NULL;
    char subj_name[128];
    char dst_path[PATH_MAX];
    char dst_hash_path[PATH_MAX];

    if (sk_X509_num(cert_chain) <= 0) {
        return 0;
    }

    /* write the certificates to a file */
    cert = sk_X509_value(cert_chain, sk_X509_num(cert_chain)-1);
    x509_subj_name = X509_get_subject_name(cert);
    X509_NAME_oneline(x509_subj_name, subj_name, 128);
    HIP_DEBUG("Got certificate chain for user: %s\n", subj_name);

    if (signaling_have_user_cert_chain(cert_chain)) {
        HIP_DEBUG("Already have user's certificate chain \n");
        return 0;
    }

    /* construct the destination path */
    memset(dst_path, 0, PATH_MAX);
    get_free_user_certchain_name_path(x509_subj_name, dst_path);
    HIP_DEBUG("User's certificate chain is new, saving to file: %s.\n", dst_path);
    HIP_IFEL(signaling_save_certificate_chain(cert_chain, dst_path),
             -1, "Could not save certificate chain to file \n");
    memset(dst_hash_path, 0, PATH_MAX);
    get_free_user_certchain_hash_path(x509_subj_name, dst_hash_path);
    if(symlink(dst_path, dst_hash_path)) {
        HIP_DEBUG("Failed creating symlink: %s -> %s \n", dst_hash_path, dst_path);
    } else {
        HIP_DEBUG("Successfully created symlink: %s -> %s \n", dst_hash_path, dst_path);
    }

out_err:
    return err;
}

/**
 * Try to verify the public key of given user.
 *
 * @param no_chain  1 if we only want to match the public key against a certificate
 *                  0 if we want to verify that certificate (and its chain) too
 *
 * @return 0 if a certificate chain could be build and verified, a non-zero error code otherwise
 */
int signaling_user_api_verify_pubkey(X509_NAME *subject, const EVP_PKEY *const pub_key, X509 *user_cert, int no_chain)
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
    memset(hash_filename, 0, PATH_MAX);
    get_user_certchain_hash_path(subject, hash_filename);
    HIP_DEBUG("Verifying public key of subject: %s \n", name);
    HIP_DEBUG("Looking up certificates index beginning at: %s\n", hash_filename);

    if (no_chain && user_cert) {
        HIP_DEBUG("Matching public key against supplied certificate only.\n");
        cert_pub_key = X509_get_pubkey(user_cert);
        if (EVP_PKEY_cmp(cert_pub_key, pub_key) == 1) {
            HIP_DEBUG("Certificates match.\n");
            return 0;
        } else {
            return -1;
        }
    } else if (no_chain && !user_cert) {
        HIP_DEBUG("Matching public key against certificates from certificate dir.\n");
    }

    /* Go through the certificate index */
    while ((cert_chain = signaling_load_certificate_chain(hash_filename)) != NULL) {
        leaf_cert = sk_X509_pop(cert_chain);
        cert_pub_key = X509_get_pubkey(leaf_cert);
        if (EVP_PKEY_cmp(cert_pub_key, pub_key) == 1) {
            break;
        }
        HIP_DEBUG("Rejecting certificate %s, because public keys did not match\n", hash_filename);
        leaf_cert = NULL;
        free(cert_chain);

        /* move to next possible certificate */
        i++;
        sprintf(hash_filename + sizeof(CERTIFICATE_INDEX_USER_DIR) + CERTIFICATE_INDEX_HASH_LENGTH - 1, ".%i", i);
    }

    if (!leaf_cert) {
        return SIGNALING_USER_AUTH_CERTIFICATE_REQUIRED;
    }

    if (!no_chain) {
        HIP_DEBUG("Found matching certificate in user cert directory.\n");
        return 0;
    } else {
        HIP_DEBUG("Found matching certificate, now verifying certificate chain.\n");
        return verify_certificate_chain(leaf_cert, CERTIFICATE_INDEX_TRUSTED_DIR, NULL, cert_chain);
    }

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

    /* sanity checks */
    HIP_IFEL(!(param_usr_ctx = hip_get_param(msg, HIP_PARAM_SIGNALING_USERINFO)),
             -1, "Need user context to verify his signature \n");
    HIP_IFEL(!(param_user_signature = hip_get_param_readwrite(msg, HIP_PARAM_SIGNALING_USER_SIGNATURE)),
             -1, "Packet contains no user signature\n");

    /* We need to construct a temporary host_id struct since, all key_rr_to_xxx functions take this as argument.
     * However, we need only to fill in hi_length, algorithm and the key rr. */
    pseudo_ui.hi_length = htons(param_usr_ctx->pkey_rr_length);
    pseudo_ui.rdata.algorithm = param_usr_ctx->rdata.algorithm;
    // note: the + 1 moves the pointer behind the parameter, where the key rr begins
    memcpy(pseudo_ui.key, param_usr_ctx + 1, pseudo_ui.hi_length - sizeof(struct hip_host_id_key_rdata));
    HIP_IFEL(!(pkey = hip_key_rr_to_evp_key(&pseudo_ui, 0)), -1, "Could not deserialize users public key\n");
    HIP_DEBUG("Verifying signature using following public key: \n");
    PEM_write_PUBKEY(stderr, pkey);

    /* Now modify the packet to verify signature */
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
    err = signaling_user_api_verify_pubkey(subject_name, pkey, NULL, 0);

out_err:
    hip_set_msg_total_len(msg, orig_len);
    RSA_free(rsa);
    EC_KEY_free(ecdsa);
    X509_NAME_free(subject_name);
    return err;
}
