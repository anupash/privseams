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

#include "signaling_x509_api.h"
#include "signaling_prot_common.h"
#include "signaling_user_api.h"

/*
 * @return NULL on error
 */
static char *get_user_homedir(const uid_t uid)
{
    int            err = 0;
    struct passwd *pw  = NULL;

    HIP_IFEL(!(pw = getpwuid(uid)),
             -1, "Failed to get info for user id %d.\n", uid);

out_err:
    if (err) {
        return NULL;
    }
    return pw->pw_dir;
}

/*
 * @return NULL on error
 */
STACK_OF(X509) * signaling_user_api_get_user_certificate_chain(const uid_t uid) {
    char  filebuf[SIGNALING_PATH_MAX_LEN];
    char *homedir = NULL;
    STACK_OF(X509) * ret = NULL;

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_I_LOAD_USER_CERT, PERF_R_LOAD_USER_CERT\n");   // test 1.1
    hip_perf_start_benchmark(perf_set, PERF_I_LOAD_USER_CERT);
    hip_perf_start_benchmark(perf_set, PERF_R_LOAD_USER_CERT);
#endif
    homedir = get_user_homedir(uid);
    sprintf(filebuf, "%s/.signaling/user-cert-chain.pem", homedir);
    if (!(ret = signaling_load_certificate_chain(filebuf))) {
        HIP_ERROR("Could not get user certificate \n");
        sk_X509_free(ret);
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Stop PERF_I_LOAD_USER_CERT, PERF_R_LOAD_USER_CERT\n"); // test 1.1
        hip_perf_stop_benchmark(perf_set, PERF_I_LOAD_USER_CERT);
        hip_perf_stop_benchmark(perf_set, PERF_R_LOAD_USER_CERT);
#endif
        return NULL;
    }
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop PERF_I_LOAD_USER_CERT, PERF_R_LOAD_USER_CERT\n");   // test 1.1
    hip_perf_stop_benchmark(perf_set, PERF_I_LOAD_USER_CERT);
    hip_perf_stop_benchmark(perf_set, PERF_R_LOAD_USER_CERT);
#endif
    return ret;
}

/**
 * sign some opaque data using rsa
 *
 * @param priv_key the RSA private key of the local host
 * @param data the data to be signed
 * @return zero on success and negative on error
 */
static int rsa_sign(RSA *const priv_key, const void *const data, const int in_len, unsigned char *const out)
{
    int          err = 0;
    unsigned int sig_len;
    uint8_t      sha1_digest[HIP_AH_SHA_LEN];

    HIP_IFEL(!priv_key,
             -1, "No private key given.\n");
    HIP_IFEL(hip_build_digest(HIP_DIGEST_SHA1, data, in_len, sha1_digest) < 0,
             -1, "Building of SHA1 digest failed\n");
    HIP_IFEL(!RSA_sign(NID_sha1, sha1_digest, SHA_DIGEST_LENGTH, out, &sig_len, priv_key),
             -1, "Signing error\n");
out_err:
    return err;
}

/**
 * sign some opaque data using ecdsa
 *
 * @param priv_key the RSA private key of the local host
 * @param data the data to be signed
 * @return zero on success and negative on error
 */
static int ecdsa_sign(EC_KEY *const priv_key, const void *const data, const int in_len, unsigned char *const out)
{
    int     err = 0;
    uint8_t sha1_digest[HIP_AH_SHA_LEN];
    HIP_IFEL(!priv_key,
             -1, "No private key given.\n");
    HIP_IFEL(hip_build_digest(HIP_DIGEST_SHA1, data, in_len, sha1_digest) < 0,
             -1, "Building of SHA1 digest failed\n");
    HIP_IFEL(impl_ecdsa_sign(sha1_digest, priv_key, out),
             -1, "Signing error\n");
out_err:
    return err;
}

int signaling_user_api_get_uname(const uid_t uid, struct signaling_user_context *const user_ctx)
{
    int err = 0;
    STACK_OF(X509) * usercert_chain = NULL;
    X509          *usercert = NULL;
    X509_NAME     *uname    = NULL;
    unsigned char *buf      = NULL;
    int            out_len;

    if ((usercert_chain = signaling_user_api_get_user_certificate_chain(uid))) {
        usercert = sk_X509_pop(usercert_chain);
        HIP_IFEL(!(uname = X509_get_subject_name(usercert)),
                 -1, "Could not get subject name from certificate\n");
        HIP_IFEL((out_len = signaling_X509_NAME_to_DER(uname, &buf)) < 0,
                 -1, "Could not DER encode X509 Subject Name");
        memcpy(user_ctx->subject_name, buf, out_len);
        user_ctx->subject_name_len = out_len;
    } else {
        err = -1;
    }

out_err:
    sk_X509_free(usercert_chain);
    X509_free(usercert);
    free(buf);
    return err;
}

/*
 * @return < 0 on error, size of computed signature on success
 */
int signaling_user_api_sign(const uid_t uid, const void *const data, const int in_len, unsigned char *out_buf, uint8_t *const sig_type)
{
    int     err     = 0;
    int     sig_len = -1;
    char    filebuf[SIGNALING_PATH_MAX_LEN];
    char   *homedir;
    EC_KEY *ecdsa = NULL;
    RSA    *rsa   = NULL;

    /* sanity checks */
    HIP_IFEL(!data,         -1, "Data to sign is NULL \n");
    HIP_IFEL(in_len < 0,    -1, "Invalid in length \n");
    HIP_IFEL(!out_buf,      -1, "Cannot write to NULL-buffer\n");
    HIP_IFEL(!sig_type,     -1, "Cannot write signature type to NULL pointer\n");

    /* Check if there is a preferred signature type */
    switch (*sig_type) {
    case HIP_HI_RSA:
        HIP_DEBUG("Computing user signature using RSA key\n");
        HIP_IFEL(!(homedir = get_user_homedir(uid)),
                 -1, "Could not get homedir for user %d.\n", uid);
        sprintf(filebuf, "%s/.signaling/user-key.pem", homedir);
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Start PERF_I_LOAD_USER_KEY, PERF_R_LOAD_USER_KEY\n");
        hip_perf_start_benchmark(perf_set, PERF_I_LOAD_USER_KEY);
        hip_perf_start_benchmark(perf_set, PERF_R_LOAD_USER_KEY);
#endif
        HIP_IFEL(load_rsa_private_key(filebuf, &rsa),
                 -1, "Could not get private key for signing \n");
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Stop PERF_I_LOAD_USER_KEY, PERF_R_LOAD_USER_KEY\n");
        hip_perf_stop_benchmark(perf_set, PERF_I_LOAD_USER_KEY);
        hip_perf_start_benchmark(perf_set, PERF_R_LOAD_USER_KEY);
#endif
        sig_len   = RSA_size(rsa);
        *sig_type = HIP_SIG_RSA;
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Start  PERF_I2_USER_SIGN, PERF_R2_USER_SIGN\n");
        hip_perf_start_benchmark(perf_set, PERF_I2_USER_SIGN);
        hip_perf_start_benchmark(perf_set, PERF_R2_USER_SIGN);
#endif
        HIP_IFEL(rsa_sign(rsa, data, in_len, out_buf),
                 -1, "Signature function failed \n");
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Stop PERF_I2_USER_SIGN, PERF_R2_USER_SIGN\n");
        hip_perf_stop_benchmark(perf_set, PERF_I2_USER_SIGN);
        hip_perf_stop_benchmark(perf_set, PERF_R2_USER_SIGN);
#endif
        break;

    case HIP_HI_ECDSA:
        HIP_DEBUG("Computing user signature using ECDSA key\n");
        HIP_IFEL(!(homedir = get_user_homedir(uid)),
                 -1, "Could not get homedir for user %d.\n", uid);
        sprintf(filebuf, "%s/.signaling/user-key.pem", homedir);
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Start PERF_I_LOAD_USER_KEY, PERF_R_LOAD_USER_KEY\n");
        hip_perf_start_benchmark(perf_set, PERF_I_LOAD_USER_KEY);
        hip_perf_start_benchmark(perf_set, PERF_R_LOAD_USER_KEY);
#endif
        HIP_IFEL(load_ecdsa_private_key(filebuf, &ecdsa),
                 -1, "Could not get private key for signing \n");
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Stop PERF_I_LOAD_USER_KEY, PERF_R_LOAD_USER_KEY\n");
        hip_perf_stop_benchmark(perf_set, PERF_I_LOAD_USER_KEY);
        hip_perf_stop_benchmark(perf_set, PERF_R_LOAD_USER_KEY);
#endif

        sig_len   = ECDSA_size(ecdsa);
        *sig_type = HIP_SIG_ECDSA;
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Start PERF_I2_USER_SIGN, PERF_R2_USER_SIGN\n");
        hip_perf_start_benchmark(perf_set, PERF_I2_USER_SIGN);
        hip_perf_start_benchmark(perf_set, PERF_R2_USER_SIGN);
#endif
        HIP_IFEL(ecdsa_sign(ecdsa, data, in_len, out_buf),
                 -1, "Signature function failed \n");
#ifdef CONFIG_HIP_PERFORMANCE
        HIP_DEBUG("Stop PERF_I2_USER_SIGN, PERF_R2_USER_SIGN\n");
        hip_perf_stop_benchmark(perf_set, PERF_I2_USER_SIGN);
        hip_perf_stop_benchmark(perf_set, PERF_R2_USER_SIGN);
#endif
        break;
    default:
        HIP_ERROR("invalid signature type");
        return -1;
    }

out_err:
    if (err) {
        return err;
    }
    return sig_len;
}

EVP_PKEY *signaling_user_api_get_user_public_key(const uid_t uid)
{
    int err = 0;
    STACK_OF(X509) * user_cert_chain = NULL;
    X509     *user_cert = NULL;
    EVP_PKEY *pkey      = NULL;

    HIP_IFEL(!(user_cert_chain = signaling_user_api_get_user_certificate_chain(uid)),
             -1, "Could not find user's certificate \n");
    user_cert = sk_X509_pop(user_cert_chain);
    HIP_IFEL(!(pkey = X509_get_pubkey(user_cert)),
             -1, "Error getting public key from users certificate \n");

out_err:
    if (err) {
        return NULL;
    }
    return pkey;
}
