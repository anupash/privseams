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
#include "signaling_user_api.h"

int signaling_X509_to_DER(X509 *const cert, unsigned char **buf) {
    int len;
    int err = 0;

    HIP_IFEL(!cert, -1, "Cannot encode NULL-certificate\n");
    *buf = NULL;
    len = i2d_X509(cert, buf);
    HIP_IFEL(len < 0, -1, "Could not DER-encode the given certificate.\n");

out_err:
    if (err) {
        return err;
    }
    return len;
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

static X509 *load_x509_certificate(const char *const file) {
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

/*
 * @return NULL on error
 */
static char *get_user_homedir(const uid_t uid) {
    int err = 0;
    struct passwd *pw = NULL;

    HIP_IFEL(!(pw = getpwuid(uid)),
            -1, "Failed to get info for user id %d.\n", uid);

out_err:
    if(err) {
        return NULL;
    }
    return pw->pw_dir;
}

/*
 * @return NULL on error
 */
X509 *signaling_user_api_get_user_certificate(const uid_t uid) {
    char filebuf[SIGNALING_PATH_MAX_LEN];
    char *homedir   = NULL;
    X509 *ret       = NULL;
    int err         = 0;

    homedir = get_user_homedir(uid);
    sprintf(filebuf, "%s/.signaling/user-cert.pem", homedir);
    HIP_IFEL(!(ret = load_x509_certificate(filebuf)),
             -1, "Could not get user certificate \n");

out_err:
    if (err) {
        X509_free(ret);
        return NULL;
    }
    return ret;
}

/**
 * sign some opaque data
 *
 * @param priv_key the RSA private key of the local host
 * @param data the data to be signed
 * @return zero on success and negative on error
 */
static int ecdsa_sign(EC_KEY *const priv_key, const void *const data, const int in_len, unsigned char *const out)
{
    int err = 0;
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

int signaling_user_api_get_uname(const uid_t uid, struct signaling_user_context *const user_ctx) {
    int err             = 0;
    X509 *usercert      = NULL;
    X509_NAME *uname    = NULL;
    struct passwd *pw   = NULL;

    if (!(usercert = signaling_user_api_get_user_certificate(uid))) {
        HIP_DEBUG("Could not get user's certificate, using system username as fallback.\n");
        HIP_IFEL(!(pw = getpwuid(uid)),
                 -1, "Failed to get info for user id %d.\n", uid);
        strncpy(user_ctx->username, pw->pw_name, SIGNALING_USER_ID_MAX_LEN-1);
        user_ctx->username[SIGNALING_USER_ID_MAX_LEN-1] = '\0';
    } else {
        HIP_IFEL(!(uname = X509_get_subject_name(usercert)),
                 -1, "Could not get subject name from certificate\n");
        X509_NAME_oneline(uname, user_ctx->username, SIGNALING_USER_ID_MAX_LEN);
        user_ctx->username[SIGNALING_USER_ID_MAX_LEN-1] = '\0';
    }

out_err:
    return err;
}

/*
 * @return < 0 on error, size of computed signature on success
 */
int signaling_user_api_sign(const uid_t uid, const void *const data, const int in_len, unsigned char *out_buf, uint8_t *const sig_type) {
    int err = 0;
    int sig_len;
    char filebuf[SIGNALING_PATH_MAX_LEN];
    char *homedir;
    EC_KEY *ecdsa = NULL;

    /* sanity checks */
    HIP_IFEL(!data,         -1, "Data to sign is NULL \n");
    HIP_IFEL(in_len < 0,    -1, "Invalid in length \n");
    HIP_IFEL(!out_buf,      -1, "Cannot write to NULL-buffer\n");
    HIP_IFEL(!sig_type,     -1, "Cannot write signature type to NULL pointer\n");

    // get users private key
    HIP_IFEL(!(homedir = get_user_homedir(uid)),
             -1, "Could not get homedir for user %d.\n", uid);
    sprintf(filebuf, "%s/.signaling/user-key.pem", homedir);
    HIP_IFEL(load_ecdsa_private_key(filebuf, &ecdsa),
             -1, "Could not get private key for signing \n");
    EC_KEY_print_fp(stdout, ecdsa, 0);

    // sign using ECDSA
    sig_len     = ECDSA_size(ecdsa);
    *sig_type   = HIP_SIG_ECDSA;
    HIP_IFEL(ecdsa_sign(ecdsa, data, in_len, out_buf),
             -1, "Signature function failed \n");

out_err:
    if (err) {
        return err;
    }
    return sig_len;
}

EVP_PKEY *signaling_user_api_get_user_public_key(const uid_t uid) {
    int err         = 0;
    X509 *user_cert = NULL;
    EVP_PKEY *pkey  = NULL;

    HIP_IFEL(!(user_cert = signaling_user_api_get_user_certificate(uid)),
             -1, "Could not find user's certificate \n");

    HIP_IFEL(!(pkey=X509_get_pubkey(user_cert)),
             -1, "Error getting public key from users certificate \n");

out_err:
    if (err) {
        return NULL;
    }
    return pkey;
}
