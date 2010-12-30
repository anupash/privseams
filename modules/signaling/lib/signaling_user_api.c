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

static X509 *load_x509_certificate(const char *file) {
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
static char *get_user_homedir(uid_t uid) {
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
static X509 *get_user_certificate(uid_t uid) {
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
static int ecdsa_sign(EC_KEY *priv_key, const void *data, int in_len, uint8_t *out)
{
    int err = 0;
    uint8_t sha1_digest[HIP_AH_SHA_LEN];

    HIP_IFEL(!priv_key,
            -1, "No private key given.\n");

    HIP_IFEL(hip_build_digest(HIP_DIGEST_SHA1, data, in_len, sha1_digest) < 0,
             -1, "Building of SHA1 digest failed\n");

    /* RSA_sign returns 0 on failure */
    HIP_IFEL(impl_ecdsa_sign(sha1_digest, priv_key, out),
             -1, "Signing error\n");

out_err:
    return err;
}

int signaling_user_api_get_uname(uid_t uid, struct signaling_user_context *user_ctx) {
    int err             = 0;
    X509 *usercert      = NULL;
    X509_NAME *uname    = NULL;
    struct passwd *pw   = NULL;

    if (!(usercert = get_user_certificate(uid))) {
        HIP_DEBUG("Could not get user's certificate, using system username as fallback.\n");
        HIP_IFEL(!(pw = getpwuid(uid)),
                 -1, "Failed to get info for user id %d.\n", uid);
        memcpy(user_ctx->username, pw->pw_name, strlen(pw->pw_name));
    } else {
        HIP_IFEL(!(uname = X509_get_subject_name(usercert)),
                 -1, "Could not get subject name from certificate\n");
        X509_NAME_oneline(uname, user_ctx->username, SIGNALING_USER_ID_MAX_LEN);
    }

out_err:
    return err;
}

/*
 * @return < 0 on error, size of computed signature on success
 */
int signaling_user_api_get_signature(uid_t uid, const void *data, int in_len, unsigned char *outbuf) {
    int err = 0;
    EC_KEY *priv_key = NULL;
    unsigned int sig_len;
    char *homedir = NULL;
    char filebuf[SIGNALING_PATH_MAX_LEN];

    // sanity checks
    HIP_IFEL(!data,
             -1, "Data to sign is NULL \n");
    HIP_IFEL(in_len < 0,
             -1, "Got bad in length \n");
    HIP_IFEL(!outbuf,
             -1, "Output buffer is NULL \n");

    // get users homedir, private key and certificate
    HIP_IFEL(!(homedir = get_user_homedir(uid)),
             -1, "Could not get homedir for user %d.\n", uid);

    sprintf(filebuf, "%s/.signaling/user-key.pem", homedir);
    HIP_DEBUG("Looking for certificate at: %s \n", filebuf);
    HIP_IFEL(load_ecdsa_private_key(filebuf, &priv_key),
             -1, "Could not get private key for signing \n");

    // sign using ECDSA
    // TODO: support for rsa, dsa...
    sig_len = ECDSA_size(priv_key);
    ecdsa_sign(priv_key, data, in_len, outbuf);

out_err:
    if (err) {
        return err;
    }
    return sig_len;
}
