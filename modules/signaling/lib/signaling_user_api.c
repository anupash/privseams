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

#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include "signaling_prot_common.h"
#include "signaling_user_api.h"

/*
 * @return NULL on error
 */
UNUSED static X509 *load_x509_certificate(const char *file) {
    X509 *cert = NULL;
    FILE *fp = fopen(file, "r");
    if(fp == NULL)
        return NULL;
    cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);
    return cert;
}

/*
 * @return NULL on error
 */
static RSA *load_rsa_private_key(const char *private_key_file) {
    RSA *privkey = NULL;
    FILE *fp = fopen (private_key_file, "r");
    if (fp == NULL)
        return NULL;
    privkey = (RSA*) PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    return privkey;
}

/*
 * @return NULL on error
 */
static char *get_user_homedir(uid_t uid) {
    int err = 0;
    struct passwd *pw = NULL;

    HIP_IFEL(!(pw = getpwuid(uid)),
            -1, "Failed to get password entry for given user id.\n");

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
    char *homedir = NULL;
    homedir = get_user_homedir(uid);
    HIP_DEBUG("Got homedir for user: %s\n", homedir);
    //if(homedir != NULL)
    //    return load_x509_certificate(homedir);
    return NULL;
}

/**
 * sign some opaque data
 *
 * @param priv_key the RSA private key of the local host
 * @param data the data to be signed
 * @return zero on success and negative on error
 */
static int rsa_sign(void *priv_key, const void *data, int in_len, uint8_t *out, unsigned int *out_len)
{
    int err = 0;
    uint8_t sha1_digest[HIP_AH_SHA_LEN];

    HIP_IFEL(!priv_key,
            -1, "No private key given.\n");

    HIP_IFEL(hip_build_digest(HIP_DIGEST_SHA1, data, in_len, sha1_digest) < 0,
             -1, "Building of SHA1 digest failed\n");

    /* RSA_sign returns 0 on failure */
    HIP_IFEL(!RSA_sign(NID_sha1, sha1_digest, SHA_DIGEST_LENGTH, out, out_len, priv_key),
                       -1, "Signing error\n");

out_err:
    return err;
}

/*
 * @return < 0 on error, size of computed signature on success
 */
int signaling_user_api_get_signature(uid_t uid, const void *data, int in_len, unsigned char *outbuf) {
    int err = 0;
    X509 *usercert = NULL;
    RSA *priv_key = NULL;
    unsigned int sig_len;
    const char *priv_key_file = "user-key.pem";

    // sanity checks
    HIP_IFEL(!data,
             -1, "Data to sign is NULL \n");
    HIP_IFEL(in_len < 0,
             -1, "Got bad in length \n");
    HIP_IFEL(!outbuf,
             -1, "Output buffer is NULL \n");

    HIP_IFEL(!(priv_key = load_rsa_private_key(priv_key_file)),
             -1, "Could not get private key for signing \n");

    HIP_IFEL(!(usercert = get_user_certificate(uid)),
             -1, "Could not get user certificate \n");

    // sign using RSA
    // TODO: support for dsa, ecdsa...
    sig_len = RSA_size(priv_key);
    rsa_sign(priv_key, data, in_len, outbuf, &sig_len);

out_err:
    if (err) {
        return err;
    }
    return sig_len;
}
