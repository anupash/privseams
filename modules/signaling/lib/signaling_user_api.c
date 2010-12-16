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
#include "lib/tool/pk.h"

#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include "signaling_prot_common.h"
#include "signaling_user_api.h"

static int load_x509_certificate(const char *file, X509 **cert) {
    int err = 0;
    FILE *fp;

    *cert = NULL;
    HIP_IFEL(!file, -ENOENT, "NULL filename\n");

    fp   = fopen(file, "rb");
    HIP_IFEL(!fp, -ENOMEM,
             "Could not open certificate key file %s for reading\n", file);

    *cert = PEM_read_X509(fp, NULL, NULL, NULL);
    if ((err = fclose(fp))) {
        HIP_ERROR("Error closing file\n");
        goto out_err;
    }

out_err:
    return err;
}

/**
 * Sign using ECDSA
 *
 * @param digest a digest of the message to sign
 * @param ecdsa the ECDSA key
 * @param signature write the signature here
 *
 * @return 0 on success and non-zero on error
 */
static int impl_ecdsa_sign(uint8_t *digest, EC_KEY *ecdsa, uint8_t *signature)
{
    ECDSA_SIG *ecdsa_sig = NULL;
    int err              = 0;
    int sig_size;

    HIP_IFEL(!EC_KEY_check_key(ecdsa),
             -1, "Check of signing key failed. \n");

    sig_size = ECDSA_size(ecdsa);
    memset(signature, 0, sig_size);

    ecdsa_sig = ECDSA_do_sign(digest, HIP_AH_SHA_LEN, ecdsa);
    HIP_IFEL(!ecdsa_sig, 1, "ECDSA_do_sign failed\n");

    /* build signature from ECDSA_SIG struct */
    bn2bin_safe(ecdsa_sig->r, signature, sig_size/2);
    bn2bin_safe(ecdsa_sig->s, signature + (sig_size/2), sig_size/2);

out_err:
    ECDSA_SIG_free(ecdsa_sig);
    return err;
}

/**
 * load host EC private keys from disk
 * @param filename the file name base of the host EC key
 * @param ec Pointer to the EC key structure.
 *
 * Loads EC private key from file filename. EC struct
 * will be allocated dynamically and it is the responsibility
 * of the caller to free it with EC_free.
 *
 * @return On success *ec contains the EC structure. On failure
 * *EC contins NULL if the key could not be loaded (not in PEM format
 * or file not found, etc).
 */
static int load_ecdsa_private_key(const char *filename, EC_KEY **ecdsa)
{
    FILE *fp = NULL;
    int err  = 0;

    *ecdsa = NULL;

    HIP_IFEL(!filename, -ENOENT, "NULL filename\n");

    fp   = fopen(filename, "rb");
    HIP_IFEL(!fp, -ENOMEM,
             "Could not open private key file %s for reading\n", filename);

    *ecdsa = PEM_read_ECPrivateKey(fp, NULL, NULL, NULL);
    if ((err = fclose(fp))) {
        HIP_ERROR("Error closing file\n");
        goto out_err;
    }

    HIP_IFEL(!EC_KEY_check_key(*ecdsa),
             -1, "Error during loading of ecdsa key.\n");

    HIP_IFEL(!*ecdsa, -EINVAL, "Read failed for %s\n", filename);

out_err:

    return err;
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
UNUSED static X509 *get_user_certificate(uid_t uid) {
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
    int err = 0;
    struct passwd *pw = NULL;

    HIP_IFEL(!(pw = getpwuid(uid)),
            -1, "Failed to get info for user id %d.\n", uid);
    memcpy(user_ctx->user_id, pw->pw_name, strlen(pw->pw_name));

out_err:
    return err;
}

/*
 * @return < 0 on error, size of computed signature on success
 */
int signaling_user_api_get_signature(uid_t uid, const void *data, int in_len, unsigned char *outbuf) {
    int err = 0;
    X509 *usercert = NULL;
    EC_KEY *priv_key = NULL;
    unsigned int sig_len;
    char *homedir = NULL;
    char filebuf[PATH_MAX];

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

    HIP_DEBUG("Homedir for user %d: %s \n", uid, homedir);

    memset(filebuf, 0, 200);
    strcat(filebuf, homedir);
    strcat(filebuf+strlen(homedir), "/.signaling/user-key.pem");
    HIP_DEBUG("Looking for certificate at: %s \n", filebuf);
    HIP_IFEL(load_ecdsa_private_key(filebuf, &priv_key),
             -1, "Could not get private key for signing \n");

    memset(filebuf, 0, 200);
    strcat(filebuf, homedir);
    strcat(filebuf+strlen(homedir), "/.signaling/user-cert.pem");
    HIP_DEBUG("Looking for certificate at: %s \n", filebuf);
    HIP_IFEL(load_x509_certificate(filebuf, &usercert),
             -1, "Could not get user certificate \n");

    // sign using RSA
    // TODO: support for dsa, ecdsa...
    sig_len = ECDSA_size(priv_key);
    ecdsa_sign(priv_key, data, in_len, outbuf);

out_err:
    if (err) {
        return err;
    }
    return sig_len;
}
