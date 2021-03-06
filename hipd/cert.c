/*
 * Copyright (c) 2010-2011 Aalto University and RWTH Aachen University.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

/**
 * @file
 *
 * This file defines the certificate signing and verification
 * functions to use with HIP
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <openssl/conf.h>
#include <openssl/dsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "lib/core/builder.h"
#include "lib/core/certtools.h"
#include "lib/core/common.h"
#include "lib/core/crypto.h"
#include "lib/core/debug.h"
#include "lib/core/ife.h"
#include "lib/core/protodefs.h"
#include "lib/core/straddr.h"
#include "lib/tool/pk.h"
#include "hidb.h"
#include "cert.h"


/****************************************************************************
 *
 * SPKI
 *
 ***************************************************************************/

/**
 * Function that signs the cert sequence and creates the public key
 * sequence and the signature sequence
 *
 * @param msg points to the msg gotten from "client" that should
 *            contain HIP_PARAM_CERT_SPKI_INFO
 *
 * @return 0 if signature was created without errors, negative value
 *         is returned on errors
 */
int hip_cert_spki_sign(struct hip_common *msg)
{
    int                              err = 0, sig_len = 0, algo = 0, t = 0;
    const struct hip_cert_spki_info *p_cert;
    struct hip_cert_spki_info       *cert;
    struct hip_host_id              *host_id = NULL;
    unsigned char                    sha_digest[SHA_DIGEST_LENGTH];
    unsigned char                   *signature_b64 = NULL;
    unsigned char                   *digest_b64    = NULL;
    unsigned char                   *sha_retval;
    uint8_t                         *signature = NULL;
    DSA_SIG                         *dsa_sig   = NULL;

    /* RSA needed variables */
    RSA           *rsa   = NULL;
    unsigned char *e_bin = NULL, *n_bin = NULL, *n_b64 = NULL;
    char          *e_hex = NULL;

    /* DSA needed variables */
    DSA           *dsa   = NULL;
    unsigned char *p_bin = NULL, *q_bin = NULL, *g_bin = NULL, *y_bin = NULL;
    unsigned char *p_b64 = NULL, *q_b64 = NULL, *g_b64 = NULL, *y_b64 = NULL;

    HIP_IFEL(!(cert = calloc(1, sizeof(struct hip_cert_spki_info))),
             -1, "calloc for cert failed\n");
    HIP_IFEL(!(p_cert = hip_get_param(msg, HIP_PARAM_CERT_SPKI_INFO)),
             -1, "No cert_info struct found\n");
    memcpy(cert, p_cert, sizeof(struct hip_cert_spki_info));

    HIP_DEBUG_HIT("Getting keys for HIT", &cert->issuer_hit);

    HIP_IFEL(hip_get_host_id_and_priv_key(hip_local_hostid_db, &cert->issuer_hit,
                                          HIP_ANY_ALGO, &host_id, (void **) &rsa),
             -1, "Private key not found\n");

    algo = host_id->rdata.algorithm;
    if (algo == HIP_HI_DSA) {
        dsa = (DSA *) rsa;
    }

    // Note: EVP_EncodeBlock(unsigned char *t, const unsigned char *f, int dlen) (vintage SSLeay
    //  code) is used to generate the different BASE64 representations. It requires an area of
    //  ((dlen + 2) / 3 * 4 + 1) bytes - so, obviously larger than the size of the input - to be
    //  available for its output (at location "t") - you have been warned.
    digest_b64 = calloc(1, (SHA_DIGEST_LENGTH + 2) / 3 * 4 + 1);
    HIP_IFEL(!digest_b64, -1, "calloc for digest_b64 failed\n");

    /* build sha1 digest that will be signed */
    HIP_IFEL(!(sha_retval = SHA1((unsigned char *) cert->cert, strlen(cert->cert), sha_digest)),
             -1, "SHA1 error when creating digest.\n");

    switch (algo) {
    case HIP_HI_RSA:
        sig_len = RSA_size(rsa);

        signature = calloc(1, sig_len);
        HIP_IFEL(!signature, -1, "calloc for signature failed\n");

        signature_b64 = calloc(1, (sig_len + 2) / 3 * 4 + 1);
        HIP_IFEL(!signature_b64, -1, "calloc for signature_b64 failed\n");

        n_bin = calloc(1, BN_num_bytes(rsa->n));
        HIP_IFEL(!n_bin, -1, "calloc for n_bin failed\n");

        n_b64 = calloc(1, (BN_num_bytes(rsa->n) + 2) / 3 * 4 + 1);
        HIP_IFEL(!n_b64, -1, "calloc for n_b64 failed\n");

        e_bin = calloc(1, BN_num_bytes(rsa->e));
        HIP_IFEL(!e_bin, -1, "calloc for e_bin failed\n");

        /* RSA sign the digest */
        err = RSA_sign(NID_sha1, sha_digest, SHA_DIGEST_LENGTH, signature,
                       (unsigned int *) &sig_len, rsa);
        HIP_IFEL((err = err == 0 ? -1 : 0), -1, "RSA_sign error\n");
        break;
    case HIP_HI_ECDSA:
        HIP_DEBUG("CALL TO UNIMPLEMENTED ECDSA CASE\n");
        HIP_OUT_ERR(-1, "Unknown algorithm\n");
        break;
    case HIP_HI_DSA:
        p_bin = malloc(BN_num_bytes(dsa->p) + 1);
        HIP_IFEL(!p_bin, -1, "Malloc for p_bin failed\n");

        q_bin = malloc(BN_num_bytes(dsa->q) + 1);
        HIP_IFEL(!q_bin, -1, "Malloc for q_bin failed\n");

        g_bin = malloc(BN_num_bytes(dsa->g) + 1);
        HIP_IFEL(!g_bin, -1, "Malloc for g_bin failed\n");

        y_bin = malloc(BN_num_bytes(dsa->pub_key) + 1);
        HIP_IFEL(!y_bin, -1, "Malloc for y_bin failed\n");

        p_b64 = malloc(BN_num_bytes(dsa->p) + 20);
        HIP_IFEL(!p_b64, -1, "Malloc for p_b64 failed\n");

        q_b64 = malloc(BN_num_bytes(dsa->q) + 20);
        HIP_IFEL(!q_b64, -1, "Malloc for q_b64 failed\n");

        g_b64 = malloc(BN_num_bytes(dsa->g) + 20);
        HIP_IFEL(!g_b64, -1, "Malloc for g_b64 failed\n");

        y_b64 = malloc(BN_num_bytes(dsa->pub_key) + 20);
        HIP_IFEL(!y_b64, -1, "Malloc for y_b64 failed\n");

#define HIP_DSA_SIG_SIZE 41 /* T(1) + R(20) + S(20)  from RFC 2536 */
        signature = calloc(1, HIP_DSA_SIG_SIZE);

        t = BN_num_bytes(dsa->p);
        t = (t - 64) / 8;
        HIP_IFEL(t > 8, 1, "Illegal DSA key\n");

        signature[0] = t;
        dsa_sig      = DSA_do_sign(sha_digest, SHA_DIGEST_LENGTH, dsa);
        bn2bin_safe(dsa_sig->r, &signature[1], DSA_PRIV);
        bn2bin_safe(dsa_sig->s, &signature[1 + DSA_PRIV], DSA_PRIV);
        sig_len = SHA_DIGEST_LENGTH + DSA_PRIV * 2;
        break;
    default:
        HIP_OUT_ERR(-1, "Unknown algorithm for signing\n");
    }

    HIP_IFEL(!EVP_EncodeBlock(digest_b64, sha_digest, SHA_DIGEST_LENGTH),
             -1, "Failed to encode digest_b64\n");
    HIP_IFEL(!EVP_EncodeBlock(signature_b64, signature, sig_len),
             -1, "Failed to encode signature_b64\n");

    /* create (signature (hash sha1 |digest|)|signature|) */
    sprintf(cert->signature, "(signature (hash sha1 |%s|)|%s|)",
            digest_b64, signature_b64);

    /* Create the public key sequence */
    switch (algo) {
    case HIP_HI_RSA:
        /*
         * RSA public-key
         * draft-paajarvi-xml-spki-cert-00 section 3.1.1
         *
         * <!ELEMENT rsa-pubkey (rsa-e,rsa-n)>
         * <!ELEMENT rsa-e (#PCDATA)>
         * <!ELEMENT rsa-n (#PCDATA)>
         */
        HIP_IFEL(!BN_bn2bin(rsa->n, n_bin),
                 -1,
                 "Error in converting public exponent from BN to bin\n");

        HIP_IFEL(!EVP_EncodeBlock(n_b64, n_bin, BN_num_bytes(rsa->n)),
                 -1,
                 "Failed to encode n_b64\n");

        HIP_IFEL(!BN_bn2bin(rsa->e, e_bin),
                 -1,
                 "Error in converting public exponent from BN to bin\n");

        e_hex = BN_bn2hex(rsa->e);

        sprintf(cert->public_key, "(public_key (rsa-pkcs1-sha1 (e #%s#)(n |%s|)))",
                e_hex,
                n_b64);
        break;
    case HIP_HI_ECDSA:
        HIP_DEBUG("CALL TO UNIMPLEMENTED ECDSA CASE\n");
        HIP_OUT_ERR(-1, "Unknown algorithm for signing\n");
        break;
    case HIP_HI_DSA:
        /*
         * DSA public-key
         * draft-paajarvi-xml-spki-cert-00 section 3.1.2
         *
         * <!ELEMENT dsa-pubkey (dsa-p,dsa-q,dsa-g,dsa-y)>
         * <!ELEMENT dsa-p (#PCDATA)>
         * <!ELEMENT dsa-q (#PCDATA)>
         * <!ELEMENT dsa-g (#PCDATA)>
         * <!ELEMENT dsa-y (#PCDATA)>
         */
        HIP_IFEL(!BN_bn2bin(dsa->p, p_bin), -1,
                 "Error in converting public exponent from BN to bin\n");
        HIP_IFEL(!EVP_EncodeBlock(p_b64, p_bin, BN_num_bytes(dsa->p)),
                 -1, "Failed to encode p_b64\n");

        HIP_IFEL(!BN_bn2bin(dsa->q, q_bin), -1,
                 "Error in converting public exponent from BN to bin\n");
        HIP_IFEL(!EVP_EncodeBlock(q_b64, q_bin, BN_num_bytes(dsa->q)),
                 -1, "Failed to encode q_64");

        HIP_IFEL(!(BN_bn2bin(dsa->g, g_bin)), -1,
                 "Error in converting public exponent from BN to bin\n");
        HIP_IFEL(!EVP_EncodeBlock(g_b64, g_bin, BN_num_bytes(dsa->g)),
                 -1, "Failed to encode g_b64\n");

        HIP_IFEL(!BN_bn2bin(dsa->pub_key, y_bin), -1,
                 "Error in converting public exponent from BN to bin\n");
        HIP_IFEL(!EVP_EncodeBlock(y_b64, y_bin, BN_num_bytes(dsa->pub_key)),
                 -1, "Failed to encode y_b64\n");

        sprintf(cert->public_key, "(public_key (dsa-pkcs1-sha1 (p |%s|)(q |%s|)"
                                  "(g |%s|)(y |%s|)))",
                p_b64, q_b64, g_b64, y_b64);
        break;
    default:
        HIP_OUT_ERR(-1, "Unknown algorithm for public-key element\n");
    }

    /* Put the results into the msg back */
    hip_msg_init(msg);

    HIP_IFEL(hip_build_user_hdr(msg, HIP_MSG_CERT_SPKI_SIGN, 0), -1,
             "Failed to build user header\n");
    HIP_IFEL(hip_build_param_cert_spki_info(msg, cert), -1,
             "Failed to build cert_info\n");

out_err:

    /* free malloced memory */
    free(digest_b64);
    free(signature_b64);
    free(signature);
    free(host_id);

    /* RSA pubkey */
    free(e_bin);
    free(n_bin);
    /* encoded */
    OPENSSL_free(e_hex);
    free(n_b64);

    /* DSA pubkey */
    free(p_bin);
    free(q_bin);
    free(g_bin);
    free(y_bin);
    /* encoded */
    free(p_b64);
    free(q_b64);
    free(g_b64);
    free(y_b64);

    DSA_SIG_free(dsa_sig);

    free(cert);

    return err;
}

/**
 * Function that verifies the signature in the given SPKI cert sent by
 * the "client"
 *
 * @param msg points to the msg gotten from "client" that contains a
 *            spki cert in CERT parameter
 *
 * @return 0 if signature matches, -1 if error or signature did NOT match
 */
int hip_cert_spki_verify(struct hip_common *msg)
{
    int  err = 0, start = 0, stop = 0, evpret = 0, keylen = 0, algo = 0;
    char buf[200];

    unsigned char  sha_digest[21];
    unsigned char *sha_retval;
    unsigned char *signature_hash     = NULL;
    unsigned char *signature_hash_b64 = NULL;
    unsigned char *signature_b64      = NULL;

    const struct hip_cert_spki_info *p_cert;
    struct hip_cert_spki_info       *cert      = NULL;
    unsigned char                   *signature = NULL;

    /** RSA */
    RSA           *rsa = NULL;
    unsigned long  e_code;
    char          *e_hex       = NULL;
    unsigned char *modulus_b64 = NULL;
    unsigned char *modulus     = NULL;

    /** DSA */
    DSA           *dsa     = NULL;
    unsigned char *p_bin   = NULL, *q_bin = NULL, *g_bin = NULL, *y_bin = NULL;
    unsigned char *p_b64   = NULL, *q_b64 = NULL, *g_b64 = NULL, *y_b64 = NULL;
    DSA_SIG       *dsa_sig = NULL;

    /* rules for regular expressions */

    /*
     * Rule to get the info if we are using DSA
     */
    char dsa_rule[] = "[d][s][a][-][p][k][c][s][1][-][s][h][a][1]";

    /*
     * Rule to get the info if we are using RSA
     */
    char rsa_rule[] = "[r][s][a][-][p][k][c][s][1][-][s][h][a][1]";

    /*
     * Rule to get DSA p
     * Look for pattern "(p |" and stop when first "|"
     * anything in base 64 is accepted inbetween
     */
    char p_rule[] = "[(][p][ ][|][[A-Za-z0-9+/()#=-]*[|]";

    /*
     * Rule to get DSA q
     * Look for pattern "(q |" and stop when first "|"
     * anything in base 64 is accepted inbetween
     */
    char q_rule[] = "[(][q][ ][|][[A-Za-z0-9+/()#=-]*[|]";

    /*
     * Rule to get DSA g
     * Look for pattern "(g |" and stop when first "|"
     * anything in base 64 is accepted inbetween
     */
    char g_rule[] = "[(][g][ ][|][[A-Za-z0-9+/()#=-]*[|]";

    /*
     * Rule to get DSA y / pub_key
     * Look for pattern "(y |" and stop when first "|"
     * anything in base 64 is accepted inbetween
     */
    char y_rule[] = "[(][y][ ][|][[A-Za-z0-9+/()#=-]*[|]";

    /*
     * rule to get the public exponent RSA
     * Look for the part that says # and after that some hex blob and #
     */
    char e_rule[] = "[#][0-9A-Fa-f]*[#]";

    /*
     * rule to get the public modulus RSA
     * Look for the part that starts with '|' and after that anything
     * that is in base 64 char set and then '|' again
     */
    char n_rule[] = "[|][A-Za-z0-9+/()#=-]*[|]";

    /*
     * rule to get the signature hash
     * Look for the similar than the n_rule
     */
    char h_rule[] = "[|][A-Za-z0-9+/()#=-]*[|]";

    /*
     * rule to get the signature
     * Look for part that starts ")|" and base 64 blob after it
     * and stops to '|' char remember to add and subtract 2 from
     * the indexes below
     */
    char s_rule[] = "[)][|][A-Za-z0-9+/()#=-]*[|]";

    cert = calloc(1, sizeof(struct hip_cert_spki_info));
    HIP_IFEL(!cert, -1, "calloc for cert failed\n");

    HIP_IFEL(!(p_cert = hip_get_param(msg, HIP_PARAM_CERT_SPKI_INFO)),
             -1, "No cert_info struct found\n");
    memcpy(cert, p_cert, sizeof(struct hip_cert_spki_info));

    /* check the algo DSA or RSA  */
    HIP_DEBUG("Verifying\nRunning regexps to identify algo\n");
    start = stop = 0;
    algo  = hip_cert_regex(dsa_rule, cert->public_key, &start, &stop);
    if (algo != -1) {
        HIP_DEBUG("Public-key is DSA\n");
        algo = HIP_HI_DSA;
        goto algo_check_done;
    }
    start = stop = 0;
    algo  = hip_cert_regex(rsa_rule, cert->public_key, &start, &stop);
    if (algo != -1) {
        HIP_DEBUG("Public-key is RSA\n");
        algo = HIP_HI_RSA;
        goto algo_check_done;
    }

algo_check_done:
    switch (algo) {
    case HIP_HI_RSA:
        /* malloc space for new rsa */
        rsa = RSA_new();
        HIP_IFEL(!rsa, -1, "Failed to malloc RSA\n");

        /* extract the public-key from cert to rsa */

        /* public exponent first */
        start = stop = 0;
        HIP_IFEL(hip_cert_regex(e_rule, cert->public_key, &start, &stop), -1,
                 "Failed to run hip_cert_regex (exponent)\n");
        e_hex = malloc(stop - start);
        HIP_IFEL(!e_hex, -1, "Malloc for e_hex failed\n");
        snprintf(e_hex, stop - start - 1, "%s", &cert->public_key[start + 1]);

        /* public modulus */
        start = stop = 0;
        HIP_IFEL(hip_cert_regex(n_rule, cert->public_key, &start, &stop), -1,
                 "Failed to run hip_cert_regex (modulus)\n");
        modulus_b64 = calloc(1, stop - start + 1);
        HIP_IFEL(!modulus_b64, -1, "calloc for modulus_b64 failed\n");
        modulus = calloc(1, stop - start + 1);
        HIP_IFEL(!modulus, -1, "calloc for modulus failed\n");
        snprintf((char *) modulus_b64, stop - start - 1, "%s",
                 &cert->public_key[start + 1]);

        /* put the stuff into the RSA struct */
        BN_hex2bn(&rsa->e, e_hex);
        evpret = EVP_DecodeBlock(modulus, modulus_b64,
                                 strlen((char *) modulus_b64));

        /* EVP returns a multiple of 3 octets, subtract any extra */
        keylen = evpret;
        if (keylen % 4 != 0) {
            --keylen;
            keylen = keylen - keylen % 2;
        }
        signature = malloc(keylen);
        HIP_IFEL(!signature, -1, "Malloc for signature failed.\n");
        rsa->n = BN_bin2bn(modulus, keylen, 0);
        break;
    case HIP_HI_DSA:
        /* malloc space for new dsa */
        dsa = DSA_new();
        HIP_IFEL(!dsa, -1, "Failed to malloc DSA\n");

        /* Extract public key from the cert */

        /* dsa->p */
        start = stop = 0;
        HIP_IFEL(hip_cert_regex(p_rule, cert->public_key, &start, &stop), -1,
                 "Failed to run hip_cert_regex dsa->p\n");
        p_b64 = calloc(1, stop - start + 1);
        HIP_IFEL(!p_b64, -1, "calloc for p_b64 failed\n");
        p_bin = calloc(1, stop - start + 1);
        HIP_IFEL(!p_bin, -1, "calloc for p_bin failed\n");
        snprintf((char *) p_b64, stop - start - 1, "%s",
                 &cert->public_key[start + 1]);
        evpret = EVP_DecodeBlock(p_bin, p_b64, strlen((char *) p_b64));

        /* dsa->q */
        start = stop = 0;
        HIP_IFEL(hip_cert_regex(q_rule, cert->public_key, &start, &stop), -1,
                 "Failed to run hip_cert_regex dsa->q\n");
        q_b64 = calloc(1, stop - start + 1);
        HIP_IFEL(!q_b64, -1, "calloc for q_b64 failed\n");
        q_bin = calloc(1, stop - start + 1);
        HIP_IFEL(!q_bin, -1, "calloc for q_bin failed\n");
        snprintf((char *) q_b64, stop - start - 1, "%s",
                 &cert->public_key[start + 1]);
        evpret = EVP_DecodeBlock(q_bin, q_b64, strlen((char *) q_b64));

        /* dsa->g */
        start = stop = 0;
        HIP_IFEL(hip_cert_regex(g_rule, cert->public_key, &start, &stop), -1,
                 "Failed to run hip_cert_regex dsa->g\n");
        g_b64 = calloc(1, stop - start + 1);
        HIP_IFEL(!g_b64, -1, "calloc for g_b64 failed\n");
        g_bin = calloc(1, stop - start + 1);
        HIP_IFEL(!g_bin, -1, "calloc for g_bin failed\n");
        snprintf((char *) g_b64, stop - start - 1, "%s",
                 &cert->public_key[start + 1]);
        evpret = EVP_DecodeBlock(g_bin, g_b64, strlen((char *) g_b64));

        /* dsa->y */
        start = stop = 0;
        HIP_IFEL(hip_cert_regex(y_rule, cert->public_key, &start, &stop), -1,
                 "Failed to run hip_cert_regex dsa->y\n");
        y_b64 = calloc(1, stop - start + 1);
        HIP_IFEL(!y_b64, -1, "calloc for y_b64 failed\n");
        y_bin = calloc(1, stop - start + 1);
        HIP_IFEL(!y_bin, -1, "calloc for y_bin failed\n");
        snprintf((char *) y_b64, stop - start - 1, "%s",
                 &cert->public_key[start + 1]);
        evpret = EVP_DecodeBlock(y_bin, y_b64, strlen((char *) y_b64));
        break;
    case HIP_HI_ECDSA:
        HIP_DEBUG("CALL TO UNIMPLEMENTED ECDSA CASE\n");
        HIP_OUT_ERR(-1, "Unknown algorithm\n");
        break;
    default:
        HIP_OUT_ERR(-1, "Unknown algorithm\n");
    }

    /* build sha1 digest that will be signed */
    HIP_IFEL(!(sha_retval = SHA1((unsigned char *) cert->cert,
                                 strlen(cert->cert), sha_digest)),
             -1, "SHA1 error when creating digest.\n");

    /* Get the signature hash and compare it to the sha_digest we just made */
    start = stop = 0;
    HIP_IFEL(hip_cert_regex(h_rule, cert->signature, &start, &stop), -1,
             "Failed to run hip_cert_regex (signature hash)\n");
    signature_hash_b64 = calloc(1, stop - start + 1);
    HIP_IFEL(!signature_hash_b64, -1, "Failed to calloc signature_hash_b64\n");
    signature_hash = malloc(stop - start + 1);
    HIP_IFEL(!signature_hash, -1, "Failed to malloc signature_hash\n");
    snprintf((char *) signature_hash_b64, stop - start - 1, "%s",
             &cert->signature[start + 1]);
    evpret = EVP_DecodeBlock(signature_hash, signature_hash_b64,
                             strlen((char *) signature_hash_b64));
    HIP_IFEL(memcmp(sha_digest, signature_hash, 20), -1,
             "Signature hash did not match of the one made from the"
             "cert sequence in the certificate\n");

    /* memset signature and put it into its place */
    start = stop = 0;
    HIP_IFEL(hip_cert_regex(s_rule, cert->signature, &start, &stop), -1,
             "Failed to run hip_cert_regex (signature)\n");
    signature_b64 = calloc(1, stop - start + 1);
    HIP_IFEL(!signature_b64, -1, "Failed to calloc signature_b64\n");
    snprintf((char *) signature_b64, stop - start - 2, "%s",
             &cert->signature[start + 2]);
    if (algo == HIP_HI_DSA) {
        signature = malloc(stop - start + 1);
        HIP_IFEL(!signature, -1, "Failed to malloc signature (dsa)\n");
    }
    evpret = EVP_DecodeBlock(signature, signature_b64,
                             strlen((char *) signature_b64));

    switch (algo) {
    case HIP_HI_RSA:
        /* do the verification */
        err = RSA_verify(NID_sha1, sha_digest, SHA_DIGEST_LENGTH,
                         signature, RSA_size(rsa), rsa);
        e_code = ERR_get_error();
        ERR_load_crypto_strings();
        ERR_error_string(e_code, buf);

        /* RSA_verify returns 1 if success. */
        cert->success = err == 1 ? 0 : -1;
        HIP_IFEL((err = err == 1 ? 0 : -1), -1, "RSA_verify error\n");
        break;
    case HIP_HI_DSA:
        /* build the signature structure */
        dsa_sig = DSA_SIG_new();
        HIP_IFEL(!dsa_sig, 1, "Failed to allocate DSA_SIG\n");
        dsa_sig->r = BN_bin2bn(&signature[1], DSA_PRIV, NULL);
        dsa_sig->s = BN_bin2bn(&signature[1 + DSA_PRIV], DSA_PRIV, NULL);

        /* verify the DSA signature */
        err = DSA_do_verify(sha_digest, SHA_DIGEST_LENGTH,
                            dsa_sig, dsa) == 0 ? 1 : 0;

        /* DSA_do_verify returns 1 if success. */
        cert->success = err == 1 ? 0 : -1;
        HIP_IFEL((err = err == 1 ? 0 : -1), -1, "DSA_do_verify error\n");
        break;
    case HIP_HI_ECDSA:
        HIP_DEBUG("CALL TO UNIMPLEMENTED ECDSA CASE\n");
        HIP_OUT_ERR(-1, "Unknown algorithm for signing\n");
        break;
    default:
        HIP_OUT_ERR(-1, "Unknown algorithm\n");
    }

    hip_msg_init(msg);

    HIP_IFEL(hip_build_user_hdr(msg, HIP_MSG_CERT_SPKI_SIGN, 0), -1,
             "Failed to build user header\n");
    HIP_IFEL(hip_build_param_cert_spki_info(msg, cert), -1,
             "Failed to build cert_info\n");

out_err:
    free(signature_hash_b64);
    free(signature_hash);
    free(modulus_b64);
    free(modulus);
    free(cert);
    free(signature);
    free(e_hex);
    RSA_free(rsa);
    DSA_free(dsa);
    DSA_SIG_free(dsa_sig);

    return err;
}

/****************************************************************************
 *
 * X.509v3
 *
 ***************************************************************************/

/**
 * Function that creates the certificate and sends it to back to the client.
 *
 * @param msg is a pointer to the msg containing a x509v3 cert in cert parameter
 *
 * @return 0 on success negative otherwise.
 */
int hip_cert_x509v3_handle_request_to_sign(struct hip_common *msg)
{
    int         err = 0, i = 0, nid = 0, ret = 0, secs = 0, algo = 0;
    CONF       *conf;
    CONF_VALUE *item;
    STACK_OF(CONF_VALUE) * sec_general = NULL;
    STACK_OF(CONF_VALUE) * sec_name    = NULL;
    STACK_OF(CONF_VALUE) * sec_ext     = NULL;

    X509_REQ       *req    = NULL;
    X509_NAME      *issuer = NULL;
    X509_NAME      *subj   = NULL;
    X509_EXTENSION *ext    = NULL;
    STACK_OF(X509_EXTENSION) * extlist = NULL;
    X509_NAME_ENTRY *ent;
    EVP_PKEY        *pkey;
    /** XX TODO THIS should come from a configuration file
     *  monotonically increasing counter */
    long                            serial = 0;
    const EVP_MD                   *digest = NULL;
    X509                           *cert;
    X509V3_CTX                      ctx;
    const struct hip_cert_x509_req *subject;
    char                            subject_hit[41];
    char                            issuer_hit[41];
    char                            ialtname[45];
    char                            saltname[45];
    struct in6_addr                *issuer_hit_n;
    struct hip_host_id             *host_id;
    RSA                            *rsa          = NULL;
    DSA                            *dsa          = NULL;
    unsigned char                  *der_cert     = NULL;
    int                             der_cert_len = 0;
    char                            arg1[21];
    char                            arg2[21];

    HIP_IFEL(!(issuer_hit_n = malloc(sizeof(struct in6_addr))), -1,
             "Malloc for subject failed\n");
    HIP_IFEL(!(pkey = malloc(sizeof(EVP_PKEY))), -1,
             "Malloc for pkey failed\n");

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    HIP_DEBUG("Reading configuration file (%s)\n", HIP_CERT_CONF_PATH);
    conf        = hip_cert_open_conf();
    sec_general = hip_cert_read_conf_section("hip_x509v3", conf);
    sec_name    = hip_cert_read_conf_section("hip_x509v3_name", conf);
    sec_ext     = hip_cert_read_conf_section("hip_x509v3_extensions", conf);
    NCONF_free(conf);

    /* Get the general information */
    HIP_IFEL(sec_general == NULL, -1,
             "Failed to load general certificate information\n");
    HIP_IFEL(!(req = X509_REQ_new()), -1, "Failed to create X509_REQ object");

    HIP_IFEL(sec_name == NULL, -1,
             "Failed to load issuer naming information for the certificate\n");

    /* Issuer naming */
    if (sec_general != NULL) {
        /* Loop through the conf stack for general information */
        extlist = sk_X509_EXTENSION_new_null();
        for (i = 0; i < sk_CONF_VALUE_num(sec_general); i++) {
            item = sk_CONF_VALUE_value(sec_general, i);
            if (!strcmp(item->name, "issuerhit")) {
                strcpy(issuer_hit, item->value);
                ret = inet_pton(AF_INET6, item->value, issuer_hit_n);
                HIP_IFEL(ret < 0 && errno == EAFNOSUPPORT, -1,
                         "Failed to convert issuer HIT to hip_hit_t\n");
                HIP_DEBUG_HIT("Issuer HIT", issuer_hit_n);
                HIP_IFEL(!inet_ntop(AF_INET6, issuer_hit_n,
                                    issuer_hit, sizeof(issuer_hit)),
                         -1, "Failed to convert subject hit to "
                             "presentation format\n");
            }
            if (!strcmp(item->name, "days")) {
                secs = HIP_CERT_DAY * atoi(item->value);
            }
        }
    }
    HIP_IFEL(!(issuer = X509_NAME_new()), -1, "Failed to set create issuer name");
    nid = OBJ_txt2nid("commonName");
    HIP_IFEL(nid == NID_undef, -1, "NID text not defined\n");
    HIP_IFEL(!(ent = X509_NAME_ENTRY_create_by_NID(NULL, nid, MBSTRING_ASC,
                                                   (unsigned char *) issuer_hit, -1)), -1,
             "Failed to create name entry for issuer\n");
    HIP_IFEL(X509_NAME_add_entry(issuer, ent, -1, 0) != 1, -1,
             "Failed to add entry to issuer name\n");

    /* Subject naming */
    /* Get the subject hit from msg */
    HIP_IFEL(!(subject = hip_get_param(msg, HIP_PARAM_CERT_X509_REQ)),
             -1, "No cert_info struct found\n");
    HIP_IFEL(!inet_ntop(AF_INET6, &subject->addr, subject_hit, sizeof(subject_hit)),
             -1, "Failed to convert subject hit to presentation format\n");
    HIP_IFEL(!(subj = X509_NAME_new()), -1, "Failed to set create subject name");
    nid = OBJ_txt2nid("commonName");
    HIP_IFEL(nid == NID_undef, -1, "NID text not defined\n");
    HIP_IFEL(!(ent = X509_NAME_ENTRY_create_by_NID(NULL, nid, MBSTRING_ASC,
                                                   (unsigned char *) subject_hit, -1)), -1,
             "Failed to create name entry for subject\n");
    HIP_IFEL(X509_NAME_add_entry(subj, ent, -1, 0) != 1, -1,
             "Failed to add entry to subject name\n");
    HIP_IFEL(X509_REQ_set_subject_name(req, subj) != 1, -1,
             "Failed to add subject name to certificate request\n");

    /* XX TODO add a check to skip subjectAltName and issuerAltName because they are
     * already in use by with IP:<hit> stuff */
    if (sec_ext != NULL) {
        /* Loop through the conf stack and add extensions to ext stack */
        extlist = sk_X509_EXTENSION_new_null();
        for (i = 0; i < sk_CONF_VALUE_num(sec_ext); i++) {
            item = sk_CONF_VALUE_value(sec_ext, i);
            HIP_IFEL(!(ext = X509V3_EXT_conf(NULL, &ctx,
                                             item->name, item->value)), -1,
                     "Failed to create extension\n");
            sk_X509_EXTENSION_push(extlist, ext);
        }
        HIP_IFEL(!X509_REQ_add_extensions(req, extlist), -1,
                 "Failed to add extensions to the request\n");
    }

    /** NOW WE ARE READY TO CREATE A CERTIFICATE FROM THE REQUEST */
    HIP_DEBUG("Starting the certificate creation\n");

    HIP_IFEL(!(cert = X509_new()), -1,
             "Failed to create X509 object\n");

    HIP_IFEL(X509_set_version(cert, 2L) != 1, -1,
             "Failed to set certificate version\n");
    /** XX TODO serial should be stored after increasing it */
    ASN1_INTEGER_set(X509_get_serialNumber(cert), serial++);

    HIP_IFEL(X509_set_subject_name(cert, subj) != 1, -1,
             "Failed to set subject name of certificate\n");
    HIP_IFEL(X509_set_issuer_name(cert, issuer) != 1, -1,
             "Failed to set issuer name of certificate\n");
    HIP_IFEL(!X509_gmtime_adj(X509_get_notBefore(cert), 0), -1,
             "Error setting beginning time of the certificate");
    HIP_IFEL(!X509_gmtime_adj(X509_get_notAfter(cert), secs), -1,
             "Error setting ending time of the certificate");

    HIP_DEBUG("Getting the key\n");

    HIP_IFEL(hip_get_host_id_and_priv_key(hip_local_hostid_db, issuer_hit_n,
                                          HIP_ANY_ALGO, &host_id, (void *) &rsa),
             -1, "Private key not found\n");

    algo = host_id->rdata.algorithm;
    if (algo == HIP_HI_DSA) {
        dsa = (DSA *) rsa;
    }

    switch (algo) {
    case HIP_HI_RSA:
        HIP_IFEL(!EVP_PKEY_assign_RSA(pkey, rsa), -1,
                 "Failed to convert RSA to EVP_PKEY\n");
        HIP_IFEL(X509_set_pubkey(cert, pkey) != 1, -1,
                 "Failed to set public key of the certificate\n");
        break;
    case HIP_HI_DSA:
        HIP_IFEL(!EVP_PKEY_assign_DSA(pkey, dsa), -1,
                 "Failed to convert DSA to EVP_PKEY\n");
        HIP_IFEL(X509_set_pubkey(cert, pkey) != 1, -1,
                 "Failed to set public key of the certificate\n");
        break;
    case HIP_HI_ECDSA:
        HIP_DEBUG("CALL TO UNIMPLEMENTED ECDSA CASE\n");
        HIP_OUT_ERR(-1, "Unknown algorithm for signing\n");
        break;
    default:
        HIP_OUT_ERR(-1, "Unknown algorithm\n");
    }

    if (sec_ext != NULL) {
        for (i = 0; i < sk_CONF_VALUE_num(sec_ext); i++) {
            item = sk_CONF_VALUE_value(sec_ext, i);
            /*
             * Skip issuerAltName and subjectAltName because
             * HITs use them already. Skip also basicConstraint =
             * CA:true and subjectKeyIdentifier because they are
             * added automatically in the code below
             */
            if (!strcmp(item->name, "issuerAltname")) {
                continue;
            }
            if (!strcmp(item->name, "subjectAltname")) {
                continue;
            }
            if (0 == memcmp(subject_hit, issuer_hit, sizeof(issuer_hit))) {
                if (!strcmp(item->name, "basicConstraints") &&
                    !strcmp(item->value, "CA:true")) {
                    continue;
                }
                if (!strcmp(item->name, "subjectKeyIdentifier")) {
                    continue;
                }
            }
            HIP_IFEL(!(ext = X509V3_EXT_conf(NULL, &ctx,
                                             item->name, item->value)), -1,
                     "Failed to create extension\n");
            HIP_IFEL(!X509_add_ext(cert, ext, -1), -1,
                     "Failed to add extensions to the cert\n");
        }
    }

    if (0 == memcmp(subject_hit, issuer_hit, sizeof(issuer_hit))) {
        /* Subjects and issuers hit match so
         * we are writing a CA cert and in CA self-signed
         * certificate you have to have subject key identifier
         * present, when adding subjectKeyIdentifier give string
         * hash to the X509_EXT_conf it knows what to do with it */

        /* X509V3_EXT_conf() doesn't accept const char *, so we
         * write the arguments to a buffer first */
        sprintf(arg1, "basicConstraints");
        sprintf(arg2, "CA:true");
        HIP_IFEL(!(ext = X509V3_EXT_conf(NULL, &ctx,
                                         arg1, arg2)), -1,
                 "Failed to create extension\n");
        HIP_IFEL(!X509_add_ext(cert, ext, -1), -1,
                 "Failed to add extensions to the cert\n");

        sprintf(arg1, "subjectKeyIdentifier");
        sprintf(arg2, "hash");
        HIP_IFEL(!(ext = X509V3_EXT_conf(NULL, &ctx,
                                         arg1, arg2)), -1,
                 "Failed to create extension\n");
        HIP_IFEL(!X509_add_ext(cert, ext, -1), -1,
                 "Failed to add extensions to the cert\n");
    }

    /* add subjectAltName = IP:<HIT> */
    sprintf(arg1, "issuerAltName");
    sprintf(ialtname, "IP:%s", issuer_hit);
    HIP_IFEL(!(ext = X509V3_EXT_conf(NULL, &ctx,
                                     arg1, ialtname)), -1,
             "Failed to create extension\n");
    HIP_IFEL(!X509_add_ext(cert, ext, -1), -1,
             "Failed to add extensions to the cert\n");
    /* add subjectAltName = IP:<HIT> */
    sprintf(arg1, "subjectAltName");
    sprintf(saltname, "IP:%s", subject_hit);
    HIP_IFEL(!(ext = X509V3_EXT_conf(NULL, &ctx,
                                     arg1, saltname)), -1,
             "Failed to create extension\n");
    HIP_IFEL(!X509_add_ext(cert, ext, -1), -1,
             "Failed to add extensions to the cert\n");

    switch (algo) {
    case HIP_HI_RSA:
        digest = EVP_sha1();
        break;
    case HIP_HI_DSA:
        digest = EVP_dss1();
        break;
    case HIP_HI_ECDSA:
        HIP_DEBUG("CALL TO UNIMPLEMENTED ECDSA CASE\n");
        HIP_OUT_ERR(-1, "Unknown algorithm for signing\n");
        break;
    default:
        HIP_OUT_ERR(-1, "Unknown algorithm\n");
    }

    HIP_IFEL(!X509_sign(cert, pkey, digest), -1,
             "Failed to sign x509v3 certificate\n");

    /** DER */
    HIP_IFEL((der_cert_len = i2d_X509(cert, &der_cert)) < 0, -1,
             "Failed to convert cert to DER\n");
    /** end DER */

    hip_msg_init(msg);

    HIP_IFEL(hip_build_user_hdr(msg, HIP_MSG_CERT_X509V3_SIGN, 0), -1,
             "Failed to build user header\n");
    HIP_IFEL(hip_build_param_cert_x509_resp(msg, (char *) der_cert, der_cert_len), -1,
             "Failed to create x509 response parameter\n");

out_err:
    free(host_id);
    X509_REQ_free(req);
    sk_X509_EXTENSION_pop_free(extlist, X509_EXTENSION_free);
    return err;
}

static int verify_callback(int ok, DBG X509_STORE_CTX *stor)
{
    /* This is not called from anywhere else than this file */
    if (!ok) {
        HIP_DEBUG("Error: %s\n", X509_verify_cert_error_string(stor->error));
    }
    return ok;
}

/**
 * Function verifies the given certificate and sends it to back to the client.
 *
 * @param msg is a pointer to the requesting msg that contains a cert parameter with x509v3 cert
 *
 * @return 0 on success negative otherwise.
 */
int hip_cert_x509v3_handle_request_to_verify(struct hip_common *msg)
{
    int                              err = 0;
    struct hip_cert_x509_resp        verify;
    const struct hip_cert_x509_resp *p;
    X509                            *cert       = NULL;
    X509_STORE                      *store      = NULL;
    X509_STORE_CTX                  *verify_ctx = NULL;
    unsigned char                   *der_cert   = NULL;
    const unsigned char             *vessel;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    HIP_IFEL(!(p = hip_get_param(msg, HIP_PARAM_CERT_X509_REQ)), -1,
             "Failed to get cert info from the msg\n");
    memcpy(&verify, p, sizeof(struct hip_cert_x509_resp));

    der_cert = (unsigned char *) &p->der;

    vessel = p->der;
    HIP_IFEL((cert = d2i_X509(NULL, &vessel, verify.der_len)) == NULL, -1,
             "Failed to convert cert from DER to internal format\n");
    /*
     * HIP_IFEL(!X509_print_fp(stdout, cert), -1,
     *       "Failed to print x.509v3 in human readable format\n");
     */

    HIP_IFEL(!(store = X509_STORE_new()), -1,
             "Failed to create X509_STORE_CTX object\n");
    X509_STORE_set_verify_cb_func(store, verify_callback);

    /* self signed so te cert itself should verify itself */

    HIP_IFEL(!X509_STORE_add_cert(store, cert), -1,
             "Failed to add cert to ctx\n");

    HIP_IFEL(!(verify_ctx = X509_STORE_CTX_new()), -1,
             "Failed to create X509_STORE_CTX object\n");

    HIP_IFEL(X509_STORE_CTX_init(verify_ctx, store, cert, NULL) != 1, -1,
             "Failed to initialize verification context\n");

    if (X509_verify_cert(verify_ctx) != 1) {
        HIP_DEBUG("Error verifying the certificate\n");
        err = -1;
    } else {
        HIP_DEBUG("Certificate verified correctly!\n");
        err = 0;
    }

    hip_msg_init(msg);
    HIP_IFEL(hip_build_user_hdr(msg, HIP_MSG_CERT_X509V3_VERIFY, err), -1,
             "Failed to build user header\n");
    HIP_IFEL(hip_build_param_cert_x509_resp(msg, (char *) &der_cert, p->der_len), -1,
             "Failed to create x509 response parameter\n");

out_err:
    X509_STORE_CTX_cleanup(verify_ctx);
    X509_STORE_free(store);
    X509_free(cert);
    return err;
}
