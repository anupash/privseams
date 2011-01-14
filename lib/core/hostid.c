/*
 * Copyright (c) 2010 Aalto University and RWTH Aachen University.
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
 * @brief Host identifier manipulation functions
 *
 * @author Miika Komu <miika@iki.fi>
 */

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/bn.h>
#include <openssl/dsa.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#include "config.h"
#include "lib/tool/pk.h"
#include "builder.h"
#include "crypto.h"
#include "debug.h"
#include "filemanip.h"
#include "ife.h"
#include "prefix.h"
#include "protodefs.h"
#include "hostid.h"

/* ACTION_ADD, ACTION_NEW are used by hip_serialize_host_id_action() */
#include "conf.h"

#define HOST_ID_FILENAME_MAX_LEN 256

/**
 * calculate a HIT from a HI without the prefix
 *
 * @param orig a pointer to a host identity
 * @param orig_len the length of the host identity in bits
 * @param encoded an output argument where the HIT will be stored
 * @param encoded_len the length of the encoded HIT in bits
 * @return zero on success or negative on error
 */
static int khi_encode(unsigned char *orig, int orig_len,
                      unsigned char *encoded,
                      int encoded_len)
{
    BIGNUM *bn  = NULL;
    int     err = 0, shift = (orig_len - encoded_len) / 2,
            len = encoded_len / 8 + ((encoded_len % 8) ? 1 : 0);

    HIP_IFEL(encoded_len > orig_len, -1, "len mismatch\n");
    HIP_IFEL(!(bn = BN_bin2bn(orig, orig_len / 8, NULL)), -1,
             "BN_bin2bn\n");
    HIP_IFEL(!BN_rshift(bn, bn, shift), -1, "BN_lshift\n");
    HIP_IFEL(!BN_mask_bits(bn, encoded_len), -1,
             "BN_mask_bits\n");
    HIP_IFEL(bn2bin_safe(bn, encoded, len) != len, -1,
             "BN_bn2bin_safe\n");

out_err:
    BN_free(bn);
    return err;
}

/**
 * Calculates a Host Identity Tag (HIT) from a Host Identifier (HI) using DSA
 * encryption.
 *
 * @param  host_id  a pointer to a Host Identifier
 * @param  hit      a target buffer where to put the calculated HIT.
 * @param  hit_type type of the HIT (must be HIP_HIT_TYPE_HASH100).
 * @return          zero on success, negative otherwise.
 */
int hip_dsa_host_id_to_hit(const struct hip_host_id *const host_id,
                           struct in6_addr *const hit, const int hit_type)
{
    int            err = 0;
    uint8_t        digest[HIP_AH_SHA_LEN];
    const uint8_t *key_rr = (const uint8_t *) host_id->key;

    /* hit excludes rdata but it is included in hi_length;
     * subtract rdata */
    unsigned int key_rr_len = ntohs(host_id->hi_length) -
                              sizeof(struct hip_host_id_key_rdata);
    uint8_t *khi_data         = NULL;
    uint8_t  khi_context_id[] = HIP_KHI_CONTEXT_ID_INIT;
    int      khi_data_len     = key_rr_len + sizeof(khi_context_id);
    int      khi_index        = 0;

    HIP_IFE(hit_type != HIP_HIT_TYPE_HASH100, -ENOSYS);

    /* Hash Input :=  Context ID | Input */
    khi_data  = malloc(khi_data_len);
    khi_index = 0;
    memcpy(khi_data + khi_index, khi_context_id, sizeof(khi_context_id));
    khi_index += sizeof(khi_context_id);
    memcpy(khi_data + khi_index, key_rr, key_rr_len);
    khi_index += key_rr_len;

    HIP_ASSERT(khi_index == khi_data_len);

    /* Hash :=  SHA1( Expand( Hash Input ) ) */
    HIP_IFEL((err = hip_build_digest(HIP_DIGEST_SHA1, khi_data,
                                     khi_data_len, digest)), err,
             "Building of digest failed\n");

    memset(hit, 0, sizeof(hip_hit_t));
    HIP_IFEL(khi_encode(digest, sizeof(digest) * 8,
                        ((uint8_t *) hit) + 3,
                        sizeof(hip_hit_t) * 8 - HIP_HIT_PREFIX_LEN),
             -1, "encoding failed\n");

    set_hit_prefix(hit);

out_err:
    free(khi_data);
    return err;
}

/**
 * convert DSA or RSA-based host id to a HIT
 *
 * @param host_id a host id
 * @param hit output argument, the calculated HIT will stored here
 * @param hit_type the type of the HIT
 * @return zero on success or negative on error
 *
 * @note see hip_dsa_host_id_to_hit for valid HIT types
 */
int hip_host_id_to_hit(const struct hip_host_id *const host_id,
                       struct in6_addr *const hit,
                       const int hit_type)
{
    int algo = hip_get_host_id_algo(host_id);
    int err  = 0;

    if (algo == HIP_HI_DSA) {
        err = hip_dsa_host_id_to_hit(host_id, hit, hit_type);
    } else if (algo == HIP_HI_RSA) {
        err = hip_rsa_host_id_to_hit(host_id, hit, hit_type);
    } else if (algo == HIP_HI_ECDSA) {
        err = hip_ecdsa_host_id_to_hit(host_id, hit, hit_type);
    } else {
        err = -ENOSYS;
    }

    return err;
}

/**
 * convert DSA-based private host id to a HIT
 *
 * @param host_id a host id
 * @param hit output argument, the calculated HIT will be stored here
 * @param hit_type the type of the HIT
 * @return zero on success or negative on error
 *
 * @note see hip_dsa_host_id_to_hit for valid HIT types
 */
int hip_private_dsa_host_id_to_hit(const struct hip_host_id_priv *const host_id,
                                   struct in6_addr *const hit,
                                   const int hit_type)
{
    uint16_t           temp;
    int                contents_len;
    int                err = 0;
    struct hip_host_id host_id_pub;

    contents_len = ntohs(host_id->hi_length);

    /** @todo add an extra check for the T val */

    HIP_IFEL(contents_len <= 20, -EMSGSIZE, "Host id too short\n");

    memset(&host_id_pub, 0, sizeof(struct hip_host_id));
    memcpy(&host_id_pub.rdata, &host_id->rdata, contents_len - DSA_PRIV);

    temp                  = ntohs(host_id->hi_length) - DSA_PRIV;
    host_id_pub.hi_length = htons(temp);
    hip_set_param_contents_len((struct hip_tlv_common *) &host_id_pub,
                               contents_len - DSA_PRIV);

    if ((err = hip_dsa_host_id_to_hit(&host_id_pub, hit, hit_type))) {
        HIP_ERROR("Failed to convert HI to HIT.\n");
        goto out_err;
    }

out_err:

    return err;
}

/**
 * convert RSA-based private host id to a HIT
 *
 * @param host_id a host id
 * @param hit output argument, the calculated HIT will be stored here
 * @param hit_type the type of the HIT
 * @return zero on success or negative on error
 *
 * @note see hip_dsa_host_id_to_hit for valid HIT types
 */
int hip_private_rsa_host_id_to_hit(const struct hip_host_id_priv *const host_id,
                                   struct in6_addr *const hit,
                                   const int hit_type)
{
    int                   err = 0;
    int                   rsa_pub_len, rsa_priv_len;
    uint16_t              temp;
    struct hip_host_id    host_id_pub;
    struct hip_rsa_keylen keylen;

    /* Length of the private part of the RSA key d + p + q
     * is twice the length of the public modulus.
     * dmp1 + dmq1 + iqmp is another 1.5 times */

    hip_get_rsa_keylen(host_id, &keylen, 1);
    rsa_pub_len  = keylen.e_len + keylen.e + keylen.n;
    rsa_priv_len = keylen.n * 7 / 2;

    memcpy(&host_id_pub, host_id, sizeof(host_id_pub)
           - sizeof(host_id_pub.key) - sizeof(host_id_pub.hostname));


    temp                  = ntohs(host_id_pub.hi_length) - rsa_priv_len;
    host_id_pub.hi_length = htons(temp);
    memcpy(host_id_pub.key, host_id->key, rsa_pub_len);

    if ((err = hip_rsa_host_id_to_hit(&host_id_pub, hit, hit_type))) {
        HIP_ERROR("Failed to convert HI to HIT.\n");
        goto out_err;
    }

out_err:

    return err;
}

/**
 * convert ECDSA-based private host id to a HIT
 *
 * @param host_id a host id
 * @param hit output argument, the calculated HIT will be stored here
 * @param hit_type the type of the HIT
 * @return zero on success or negative on error
 *
 * @note see hip_dsa_host_id_to_hit for valid HIT types
 */
int hip_private_ecdsa_host_id_to_hit(const struct hip_host_id_priv *host_id,
                                     struct in6_addr *const hit,
                                     int hit_type)
{
    int err = 0;
    struct hip_ecdsa_keylen key_lens;
    struct hip_host_id host_id_pub;

    HIP_IFEL(hip_get_ecdsa_keylen(host_id, &key_lens),
             -1, "Failed computing key sizes.\n");

    memcpy(&host_id_pub, host_id,
           sizeof(host_id_pub) - sizeof(host_id_pub.key) - sizeof(host_id_pub.hostname));
    /* copy the key rr
     * the size of the key rr has the size of the public key + 2 bytes for the curve identifier (see RFC5201-bis 5.2.8.)*/
    memcpy(host_id_pub.key, host_id->key, key_lens.Y_len + HIP_CURVE_ID_LENGTH);
    /* set the hi length
     * the hi length is the length of the key rr data + the key rr header */
    host_id_pub.hi_length = htons(key_lens.Y_len + HIP_CURVE_ID_LENGTH + sizeof(struct hip_host_id_key_rdata));

    hip_set_param_contents_len((struct hip_tlv_common *) &host_id_pub, sizeof(struct hip_host_id)-sizeof(struct hip_tlv_common));

    HIP_IFEL(hip_rsa_host_id_to_hit(&host_id_pub, hit, hit_type),
             -1, "Failed to convert HI to HIT.\n");

out_err:
    return err;
}

/**
 * convert RSA or DSA-based private host id to a HIT
 *
 * @param host_id a host id
 * @param hit output argument, the calculated HIT will be stored here
 * @param hit_type the type of the HIT
 * @return zero on success or negative on error
 *
 * @note see hip_dsa_host_id_to_hit for valid HIT types
 */
int hip_private_host_id_to_hit(const struct hip_host_id_priv *const host_id,
                               struct in6_addr *const hit,
                               const int hit_type)
{
    int algo = hip_get_host_id_algo((const struct hip_host_id *) host_id);
    int err  = 0;

    if (algo == HIP_HI_DSA) {
        err = hip_private_dsa_host_id_to_hit(host_id, hit,
                                             hit_type);
    } else if (algo == HIP_HI_RSA) {
        err = hip_private_rsa_host_id_to_hit(host_id, hit,
                                             hit_type);
    } else if (algo == HIP_HI_ECDSA) {
        err = hip_private_ecdsa_host_id_to_hit(host_id, hit,
                                               hit_type);
    } else {
        err = -ENOSYS;
    }

    return err;
}

/*
 * Translate the openssl specific curve id into the coressponding HIP id.
 *
 * @param nid the openssl specific ID of the curve
 *
 * @return the HIP ID of the curve (according to RFC5201-bis) or HIP_UNSUPPORTED_CURVE on error
 *
 */
static enum hip_cuve_id get_ecdsa_curve_hip_name(const int nid)
{
    /* Determine the curve */
    switch (nid) {
    case NID_secp160r1:
        return NIST_ECDSA_160;
    case NID_X9_62_prime256v1:
        return NIST_ECDSA_256;
    case NID_secp384r1:
        return NIST_ECDSA_384;
    default:
        HIP_DEBUG("Curve not supported.\n");
        return UNSUPPORTED_CURVE;
    }
}

/*
 * Get the curve nid from the ECC curve field in the host_id parameter.
 * It is contained in the first two bytes of the ecdsa keyrr data.
 *
 * @param host_id a pointer to the ecdsa based host id from which to get the curve id information
 *
 * @return the openssl specific curve id used with this host identity or -1 on error.
 */
static int get_ecdsa_curve_nid(const struct hip_host_id *const host_id)
{
    int err = 0;
    enum hip_cuve_id curve_id;
    int nid;

    /* Determine the curve
     * The first two bytes contain the hip curve identifier
     * as defined in RFC5201-bis */
    curve_id = ntohs(*(const uint16_t*)host_id->key);
    HIP_DEBUG("Got curve id %d \n", curve_id);
    switch (curve_id) {
    case NIST_ECDSA_160:
        HIP_DEBUG("Using curve secp160r1\n");
        nid = NID_secp160r1;
        break;
    case NIST_ECDSA_256:
        HIP_DEBUG("Using curve secp256r1/prime256v1 \n");
        nid = NID_X9_62_prime256v1;
        break;
    case NIST_ECDSA_384:
        HIP_DEBUG("Using curve secp384r1 \n");
        nid = NID_secp384r1;
        break;
    case brainpoolP160r1:
        HIP_DEBUG("Curve brainpoolP160r1 is not supported, use NIST_ECDSA_160 instead.\n");
    default:
        HIP_DEBUG("Curve not supported.\n");
        err = -1;
        goto out_err;
    }

out_err:
    if (err)
        return -1;
    return nid;
}

/**
 * Get ECDSA key length from an host id.
 * The keylength is determined by the elliptic curve that is being used.
 *
 * @param host_id the host id
 * @param ret the ECDSA key component lengths will be stored here
 *
 * @return 0 on success, non-0 otherwise
 */
int hip_get_ecdsa_keylen(const struct hip_host_id_priv *const host_id,
                         struct hip_ecdsa_keylen *ret)
{
    int err = 0;
    int nid;
    int curve_size;

    nid = get_ecdsa_curve_nid((const struct hip_host_id *) host_id);
    switch (nid) {
    case NID_secp160r1:
        curve_size = 160;
        break;
    case NID_X9_62_prime256v1:
        curve_size = 256;
        break;
    case NID_secp384r1:
        curve_size = 384;
        break;
    default:
        HIP_DEBUG("Curve not supported.\n");
        err = -1;
        goto out_err;
    }

    /* Size is always
     *    (curve_size+7)/8 for private key
     *    2*((curve_size+7)/8)+1 for public key
     *
     *    Attention to integer division: 2*(x)/8 != 2*((x)/8) != x/4
     *
     *    NOTE:
     *      An ECDSA public key is a point on a specific curve.
     *      Points have two coordinates (scalar values) which come
     *      from the field over which the curve is built.
     *      Thus the size of the public key is twice the size of the curve.
     *      (Actually, there is one additional openssl-specific magic byte)
     */
    ret->z_len = (curve_size + 7) / 8;
    ret->Y_len = ret->z_len * 2 + 1;

out_err:
    return err;
}

/**
 * dig out RSA key length from an host id
 *
 * @param host_id the host id
 * @param ret the RSA key component lengths will be stored here
 * @param is_priv one if the host_id contains also the private key
 *                component or zero otherwise
 */
void hip_get_rsa_keylen(const struct hip_host_id_priv *const host_id,
                        struct hip_rsa_keylen *const ret,
                        const int is_priv)
{
    int            bytes;
    const uint8_t *tmp    = (const uint8_t *) host_id->key;
    int            offset = 0;
    int            e_len  = tmp[offset++];

    /* Check for public exponent longer than 255 bytes (see RFC 3110) */
    if (e_len == 0) {
        e_len   = ntohs((uint16_t) tmp[offset]);
        offset += 2;
    }

    /*
     * hi_length is the total length of:
     * rdata struct (4 bytes), length of e (1 byte for e < 255 bytes, 3 bytes otherwise),
     * e (normally 3 bytes), followed by public n, private d, p, q, dmp1, dmq1, iqmp
     * n_len == d_len == 2 * p_len == 2 * q_len == dmp1_len == dmq1_len == iqmp_len
     * for 9/2 * n_len
     */
    if (is_priv) {
        bytes = (ntohs(host_id->hi_length) - sizeof(struct hip_host_id_key_rdata) -
                 offset - e_len) * 2 / 9;
    } else {
        bytes = (ntohs(host_id->hi_length) - sizeof(struct hip_host_id_key_rdata) -
                 offset - e_len);
    }

    ret->e_len = offset;
    ret->e     = e_len;
    ret->n     = bytes;
}

/**
 * convert a RSA-based host id into an OpenSSL structure
 *
 * @param host_id the host id
 * @param is_priv one if the host_id contains also the private key
 *                component or zero otherwise
 * @return The OpenSSL formatted RSA key corresponding to @c host_id.
 *         Caller is responsible of freeing.
 */
RSA *hip_key_rr_to_rsa(const struct hip_host_id_priv *const host_id, const int is_priv)
{
    int                   offset;
    struct hip_rsa_keylen keylen;
    RSA                  *rsa = NULL;

    hip_get_rsa_keylen(host_id, &keylen, is_priv);

    rsa = RSA_new();
    if (!rsa) {
        HIP_ERROR("Failed to allocate RSA\n");
        return NULL;
    }

    offset  = keylen.e_len;
    rsa->e  = BN_bin2bn(&host_id->key[offset], keylen.e, 0);
    offset += keylen.e;
    rsa->n  = BN_bin2bn(&host_id->key[offset], keylen.n, 0);

    if (is_priv) {
        offset   += keylen.n;
        rsa->d    = BN_bin2bn(&host_id->key[offset], keylen.n, 0);
        offset   += keylen.n;
        rsa->p    = BN_bin2bn(&host_id->key[offset], keylen.n / 2, 0);
        offset   += keylen.n / 2;
        rsa->q    = BN_bin2bn(&host_id->key[offset], keylen.n / 2, 0);
        offset   += keylen.n / 2;
        rsa->dmp1 = BN_bin2bn(&host_id->key[offset], keylen.n / 2, 0);
        offset   += keylen.n / 2;
        rsa->dmq1 = BN_bin2bn(&host_id->key[offset], keylen.n / 2, 0);
        offset   += keylen.n / 2;
        rsa->iqmp = BN_bin2bn(&host_id->key[offset], keylen.n / 2, 0);
    }

    return rsa;
}

/**
 * convert a DSA-based host id into an OpenSSL structure
 *
 * @param host_id the host id
 * @param is_priv one if the host_id contains also the private key
 *                component or zero otherwise
 * @return The OpenSSL formatted DSA key corresponding to @c host_id.
 *         Caller is responsible of freeing.
 */
DSA *hip_key_rr_to_dsa(const struct hip_host_id_priv *const host_id, const int is_priv)
{
    int     offset  = 0;
    DSA    *dsa     = NULL;
    uint8_t t       = host_id->key[offset++];
    int     key_len = 64 + (t * 8);

    dsa = DSA_new();
    if (!dsa) {
        HIP_ERROR("Failed to allocate DSA\n");
        return NULL;
    }

    dsa->q       = BN_bin2bn(&host_id->key[offset], DSA_PRIV, 0);
    offset      += DSA_PRIV;
    dsa->p       = BN_bin2bn(&host_id->key[offset], key_len, 0);
    offset      += key_len;
    dsa->g       = BN_bin2bn(&host_id->key[offset], key_len, 0);
    offset      += key_len;
    dsa->pub_key = BN_bin2bn(&host_id->key[offset], key_len, 0);

    if (is_priv) {
        offset       += key_len;
        dsa->priv_key = BN_bin2bn(&host_id->key[offset], DSA_PRIV, 0);

        /* Precompute values for faster signing */
        DSA_sign_setup(dsa, NULL, &dsa->kinv, &dsa->r);
    }

    return dsa;
}

/**
 * convert a ECDSA-based host id into an OpenSSL structure
 *
 * @param host_id the host id
 * @param is_priv one if the host_id contains also the private key
 *                component or zero otherwise
 * @return The OpenSSL formatted ECDSA key corresponding to @c host_id.
 *         Caller is responsible of freeing.
 */
EC_KEY *hip_key_rr_to_ecdsa(const struct hip_host_id_priv *const host_id, const int is_priv)
{
    int err             = 0;
    int nid             = 0;
    EC_POINT *pub_key   = NULL;
    EC_GROUP *group     = NULL;
    BIGNUM *priv_key    = NULL;
    struct hip_ecdsa_keylen key_lens;
    EC_KEY *ret;

    nid = get_ecdsa_curve_nid((const struct hip_host_id *) host_id);
    HIP_IFEL(hip_get_ecdsa_keylen(host_id, &key_lens),
             -1, "Failed computing key sizes.\n");

    /* Build public key structure from key rr */
    HIP_IFEL(!(ret = EC_KEY_new()),
             -1, "Failed to init new key. \n");

    HIP_IFEL(!(group = EC_GROUP_new_by_curve_name(nid)),
             -1, "Failed building the group.\n");

    EC_GROUP_set_asn1_flag(group, OPENSSL_EC_NAMED_CURVE);

    HIP_IFEL(!(pub_key = EC_POINT_new(group)),
             -1, "Failed to init public key (point).\n");

    HIP_IFEL(!EC_KEY_set_group(ret, group),
             -1, "Failed setting the group for key.\n");

    HIP_IFEL(!EC_POINT_oct2point(group, pub_key, host_id->key + HIP_CURVE_ID_LENGTH, key_lens.Y_len, NULL),
             -1, "Failed deserializing public key.\n");

    HIP_IFEL(!EC_KEY_set_public_key(ret, pub_key),
            -1, "Failed setting public key.\n");

    /* Build private key from key rr */
    if (is_priv) {
        HIP_IFEL(!(priv_key = BN_bin2bn(host_id->key + HIP_CURVE_ID_LENGTH + key_lens.Y_len, key_lens.z_len, priv_key)),
                 -1, "Failed deserializing private key.\n");
        HIP_IFEL(!EC_KEY_set_private_key(ret, priv_key),
                 -1, "Failed setting private key.\n");
    }

    /* Check the result before returning it */
    HIP_IFEL(!EC_KEY_check_key(ret),
             -1, "Key check failed. \n");

out_err:
    if (err)
        return NULL;
    return ret;
}

/**
 * (Re)create new host identities or load existing ones, and append the
 * private identities into a message. This functionality is used by hipd
 * but can also be invoked with hipconf.
 *
 * @param msg an output argument where the identities will be appended
 * @param action Currently ACTION_ADD and ACTION_NEW are supported. Warning,
 *               ACTION_NEW will override the existing identities on disk!
 * @param anon set to one when you want to process only anonymous (short-term)
 *             identities or zero otherwise
 * @param use_default One when dealing with default identities in HIPL_SYSCONFDIR.
 *                    Zero when user supplies own identities denoted by
 *                    @c hi_file argument.
 * @param hi_fmt "dsa", "rsa" or "ecdsa" are currently supported
 * @param hi_file an optional location for user-supplied host identities.
 *                Argument @c use_default must be zero when used.
 * @param rsa_key_bits size for RSA keys in bits
 * @param dsa_key_bits size of DSA keys in bits
 * @param ecdsa_nid openssl specific curve id
 *
 * @return zero on success and negative on error
 */

int hip_serialize_host_id_action(struct hip_common *const msg,
                                 const int action,
                                 const int anon,
                                 const int use_default,
                                 const char *hi_fmt,
                                 const char *hi_file,
                                 const int rsa_key_bits,
                                 const int dsa_key_bits,
                                 const int ecdsa_nid)
{
    int                  err                = 0, dsa_key_rr_len = 0, rsa_key_rr_len = 0, ecdsa_key_rr_len = 0;
    int                  dsa_pub_key_rr_len = 0, rsa_pub_key_rr_len = 0, ecdsa_pub_key_rr_len = 0;;
    hip_hdr              numeric_action     = 0;
    char                 hostname[HIP_HOST_ID_HOSTNAME_LEN_MAX];
    const char          *rsa_filenamebase       = DEFAULT_HOST_RSA_KEY_FILE_BASE DEFAULT_ANON_HI_FILE_NAME_SUFFIX;
    const char          *dsa_filenamebase       = DEFAULT_HOST_DSA_KEY_FILE_BASE DEFAULT_ANON_HI_FILE_NAME_SUFFIX;
    const char          *ecdsa_filenamebase     = DEFAULT_HOST_ECDSA_KEY_FILE_BASE DEFAULT_ANON_HI_FILE_NAME_SUFFIX;
    const char          *rsa_filenamebase_pub   = DEFAULT_HOST_RSA_KEY_FILE_BASE DEFAULT_PUB_HI_FILE_NAME_SUFFIX;
    const char          *dsa_filenamebase_pub   = DEFAULT_HOST_DSA_KEY_FILE_BASE DEFAULT_PUB_HI_FILE_NAME_SUFFIX;
    const char          *ecdsa_filenamebase_pub = DEFAULT_HOST_ECDSA_KEY_FILE_BASE DEFAULT_PUB_HI_FILE_NAME_SUFFIX;;
    unsigned char       *dsa_key_rr             = NULL, *rsa_key_rr = NULL, *ecdsa_key_rr = NULL;
    unsigned char       *dsa_pub_key_rr         = NULL, *rsa_pub_key_rr = NULL, *ecdsa_pub_key_rr = NULL;
    DSA                 *dsa_key                = NULL, *dsa_pub_key = NULL;
    RSA                 *rsa_key                = NULL, *rsa_pub_key = NULL;
    EC_KEY              *ecdsa_key              = NULL, *ecdsa_pub_key = NULL;
    struct hip_lhi       rsa_lhi, dsa_lhi, ecdsa_lhi, rsa_pub_lhi, dsa_pub_lhi, ecdsa_pub_lhi;
    struct hip_host_id  *dsa_host_id            = NULL, *rsa_host_id = NULL, *ecdsa_host_id = NULL;
    struct hip_host_id  *dsa_pub_host_id        = NULL, *rsa_pub_host_id = NULL, *ecdsa_pub_host_id = NULL;
    struct endpoint_hip *endpoint_dsa_hip       = NULL;
    struct endpoint_hip *endpoint_dsa_pub_hip   = NULL;
    struct endpoint_hip *endpoint_rsa_hip       = NULL;
    struct endpoint_hip *endpoint_rsa_pub_hip   = NULL;
    struct endpoint_hip *endpoint_ecdsa_hip     = NULL;
    struct endpoint_hip *endpoint_ecdsa_pub_hip = NULL;

    if (action == ACTION_ADD) {
        numeric_action = HIP_MSG_ADD_LOCAL_HI;
    }

    if ((err = hip_build_user_hdr(msg, numeric_action, 0))) {
        HIP_ERROR("build hdr error %d\n", err);
        goto out_err;
    }

    memset(hostname, '\0', HIP_HOST_ID_HOSTNAME_LEN_MAX);

    if ((err = -gethostname(hostname, HIP_HOST_ID_HOSTNAME_LEN_MAX - 1))) {
        HIP_ERROR("Failed to get hostname. Err is (%d).\n", err);
        goto out_err;
    }

    HIP_INFO("Using hostname: %s\n", hostname);

    HIP_IFEL(!use_default && strcmp(hi_fmt, "rsa") && strcmp(hi_fmt, "dsa"),
             -ENOSYS, "Only RSA, DSA and EC keys are supported\n");

    HIP_DEBUG("Using format %s and file %s \n", hi_fmt, hi_file);

    switch (action) {
    case ACTION_NEW:
        /* Default directory is created only in "hipconf new default hi" */
        if (use_default) {
            if ((err = check_and_create_dir(HIPL_SYSCONFDIR,
                                            HIP_DIR_MODE))) {
                HIP_ERROR("Could not create default directory.\n");
                goto out_err;
            }
        } else if (!use_default) {
            if (!strcmp(hi_fmt, "dsa")) {
                dsa_key = create_dsa_key(dsa_key_bits);
                HIP_IFEL(!dsa_key, -EINVAL,
                         "Creation of DSA key failed.\n");
                if ((err = save_dsa_private_key(dsa_filenamebase, dsa_key))) {
                    HIP_ERROR("Saving of DSA key failed.\n");
                    goto out_err;
                }
            } else if(!strcmp(hi_fmt, "ecdsa")) {
                ecdsa_key = create_ecdsa_key(ecdsa_nid);
                HIP_IFEL(!ecdsa_key, -EINVAL,
                         "Creation of ECDSA key failed.\n");
                if ((err = save_ecdsa_private_key(ecdsa_filenamebase, ecdsa_key))) {
                    HIP_ERROR("Saving of ECDSA key failed.\n");
                    goto out_err;
                }
            } else {             /*RSA*/
                rsa_key = create_rsa_key(rsa_key_bits);
                HIP_IFEL(!rsa_key, -EINVAL,
                         "Creation of RSA key failed.\n");
                if ((err = save_rsa_private_key(rsa_filenamebase, rsa_key))) {
                    HIP_ERROR("Saving of RSA key failed.\n");
                    goto out_err;
                }
            }
            HIP_DEBUG("Key saved.\n");
            break;
        }

        /* Using default */
        dsa_key = create_dsa_key(dsa_key_bits);
        HIP_IFEL(!dsa_key, -EINVAL,
                 "Creation of DSA key failed.\n");

        dsa_pub_key = create_dsa_key(dsa_key_bits);
        HIP_IFEL(!dsa_pub_key, -EINVAL,
                 "Creation of public DSA key failed.\n");

        rsa_key = create_rsa_key(rsa_key_bits);
        HIP_IFEL(!rsa_key, -EINVAL,
                 "Creation of RSA key failed.\n");

        rsa_pub_key = create_rsa_key(rsa_key_bits);
        HIP_IFEL(!rsa_pub_key, -EINVAL,
                 "Creation of public RSA key failed.\n");

        ecdsa_key = create_ecdsa_key(ecdsa_nid);
        HIP_IFEL(!ecdsa_key, -EINVAL,
                 "Creation of ECDSA key failed.\n");

        ecdsa_pub_key = create_ecdsa_key(ecdsa_nid);
        HIP_IFEL(!ecdsa_pub_key, -EINVAL,
                 "Creation of public ECDSA key failed.\n");

        if ((err = save_dsa_private_key(dsa_filenamebase, dsa_key))) {
            HIP_ERROR("Saving of DSA key failed.\n");
            goto out_err;
        }

        if ((err = save_dsa_private_key(dsa_filenamebase_pub, dsa_pub_key))) {
            HIP_ERROR("Saving of public DSA key failed.\n");
            goto out_err;
        }

        if ((err = save_rsa_private_key(rsa_filenamebase, rsa_key))) {
            HIP_ERROR("Saving of RSA key failed.\n");
            goto out_err;
        }

        if ((err = save_rsa_private_key(rsa_filenamebase_pub, rsa_pub_key))) {
            HIP_ERROR("Saving of public RSA key failed.\n");
            goto out_err;
        }

        if ((err = save_ecdsa_private_key(ecdsa_filenamebase, ecdsa_key))) {
            HIP_ERROR("Saving of ECDSA key failed.\n");
            goto out_err;
        }

        if ((err = save_ecdsa_private_key(ecdsa_filenamebase_pub, ecdsa_pub_key))) {
            HIP_ERROR("Saving of public ECDSA key failed.\n");
            goto out_err;
        }

        break;

    case ACTION_ADD:
        if (!use_default) {
            if (!strcmp(hi_fmt, "dsa")) {
                if ((err = load_dsa_private_key(hi_file, &dsa_key))) {
                    HIP_ERROR("Failed to load DSA key from file %s\n", hi_file);
                    goto out_err;
                }
                dsa_key_rr_len = dsa_to_dns_key_rr(dsa_key, &dsa_key_rr);
                HIP_IFEL(dsa_key_rr_len <= 0, -EFAULT, "dsa_key_rr_len <= 0\n");

                if ((err = dsa_to_hip_endpoint(dsa_key, &endpoint_dsa_hip,
                                               anon ? HIP_ENDPOINT_FLAG_ANON : 0, hostname))) {
                    HIP_ERROR("Failed to allocate and build DSA endpoint.\n");
                    goto out_err;
                }
                if ((err = hip_build_param_eid_endpoint(msg, endpoint_dsa_hip))) {
                    HIP_ERROR("Building of host id failed\n");
                    goto out_err;
                }
            } else if (!strcmp(hi_fmt, "ecdsa")) {
                if ((err = load_ecdsa_private_key(ecdsa_filenamebase, &ecdsa_key))) {
                    HIP_ERROR("Loading of the ECDSA key failed\n");
                    goto out_err;
                }
                ecdsa_key_rr_len = ecdsa_to_key_rr(ecdsa_key, &ecdsa_key_rr);
                HIP_IFEL(ecdsa_key_rr_len <= 0, -EFAULT, "ecdsa_key_rr_len <= 0\n");
                if ((err = ecdsa_to_hip_endpoint(ecdsa_key, &endpoint_ecdsa_hip,
                                                 anon ? HIP_ENDPOINT_FLAG_ANON : 0, hostname))) {
                    HIP_ERROR("Failed to allocate and build ECDSA endpoint.\n");
                    goto out_err;
                }
                if ((err = hip_build_param_eid_endpoint(msg, endpoint_ecdsa_hip))) {
                    HIP_ERROR("Building of host id failed\n");
                    goto out_err;
                }
                HIP_DEBUG("done loading, key rring and endointing\n");
            } else { /*RSA*/
                if ((err = load_rsa_private_key(hi_file, &rsa_key))) {
                    HIP_ERROR("Failed to load RSA key from file %s\n", hi_file);
                    goto out_err;
                }
                rsa_key_rr_len = rsa_to_dns_key_rr(rsa_key, &rsa_key_rr);
                HIP_IFEL(rsa_key_rr_len <= 0, -EFAULT, "rsa_key_rr_len <= 0\n");

                if ((err = rsa_to_hip_endpoint(rsa_key, &endpoint_rsa_hip,
                                               anon ? HIP_ENDPOINT_FLAG_ANON : 0, hostname))) {
                    HIP_ERROR("Failed to allocate and build RSA endpoint.\n");
                    goto out_err;
                }
                if ((err = hip_build_param_eid_endpoint(msg, endpoint_rsa_hip))) {
                    HIP_ERROR("Building of host id failed\n");
                    goto out_err;
                }
            }
            goto skip_host_id;
        }

        /* using default */

        HIP_IFEL(hi_fmt == NULL, -1, "Key type is null.\n");

        if (!strcmp(hi_fmt, "dsa")) {
            if (anon) {
                if ((err = load_dsa_private_key(dsa_filenamebase, &dsa_key))) {
                    HIP_ERROR("Loading of the DSA key failed\n");
                    goto out_err;
                }

                dsa_key_rr_len = dsa_to_dns_key_rr(dsa_key, &dsa_key_rr);
                HIP_IFEL(dsa_key_rr_len <= 0, -EFAULT, "dsa_key_rr_len <= 0\n");

                if ((err = hip_any_key_to_hit(dsa_key, &dsa_lhi.hit, 0, HIP_HI_DSA))) {
                    HIP_ERROR("Conversion from DSA to HIT failed\n");
                    goto out_err;
                }
                HIP_DEBUG_HIT("DSA HIT", &dsa_pub_lhi.hit);

                if ((err = dsa_to_hip_endpoint(dsa_key, &endpoint_dsa_hip,
                                               HIP_ENDPOINT_FLAG_ANON,
                                               hostname))) {
                    HIP_ERROR("Failed to allocate and build DSA endpoint (anon).\n");
                    goto out_err;
                }
            } else { /* pub */
                if ((err = load_dsa_private_key(dsa_filenamebase_pub,
                                                &dsa_pub_key))) {
                    HIP_ERROR("Loading of the DSA key (pub) failed\n");
                    goto out_err;
                }

                dsa_pub_key_rr_len = dsa_to_dns_key_rr(dsa_pub_key,
                                                       &dsa_pub_key_rr);
                HIP_IFEL(dsa_pub_key_rr_len <= 0, -EFAULT,
                         "dsa_pub_key_rr_len <= 0\n");

                if ((err = hip_any_key_to_hit(dsa_pub_key, &dsa_pub_lhi.hit, 0, HIP_HI_DSA))) {
                    HIP_ERROR("Conversion from DSA to HIT failed\n");
                    goto out_err;
                }
                HIP_DEBUG_HIT("DSA HIT", &dsa_pub_lhi.hit);

                if ((err = dsa_to_hip_endpoint(dsa_pub_key,
                                               &endpoint_dsa_pub_hip, 0,
                                               hostname))) {
                    HIP_ERROR("Failed to allocate and build DSA endpoint (pub).\n");
                    goto out_err;
                }
            }
        } else if (!strcmp(hi_fmt, "ecdsa")) {
            if (anon) {
              if ((err = load_ecdsa_private_key(ecdsa_filenamebase, &ecdsa_key))) {
                 HIP_ERROR("Loading of the ECDSA key failed\n");
                    goto out_err;
                }

                ecdsa_key_rr_len = ecdsa_to_key_rr(ecdsa_key, &ecdsa_key_rr);
                HIP_IFEL(ecdsa_key_rr_len <= 0, -EFAULT,
                         "ecdsa_key_rr_len <= 0\n");

                if ((err = hip_any_key_to_hit(ecdsa_key, &ecdsa_lhi.hit, 0, HIP_HI_ECDSA))) {
                   HIP_ERROR("Conversion from ECDSA to HIT failed\n");
                   goto out_err;
                }
                HIP_DEBUG_HIT("ECDSA HIT", &ecdsa_lhi.hit);

                if ((err = ecdsa_to_hip_endpoint(ecdsa_key, &endpoint_ecdsa_hip,
                                                 HIP_ENDPOINT_FLAG_ANON,
                                                 hostname))) {
                    HIP_ERROR("Failed to allocate and build ECDSA endpoint (anon).\n");
                    goto out_err;
                }

            } else { /* pub */

                if ((err = load_ecdsa_private_key(ecdsa_filenamebase_pub,
                                                  &ecdsa_pub_key))) {
                    HIP_ERROR("Loading of the ECDSA key (pub) failed\n");
                    goto out_err;
                }

                ecdsa_pub_key_rr_len = ecdsa_to_key_rr(ecdsa_pub_key,
                                                       &ecdsa_pub_key_rr);
                HIP_IFEL(ecdsa_pub_key_rr_len <= 0, -EFAULT,
                         "ecdsa_pub_key_rr_len <= 0\n");

                if ((err = hip_any_key_to_hit(ecdsa_pub_key, &ecdsa_pub_lhi.hit, 0, HIP_HI_ECDSA))) {
                    HIP_ERROR("Conversion from ECDSA to HIT failed\n");
                    goto out_err;
                }
                HIP_DEBUG_HIT("ECDSA HIT", &ecdsa_pub_lhi.hit);

                if ((err = ecdsa_to_hip_endpoint(ecdsa_pub_key,
                                                 &endpoint_ecdsa_pub_hip, 0,
                                                 hostname))) {
                    HIP_ERROR("Failed to allocate and build ECDSA endpoint (pub).\n");
                    goto out_err;
                }
            }
        } else if (anon) { /* rsa anon */
            if ((err = load_rsa_private_key(rsa_filenamebase, &rsa_key))) {
                HIP_ERROR("Loading of the RSA key failed\n");
                goto out_err;
            }

            rsa_key_rr_len = rsa_to_dns_key_rr(rsa_key, &rsa_key_rr);
            HIP_IFEL(rsa_key_rr_len <= 0, -EFAULT, "rsa_key_rr_len <= 0\n");

            if ((err = rsa_to_hip_endpoint(rsa_key, &endpoint_rsa_hip,
                                           HIP_ENDPOINT_FLAG_ANON, hostname))) {
                HIP_ERROR("Failed to allocate and build RSA endpoint (anon).\n");
                goto out_err;
            }

            if ((err = hip_any_key_to_hit(rsa_key, &rsa_lhi.hit, 0, HIP_HI_RSA))) {
                HIP_ERROR("Conversion from RSA to HIT failed\n");
                goto out_err;
            }
            HIP_DEBUG_HIT("RSA HIT", &rsa_lhi.hit);
        } else { /* rsa pub */
            if ((err = load_rsa_private_key(rsa_filenamebase_pub, &rsa_pub_key))) {
                HIP_ERROR("Loading of the RSA key (pub) failed\n");
                goto out_err;
            }

            rsa_pub_key_rr_len = rsa_to_dns_key_rr(rsa_pub_key, &rsa_pub_key_rr);
            HIP_IFEL(rsa_pub_key_rr_len <= 0, -EFAULT, "rsa_pub_key_rr_len <= 0\n");

            if ((err = rsa_to_hip_endpoint(rsa_pub_key,
                                           &endpoint_rsa_pub_hip, 0, hostname))) {
                HIP_ERROR("Failed to allocate and build RSA endpoint (pub).\n");
                goto out_err;
            }

            if ((err = hip_any_key_to_hit(rsa_pub_key, &rsa_pub_lhi.hit, 0, HIP_HI_RSA))) {
                HIP_ERROR("Conversion from RSA to HIT failed\n");
                goto out_err;
            }
            HIP_DEBUG_HIT("RSA HIT", &rsa_pub_lhi.hit);
        }

        break;
    } /* end switch */

    if (numeric_action == 0) {
        goto skip_msg;
    }

    if (!strcmp(hi_fmt, "dsa")) {
        if (anon) {
            if ((err = hip_build_param_eid_endpoint(msg, endpoint_dsa_hip))) {
                HIP_ERROR("Building of host id failed\n");
                goto out_err;
            }
        } else {
            if ((err = hip_build_param_eid_endpoint(msg, endpoint_dsa_pub_hip))) {
                HIP_ERROR("Building of host id failed\n");
                goto out_err;
            }
        }
    } else if (!strcmp(hi_fmt, "ecdsa")) {
        if (anon) {
            if ((err = hip_build_param_eid_endpoint(msg, endpoint_ecdsa_hip))) {
                HIP_ERROR("Building of host id failed\n");
                goto out_err;
            }
        } else {
           if ((err = hip_build_param_eid_endpoint(msg, endpoint_ecdsa_pub_hip))) {
              HIP_ERROR("Building of host id failed\n");
                goto out_err;
           }
        }
    } else if (anon) { /* rsa anon */
        if ((err = hip_build_param_eid_endpoint(msg, endpoint_rsa_hip))) {
            HIP_ERROR("Building of host id failed\n");
            goto out_err;
        }
    } else { /* rsa */
        if ((err = hip_build_param_eid_endpoint(msg, endpoint_rsa_pub_hip))) {
            HIP_ERROR("Building of host id failed\n");
            goto out_err;
        }
    }

skip_host_id:
skip_msg:

out_err:
    if (dsa_filenamebase != NULL) {
        change_key_file_perms(dsa_filenamebase);
    }
    if (rsa_filenamebase != NULL) {
        change_key_file_perms(rsa_filenamebase);
    }
    if (dsa_filenamebase_pub != NULL) {
        change_key_file_perms(dsa_filenamebase_pub);
    }
    if (rsa_filenamebase_pub != NULL) {
        change_key_file_perms(rsa_filenamebase_pub);
    }
    if (ecdsa_filenamebase_pub != NULL) {
        change_key_file_perms(ecdsa_filenamebase_pub);
    }
    if (ecdsa_filenamebase_pub != NULL) {
        change_key_file_perms(ecdsa_filenamebase_pub);
    }

    free(dsa_host_id);
    free(dsa_pub_host_id);
    free(ecdsa_host_id);
    free(ecdsa_pub_host_id);
    free(rsa_host_id);
    free(rsa_pub_host_id);
    DSA_free(dsa_key);
    EC_KEY_free(ecdsa_key);
    RSA_free(rsa_key);
    DSA_free(dsa_pub_key);
    EC_KEY_free(ecdsa_pub_key);
    RSA_free(rsa_pub_key);
    free(dsa_key_rr);
    free(ecdsa_key_rr);
    free(rsa_key_rr);
    free(dsa_pub_key_rr);
    free(ecdsa_pub_key_rr);
    free(rsa_pub_key_rr);
    free(endpoint_dsa_hip);
    free(endpoint_ecdsa_hip);
    free(endpoint_rsa_hip);
    free(endpoint_dsa_pub_hip);
    free(endpoint_ecdsa_pub_hip);
    free(endpoint_rsa_pub_hip);

    return err;
}

/**
 * Serialize a ECDSA public key
 *
 * @note This functions assumes that the key is public.
 */
int ecdsa_to_key_rr(const EC_KEY *const ecdsa, unsigned char **ec_key_rr)
{
    int err = 0;
    int public = 0;
    unsigned char *buffer = NULL;
    size_t pub_key_len = 0;
    size_t priv_key_len = 0;
    int out_len = 0;
    const BIGNUM *priv_key = NULL;
    uint16_t curveid;
    const EC_GROUP *group = NULL;

    /* sanity check */
    HIP_IFEL(!EC_KEY_check_key(ecdsa),
             -1, "Invalid public key.\n");

    /* get sizes for public and private key, allocate memory for output */
    HIP_IFEL(!(pub_key_len = EC_POINT_point2oct(EC_KEY_get0_group(ecdsa), EC_KEY_get0_public_key(ecdsa), EC_KEY_get_conv_form(ecdsa), NULL, 0, NULL)),
             -1, "Failed to calculate out length of serialized key.\n");
    public = ((priv_key = EC_KEY_get0_private_key(ecdsa)) == NULL ? 1: 0);
    if(!public) {
        priv_key_len = (pub_key_len - 1)/2;
    }
    out_len = HIP_CURVE_ID_LENGTH + pub_key_len + priv_key_len;
    HIP_IFEL(!(buffer = malloc(out_len)),
             -ENOMEM, "Could not allocate memory for serialization of ECDSA key.\n");

    /* insert curve id */
    HIP_IFEL(!(group = EC_KEY_get0_group(ecdsa)),
             -1, "Could not get group from key structure. \n");
    curveid = get_ecdsa_curve_hip_name(EC_GROUP_get_curve_name(group));
    HIP_IFEL(curveid == UNSUPPORTED_CURVE,
             -1, "Curve is not supported.\n");
    *(uint16_t *) buffer = htons(curveid);

    /* serialize public key */
    HIP_IFEL(!EC_POINT_point2oct(EC_KEY_get0_group(ecdsa),
                                 EC_KEY_get0_public_key(ecdsa),
                                 EC_KEY_get_conv_form(ecdsa),
                                 buffer + HIP_CURVE_ID_LENGTH,
                                 out_len,
                                 NULL),
             -1, "Failed to serialize public key key.\n");

    /* serialize private key */
    if(!public) {
        bn2bin_safe(priv_key, buffer + HIP_CURVE_ID_LENGTH + pub_key_len, priv_key_len);
    }

out_err:
    if(err) {
        *ec_key_rr = NULL;
        free(buffer);
        return -1;
    }
    *ec_key_rr = buffer;
    return out_len;
}

/**
 * create DNS KEY RR record from host DSA key
 * @param dsa the DSA structure from where the KEY RR record is to be created
 * @param dsa_key_rr where the resultin KEY RR is stored
 *
 * @note Caller must free dsa_key_rr when it is not used anymore.
 *
 * @return On successful operation, the length of the KEY RR buffer is
 * returned (greater than zero) and pointer to the buffer containing
 * DNS KEY RR is stored at dsa_key_rr. On error function returns negative
 * and sets dsa_key_rr to NULL.
 */
int dsa_to_dns_key_rr(const DSA *const dsa, unsigned char **dsa_key_rr)
{
    int            err            = 0;
    int            dsa_key_rr_len = -1;
    signed char    t; /* in units of 8 bytes */
    unsigned char *p = NULL;
    int            key_len;

    HIP_ASSERT(dsa != NULL); /* should not happen */

    *dsa_key_rr = NULL;

    /* ***** is use of BN_num_bytes ok ? ***** */
    t = (BN_num_bytes(dsa->p) - 64) / 8;
    HIP_IFEL(t < 0 || t > 8, -EINVAL,
             "Invalid RSA key length %d bits\n", (64 + t * 8) * 8);

    /* RFC 2536 section 2 */
    /*
     *       Field     Size
     *       -----     ----
     *        T         1  octet
     *        Q        20  octets
     *        P        64 + T*8  octets
     *        G        64 + T*8  octets
     *        Y        64 + T*8  octets
     *      [ X        20 optional octets (private key hack) ]
     *
     */
    key_len        = 64 + t * 8;
    dsa_key_rr_len = 1 + DSA_PRIV + 3 * key_len;

    if (dsa->priv_key) {
        dsa_key_rr_len += DSA_PRIV; /* private key hack */
    }

    *dsa_key_rr = calloc(1, dsa_key_rr_len);
    HIP_IFEL(!*dsa_key_rr, -ENOMEM, "Malloc for *dsa_key_rr failed\n");

    p = *dsa_key_rr;

    /* set T */
    memset(p, t, 1); // XX FIX: WTF MEMSET?
    p++;

    /* add given dsa_param to the *dsa_key_rr */

    bn2bin_safe(dsa->q, p, DSA_PRIV);
    p += DSA_PRIV;

    bn2bin_safe(dsa->p, p, key_len);
    p += key_len;

    bn2bin_safe(dsa->g, p, key_len);
    p += key_len;

    bn2bin_safe(dsa->pub_key, p, key_len);
    p += key_len;

    if (dsa->priv_key) {
        bn2bin_safe(dsa->priv_key, p, DSA_PRIV);
    }

out_err:

    if (err) {
        free(*dsa_key_rr);
        return err;
    } else {
        return dsa_key_rr_len;
    }
}

/**
 * create a DNS KEY RR record from a given host RSA public key
 *
 * @param rsa the RSA structure from where the KEY RR record is to be created
 * @param rsa_key_rr where the resultin KEY RR is stored
 * @return On successful operation, the length of the KEY RR buffer is
 *         returned (greater than zero) and pointer to the buffer containing
 *         DNS KEY RR is stored at rsa_key_rr. On error function returns
 *         negative and sets rsa_key_rr to NULL.
 * @note Caller must free rsa_key_rr when it is not used anymore.
 * @note This function assumes that RSA given as a parameter is always public.
 */
int rsa_to_dns_key_rr(const RSA *const rsa, unsigned char **rsa_key_rr)
{
    int            err            = 0;
    int            rsa_key_rr_len = -1;
    unsigned char *c              = NULL;
    int public = -1;
    int e_len_bytes = 1;
    int e_len, key_len;

    HIP_ASSERT(rsa != NULL); /* should not happen */

    *rsa_key_rr = NULL;

    e_len   = BN_num_bytes(rsa->e);
    key_len = RSA_size(rsa);

    /* RFC 3110 limits e to 4096 bits */
    HIP_IFEL(e_len > 512, -EINVAL,  "Invalid rsa->e length %d bytes\n", e_len);
    if (e_len > 255) {
        e_len_bytes = 3;
    }

    /* let's check if the RSA key is public or private
     * private exponent is NULL in public keys */
    if (rsa->d == NULL) {
        public         = 1;
        rsa_key_rr_len = e_len_bytes + e_len + key_len;

        /*
         * See RFC 2537 for flags, protocol and algorithm and check RFC 3110 for
         * the RSA public key part ( 1-3 octets defining length of the exponent,
         * exponent is as many octets as the length defines and the modulus is
         * all the rest of the bytes).
         */
    } else {
        public         = 0;
        rsa_key_rr_len = e_len_bytes + e_len + key_len * 9 / 2;
    }

    *rsa_key_rr = calloc(1, rsa_key_rr_len);
    HIP_IFEL(!*rsa_key_rr, -ENOMEM, "Malloc for *rsa_key_rr failed\n");

    c = *rsa_key_rr;

    if (e_len_bytes == 1) {
        *c = (unsigned char) e_len;
    }
    c++; /* If e_len is more than one byte, first byte is 0. */
    if (e_len_bytes == 3) {
        *c = htons((uint16_t) e_len);
        c += 2;
    }

    bn2bin_safe(rsa->e, c, e_len);
    c += e_len;
    bn2bin_safe(rsa->n, c, key_len);
    c += key_len;

    if (!public) {
        bn2bin_safe(rsa->d, c, key_len);
        c += key_len;
        bn2bin_safe(rsa->p, c, key_len / 2);
        c += key_len / 2;
        bn2bin_safe(rsa->q, c, key_len / 2);
        c += key_len / 2;
        bn2bin_safe(rsa->dmp1, c, key_len / 2);
        c += key_len / 2;
        bn2bin_safe(rsa->dmq1, c, key_len / 2);
        c += key_len / 2;
        bn2bin_safe(rsa->iqmp, c, key_len / 2);
    }

out_err:

    if (err) {
        free(*rsa_key_rr);
        return err;
    }

    return rsa_key_rr_len;
}
