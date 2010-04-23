/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 *
 * HIPL wrappers for OpenSSL public key operations.
 *
 * @brief HIPL wrappers for OpenSSL public key operations.
 *
 * @author Miika Komu <miika@iki.fi>
 */

#include "config.h"
#include "pk.h"
#include "lib/core/performance.h"

/**
 * sign a HIP control message with a private RSA key
 *
 * @param priv_key the RSA private key of the local host
 * @param msg The HIP control message to sign. The signature
 *            is appended as a parameter to the message.
 * @return zero on success and negative on error
 * @note the order of parameters is significant so this function
 *       must be called at the right time of building of the parameters
 */
int hip_rsa_sign(void *priv_key, struct hip_common *msg)
{
    RSA *rsa      = (RSA *) priv_key;
    uint8_t sha1_digest[HIP_AH_SHA_LEN];
    uint8_t *signature = NULL;
    int err       = 0, len;
    unsigned int sig_len;

    len       = hip_get_msg_total_len(msg);
    HIP_IFEL(hip_build_digest(HIP_DIGEST_SHA1, msg, len, sha1_digest) < 0,
             -1, "Building of SHA1 digest failed\n");

    len       = RSA_size(rsa);
    signature = malloc(len);
    HIP_IFEL(!signature, -1, "Malloc for signature failed.");
    memset(signature, 0, len);

    /* RSA_sign returns 0 on failure */
    HIP_IFEL(!RSA_sign(NID_sha1, sha1_digest, SHA_DIGEST_LENGTH, signature,
                       &sig_len, rsa), -1, "Signing error\n");


    if (hip_get_msg_type(msg) == HIP_R1) {
        HIP_IFEL(hip_build_param_signature2_contents(msg, signature,
                                                     len, HIP_SIG_RSA),
                 -1,  "Building of signature failed\n");
    } else {
        HIP_IFEL(hip_build_param_signature_contents(msg, signature,
                                                    len, HIP_SIG_RSA),
                 -1, "Building of signature failed\n");
    }

out_err:
    if (signature) {
        free(signature);
    }
    return err;
}

/**
 * sign a HIP control message with a private DSA key
 *
 * @param priv_key the DSA private key of the local host
 * @param msg The HIP control message to sign. The signature
 *            is appended as a parameter to the message.
 * @return zero on success and negative on error
 * @note the order of parameters is significant so this function
 *       must be called at the right time of building of the parameters
 */
int hip_dsa_sign(void *priv_key, struct hip_common *msg)
{
    DSA *dsa = (DSA *) priv_key;
    uint8_t sha1_digest[HIP_AH_SHA_LEN];
    uint8_t signature[HIP_DSA_SIGNATURE_LEN];
    int err  = 0, len;

    len = hip_get_msg_total_len(msg);
    HIP_IFEL(hip_build_digest(HIP_DIGEST_SHA1, msg, len, sha1_digest) < 0,
             -1, "Building of SHA1 digest failed\n");
    HIP_IFEL(impl_dsa_sign(sha1_digest, dsa, signature),
             -1, "Signing error\n");

    if (hip_get_msg_type(msg) == HIP_R1) {
        HIP_IFEL(hip_build_param_signature2_contents(
                msg, signature,
                HIP_DSA_SIGNATURE_LEN, HIP_SIG_DSA),
                -1, "Building of signature failed\n");
    } else {
        HIP_IFEL(hip_build_param_signature_contents(
                msg, signature,
                HIP_DSA_SIGNATURE_LEN, HIP_SIG_DSA),
                 -1, "Building of signature failed\n");
    }

out_err:
    return err;
}

/**
 * Generic signature verification function for DSA and RSA.
 *
 * @param peer_pub public key of the peer
 * @param msg a HIP control message containing a signature parameter to
 *            be verified
 * @param rsa zero for DSA-based public key and one for RSA
 * @return zero on success and non-zero on failure
 */
static int verify(void *peer_pub, struct hip_common *msg, const int rsa)
{
    int err               = 0, len, origlen;
    struct hip_sig *sig;
    uint8_t sha1_digest[HIP_AH_SHA_LEN];
    struct in6_addr tmpaddr;
    struct hip_puzzle *pz = NULL;
    uint8_t opaque[3];
    uint64_t randi        = 0;

    ipv6_addr_copy(&tmpaddr, &msg->hitr);     /* so update is handled, too */

    origlen = hip_get_msg_total_len(msg);
    if (hip_get_msg_type(msg) == HIP_R1) {
        HIP_IFEL(!(sig = hip_get_param(msg, HIP_PARAM_HIP_SIGNATURE2)),
                 -ENOENT, "Could not find signature2\n");

        memset(&msg->hitr, 0, sizeof(struct in6_addr));

        HIP_IFEL(!(pz = hip_get_param(msg, HIP_PARAM_PUZZLE)),
                 -ENOENT, "Illegal R1 packet (puzzle missing)\n");
        memcpy(opaque, pz->opaque, 3);
        randi = pz->I;

        memset(pz->opaque, 0, 3);
        pz->I = 0;
    } else {
        HIP_IFEL(!(sig = hip_get_param(msg, HIP_PARAM_HIP_SIGNATURE)),
                 -ENOENT, "Could not find signature\n");
    }

    len = ((uint8_t *) sig) - ((uint8_t *) msg);
    hip_zero_msg_checksum(msg);
    HIP_IFEL(len < 0, -ENOENT, "Invalid signature len\n");
    hip_set_msg_total_len(msg, len);

    HIP_IFEL(hip_build_digest(HIP_DIGEST_SHA1, msg, len, sha1_digest),
             -1, "Could not calculate SHA1 digest\n");
    if (rsa) {
        /* RSA_verify returns 0 on failure */
        err = !RSA_verify(NID_sha1, sha1_digest, SHA_DIGEST_LENGTH,
                          sig->signature, RSA_size(peer_pub), peer_pub);
    } else {
        err = impl_dsa_verify(sha1_digest, peer_pub, sig->signature);
    }

#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Stop and write PERF_VERIFY, PERF_RSA_VERIFY_IMPL, PERF_DSA_VERIFY_IMPL\n");
    hip_perf_stop_benchmark(perf_set, PERF_VERIFY);
    hip_perf_stop_benchmark(perf_set, PERF_RSA_VERIFY_IMPL);
    hip_perf_stop_benchmark(perf_set, PERF_DSA_VERIFY_IMPL);
    hip_perf_write_benchmark(perf_set, PERF_VERIFY);
    hip_perf_write_benchmark(perf_set, PERF_RSA_VERIFY_IMPL);
    hip_perf_write_benchmark(perf_set, PERF_DSA_VERIFY_IMPL);
#endif

    if (hip_get_msg_type(msg) == HIP_R1) {
        memcpy(pz->opaque, opaque, 3);
        pz->I = randi;
    }

    ipv6_addr_copy(&msg->hitr, &tmpaddr);

    if (err) {
        err = -1;
    }

out_err:
    hip_set_msg_total_len(msg, origlen);
    return err;
}

/**
 * RSA signature verification function
 *
 * @param peer_pub public key of the peer
 * @param msg a HIP control message containing a signature parameter to
 *            be verified
 * @return zero on success and non-zero on failure
 */
int hip_rsa_verify(void *peer_pub, struct hip_common *msg)
{
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_RSA_VERIFY_IMPL\n");
    hip_perf_start_benchmark(perf_set, PERF_RSA_VERIFY_IMPL);
#endif
    return verify((RSA *) peer_pub, msg, 1);
}

/**
 * DSA signature verification function
 *
 * @param peer_pub public key of the peer
 * @param msg a HIP control message containing a signature parameter to
 *            be verified
 * @return zero on success and non-zero on failure
 */
int hip_dsa_verify(void *peer_pub, struct hip_common *msg)
{
#ifdef CONFIG_HIP_PERFORMANCE
    HIP_DEBUG("Start PERF_DSA_VERIFY_IMPL\n");
    hip_perf_start_benchmark(perf_set, PERF_DSA_VERIFY_IMPL);
#endif
    return verify((DSA *) peer_pub, msg, 0);
}

/**
 * BN_bin2bn() chops off the leading zero(es) of the BIGNUM,
 * so that numbers end up being left shifted. This fixes that by
 * enforcing an expected destination length
 *
 * @note This function is originally from OpenHIP
 */
int bn2bin_safe(const BIGNUM *a, unsigned char *to, int len)
{
    int padlen = len - BN_num_bytes(a);
    /* add leading zeroes when needed */
    if (padlen > 0) {
        memset(to, 0, padlen);
    }
    BN_bn2bin(a, &to[padlen]);
    /* return value from BN_bn2bin() may differ from length */
    return len;
}
