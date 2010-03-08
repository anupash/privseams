/** @file
 * This file defines miscellaneous utility functions
 *
 * @author Miika Komu
 * @author Mika Kousa
 * @author Bing Zhou
 * @note   Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 */

/* required for s6_addr32 */
#define _BSD_SOURCE

#ifdef HAVE_CONFIG_H
  #include "config.h"
#endif /* HAVE_CONFIG_H */

#include <string.h>
#include "filemanip.h"

#include "misc.h"
#include "prefix.h"

/**
 * convert a binary HIT into a string
 *
 * @param hit a binary HIT
 * @param prefix an optional HIT prefix as a string
 * @param hit_str the HIT as a string with the given prefix
 * @return zero on success and negative on error
 */
int hip_convert_hit_to_str(const hip_hit_t *hit,
                           const char *prefix,
                           char *hit_str)
{
    int err = 0;

    HIP_ASSERT(hit);

    memset(hit_str, 0, INET6_ADDRSTRLEN);
    err = !hip_in6_ntop(hit, hit_str);

    if (prefix) {
        memcpy(hit_str + strlen(hit_str), prefix, strlen(prefix));
    }

    return err;
}

/**
 * find the maximum value from a variable list of integers
 *
 * @param num_args number of list items
 * @param ... the integers from which to find maximum
 * @return the integer with the largest value from the
 *         list provided
 */
int maxof(int num_args, ...)
{
    int max, i, a;
    va_list ap;

    va_start(ap, num_args);
    max = va_arg(ap, int);
    for (i = 2; i <= num_args; i++) {
        if ((a = va_arg(ap, int)) > max) {
            max = a;
        }
    }
    va_end(ap);
    return max;
}

/**
 * compare two LSIs for equality
 *
 * @param lsi1 an LSI
 * @param lsi2 an LSI
 * @return one if the LSIs are equal or zero otherwise
 */
int hip_lsi_are_equal(const hip_lsi_t *lsi1,
                      const hip_lsi_t *lsi2)
{
    return ipv4_addr_cmp(lsi1, lsi2) == 0;
}

/**
 * compare two HITs to check which HIT is "bigger"
 *
 * @param hit1 the first HIT to be compared
 * @param hit2 the second HIT to be compared
 *
 * @return 1 if hit1 was bigger than hit2, or else 0
 */
int hip_hit_is_bigger(const struct in6_addr *hit1,
                      const struct in6_addr *hit2)
{
    return ipv6_addr_cmp(hit1, hit2) > 0;
}

/**
 * compare two HITs to check which if they are equal
 *
 * @param hit1 the first HIT to be compared
 * @param hit2 the second HIT to be compared
 *
 * @return 1 if the HITs were equal and zero otherwise
 */
int hip_hit_are_equal(const struct in6_addr *hit1,
                      const struct in6_addr *hit2)
{
    return ipv6_addr_cmp(hit1, hit2) == 0;
}

/**
 * convert a binary IPv6 address to a string
 *
 * @param in6 the IPv6 address to convert
 * @param buf a preallocated buffer where the string will be stored
 * @return a pointer to the buf
 */
char *hip_in6_ntop(const struct in6_addr *in6, char *buf)
{
    if (!buf) {
        return NULL;
    }
    sprintf(buf,
            "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
            ntohs(in6->s6_addr16[0]), ntohs(in6->s6_addr16[1]),
            ntohs(in6->s6_addr16[2]), ntohs(in6->s6_addr16[3]),
            ntohs(in6->s6_addr16[4]), ntohs(in6->s6_addr16[5]),
            ntohs(in6->s6_addr16[6]), ntohs(in6->s6_addr16[7]));
    return buf;
}

/**
 * A generic object hashing function for lib/core/hashtable.c
 *
 * @param ptr an pointer to hash (must be at least 32 bits)
 * @return a hash of the first 32-bits of the ptr's data
 */
unsigned long hip_hash_generic(const void *ptr)
{
    unsigned long hash = (unsigned long) (*((uint32_t *) ptr));
    return hash % ULONG_MAX;
}

/**
 * A generic matching function for lib/core/hashtable.c
 *
 * @param ptr1 a pointer to an item in the hash table
 * @param ptr2 a pointer to an item in the hash table
 * @return zero if the pointers match or one otherwise
 */
int hip_match_generic(const void *ptr1, const void *ptr2)
{
    return ptr1 != ptr2;
}

/**
 * Returns a generic linked list based on the hash table implementation
 *
 * @return an allocated hash table which is caller is responsible to free
 */
HIP_HASHTABLE *hip_linked_list_init()
{
    return (HIP_HASHTABLE *) hip_ht_init(hip_hash_generic, hip_match_generic);
}

/**
 * hip_hash_hit - calculate a hash from a HIT
 *
 * @param key pointer to a HIT
 * @param range range of the hash
 *
 * Returns value in range: 0 <= x < range
 */
unsigned long hip_hash_hit(const void *ptr)
{
    uint8_t hash[HIP_AH_SHA_LEN];

    hip_build_digest(HIP_DIGEST_SHA1, ptr + sizeof(uint16_t),
                     7 * sizeof(uint16_t), hash);

    return *((unsigned long *) hash);
}

/**
 * Verify if if two HITs match based on hashing
 *
 * @param ptr1 a HIT
 * @param ptr2 a HIT
 * @return zero if the HITs match or one otherwise
 */
int hip_match_hit(const void *ptr1, const void *ptr2)
{
    return hip_hash_hit(ptr1) != hip_hash_hit(ptr2);
}

/**
 * get encryption key length for a transform
 *
 * @param tid transform
 * @return the encryption key length of the chosen transform,
 *         or negative  on error.
 */
int hip_enc_key_length(int tid)
{
    int ret = -1;

    switch (tid) {
    case HIP_ESP_AES_SHA1:
        ret = 16;
        break;
    case HIP_ESP_3DES_SHA1:
        ret = 24;
        break;
    case HIP_ESP_NULL_SHA1:
    case HIP_ESP_NULL_NULL:
        ret = 0;
        break;
    default:
        HIP_ERROR("unknown tid=%d\n", tid);
        HIP_ASSERT(0);
        break;
    }

    return ret;
}

/**
 * get hmac key length of a transform
 *
 * @param tid transform
 * @return the encryption key length based of the chosen transform,
 *         or negative  on error.
 */
int hip_hmac_key_length(int tid)
{
    int ret = -1;
    switch (tid) {
    case HIP_ESP_AES_SHA1:
    case HIP_ESP_3DES_SHA1:
    case HIP_ESP_NULL_SHA1:
        ret = 20;
        break;
    case HIP_ESP_NULL_NULL:
        ret = 0;
        break;
    default:
        HIP_ERROR("unknown tid=%d\n", tid);
        HIP_ASSERT(0);
        break;
    }

    return ret;
}

/**
 * get transform key length for a transform
 * @param tid transform
 *
 * @return the transform key length based for the chosen transform,
 * or negative on error.
 */
int hip_transform_key_length(int tid)
{
    int ret = -1;

    switch (tid) {
    case HIP_HIP_AES_SHA1:
        ret = 16;
        break;
    case HIP_HIP_3DES_SHA1:
        ret = 24;
        break;
    case HIP_HIP_NULL_SHA1:     // XX FIXME: SHOULD BE NULL_SHA1?
        ret = 0;
        break;
    default:
        HIP_ERROR("unknown tid=%d\n", tid);
        HIP_ASSERT(0);
        break;
    }

    return ret;
}

/**
 * get authentication key length for an ESP transform
 *
 * @param tid transform
 * @return the authentication key length for the chosen transform.
 * or negative on error
 */
int hip_auth_key_length_esp(int tid)
{
    int ret = -1;

    switch (tid) {
    case HIP_ESP_AES_SHA1:
    case HIP_ESP_NULL_SHA1:
    case HIP_ESP_3DES_SHA1:
        ret = 20;
        break;
    case HIP_ESP_NULL_NULL:
        ret = 0;
        break;
    default:
        HIP_ERROR("unknown tid=%d\n", tid);
        HIP_ASSERT(0);
        break;
    }

    return ret;
}

/**
 * select a HIP transform
 *
 * @param ht HIP_TRANSFORM payload where the transform is selected from
 * @return the first acceptable Transform-ID or negative if no
 * acceptable transform was found. The return value is in host byte order.
 */
hip_transform_suite_t hip_select_hip_transform(struct hip_hip_transform *ht)
{
    hip_transform_suite_t tid = 0;
    int i;
    int length;
    hip_transform_suite_t *suggestion;

    length     = ntohs(ht->length);
    suggestion = (hip_transform_suite_t *) &ht->suite_id[0];

    if ((length >> 1) > 6) {
        HIP_ERROR("Too many transforms (%d)\n", length >> 1);
        goto out;
    }

    for (i = 0; i < length; i++) {
        switch (ntohs(*suggestion)) {
        case HIP_HIP_AES_SHA1:
        case HIP_HIP_3DES_SHA1:
        case HIP_HIP_NULL_SHA1:
            tid = ntohs(*suggestion);
            goto out;
            break;

        default:
            /* Specs don't say what to do when unknown are found.
             * We ignore.
             */
            HIP_ERROR("Unknown HIP suite id suggestion (%u)\n",
                      ntohs(*suggestion));
            break;
        }
        suggestion++;
    }

out:
    if (tid == 0) {
        HIP_ERROR("None HIP transforms accepted\n");
    } else {
        HIP_DEBUG("Chose HIP transform: %d\n", tid);
    }

    return tid;
}

/**
 * select an ESP transform to use
 * @param ht ESP_TRANSFORM payload where the transform is selected from
 *
 * @return the first acceptable Suite-ID or negative if no
 * acceptable Suite-ID was found.
 */
hip_transform_suite_t hip_select_esp_transform(struct hip_esp_transform *ht)
{
    hip_transform_suite_t tid = 0;
    int i;
    int length;
    hip_transform_suite_t *suggestion;

    length     = hip_get_param_contents_len(ht);
    suggestion = (uint16_t *) &ht->suite_id[0];

    if (length > sizeof(struct hip_esp_transform) -
        sizeof(struct hip_common)) {
        HIP_ERROR("Too many transforms\n");
        goto out;
    }

    for (i = 0; i < length; i++) {
        switch (ntohs(*suggestion)) {
        case HIP_ESP_AES_SHA1:
        case HIP_ESP_NULL_NULL:
        case HIP_ESP_3DES_SHA1:
        case HIP_ESP_NULL_SHA1:
            tid = ntohs(*suggestion);
            goto out;
            break;
        default:
            /* Specs don't say what to do when unknowns are found.
             * We ignore.
             */
            HIP_ERROR("Unknown ESP suite id suggestion (%u)\n",
                      ntohs(*suggestion));
            break;
        }
        suggestion++;
    }

out:
    HIP_DEBUG("Took ESP transform %d\n", tid);

    if (tid == 0) {
        HIP_ERROR("Faulty ESP transform\n");
    }

    return tid;
}

/**
 * Generate the IPv4 header checksum
 *
 * @param s     source address
 * @param d     destination address
 * @param c     data
 * @return the calculated IPv4 header checksum
 */
uint16_t ipv4_checksum(uint8_t protocol, void *s, void *d, void *c, uint16_t len)
{
    uint8_t *src   = s;
    uint8_t *dst   = d;
    uint8_t *data  = c;
    uint16_t word16;
    uint32_t sum;
    uint16_t i;

    /* initialize sum to zero */
    sum = 0;

    /* make 16 bit words out of every two adjacent 8 bit words and */
    /* calculate the sum of all 16 vit words */
    for (i = 0; i < len; i = i + 2) {
        word16 = ((((uint16_t) (data[i] << 8))) & 0xFF00) + (((uint16_t) data[i + 1]) & 0xFF);
        sum    = sum + (unsigned long) word16;
    }
    /* add the TCP pseudo header which contains:
       the IP source and destination addresses, */
    for (i = 0; i < 4; i = i + 2) {
        word16 = ((src[i] << 8) & 0xFF00) + (src[i + 1] & 0xFF);
        sum    = sum + word16;
    }
    for (i = 0; i < 4; i = i + 2) {
        word16 = ((dst[i] << 8) & 0xFF00) + (dst[i + 1] & 0xFF);
        sum    = sum + word16;
    }
    /* the protocol number and the length of the TCP packet */
    sum = sum + protocol + len;

    /* keep only the last 16 bits of the 32 bit calculated sum
       and add the carries */
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    /* Take the one's complement of sum */
    sum = ~sum;
    return htons((unsigned short) sum);
}

/**
 * convert a string into a binary IPv4 address (a wrapper for inet_pton())
 *
 * @param str the string to convert
 * @param ip an output argument that will contain a binary IPv4 calculated
 *        from the @c str
 * @return zero on success and negative on error
 */
int convert_string_to_address_v4(const char *str, struct in_addr *ip)
{
    int ret = 0, err = 0;

    ret = inet_pton(AF_INET, str, ip);
    HIP_IFEL((ret < 0 && errno == EAFNOSUPPORT), -1,
             "inet_pton: not a valid address family\n");
    HIP_IFEL((ret == 0), -1,
             "inet_pton: %s: not a valid network address\n", str);
out_err:
    return err;
}

/**
 * Convert a string to an IPv6 address. This function can handle
 * also IPv6 mapped addresses.
 *
 * @param str the string to convert
 * @param ip6 An output argument that will contain a binary IPv4 calculated
 *        from the @c str. Possibly in IPv6 mapped format.
 */
int convert_string_to_address(const char *str,
                              struct in6_addr *ip6)
{
    int ret = 0, err = 0;
    struct in_addr ip4;

    ret = inet_pton(AF_INET6, str, ip6);
    HIP_IFEL((ret < 0 && errno == EAFNOSUPPORT), -1,
             "\"%s\" is not of valid address family.\n", str);
    if (ret > 0) {
        /* IPv6 address conversion was ok */
        _HIP_DEBUG_IN6ADDR("Converted IPv6", ip6);
        goto out_err;
    }

    /* Might be an ipv4 address (ret == 0). Lets catch it here. */
    err = convert_string_to_address_v4(str, &ip4);
    if (err) {
        goto out_err;
    }

    IPV4_TO_IPV6_MAP(&ip4, ip6);
    HIP_DEBUG("Mapped v4 to v6.\n");
    HIP_DEBUG_IN6ADDR("mapped v6", ip6);

out_err:
    return err;
}

/**
 * calculate a HIT from a HI without the prefix
 *
 * @param orig a pointer to a host identity
 * @param orig_len the length of the host identity in bits
 * @param encoded an output argument where the HIT will be stored
 * @param encoded_len the length of the encoded HIT in bits
 * @return zero on success or negative on error
 */
int khi_encode(unsigned char *orig, int orig_len,
               unsigned char *encoded,
               int encoded_len)
{
    BIGNUM *bn = NULL;
    int err    = 0, shift = (orig_len - encoded_len) / 2,
        len    = encoded_len / 8 + ((encoded_len % 8) ? 1 : 0);

    HIP_IFEL((encoded_len > orig_len), -1, "len mismatch\n");
    HIP_IFEL((!(bn = BN_bin2bn(orig, orig_len / 8, NULL))), -1,
             "BN_bin2bn\n");
    HIP_IFEL(!BN_rshift(bn, bn, shift), -1, "BN_lshift\n");
    HIP_IFEL(!BN_mask_bits(bn, encoded_len), -1,
             "BN_mask_bits\n");
    HIP_IFEL((bn2bin_safe(bn, encoded, len) != len), -1,
             "BN_bn2bin_safe\n");

    _HIP_HEXDUMP("encoded: ", encoded, len);

out_err:
    if (bn) {
        BN_free(bn);
    }
    return err;
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
int dsa_to_dns_key_rr(DSA *dsa, unsigned char **dsa_key_rr)
{
    int err            = 0;
    int dsa_key_rr_len = -1;
    signed char t; /* in units of 8 bytes */
    unsigned char *p = NULL;
    int key_len;

    HIP_ASSERT(dsa != NULL); /* should not happen */

    *dsa_key_rr = NULL;

    _HIP_DEBUG("numbytes p=%d\n", BN_num_bytes(dsa->p));
    _HIP_DEBUG("numbytes q=%d\n", BN_num_bytes(dsa->q));
    _HIP_DEBUG("numbytes g=%d\n", BN_num_bytes(dsa->g));
    // shouldn't this be NULL also?
    _HIP_DEBUG("numbytes pubkey=%d\n", BN_num_bytes(dsa->pub_key));


    /* notice that these functions allocate memory */
    _HIP_DEBUG("p=%s\n", BN_bn2hex(dsa->p));
    _HIP_DEBUG("q=%s\n", BN_bn2hex(dsa->q));
    _HIP_DEBUG("g=%s\n", BN_bn2hex(dsa->g));
    _HIP_DEBUG("pubkey=%s\n", BN_bn2hex(dsa->pub_key));

    /* ***** is use of BN_num_bytes ok ? ***** */
    t = (BN_num_bytes(dsa->p) - 64) / 8;
    HIP_IFEL((t < 0 || t > 8), -EINVAL,
             "Invalid RSA key length %d bits\n", (64 + t * 8) * 8);
    _HIP_DEBUG("t=%d\n", t);

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
        _HIP_DEBUG("Private key included\n");
    } else {
        _HIP_DEBUG("No private key\n");
    }

    _HIP_DEBUG("dsa key rr len = %d\n", dsa_key_rr_len);
    *dsa_key_rr = malloc(dsa_key_rr_len);
    HIP_IFEL(!*dsa_key_rr, -ENOMEM, "Malloc for *dsa_key_rr failed\n");
    memset(*dsa_key_rr, 0, dsa_key_rr_len);

    p           = *dsa_key_rr;

    /* set T */
    memset(p, t, 1); // XX FIX: WTF MEMSET?
    p++;
    _HIP_HEXDUMP("DSA KEY RR after T:", *dsa_key_rr, p - *dsa_key_rr);

    /* add given dsa_param to the *dsa_key_rr */

    bn2bin_safe(dsa->q, p, DSA_PRIV);
    p += DSA_PRIV;
    _HIP_HEXDUMP("DSA KEY RR after Q:", *dsa_key_rr, p - *dsa_key_rr);

    bn2bin_safe(dsa->p, p, key_len);
    p += key_len;
    _HIP_HEXDUMP("DSA KEY RR after P:", *dsa_key_rr, p - *dsa_key_rr);

    bn2bin_safe(dsa->g, p, key_len);
    p += key_len;
    _HIP_HEXDUMP("DSA KEY RR after G:", *dsa_key_rr, p - *dsa_key_rr);

    bn2bin_safe(dsa->pub_key, p, key_len);
    p += key_len;
    _HIP_HEXDUMP("DSA KEY RR after Y:", *dsa_key_rr, p - *dsa_key_rr);

    if (dsa->priv_key) {
        bn2bin_safe(dsa->priv_key, p, DSA_PRIV);
        _HIP_HEXDUMP("DSA KEY RR after X:", *dsa_key_rr, p - *dsa_key_rr);
    }

out_err:

    if (err) {
        if (*dsa_key_rr) {
            free(*dsa_key_rr);
        }
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
int rsa_to_dns_key_rr(RSA *rsa, unsigned char **rsa_key_rr)
{
    int err            = 0;
    int rsa_key_rr_len = -1;
    unsigned char *c = NULL;
    int public = -1;
    int e_len_bytes    = 1;
    int e_len, key_len;

    HIP_ASSERT(rsa != NULL); // should not happen

    *rsa_key_rr = NULL;

    e_len       = BN_num_bytes(rsa->e);
    key_len     = RSA_size(rsa);

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

    *rsa_key_rr = malloc(rsa_key_rr_len);
    HIP_IFEL(!*rsa_key_rr, -ENOMEM, "Malloc for *rsa_key_rr failed\n");
    memset(*rsa_key_rr, 0, rsa_key_rr_len);

    c           = *rsa_key_rr;

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
        if (*rsa_key_rr) {
            free(*rsa_key_rr);
        }
        return err;
    }

    return rsa_key_rr_len;
}



/**
 * solve a computational puzzle for HIP
 *
 * @param puzzle_or_solution Either a pointer to hip_puzzle or hip_solution structure
 * @param hdr The incoming R1/I2 packet header.
 * @param mode Either HIP_VERIFY_PUZZLE of HIP_SOLVE_PUZZLE
 *
 * @note The K and I is read from the @c puzzle_or_solution.
 * @note Regarding to return value of zero, I don't see why 0 couldn't solve the
 *       puzzle too, but since the odds are 1/2^64 to try 0, I don't see the point
 *       in improving this now.
 * @return The J that solves the puzzle is returned, or 0 to indicate an error.
 */
uint64_t hip_solve_puzzle(void *puzzle_or_solution,
                          struct hip_common *hdr,
                          int mode)
{
    uint64_t mask     = 0;
    uint64_t randval  = 0;
    uint64_t maxtries = 0;
    uint64_t digest   = 0;
    uint8_t cookie[48];
    int err           = 0;
    union {
        struct hip_puzzle   pz;
        struct hip_solution sl;
    } *u;

    HIP_HEXDUMP("puzzle", puzzle_or_solution,
                (mode == HIP_VERIFY_PUZZLE ? sizeof(struct hip_solution) :
                                             sizeof(struct hip_puzzle)));

    _HIP_DEBUG("\n");
    /* pre-create cookie */
    u = puzzle_or_solution;

    _HIP_DEBUG("current hip_cookie_max_k_r1=%d\n", max_k);
    HIP_IFEL(u->pz.K > HIP_PUZZLE_MAX_K, 0,
             "Cookie K %u is higher than we are willing to calculate"
             " (current max K=%d)\n", u->pz.K, HIP_PUZZLE_MAX_K);

    mask = hton64((1ULL << u->pz.K) - 1);
    memcpy(cookie, (uint8_t *) &(u->pz.I), sizeof(uint64_t));

    HIP_DEBUG("(u->pz.I: 0x%llx\n", u->pz.I);

    if (mode == HIP_VERIFY_PUZZLE) {
        ipv6_addr_copy((hip_hit_t *) (cookie + 8), &hdr->hits);
        ipv6_addr_copy((hip_hit_t *) (cookie + 24), &hdr->hitr);
        //randval = ntoh64(u->sl.J);
        randval  = u->sl.J;
        _HIP_DEBUG("u->sl.J: 0x%llx\n", randval);
        maxtries = 1;
    } else if (mode == HIP_SOLVE_PUZZLE) {
        ipv6_addr_copy((hip_hit_t *) (cookie + 8), &hdr->hitr);
        ipv6_addr_copy((hip_hit_t *) (cookie + 24), &hdr->hits);
        maxtries = 1ULL << (u->pz.K + 3);
        get_random_bytes(&randval, sizeof(u_int64_t));
    } else {
        HIP_IFEL(1, 0, "Unknown mode: %d\n", mode);
    }

    HIP_DEBUG("K=%u, maxtries (with k+2)=%llu\n", u->pz.K, maxtries);
    /* while loops should work even if the maxtries is unsigned
     * if maxtries = 1 ---> while(1 > 0) [maxtries == 0 now]...
     * the next round while (0 > 0) [maxtries > 0 now]
     */
    while (maxtries-- > 0) {
        uint8_t sha_digest[HIP_AH_SHA_LEN];

        /* must be 8 */
        memcpy(cookie + 40, (uint8_t *) &randval, sizeof(uint64_t));

        hip_build_digest(HIP_DIGEST_SHA1, cookie, 48, sha_digest);

        /* copy the last 8 bytes for checking */
        memcpy(&digest, sha_digest + 12, sizeof(uint64_t));

        /* now, in order to be able to do correctly the bitwise
         * AND-operation we have to remember that little endian
         * processors will interpret the digest and mask reversely.
         * digest is the last 64 bits of the sha1-digest.. how that is
         * ordered in processors registers etc.. does not matter to us.
         * If the last 64 bits of the sha1-digest is
         * 0x12345678DEADBEEF, whether we have 0xEFBEADDE78563412
         * doesn't matter because the mask matters... if the mask is
         * 0x000000000000FFFF (or in other endianness
         * 0xFFFF000000000000). Either ways... the result is
         * 0x000000000000BEEF or 0xEFBE000000000000, which the cpu
         * interprets as 0xBEEF. The mask is converted to network byte
         * order (above).
         */
        if ((digest & mask) == 0) {
            _HIP_DEBUG("*** Puzzle solved ***: 0x%llx\n", randval);
            _HIP_HEXDUMP("digest", sha_digest, HIP_AH_SHA_LEN);
            _HIP_HEXDUMP("cookie", cookie, sizeof(cookie));
            return randval;
        }

        /* It seems like the puzzle was not correctly solved */
        HIP_IFEL(mode == HIP_VERIFY_PUZZLE, 0, "Puzzle incorrect\n");
        randval++;
    }

    HIP_ERROR("Could not solve the puzzle, no solution found\n");
out_err:
    return err;
}

#ifdef CONFIG_HIP_MIDAUTH
/**
 * solve a midauth puzzle which is essentially a normal HIP cookie
 * with some extra whipped cream on the top
 *
 * @param out the received R1 message
 * @param in an I2 message where the solution will be written
 * @param entry the related host association
 * @return zero on success and negative on error
 * @see <a
 * href="http://tools.ietf.org/id/draft-heer-hip-middle-auth">Heer et
 * al, End-Host Authentication for HIP Middleboxes, Internet draft,
 * work in progress, February 2009</a>
 */
int hip_solve_puzzle_m(struct hip_common *out,
                       struct hip_common *in,
                       hip_ha_t *entry)
{
    struct hip_challenge_request *pz;
    struct hip_puzzle tmp;
    uint64_t solution;
    int err = 0;
    uint8_t digist[HIP_AH_SHA_LEN];


    pz = hip_get_param(in, HIP_PARAM_CHALLENGE_REQUEST);
    while (pz) {
        if (hip_get_param_type(pz) != HIP_PARAM_CHALLENGE_REQUEST) {
            break;
        }

        HIP_IFEL(hip_build_digest(HIP_DIGEST_SHA1, pz->opaque, 24, digist) < 0,
                 -1, "Building of SHA1 Random seed I failed\n");
        tmp.type      = pz->type;
        tmp.length    = pz->length;
        tmp.K         = pz->K;
        tmp.lifetime  = pz->lifetime;
        tmp.opaque[0] = tmp.opaque[1] = 0;
        tmp.I         = *digist & 0x40; //truncate I to 8 byte length

        HIP_IFEL((solution = entry->hadb_misc_func->hip_solve_puzzle(
                      &tmp, in, HIP_SOLVE_PUZZLE)) == 0,
                 -EINVAL, "Solving of puzzle failed\n");

        HIP_IFEL(hip_build_param_challenge_response(out, pz, ntoh64(solution)) < 0,
                 -1,
                 "Error while creating solution_m reply parameter\n");
        pz = (struct hip_challenge_request *) hip_get_next_param(in,
                                                                 (struct hip_tlv_common *) pz);
    }

out_err:
    return err;
}
#endif /* CONFIG_HIP_MIDAUTH */

/**
 * get the state of the bex for a pair of ip addresses.
 *
 * @param src_ip       input for finding the correct entries
 * @param dst_ip       input for finding the correct entries
 * @param src_hit      output data of the correct entry
 * @param dst_hit      output data of the correct entry
 * @param src_lsi      output data of the correct entry
 * @param dst_lsi      output data of the correct entry
 * @return             the state of the bex if the entry is found
 *                     otherwise returns -1
 */
int hip_get_bex_state_from_LSIs(hip_lsi_t       *src_lsi,
                                hip_lsi_t       *dst_lsi,
                                struct in6_addr *src_ip,
                                struct in6_addr *dst_ip,
                                struct in6_addr *src_hit,
                                struct in6_addr *dst_hit)
{
    int err = 0, res = -1;
    struct hip_tlv_common *current_param = NULL;
    struct hip_common *msg               = NULL;
    struct hip_hadb_user_info_state *ha;

    HIP_ASSERT(src_ip != NULL && dst_ip != NULL);

    HIP_IFEL(!(msg = hip_msg_alloc()), -1, "malloc failed\n");
    hip_msg_init(msg);
    HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_GET_HA_INFO, 0),
             -1, "Building of daemon header failed\n");
    HIP_IFEL(hip_send_recv_daemon_info(msg, 0, 0), -1, "send recv daemon info\n");

    while ((current_param = hip_get_next_param(msg, current_param)) != NULL) {
        ha = hip_get_param_contents_direct(current_param);

        if ((ipv4_addr_cmp(dst_lsi, &ha->lsi_our) == 0)  &&
            (ipv4_addr_cmp(src_lsi, &ha->lsi_peer) == 0)) {
            *src_hit = ha->hit_peer;
            *dst_hit = ha->hit_our;
            *src_ip  = ha->ip_peer;
            *dst_ip  = ha->ip_our;
            res      = ha->state;
            break;
        } else if ((ipv4_addr_cmp(src_lsi, &ha->lsi_our) == 0)  &&
                   (ipv4_addr_cmp(dst_lsi, &ha->lsi_peer) == 0)) {
            *src_hit = ha->hit_our;
            *dst_hit = ha->hit_peer;
            *src_ip  = ha->ip_our;
            *dst_ip  = ha->ip_peer;
            res      = ha->state;
            break;
        }
    }

out_err:
    if (msg) {
        HIP_FREE(msg);
    }
    return res;
}

/**
 * build a message for hipd to trigger a base exchange
 *
 * @param src_hit an optional source HIT for the I1
 * @param dst_hit a destination HIT for the I1
 * @param src_lsi an optional source LSI (corresponding to a local HIT)
 * @param dst_lsi a destination LSI for the I1
 * @param src_ip  an optional source IP address for the I1
 * @param dst_ip  a destination IP for the I1
 * @return        zero on success or negative on error

 * @note Many of the parameters are optional, but at least a
 * destination LSI, HIT or IP (for opportunistic BEX) must to be
 * provided
 */
int hip_trigger_bex(const struct in6_addr *src_hit,
                    const struct in6_addr *dst_hit,
                    struct in6_addr *src_lsi,
                    struct in6_addr *dst_lsi,
                    struct in6_addr *src_ip,
                    struct in6_addr *dst_ip)
{
    struct hip_common *msg = NULL;
    int err                = 0;
    HIP_IFE(!(msg = hip_msg_alloc()), -1);
    HIP_IFEL(!dst_hit && !dst_ip, -1,
             "neither destination hit nor ip provided\n");

    /* NOTE: we need this sequence in order to process the incoming
     * message correctly */

    /* build the message header */
    HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_TRIGGER_BEX, 0),
             -1, "build hdr failed\n");

    /* destination HIT, LSI or IP are obligatory */
    if (dst_hit) {
        HIP_DEBUG_HIT("dst_hit: ", dst_hit);
        HIP_IFEL(hip_build_param_contents(msg, (void *) (dst_hit),
                                          HIP_PARAM_HIT,
                                          sizeof(struct in6_addr)),
                 -1, "build param HIP_PARAM_HIT failed\n");
    }

    /* source HIT is optional */
    if (src_hit) {
        HIP_DEBUG_HIT("src_hit: ", src_hit);
        HIP_IFEL(hip_build_param_contents(msg, (void *) (src_hit),
                                          HIP_PARAM_HIT,
                                          sizeof(struct in6_addr)),
                 -1, "build param HIP_PARAM_HIT failed\n");
    }

    /* destination LSI is obligatory */
    if (dst_lsi) {
        HIP_DEBUG_IN6ADDR("dst lsi: ", dst_lsi);
        HIP_IFEL(hip_build_param_contents(msg, (void *) (dst_lsi),
                                          HIP_PARAM_LSI,
                                          sizeof(struct in6_addr)),
                 -1, "build param HIP_PARAM_LSI failed\n");
    }

    /* source LSI is optional */
    if (src_lsi) {
        HIP_DEBUG_IN6ADDR("src lsi: ", src_lsi);
        HIP_IFEL(hip_build_param_contents(msg, (void *) (src_lsi),
                                          HIP_PARAM_LSI,
                                          sizeof(struct in6_addr)),
                 -1, "build param HIP_PARAM_LSI failed\n");
    }

    /* if no destination HIT is provided, at least destination IP must
       exist */
    if (dst_ip) {
        HIP_DEBUG_IN6ADDR("dst_ip: ", dst_ip);
        HIP_IFEL(hip_build_param_contents(msg, (void *) (dst_ip),
                                          HIP_PARAM_IPV6_ADDR,
                                          sizeof(struct in6_addr)),
                 -1, "build param HIP_PARAM_IPV6_ADDR failed\n");
    }

    /* this again is optional */
    if (src_ip) {
        HIP_DEBUG_IN6ADDR("src_ip: ", src_ip);
        HIP_IFEL(hip_build_param_contents(msg, (void *) (src_ip),
                                          HIP_PARAM_IPV6_ADDR,
                                          sizeof(struct in6_addr)),
                 -1, "build param HIP_PARAM_IPV6_ADDR failed\n");
    }

    HIP_DUMP_MSG(msg);

    /* send msg to hipd and receive corresponding reply */
    HIP_IFEL(hip_send_recv_daemon_info(msg, 0, 0), -1, "send_recv msg failed\n");

    /* check error value */
    HIP_IFEL(hip_get_msg_err(msg), -1, "hipd returned error message!\n");
    HIP_DEBUG("Send_recv msg succeed \n");

out_err:
    if (msg) {
        HIP_FREE(msg);
    }
    return err;
}

/**
 * ask hipd to sign a hiccups data packet
 *
 * @param src_hit the source HIT of the data packet
 * @param dst_hit the destination HIT of the data packet
 * @param payload the payload protocol value
 * @param msg     An input/output parameter. For input, contains the
 *                data packet with payload. For output, contains the
 *                same but including a signature from hipd.
 * @return        zero on success or negative on error
 */
int hip_get_data_packet_header(const struct in6_addr *src_hit,
                               const struct in6_addr *dst_hit,
                               int payload,
                               struct hip_common *msg)
{
    int err = 0;

    hip_build_network_hdr(msg, HIP_DATA, 0, src_hit, dst_hit);
    msg->payload_proto = payload;

    HIP_DEBUG("PAYLOAD_PROTO in HIP DATA HEADER = %d  ", payload );

    /* @todo: this will assert  */
    HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_BUILD_HOST_ID_SIGNATURE_DATAPACKET, 0),
             -1, "build hdr failed\n");
    _HIP_DUMP_MSG(msg);

    /* send msg to hipd and receive corresponding reply */
    HIP_IFEL(hip_send_recv_daemon_info(msg, 0, 0), -1, "send_recv msg failed\n");

    /* check error value */
    HIP_IFEL(hip_get_msg_err(msg), -1, "hipd returned error message!\n");
    HIP_DEBUG("Send_recv msg succeed \n");

out_err:
    msg->type_hdr      = HIP_DATA;
    /* this was overwritten by some mischief.. So reseting it */
    msg->payload_proto = payload;

    return err;
}

/**
 * Check from the proc file system whether a local port is attached
 * to an IPv4 or IPv6 address. This is required to determine whether
 * incoming packets should be diverted to an LSI.
 *
 * @param port_dest     the port number of the socket
 * @param *proto        protocol type
 * @return              1 if it finds the required socket, 0 otherwise
 *
 * @note this is used only from the firewall, so move this there
 */
int hip_get_proto_info(in_port_t port_dest, char *proto)
{
    FILE *fd       = NULL;
    char line[500], sub_string_addr_hex[8], path[11 + sizeof(proto)];
    char *fqdn_str = NULL, *separator = NULL, *sub_string_port_hex = NULL;
    int lineno     = 0, index_addr_port = 0, exists = 0, result;
    uint32_t result_addr;
    struct in_addr addr;
    List list;

    if (!proto) {
        return 0;
    }

    if (!strcmp(proto, "tcp6") || !strcmp(proto, "tcp")) {
        index_addr_port = 15;
    } else if (!strcmp(proto, "udp6") || !strcmp(proto, "udp")) {
        index_addr_port = 10;
    } else {
        return 0;
    }

    strcpy(path, "/proc/net/");
    strcat(path, proto);
    fd = fopen(path, "r");

    initlist(&list);
    while (fd && getwithoutnewline(line, 500, fd) != NULL && !exists) {
        lineno++;

        destroy(&list);
        initlist(&list);

        if (lineno == 1 || strlen(line) <= 1) {
            continue;
        }

        extractsubstrings(line, &list);

        fqdn_str = getitem(&list, index_addr_port);
        if (fqdn_str) {
            separator = strrchr(fqdn_str, ':');
        }

        if (!separator) {
            continue;
        }

        sub_string_port_hex = strtok(separator, ":");
        sscanf(sub_string_port_hex, "%X", &result);
        HIP_DEBUG("Result %i\n", result);
        HIP_DEBUG("port dest %i\n", port_dest);
        if (result == port_dest) {
            strncpy(sub_string_addr_hex, fqdn_str, 8);
            sscanf(sub_string_addr_hex, "%X", &result_addr);
            addr.s_addr = result_addr;
            if (IS_LSI32(addr.s_addr)) {
                exists = 2;
                break;
            } else {
                exists = 1;
                break;
            }
        }
    }     /* end of while */
    if (fd) {
        fclose(fd);
    }
    destroy(&list);

    return exists;
}


/**
 * convert a string containing upper case characters to lower case
 *
 * @param to the result of the conversion (minimum length @c count)
 * @param from a string possibly containing upper case characters
 * @return zero on success or negative on failure
 */
int hip_string_to_lowercase(char *to, const char *from, const size_t count)
{
    if (to == NULL || from == NULL || count == 0) {
        return -1;
    }

    int i = 0;

    for (; i < count; i++) {
        if (isalpha(from[i])) {
            to[i] = tolower(from[i]);
        } else {
            to[i] = from[i];
        }
    }
    return 0;
}

/**
 * test if a given string contains a positive integer
 *
 * @param string the string to test
 * @return zero if the string is digit or negative otherwise
 */
int hip_string_is_digit(const char *string)
{
    if (string == NULL) {
        return -1;
    }

    int i = 0;

    while (string[i] != '\0') {
        if (!isdigit(string[i])) {
            return -1;
        }
        i++;
    }
    return 0;
}



/**
 * verify if a given IPv6 address or IPv6 mapped IPv4 address
 * is a loopback
 *
 * @param addr the address to verify
 * @return one if the address if loopback or zero otherwise
 */
int hip_addr_is_loopback(struct in6_addr *addr)
{
    struct in_addr addr_in;

    if (!IN6_IS_ADDR_V4MAPPED(addr)) {
        return IN6_IS_ADDR_LOOPBACK(addr);
    }
    IPV6_TO_IPV4_MAP(addr, &addr_in);
    return IS_IPV4_LOOPBACK(addr_in.s_addr);
}

/**
 * encode the given content to Base64
 *
 * @param buf Pointer to contents to be encoded
 * @param len How long is the first parameter in bytes
 *
 * @return Returns a pointer to encoded content or NULL on error
 */
unsigned char *base64_encode(unsigned char *buf, unsigned int len)
{
    unsigned char *ret;
    unsigned int b64_len;

    b64_len = (((len + 2) / 3) * 4) + 1;
    ret     = (unsigned char *) malloc(b64_len);
    if (ret == NULL) {
        goto out_err;
    }
    EVP_EncodeBlock(ret, buf, len);
    return ret;
out_err:
    if (ret) {
        free(ret);
    }
    return NULL;
}
