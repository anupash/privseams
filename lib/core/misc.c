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

#include <string.h>

#include "config.h"
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
 * @return zero on success or negative on error
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
