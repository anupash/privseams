/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 *
 * @brief Conversion functions from string to address and vice versa
 *
 * @author Miika Komu <miika@iki.fi>
 */

#define _BSD_SOURCE

#include <errno.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <openssl/evp.h>
#include "config.h"
#include "straddr.h"
#include "debug.h"

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

