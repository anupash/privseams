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
 * @brief Conversion functions from string to address and vice versa
 */

#define _BSD_SOURCE

#include <stdio.h>
#include <arpa/inet.h>

#include "debug.h"
#include "prefix.h"
#include "straddr.h"

/**
 * Convert a binary IPv6 address to a hexadecimal string representation of the
 * form 0011:2233:4455:6677:8899:AABB:CCDD:EEFF terminated by a NULL character.
 *
 * @param in6 a pointer to a binary IPv6 address.
 * @param buf a pointer to a buffer to write the string representation to. The
 *  result of passing a buffer that is too short to hold the string
 *  representation is undefined.
 * @return The function returns a pointer to the output buffer buf if the
 *  address is successfully converted. It returns a negative value if in6 is
 *  NULL or buf is NULL.
 */
char *hip_in6_ntop(const struct in6_addr *const in6, char *const buf)
{
    if (!in6 || !buf) {
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
 * Convert a string representation of an IPv6 or IPv4 address to a struct
 * in6_addr.
 * If the string contains an IPv4 address, it is converted to its
 * IPv6-compatible mapping.
 *
 * @param str points to the string to convert.
 * @param ip6 points to a buffer where the function stores the binary address
 *  if it could be converted.
 * @return The return value is 0 if the conversion succeeds. It is a
 *  negative value if str or ip6 are NULL or if str contains neither a
 *  parseable IPv6 or IPv4 address.
 */
int hip_convert_string_to_address(const char *const str,
                                  struct in6_addr *const ip6)
{
    if (str && ip6) {
        if (inet_pton(AF_INET6, str, ip6) == 1) {
            /* IPv6 address conversion was ok */
            return 0;
        } else {
            struct in_addr ip4;

            /* Might be an ipv4 address (ret == 0). Lets catch it here. */
            if (inet_pton(AF_INET, str, &ip4) == 1) {
                IPV4_TO_IPV6_MAP(&ip4, ip6);
                HIP_DEBUG("Mapped v4 to v6.\n");
                HIP_DEBUG_IN6ADDR("mapped v6", ip6);
                return 0;
            }
        }
    }

    return -1;
}
