/**
 * @file
 *
 * Copyright (c) 2010 Aalto University) and RWTH Aachen University.
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
 *
 * This file contains address-related utility functions to
 * manipulate LSI/HIT prefixes
 *
 * @brief Address-related utility functions
 *
 * @author Miika Komu <miika@iki.fi>
 */

#define _BSD_SOURCE

#include "prefix.h"
#include "builder.h"

/* Definitions */
#define HIP_ID_TYPE_HIT     1
#define HIP_ID_TYPE_LSI     2

/**
 * Test if the given IPv6 address has HIT prefix (RFC4843 ORCHID prefix)
 *
 * @param hit the address to be tested
 * @return 1 if the address has the HIT prefix or zero otherwise
 */
int ipv6_addr_is_hit(const struct in6_addr *hit)
{
    hip_closest_prefix_type_t hit_begin;
    memcpy(&hit_begin, hit, sizeof(hip_closest_prefix_type_t));
    hit_begin  = ntohl(hit_begin);
    hit_begin &= HIP_HIT_TYPE_MASK_INV;
    return hit_begin == HIP_HIT_PREFIX;
}

/**
 * Test if a given IPv6 address has a Teredo (RFC4380) prefix
 *
 * @param teredo the IPv6 address to be tested for Teredo prefix
 * @return 1 if the address has the Teredo prefix or zero otherwise
 */
int ipv6_addr_is_teredo(const struct in6_addr *teredo)
{
    hip_closest_prefix_type_t teredo_begin;
    memcpy(&teredo_begin, teredo, sizeof(hip_closest_prefix_type_t));
    teredo_begin  = ntohl(teredo_begin);
    teredo_begin &= HIP_TEREDO_TYPE_MASK_INV;
    return teredo_begin == HIP_TEREDO_PREFIX;
}

/**
 * Test if an IPv6 address is all zeroes
 *
 * @param ip the IPv6 address to test
 * @return one if the address is all zeroes and zero otherwise
 */
int ipv6_addr_is_null(struct in6_addr *ip)
{
    return (ip->s6_addr32[0] | ip->s6_addr32[1] |
            ip->s6_addr32[2] | ip->s6_addr32[3]) == 0;
}

/**
 * Test if a given IPv6 address is a real HIT instead of a
 * pseudo hit
 *
 * @param hit the IPv6 address to be tested
 * @return one if the IPv6 address was a real HIT and
'          zero if it was a pseudo HIT
 */
int hit_is_real_hit(const struct in6_addr *hit)
{
    return ipv6_addr_is_hit(hit) && (hit->s6_addr32[3] != 0);
}

/**
 * Test if a given IPv6 address is a pseudo HIT instead of a
 * real HIT
 *
 * @param hit the IPv6 address to be tested
 * @return zero if the IPv6 address was a real HIT and
'          one if it was a pseudo HIT
 */
int hit_is_opportunistic_hit(const struct in6_addr *hit)
{
    return ipv6_addr_is_hit(hit) && (hit->s6_addr32[3] == 0);
}

/**
 * Fill in the HIT prefix for a given IPv6 address
 *
 * @param hit an IPv6 address for which to set the HIT prefix
 */
void set_hit_prefix(struct in6_addr *hit)
{
    hip_closest_prefix_type_t hit_begin;
    memcpy(&hit_begin, hit, sizeof(hip_closest_prefix_type_t));
    hit_begin &= htonl(HIP_HIT_TYPE_MASK_CLEAR);
    hit_begin |= htonl(HIP_HIT_PREFIX);
    memcpy(hit, &hit_begin, sizeof(hip_closest_prefix_type_t));
}

/**
 * Fill in the LSI prefix for a given IPv4 address
 *
 * @param lsi an IPv4 address for which to set the LSI prefix
 */
void set_lsi_prefix(hip_lsi_t *lsi)
{
    hip_closest_prefix_type_t lsi_begin;
    memcpy(&lsi_begin, lsi, sizeof(hip_closest_prefix_type_t));
    lsi_begin &= htonl(HIP_LSI_TYPE_MASK_CLEAR);
    lsi_begin |= htonl(HIP_LSI_PREFIX);
    memcpy(lsi, &lsi_begin, sizeof(hip_closest_prefix_type_t));
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
 * check the type of an IPv6 addresses
 *
 * @param id an IPv6 address, possibly in IPv6 mapped format
 * @param id_type HIP_ID_TYPE_HIT or HIP_ID_TYPE_LSI
 *
 * @return zero for type match, greater than zero for mismatch or
 * negative on error
 */
int hip_id_type_match(const struct in6_addr *id, int id_type)
{
    int ret = 0, is_lsi = 0, is_hit = 0;
    hip_lsi_t lsi;

    if (ipv6_addr_is_hit(id)) {
        is_hit = 1;
    } else if (IN6_IS_ADDR_V4MAPPED(id)) {
        IPV6_TO_IPV4_MAP(id, &lsi);
        if (IS_LSI32(lsi.s_addr)) {
            is_lsi = 1;
        }
    }

    HIP_ASSERT(!(is_lsi && is_hit));

    if (id_type == HIP_ID_TYPE_HIT) {
        ret = (is_hit ? 1 : 0);
    } else if (id_type == HIP_ID_TYPE_LSI) {
        ret = (is_lsi ? 1 : 0);
    } else {
        ret = ((is_hit || is_lsi) ? 0 : 1);
    }

    return ret;
}

#ifdef CONFIG_HIP_OPPORTUNISTIC
/**
 * Convert a given IP address into a pseudo HIT
 *
 * @param ip an IPv4 or IPv6 address address
 * @param hit a pseudo HIT generated from the IP address
 * @param hit_type the type of the HIT
 * @return zero on success and non-zero on failure
 * @see  <a
 * href="http://hipl.hiit.fi/hipl/thesis_teresa_finez.pdf">T. Finez,
 * Backwards Compatibility Experimentation with Host Identity Protocol
 * and Legacy Software and Networks , final project, December 2008</a>
 *
 */
int hip_opportunistic_ipv6_to_hit(const struct in6_addr *ip,
                                  struct in6_addr *hit,
                                  int hit_type)
{
    int err              = 0;
    uint8_t digest[HIP_AH_SHA_LEN];
    char *key            = (char *) (ip);
    unsigned int key_len = sizeof(struct in6_addr);

    HIP_IFE(hit_type != HIP_HIT_TYPE_HASH100, -ENOSYS);
    HIP_IFEL((err = hip_build_digest(HIP_DIGEST_SHA1, key, key_len, digest)),
             err,
             "Building of digest failed\n");

    memcpy(hit, digest + (HIP_AH_SHA_LEN - sizeof(struct in6_addr)),
           sizeof(struct in6_addr));

    hit->s6_addr32[3] = 0; // this separates phit from normal hit

    set_hit_prefix(hit);

out_err:

    return err;
}

#endif /* CONFIG_HIP_OPPORTUNISTIC */

/**
 * cast a socket address to an IPv4 or IPv6 address.
 *
 * @note The parameter @c sockaddr is first cast to a struct sockaddr
 * and the IP address cast is then done based on the value of the
 * sa_family field in the struct sockaddr. If sa_family is neither
 * AF_INET nor AF_INET6, the cast fails.
 *
 * @param  sa a pointer to a socket address that holds the IP address.
 * @return          a pointer to an IPv4 or IPv6 address inside @c sockaddr or
 *                  NULL if the cast fails.
 */

void *hip_cast_sa_addr(const struct sockaddr *sa)
{
    if (sa == NULL) {
        HIP_ERROR("sockaddr is NULL, skipping type conversion\n");

        return NULL;
    }

    switch (sa->sa_family) {
    case AF_INET:
        return &(((struct sockaddr_in *) sa)->sin_addr);
    case AF_INET6:
        return &(((struct sockaddr_in6 *) sa)->sin6_addr);
    default:
        HIP_ERROR("unhandled type: %i, skipping cast\n", sa->sa_family);
        return NULL;
    }
}

/**
 * Test if a sockaddr_in6 structure is in IPv6 mapped format (i.e.
 * contains an IPv4 address)
 *
 * @param sa socket address structure
 * @return one if the structure is in IPv6 mapped format or zero otherwise
 */
int hip_sockaddr_is_v6_mapped(struct sockaddr *sa)
{
    int family = sa->sa_family;

    HIP_ASSERT(family == AF_INET || family == AF_INET6);
    if (family != AF_INET6) {
        return 0;
    } else {
        return IN6_IS_ADDR_V4MAPPED((struct in6_addr *) hip_cast_sa_addr(sa));
    }
}

/**
 * Calculate the actual length of any sockaddr structure
 *
 * @param sockaddr the sockaddr structure
 * @return the length of the actual sockaddr structure in bytes
 */
int hip_sockaddr_len(const void *sockaddr)
{
    struct sockaddr *sa = (struct sockaddr *) sockaddr;
    int len;

    switch (sa->sa_family) {
    case AF_INET:
        len = sizeof(struct sockaddr_in);
        break;
    case AF_INET6:
        len = sizeof(struct sockaddr_in6);
        break;
    case AF_UNIX:
        len = sizeof(struct sockaddr_un);
        break;
    default:
        len = 0;
    }
    return len;
}

/**
 * Calculate the address field length of any sockaddr structure
 *
 * @param sockaddr the sockaddr structure
 * @return the length of the address field in the @c sockaddr structure
 */
int hip_sa_addr_len(void *sockaddr)
{
    struct sockaddr *sa = (struct sockaddr *) sockaddr;
    int len;

    switch (sa->sa_family) {
    case AF_INET:
        len = 4;
        break;
    case AF_INET6:
        len = 16;
        break;
    default:
        len = 0;
    }
    return len;
}

/**
 * converts an in6_addr structure to sockaddr_storage
 *
 * @param addr the in6_addr to convert
 * @param sa a sockaddr_storage structure where the result is stored
 * @note remember to fill in the port number by yourself
 *       if necessary
 */
void hip_addr_to_sockaddr(struct in6_addr *addr, struct sockaddr_storage *sa)
{
    memset(sa, 0, sizeof(struct sockaddr_storage));

    if (IN6_IS_ADDR_V4MAPPED(addr)) {
        struct sockaddr_in *in = (struct sockaddr_in *) sa;
        in->sin_family = AF_INET;
        IPV6_TO_IPV4_MAP(addr, &in->sin_addr);
    } else {
        struct sockaddr_in6 *in6 = (struct sockaddr_in6 *) sa;
        in6->sin6_family = AF_INET6;
        ipv6_addr_copy(&in6->sin6_addr, addr);
    }
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

int ipv4_addr_cmp(const struct in_addr *a1,
                                const struct in_addr *a2) {
    return memcmp((const char *) a1, (const char *) a2,
                  sizeof(struct in_addr));
}

void ipv4_addr_copy(struct in_addr *a1,
                                  const struct in_addr *a2) {
    memcpy((char *) a1, (const char *) a2, sizeof(struct in_addr));
}

int ipv6_addr_cmp(const struct in6_addr *a1,
                  const struct in6_addr *a2) {
    return memcmp((const char *) a1, (const char *) a2,
                  sizeof(struct in6_addr));
}

void ipv6_addr_copy(struct in6_addr *a1,
               const struct in6_addr *a2) {
    memcpy((char *) a1, (const char *) a2, sizeof(struct in6_addr));
}

int ipv6_addr_any(const struct in6_addr *a) {
    return (a->s6_addr[0] | a->s6_addr[1] | a->s6_addr[2] | a->s6_addr[3] |
            a->s6_addr[4] |a->s6_addr[5] |a->s6_addr[6] |a->s6_addr[7] |
            a->s6_addr[8] |a->s6_addr[9] |a->s6_addr[10] |a->s6_addr[11] |
            a->s6_addr[12] |a->s6_addr[13] |a->s6_addr[14] |a->s6_addr[15]) == 0;
}

void hip_copy_in6addr_null_check(struct in6_addr *to,
                                 struct in6_addr *from) {
    HIP_ASSERT(to);
    if (from) {
        ipv6_addr_copy(to, from);
    } else {
        memset(to, 0, sizeof(*to));
    }
}

void hip_copy_inaddr_null_check(struct in_addr *to,
                                struct in_addr *from) {
    HIP_ASSERT(to);
    if (from) {
        memcpy(to, from, sizeof(*to));
    } else {
        memset(to, 0, sizeof(*to));
    }
}


