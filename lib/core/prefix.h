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

#ifndef HIP_LIB_CORE_PREFIX_H
#define HIP_LIB_CORE_PREFIX_H

#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "protodefs.h"

#define HIP_TMP_FNAME_TEMPLATE "/tmp/hip_XXXXXX"

struct hosts_file_line {
    char            *hostname, *alias, *alias2;
    struct in6_addr id;
    int             lineno;
};


typedef uint32_t hip_closest_prefix_type_t;

int ipv6_addr_is_hit(const struct in6_addr *hit);
int ipv6_addr_is_teredo(const struct in6_addr *teredo);
int ipv6_addr_is_null(const struct in6_addr *ip);
int hit_is_real_hit(const struct in6_addr *hit);
int hit_is_opportunistic_hit(const struct in6_addr *hit);
void set_hit_prefix(struct in6_addr *hit);
void set_lsi_prefix(hip_lsi_t *lsi);
int hip_id_type_match(const struct in6_addr *id, int id_type);
int hip_opportunistic_ipv6_to_hit(const struct in6_addr *ip,
                                  struct in6_addr *hit, int hit_type);
void *hip_cast_sa_addr(struct sockaddr *sa);
int hip_sockaddr_len(const void *sockaddr);
int hip_sa_addr_len(void *sockaddr);
void hip_addr_to_sockaddr(struct in6_addr *addr, struct sockaddr_storage *sa);
int hip_sockaddr_is_v6_mapped(struct sockaddr *sa);
int hip_addr_is_loopback(struct in6_addr *addr);
int hip_lsi_are_equal(const hip_lsi_t *lsi1,
                      const hip_lsi_t *lsi2);

int ipv4_addr_cmp(const struct in_addr *a1,
                  const struct in_addr *a2);
void ipv4_addr_copy(struct in_addr *a1,
                    const struct in_addr *a2);
int ipv6_addr_cmp(const struct in6_addr *a1,
                  const struct in6_addr *a2);
void ipv6_addr_copy(struct in6_addr *a1,
                    const struct in6_addr *a2);
int ipv6_addr_any(const struct in6_addr *a);
void hip_copy_in6addr_null_check(struct in6_addr *to,
                                 const struct in6_addr *from);
void hip_copy_inaddr_null_check(struct in_addr *to,
                                const struct in_addr *from);

/* IN6_IS_ADDR_V4MAPPED(a) is defined in /usr/include/netinet/in.h */

#define IPV4_TO_IPV6_MAP(in_addr_from, in6_addr_to)                       \
    {(in6_addr_to)->s6_addr32[0] = 0;                                \
     (in6_addr_to)->s6_addr32[1] = 0;                                \
     (in6_addr_to)->s6_addr32[2] = htonl(0xffff);                    \
     (in6_addr_to)->s6_addr32[3] = (uint32_t) ((in_addr_from)->s_addr); }

#define IPV6_TO_IPV4_MAP(in6_addr_from, in_addr_to)    \
    { ((in_addr_to)->s_addr) =                       \
          ((in6_addr_from)->s6_addr32[3]); }

#define IPV6_EQ_IPV4(in6_addr_a, in_addr_b)   \
    (IN6_IS_ADDR_V4MAPPED(in6_addr_a) && \
    (((const uint32_t *) (in6_addr_a))[3] == (in_addr_b)->s_addr))

/**
 * Checks if a uint32_t represents a Local Scope Identifier (LSI).
 *
 * @param       a the uint32_t to test
 * @return      true if @c a is from 1.0.0.0/8
 * @note        This macro tests directly uint32_t, not struct in_addr or a pointer
 *              to a struct in_addr. To use this macro in context with struct
 *              in_addr call it with ipv4->s_addr where ipv4 is a pointer to a
 *              struct in_addr.
 */
#define IS_LSI32(a) ((a & 0x000000FF) == 0x00000001)

#define IS_LSI(a) ((((struct sockaddr *) a)->sa_family == AF_INET) ? \
                   (IS_LSI32(((struct sockaddr_in *) a)->sin_addr.s_addr)) : \
                   (ipv6_addr_is_hit( &((struct sockaddr_in6 *) a)->sin6_addr)))

/**
 * A macro to test if a uint32_t represents an IPv4 loopback address.
 *
 * @param a the uint32_t to test
 * @return  non-zero if @c a is from 127.0.0.0/8
 * @note    This macro tests directly uint32_t, not struct in_addr or a pointer
 *          to a struct in_addr. To use this macro in context with struct
 *          in_addr call it with ipv4->s_addr where ipv4 is a pointer to a
 *          struct in_addr.
 */
#define IS_IPV4_LOOPBACK(a) ((a & 0x000000FF) == 0x0000007F)

#ifndef MIN
#  define MIN(a, b)      ((a) < (b) ? (a) : (b))
#endif

#ifndef MAX
#  define MAX(a, b)      ((a) > (b) ? (a) : (b))
#endif

#if __BYTE_ORDER == __BIG_ENDIAN
#define hton64(i) (i)
#define ntoh64(i) (i)
#else
#define hton64(i) (((uint64_t) (htonl((i) & 0xffffffff)) << 32) | htonl(((i) >> 32) & 0xffffffff ))
#define ntoh64 hton64
#endif

#endif /* HIP_LIB_CORE_PREFIX_H */
