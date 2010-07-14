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
 * @brief HIT-related utility functions
 *
 * @author Miika Komu <miika@iki.fi>
 */

#include <stdint.h>
#include <string.h>

#include "config.h"
#include "builder.h"
#include "debug.h"
#include "prefix.h"
#include "protodefs.h"
#include "straddr.h"
#include "hit.h"

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
 * hip_hash_hit - calculate a hash from a HIT
 *
 * @param ptr pointer to a HIT
 *
 * Returns value in range: 0 <= x < range
 */
unsigned long hip_hash_hit(const void *ptr)
{
    uint8_t hash[HIP_AH_SHA_LEN];

    hip_build_digest(HIP_DIGEST_SHA1, (uint8_t *)ptr + sizeof(uint16_t),
                     7 * sizeof(uint16_t), hash);

    return *((unsigned long *) hash);
}
