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
 * @brief HIT-related utility functions
 */

#include <string.h>

#include "debug.h"
#include "prefix.h"
#include "straddr.h"
#include "hit.h"

/**
 * Convert a binary HIT to a hexadecimal string representation of the form
 * 0011:2233:4455:6677:8899:AABB:CCDD:EEFF terminated by a NULL character.
 *
 * @param hit a pointer to a binary HIT.
 * @param suffix an optional NULL-terminated string suffix to be appended to
 *  the HIT. If suffix is NULL or the empty string, no suffix is appended. If
 *  suffix is not NULL-terminated, the result is undefined.
 * @param hit_str a pointer to a buffer to write the HIT and the suffix to. The
 *  result of passing a buffer that is too short to hold the string
 *  representation plus the suffix is undefined.
 * @return 0 if the HIT was successfully converted. Returns a negative value if
 *  hit is NULL or hit_str is NULL.
 */
int hip_convert_hit_to_str(const hip_hit_t *const hit,
                           const char *const suffix,
                           char *const hit_str)
{
    if (hit && hit_str) {
        if (hip_in6_ntop(hit, hit_str)) {
            if (suffix && *suffix != '\0') {
                strcpy(hit_str + strlen(hit_str), suffix);
            }
            return 0;
        }
    }

    return -1;
}

/**
 * Determine whether a HIT is numerically greater than another.
 *
 * @param hit_gt    a pointer to a HIT. When passing a NULL pointer, the result
 *  of this function is undefined.
 * @param hit_le    a pointer to a HIT. When passing a NULL pointer, the result
 *  of this function is undefined.
 * @return 1 if hit_gt is greater than hit_le, otherwise 0.
 */
int hip_hit_is_bigger(const struct in6_addr *const hit_gt,
                      const struct in6_addr *const hit_le)
{
    HIP_ASSERT(hit_gt);
    HIP_ASSERT(hit_le);
    return ipv6_addr_cmp(hit_gt, hit_le) > 0;
}
