/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 *
 * @brief HIT-related utility functions
 *
 * @author Miika Komu <miika@iki.fi>
 */

#define _BSD_SOURCE

#include "config.h"
#include "hit.h"
#include "debug.h"
#include "straddr.h"
#include "builder.h"

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