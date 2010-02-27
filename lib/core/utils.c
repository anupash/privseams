/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 *
 * This file contains mostly address-related utility functions to
 * manipulate LSI/HIT prefixes
 *
 * @brief Address-related utility functions
 *
 * @author Miika Komu <miika@iki.fi>
 */

/* required for s6_addr32 */
#define _BSD_SOURCE

#include "utils.h"

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
 * Test if a given IPv6 address is a pseudo HIT instead of a
 * real HIT
 *
 * @param hit the IPv6 address to be tested
 * @return zero if the IPv6 address was a real HIT and
'          one if it was a pseudo HIT
 */
int hit_is_opportunistic_hashed_hit(const struct in6_addr *hit)
{
    return hit_is_opportunistic_hit(hit);
}

/**
 * Test if an IPv6 address is all zeroes
 *
 * @param ip the IPv6 address to test
 * @return one if the address is all zeroes and zero otherwise
 */
int hit_is_opportunistic_null(const struct in6_addr *hit)
{
    // return hit_is_opportunistic_hit(hit);
    return (hit->s6_addr32[0] | hit->s6_addr32[1] |
            hit->s6_addr32[2] | (hit->s6_addr32[3]))  == 0;
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
inline void set_lsi_prefix(hip_lsi_t *lsi)
{
    hip_closest_prefix_type_t lsi_begin;
    memcpy(&lsi_begin, lsi, sizeof(hip_closest_prefix_type_t));
    lsi_begin &= htonl(HIP_LSI_TYPE_MASK_CLEAR);
    lsi_begin |= htonl(HIP_LSI_PREFIX);
    memcpy(lsi, &lsi_begin, sizeof(hip_closest_prefix_type_t));
}
