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
 * @brief HIP computation puzzle solving algorithms
 *
 * @author Miika Komu <miika@iki.fi>
 */

#include "solve.h"

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

    /* pre-create cookie */
    u = puzzle_or_solution;

    HIP_IFEL(u->pz.K > HIP_PUZZLE_MAX_K, 0,
             "Cookie K %u is higher than we are willing to calculate"
             " (current max K=%d)\n", u->pz.K, HIP_PUZZLE_MAX_K);

    mask = hton64((1ULL << u->pz.K) - 1);
    memcpy(cookie, (uint8_t *) &(u->pz.I), sizeof(uint64_t));

    HIP_DEBUG("(u->pz.I: 0x%llx\n", u->pz.I);

    if (mode == HIP_VERIFY_PUZZLE) {
        ipv6_addr_copy((hip_hit_t *) (cookie + 8), &hdr->hits);
        ipv6_addr_copy((hip_hit_t *) (cookie + 24), &hdr->hitr);
        randval  = u->sl.J;
        maxtries = 1;
    } else if (mode == HIP_SOLVE_PUZZLE) {
        ipv6_addr_copy((hip_hit_t *) (cookie + 8), &hdr->hitr);
        ipv6_addr_copy((hip_hit_t *) (cookie + 24), &hdr->hits);
        maxtries = 1ULL << (u->pz.K + 3);
        get_random_bytes(&randval, sizeof(uint64_t));
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
 * @return zero on success and negative on error
 * @see <a
 * href="http://tools.ietf.org/id/draft-heer-hip-middle-auth">Heer et
 * al, End-Host Authentication for HIP Middleboxes, Internet draft,
 * work in progress, February 2009</a>
 */
int hip_solve_puzzle_m(struct hip_common *out, struct hip_common *in)
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

        HIP_IFEL((solution = hip_solve_puzzle(&tmp, in, HIP_SOLVE_PUZZLE)) == 0,
                 -EINVAL,
                 "Solving of puzzle failed\n");

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

