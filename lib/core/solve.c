/*
 * Copyright (c) 2010-2011 Aalto University and RWTH Aachen University.
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
 * @brief HIP computation puzzle solving algorithms
 */

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <openssl/rand.h>

#include "config.h"
#include "builder.h"
#include "crypto.h"
#include "debug.h"
#include "prefix.h"
#include "protodefs.h"
#include "solve.h"

// max. 2^max_puzzle_difficulty tries to solve a puzzle
#define MAX_PUZZLE_SOLUTION_TRIES (1ULL << MAX_PUZZLE_DIFFICULTY)

/**
 * Computes a single iteration for a computational puzzle
 *
 * @param puzzle_input      puzzle to be solved or verified
 * @param difficulty        difficulty of the puzzle (number of leading zeros)
 * @return 0 when hash has >= @a difficulty least significant bits as zeros, 1
 *         when hash has < @a difficulty least significant bits as zeros,
 *         -1 in case of an error
 */
static int hip_single_puzzle_computation(const struct puzzle_hash_input *const puzzle_input,
                                         const uint8_t difficulty)
{
    unsigned char sha_digest[SHA_DIGEST_LENGTH];
    uint32_t      truncated_digest = 0;

    /* any puzzle solution is acceptable for difficulty 0 */
    if (difficulty == 0) {
        return 0;
    }

    if (difficulty > MAX_PUZZLE_DIFFICULTY) {
        HIP_ERROR("difficulty exceeds max. configured difficulty\n");
        return -1;
    }

    if (hip_build_digest(HIP_DIGEST_SHA1, puzzle_input,
                         sizeof(struct puzzle_hash_input), sha_digest)) {
        HIP_ERROR("failed to compute hash digest\n");
        return -1;
    }

    /* In reference to RFC 5201, we need to interpret the hash digest as an
     * integer in network byte-order. We are interested in least significant
     * bits here. */
    truncated_digest = *(uint32_t *) &sha_digest[SHA_DIGEST_LENGTH - sizeof(truncated_digest)];

    /* Make sure to interpret the solution equally across platforms
     * (i.e., network byte-order), when calculating the puzzle solution.
     *
     * The problem is that ffs() interprets its input not as a byte array
     * but as an integer with an encoding that depends on the host byte order.
     * htonl() ensures that ffs() performs the check in network byte order
     * independent from the actual host byte order. */
    truncated_digest = htonl(truncated_digest);

    /* check if position of first least significant 1-bit is higher than
     * difficulty */
    if (ffs(truncated_digest) > difficulty) {
        return 0;
    }

    return 1;
}

/**
 * Solve a computational puzzle for HIP
 *
 * @param puzzle_input  puzzle to be solved or verified
 * @param difficulty    difficulty of the puzzle
 * @return 0 when solution was found, 1 in case no solution was found after
 *         ::MAX_PUZZLE_SOLUTION_TRIES, -1 in case of an error
 *
 * @note provide data for all members of puzzle_input when calling this function
 * @note puzzle_input will contain the solution on successful exit
 */
int hip_solve_puzzle(struct puzzle_hash_input *const puzzle_input,
                     const uint8_t difficulty)
{
    int err = -1;

    // any puzzle solution is acceptable for difficulty 0
    if (difficulty == 0) {
        return 0;
    }

    /* If max_puzzle_difficulty >= 64, MAX_PUZZLE_SOLUTION_TRIES will be 0.
     * Hence, no solution will be found for these cases. */
    HIP_ASSERT(MAX_PUZZLE_DIFFICULTY < sizeof(unsigned long long) * 8);

    if (difficulty > MAX_PUZZLE_DIFFICULTY) {
        HIP_ERROR("Cookie (K = %u) is higher than we are willing to calculate "
                  "(current max K = %u)\n", difficulty, MAX_PUZZLE_DIFFICULTY);
        return -1;
    }

    for (unsigned long long i = 0; i < MAX_PUZZLE_SOLUTION_TRIES; i++) {
        err = hip_single_puzzle_computation(puzzle_input,
                                            difficulty);
        if (err == 0) {
            return 0;
        } else if (err > 0) {
            // increase random value by one and try again
            (*(uint64_t *) puzzle_input->solution)++;
        } else {
            HIP_ERROR("error while computing the puzzle solution\n");
            memset(puzzle_input, 0, PUZZLE_LENGTH);
            return -1;
        }
    }

    HIP_ERROR("Could not solve the puzzle, no solution found\n");
    return 1;
}

/**
 * Verify a computational puzzle for HIP
 *
 * @param puzzle_input  puzzle to be solved or verified
 * @param difficulty    difficulty of the puzzle
 * @return 0 when solution is correct, -1 otherwise
 */
int hip_verify_puzzle_solution(const struct puzzle_hash_input *const puzzle_input,
                               const uint8_t difficulty)
{
    // any puzzle solution is acceptable for difficulty 0
    if (difficulty == 0) {
        return 0;
    }

    if (hip_single_puzzle_computation(puzzle_input, difficulty)) {
        HIP_ERROR("failed to verify puzzle solution\n");
        return -1;
    }

    return 0;
}
