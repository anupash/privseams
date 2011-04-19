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

#ifndef HIP_LIB_CORE_SOLVE_H
#define HIP_LIB_CORE_SOLVE_H

#include <stdint.h>

#include "protodefs.h"

/* ensure that the max puzzle difficulty (here 28) is limited by sizeof(int),
 * as ffs() is working on int type.
 *
 * NOTE: ffsll() allowing for sizeof(long long int) is currently not available
 *       on OpenWRT. */
static const uint8_t MAX_PUZZLE_DIFFICULTY = sizeof(int) * 8 >= 28 ? 28 : sizeof(int) * 8;

/** This data type represents the ordered input for the hash function used to
 *  solve a given puzzle challenge as defined in RFC 5201 - Appendix A
 *
 *  solution is correct iff:
 *  0 == V := Ltrunc( RHASH( I2.I | I2.hit_i | I2.hit_r | I2.J ), K ) */
struct puzzle_hash_input {
    uint8_t   puzzle[PUZZLE_LENGTH];
    hip_hit_t initiator_hit;
    hip_hit_t responder_hit;
    uint8_t   solution[PUZZLE_LENGTH];
} __attribute__ ((packed));

int hip_solve_puzzle(struct puzzle_hash_input *puzzle_input,
                     const uint8_t difficulty);

int hip_verify_puzzle_solution(const struct puzzle_hash_input *const puzzle_input,
                               const uint8_t difficulty);

#endif /* HIP_LIB_CORE_SOLVE_H */
