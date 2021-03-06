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

#ifndef HIP_HIPD_KEYMAT_H
#define HIP_HIPD_KEYMAT_H

#include <stdint.h>
#include <netinet/in.h>
#include <sys/types.h>

#include "lib/core/protodefs.h"
#include "lib/core/state.h"


void hip_make_keymat(char *kij, size_t kij_len,
                     struct hip_keymat_keymat *keymat,
                     void *dstbuf, size_t dstbuflen, struct in6_addr *hit1,
                     struct in6_addr *hit2, uint8_t *calc_index,
                     const uint8_t I[PUZZLE_LENGTH],
                     const uint8_t J[PUZZLE_LENGTH]);
int hip_keymat_draw_and_copy(unsigned char *dst,
                             struct hip_keymat_keymat *keymat,
                             int len);

#endif /* HIP_HIPD_KEYMAT_H */
