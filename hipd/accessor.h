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
 */

#ifndef HIP_HIPD_ACCESSOR_H
#define HIP_HIPD_ACCESSOR_H

#include "lib/core/protodefs.h"

/** @defgroup daemon_states HIP daemon states
 * @{
 */
/** Low mask for daemon states. */
#define HIPD_STATE_MASK         0xff
/** Daemon is ok and executing. */
#define HIPD_STATE_EXEC         0x00
/** Daemon is closing. */
#define HIPD_STATE_CLOSING      0x01
/** Daemon is closed, exiting main(). */
#define HIPD_STATE_CLOSED       0x02

/** Daemon is restarting. */
#define HIPD_FLAG_RESTART       0x00000100
/* @} */

#define INDEX_HASH_LENGTH       SHA_DIGEST_LENGTH

#define INDEX_HASH_FN           HIP_DIGEST_SHA1

unsigned int hipd_get_state(void);
void hipd_set_state(unsigned int);
int hipd_get_flag(unsigned int);
void hipd_set_flag(unsigned int);

#endif /* HIP_HIPD_ACCESSOR_H */

