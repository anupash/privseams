/**
 * @file
 *
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
 *
 * @author Stefan Goetz <stefan.goetz@cs.rwth-aachen.de>
 */
#ifndef HIP_FIREWALL_LINE_PARSER_INLINE_H
#define HIP_FIREWALL_LINE_PARSER_INLINE_H

#ifndef HIP_FIREWALL_LINE_PARSER_H
#error This file must not be included directly because it contains implementation details. It may only be included by line_parser.h.
#endif

#include <string.h> // memchr()

#include "lib/core/debug.h" // HIP_ASSERT()
#include "firewall/file_buffer.h"   // hip_lp_create()

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A line parser object is used to linearly iterate over the lines in a memory
 * area that holds text.
 * The buffer contents are not modified and the returned line pointers are
 * terminated by newline characters, not null characters.
 */
struct hip_line_parser {
    /**
     * The current parsing position.
     * If NULL, hip_lp_first() needs to be called.
     * If != NULL, points to the start of line in the memory buffer.
     */
    char *cur;
    /**
     * The memory buffer this parser operates on.
     */
    hip_file_buffer_t *fb;
};

/**
 * Start a new parsing pass with a line parser and return the first line in the
 * buffer.
 * The buffer is not modified and the line is terminated by a newline
 * character (not a null character).
 *
 * A parsing pass consists of starting it via hip_lp_first() and iterating over
 * the lines in the file via hip_lp_next() until it returns NULL.
 *
 * @param lp the line parser to use.
 * @return a pointer to the first line in the file or NULL if no line is
 *  available.
 */
static inline char *hip_lp_first(hip_line_parser_t *lp)
{
    if (NULL == lp ||
        NULL == lp->fb) {
        return NULL;
    }

    lp->cur = lp->fb->start;

    return lp->cur;
}

/**
 * Get the next line in a parsing pass with a line parser.
 *
 * Each invocation of this function returns a pointer to consecutive lines in
 * the buffer to parse.
 * After the last line has been reached, NULL is returned.
 * In that case, parsing can restart by calling hip_lp_first().
 *
 * @param lp the line parser parser to use.
 * @return a pointer to a line in the buffer or NULL if there are no more lines
 *  available.
 */
static inline char *hip_lp_next(hip_line_parser_t *lp)
{
    size_t remaining;

    if (NULL == lp ||
        NULL == lp->cur ||
        NULL == lp->fb ||
        NULL == lp->fb->start ||
        NULL == lp->fb->end ||
        lp->cur < lp->fb->start ||
        lp->cur >= lp->fb->end) {
        return NULL;
    }

    remaining = lp->fb->end - lp->cur;
    lp->cur = (char *)memchr(lp->cur, '\n', remaining);

    // given the rest of the parsing code, we should always find a \n, but
    // let's check to be sure
    if (lp->cur != NULL) {
        // cur should not point to the new-line character but to the next one:
        lp->cur += 1;
        // is there text on the line here or are we at the end?
        if (lp->cur >= lp->fb->end) {
            lp->cur = NULL;
        }
    }

    return lp->cur;
}

#ifdef __cplusplus
}
#endif

#endif
