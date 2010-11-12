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
 * @author Stefan Goetz <stefan.goetz@cs.rwth-aachen.de>
 */

#ifndef HIP_FIREWALL_LINE_PARSER_INLINE_H
#define HIP_FIREWALL_LINE_PARSER_INLINE_H

/* On the one hand, the contents of this file are part of the public interface
 * and thus only their declaration should go into the public header file.
 * On the other hand, these functions should be inlineable so their definitions
 * have to appear in a header file.
 * To achieve inlineability and still hide the implementation, we use this
 * secondary header file that is not part of the public interface. */
#ifndef HIP_FIREWALL_LINE_PARSER_H
#error This file must not be included directly because it contains implementation details. It may only be included by line_parser.h.
#endif

#include <string.h>

#include "lib/core/debug.h"
#include "file_buffer.h"

/**
 * Represents the parsing state on a memory area object.
 */
struct hip_line_parser {
    /**
     * The memory area this parser operates on.
     */
    const struct hip_mem_area *ma;
    /**
     * The current parsing position.
     * If NULL, hip_lp_first() needs to be called.
     * If != NULL, points to the start of line in the memory buffer.
     */
    char *cur;
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
static inline char *hip_lp_first(struct hip_line_parser *const lp)
{
    if (!lp ||
        !lp->ma) {
        return NULL;
    }

    lp->cur = lp->ma->start;

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
static inline char *hip_lp_next(struct hip_line_parser *const lp)
{
    size_t remaining;

    if (!lp ||
        !lp->cur ||
        !lp->ma ||
        !lp->ma->start ||
        !lp->ma->end ||
        lp->cur < lp->ma->start ||
        lp->cur >= lp->ma->end) {
        return NULL;
    }

    remaining   = lp->ma->end - lp->cur;
    lp->cur     = memchr(lp->cur, '\n', remaining);

    // given the rest of the parsing code, we should always find a \n, but
    // let's check to be sure
    if (lp->cur) {
        // cur should not point to the new-line character but to the next one:
        lp->cur += 1;
        // is there text on the line here or are we at the end?
        if (lp->cur >= lp->ma->end) {
            lp->cur = NULL;
        }
    }

    return lp->cur;
}

#endif /* HIP_FIREWALL_LINE_PARSER_INLINE_H */
