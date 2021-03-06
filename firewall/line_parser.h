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

#ifndef HIP_FIREWALL_LINE_PARSER_H
#define HIP_FIREWALL_LINE_PARSER_H

#include <string.h>

#include "mem_area.h"

struct hip_line_parser;

int hip_lp_create(struct hip_line_parser *const lp,
                  const struct hip_mem_area *const ma);
void hip_lp_delete(struct hip_line_parser *const lp);
char *hip_lp_next(struct hip_line_parser *const lp);

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
 * character (not a NULL character).
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

#endif /* HIP_FIREWALL_LINE_PARSER_H */
