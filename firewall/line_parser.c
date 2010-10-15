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
#include <stdlib.h>  // calloc()

#include "firewall/file_buffer.h"   // hip_fb_create()
#include "firewall/line_parser.h"

/**
 * Creates a parser that iterates over the lines of a given memory area.
 *
 * A line parser object is used to linearly iterate over the lines in a memory
 * area that holds text.
 * The memory area contents are not modified and the returned line pointers are
 * terminated by newline characters, not null characters.
 *
 * When this function returns successfully, hip_lp_first() can be called
 * immediately to start parsing.
 * This function allocates resources, in particular memory, for the returned
 * struct hip_line_parser object.
 * To free these resources and to avoid memory leaks, it is imperative to call
 * hip_lp_delete() when the object created here is no longer used.
 *
 * @param ma the memory area to interpret as text and to parse by lines.
 * @return a line parser instance if the parser could initialize correctly.
 *  NULL, if the specified file could not be accessed.
 */
struct hip_line_parser *hip_lp_create(const struct hip_mem_area *const ma)
{
    struct hip_line_parser *lp = NULL;

    if (ma != NULL) {
        lp = calloc(1, sizeof(struct hip_line_parser));
        if (lp != NULL) {
            // cur is NULL as it should be thanks to calloc()
            lp->ma = ma;
            return lp;
        }
    }

    return NULL;
}

/**
 * Deletes a line parser and releases all resources associated with it (but not
 * the struct hip_mem_area object this parser was created with or the memory
 * backing that memory area).
 *
 * @param lp the line parser object to delete.
 */
void hip_lp_delete(struct hip_line_parser *const lp)
{
    if (lp != NULL) {
        free(lp);
    }
}
