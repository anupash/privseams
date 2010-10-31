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
 * Initializes a parser that iterates over the lines of a given memory area.
 *
 * A line parser object is used to linearly iterate over the lines in a memory
 * area that holds text.
 * The memory area contents are not modified and the returned line pointers are
 * terminated by newline characters, not null characters.
 *
 * When this function returns successfully, hip_lp_first() can be called
 * immediately to start parsing.
 * This function allocates resources, in particular memory, for the returned
 * object.
 * To free these resources and to avoid memory leaks, it is imperative to call
 * hip_lp_delete() when the object created here is no longer used.
 *
 * @param lp a pointer to a valid, allocated instance of struct hip_line_parser.
 *  Upon successful completion, the function writes parser-specific context
 *  data to the location referenced by lp.
 * @param ma the memory area to interpret as text and to parse by lines.
 * @return 0 if the line parser lp was successfully initialized.
 *  This function return -1 if lp is NULL or if ma is NULL.
 */
int hip_lp_create(struct hip_line_parser *const lp,
                  const struct hip_mem_area *const ma)
{
    if (lp && ma) {
        lp->ma  = ma;
        lp->cur = NULL;
        return 0;
    }

    return -1;
}

/**
 * Releases the resources allocated for a line parser object in
 * hip_lp_create().
 * This does not include the memory pointed to by lp or the struct hip_mem_area
 * object this parser was created with or the memory backing that memory area).
 *
 * @param lp the line parser object to delete.
 *  If lp is NULL, calling this function has no effect.
 */
void hip_lp_delete(struct hip_line_parser *const lp)
{
    if (lp != NULL) {
        lp->ma  = NULL;
        lp->cur = NULL;
    }
}
