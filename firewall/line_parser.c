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
#include <stdlib.h>  // calloc()

#include "lib/core/debug.h" // HIP_ASSERT()
#include "firewall/file_buffer.h"   // hip_fb_new()
#include "firewall/line_parser.h"

/**
 * Creates a line parser that can parse the specified file.
 *
 * When this function returns successfully, hip_lp_first() can be called
 * immediately to start parsing.
 *
 * @param file_name the name of the file to parse.
 * @return a line parser instance if the parser could initialize correctly.
 *  NULL, if the specified file could not be accessed.
 */
hip_line_parser_t *hip_lp_new(const char *file_name)
{
    hip_line_parser_t *lp = NULL;

    HIP_ASSERT(file_name != NULL);

    lp = (hip_line_parser_t *)calloc(1, sizeof(hip_line_parser_t));
    if (lp != NULL) {
        // cur is NULL as it should be thanks to calloc()
        lp->fb = hip_fb_new(file_name);
        if (lp->fb != NULL) {
            return lp;
        }
        hip_lp_delete(lp);
    }

    return NULL;
}

/**
 * Deletes a line parser and releases all resources associated with it.
 *
 * @param lp the line parser object to delete.
 */
void hip_lp_delete(hip_line_parser_t *lp)
{
    HIP_ASSERT(lp != NULL);
    if (lp->fb != NULL) {
        hip_fb_delete(lp->fb);
    }
    free(lp);
}

/**
 * If the line parser uses a file-based memory buffer, reload the file contents
 * to reflect any changes in the file since the last invocation of hip_lp_new()
 * or hip_lp_reload().
 *
 * @param lp the line parser to use.
 * @return 0 if the file contents could be successfully reloaded or 1 on error.
 */
int hip_lp_reload(hip_line_parser_t *lp)
{
    return hip_fb_reload(lp->fb);
}
