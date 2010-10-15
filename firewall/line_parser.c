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

#include "firewall/file_buffer.h"   // hip_fb_create()
#include "firewall/line_parser.h"

/**
 * Creates a line parser that can parse the specified file.
 *
 * When this function returns successfully, hip_lp_first() can be called
 * immediately to start parsing.
 * This function allocates resources, in particular memory, for the returned
 * struct hip_line_parser object.
 * To free these resources and to avoid memory leaks, it is imperative to call
 * hip_lp_delete() when the object created here is no longer used.
 *
 * @param file_name the name of the file to parse.
 * @return a line parser instance if the parser could initialize correctly.
 *  NULL, if the specified file could not be accessed.
 */
struct hip_line_parser *hip_lp_create(const char *const file_name)
{
    struct hip_line_parser *lp = NULL;

    if (file_name != NULL) {
        lp = calloc(1, sizeof(struct hip_line_parser));
        if (lp != NULL) {
            // cur is NULL as it should be thanks to calloc()
            lp->fb = hip_fb_create(file_name);
            if (lp->fb != NULL) {
                return lp;
            }
            hip_lp_delete(lp);
        }
    }

    return NULL;
}

/**
 * Deletes a line parser and releases all resources associated with it.
 *
 * @param lp the line parser object to delete.
 */
void hip_lp_delete(struct hip_line_parser *const lp)
{
    if (lp != NULL) {
        if (lp->fb != NULL) {
            hip_fb_delete(lp->fb);
        }
        free(lp);
    }
}

/**
 * If the line parser uses a file-based memory buffer, reload the file contents
 * to reflect any changes in the file since the last invocation of hip_lp_create()
 * or hip_lp_reload().
 * When this function returns, the current parsing position is reset and parsing
 * must be restarted by calling hip_lp_first().
 *
 * @param lp the line parser to use.
 * @return 0 if the file contents could be successfully reloaded or 1 on error.
 */
int hip_lp_reload(struct hip_line_parser *const lp)
{
    if (NULL == lp ||
        NULL == lp->fb) {
        return 1;
    }

    // Reset the parsing position because
    // a) if the file was successfully reloaded, the contents may have changed
    //    and the parsing position has become meaningless;
    // b) if the file was not successfully reloaded, the memory buffer does not
    //    hold valid data and parsing cannot be performed.
    lp->cur = NULL;

    return hip_fb_reload(lp->fb);
}
