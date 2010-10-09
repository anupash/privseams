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
#include <string.h>     // memchr()

#include "lib/core/debug.h" // HIP_ASSERT()
#include "firewall/file_buffer.h"   // hip_lp_new()
#include "firewall/line_parser.h"

/**
 * A line parser object is used to linearly iterate over the lines in a memory
 * area that holds text.
 * The buffer contents are not modified and the returned line pointers are
 * terminated by \n characters, not \0 characters.
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
 * Start a new parsing pass with a line parser and return the first line in the
 * buffer.
 * The buffer is not modified and the line is terminated by a new-line
 * character (not a \0 character).
 *
 * A parsing pass consists of starting it via hip_lp_first() and iterating over
 * the lines in the file via hip_lp_next() until it returns NULL.
 *
 * @param lp the line parser to use.
 * @return a pointer to the first line in the file or NULL if no line is
 *  available.
 */
char *hip_lp_first(hip_line_parser_t *lp)
{
    HIP_ASSERT(lp != NULL);

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
char *hip_lp_next(hip_line_parser_t *lp)
{
    HIP_ASSERT(lp != NULL);

    // have we reached the end of the buffer in a previous invocation?
    if (lp->cur != NULL) {
        size_t remaining;

        // for basic sanity, make sure that lp->cur points somewhere into the buffer
        HIP_ASSERT(lp->cur >= lp->fb->start && lp->cur < lp->fb->end);

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
    }

    return lp->cur;
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
