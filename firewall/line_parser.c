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
 * @brief Iterates over lines in a file.
 *
 * @author Stefan Goetz <stefan.goetz@cs.rwth-aachen.de>
 */
#include <string.h>     // sscanf()
#include <sys/types.h>  // off_t, size_t
#include <unistd.h>     // lseek(), close(), read()
#include <fcntl.h>      // open()

#include "lib/core/debug.h"
#include "firewall/line_parser.h"

/**
 * A line parser object.
 */
struct line_parser {
    /**
     * Points to the file contents in memory.
     */
    char *start;
    /**
     * Points to the current parsing position.
     */
    char *cur;
    /**
     * Points to the last byte of file data + 1.
     */
    char *end;
    /**
     * The number of bytes in the allocated buffer.
     */
    size_t size;
    /**
     * The file descriptor this parser operates on.
     */
    int fd;
};

/**
 * (Re-)allocates a string buffer for a line parser so that it can hold a
 * complete copy of the file in memory.
 *
 * If the size of a file cannot be determined (lseek() does not work on proc
 * files), the buffer size is increased with each invocation.
 *
 * @param lp the line parser to use.
 * @return 0 if the buffer could be allocated, a non-zero value else.
 */
static int
lp__resize(line_parser_t *lp)
{
    off_t file_size = 0;

    HIP_ASSERT(lp != NULL);

    if (lp->start != NULL) {
        free(lp->start);
    }

    /* First, we try to determine the current file size for the new buffer size.
     * If that fails (it does, e.g., for proc files), we just increase the
     * current buffer size. */
    file_size = lseek(lp->fd, 0, SEEK_END);
    if (file_size != -1) {
        lp->size = file_size + 4096; // add a little head room
    } else {
        if (lp->size < 4096) {
            lp->size = 4096;
        } else {
            HIP_ASSERT(lp->size < 1024 * 1024 * 1024);
            lp->size *= 2;
        }
    }

    // allocate the buffer
    lp->start = (char *)malloc(lp->size);
    if (NULL == lp->start) {
        lp->size = 0;
    }

    return (NULL == lp->start);
}

/**
 * Make sure that modifications to the file since the last invocation of
 * lp_new() or lp_refresh() are visible to subsequent calls to lp_next().
 *
 * This function implicitly ends a parsing pass and a call to lp_first() should
 * follow.
 *
 * @param lp the line parser to use.
 * @return 0 if the parser was successfully refreshed. A non-zero value if an
 *  error occurred and lp_next() should not be called.
 */
int
lp_refresh(line_parser_t *lp)
{
    ssize_t bytes = 0;

    HIP_ASSERT(lp != NULL);

    // force a new parsing pass in any case
    lp->cur = NULL;

    while (1) {
        // can we re-read the whole file into the memory buffer?
        lseek(lp->fd, 0, SEEK_SET);
        bytes = read(lp->fd, lp->start, lp->size);
        if (bytes == -1) {
            // we can't read from the file at all -> return error
            break;
        } else if ((size_t)bytes == lp->size) {
            // we can't fit the file into the memory buffer -> resize it
            if (lp__resize(lp) == 0) {
                // successful resize -> retry reading
                continue;
            } else {
                // error resizing -> return error
                break;
            }
        } else {
            // successfully read the file contents into the buffer
            lp->cur = lp->start;
            lp->end = lp->start + bytes;
            return 0;
        }
    }

    lp->end = NULL;

    return 1;
}

/**
 * Creates a line parser that can parse the specified file.
 *
 * When this function returns successfully, lp_first() can be called immediately
 * without calling lp_refresh() first.
 *
 * @param file_name the name of the file to parse. The line parser only
 *  supports the files tcp, tcp6, udp, and udp6 in /proc/net/.
 * @return a line parser instance if the parser could initialize correctly.
 *  NULL, if the specified file is not supported.
 */
line_parser_t *
lp_new(const char *file_name)
{
    line_parser_t *lp = NULL;

    HIP_ASSERT(file_name != NULL);

    lp = (line_parser_t *)calloc(1, sizeof(line_parser_t));
    if (lp != NULL) {
        lp->fd = open(file_name, O_RDONLY);
        if (lp->fd != -1) {
            // start, cur, end, size are now NULL/0 thanks to calloc()
            // initialize file mapping/buffer
            if (lp_refresh(lp) == 0) {
                return lp;
            }
        }
        free(lp);
    }

    return NULL;
}

/**
 * Deletes a line parser and releases all resources associated with it.
 */
void
lp_delete(line_parser_t *lp)
{
    HIP_ASSERT(lp != NULL);
    if (lp->fd != -1) {
        close(lp->fd);
    }
    if (lp->start != NULL) {
        free(lp->start);
    }
    free(lp);
}

/**
 * Start a new parsing pass with a line parser.
 *
 * A parsing pass consists of starting it via lp_first() and iterating over
 * the lines in the file via lp_next() until it returns NULL.
 * If the file contents have changed since the previous parsing pass, they are
 * not guaranteed to be visible in the new parsing pass.
 * To ensure that modifications are visible, by lp_next(), call lp_refresh().
 *
 * @param lp the line parser to use.
 * @return a pointer to the first line in the file or NULL if no line is
 *  available.
 */
char *
lp_first(line_parser_t *lp)
{
    HIP_ASSERT(lp != NULL);

    lp->cur = lp->start;

    return lp->cur;
}

/**
 * Get the next line in a parsing pass with a line parser.
 *
 * Each invocation of this function returns a pointer to consecutive lines in
 * the file to parse.
 * After the last line has been reached, NULL is returned.
 * In that case, parsing can restart by calling lp_first().
 *
 * @param lp the line parser parser to use.
 * @return a pointer to a line in the file or NULL if there are no more lines
 *  available.
 */
char *
lp_next(line_parser_t *lp)
{
    HIP_ASSERT(lp != NULL);

    // have we reached the end of the buffer in a previous invocation?
    if (lp->cur != NULL) {
        size_t remaining;

        // for basic sanity, make sure that lp->cur points somewhere into the buffer
        HIP_ASSERT(lp->cur >= lp->start && lp->cur < lp->end);

        remaining = lp->end - lp->cur;
        lp->cur = (char *)memchr(lp->cur, '\n', remaining);

        // given the rest of the parsing code, we should always find a \n, but
        // let's check to be sure
        if (lp->cur != NULL) {
            // cur should not point to the new-line character but to the next one:
            lp->cur += 1;
            // is there text on the line here or are we at the end?
            if (lp->cur >= lp->end) {
                lp->cur = NULL;
            }
        }
    }

    return lp->cur;
}
