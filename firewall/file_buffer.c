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
#include <stdlib.h>     // malloc(), free()
#include <unistd.h>     // lseek(), close(), read()
#include <fcntl.h>      // open()

#include "firewall/file_buffer.h"

/**
 * Always allocate this many more bytes for the memory buffer than is needed
 * the actual file contents.
 * This avoids having to re-allocate the buffer for very small increases in the
 * file size.
 */
static const unsigned int HIP_FB_HEADROOM = 4096;

/**
 * Allocate at most this many bytes, i.e., the maximum supported file size.
 * This is an arbitrary number used for sanity checking.
 */
static const unsigned long HIP_FB_MAX_SIZE = 1024 * 1024 * 1024;

/**
 * (Re-)allocates the file buffer so that it can hold a complete copy of the
 * file in memory.
 *
 * If the size of a file cannot be determined (lseek() does not work on proc
 * files), the buffer size is increased with each invocation.
 *
 * @param fb the file buffer to use.
 * @return 0 if the buffer could be allocated, a non-zero value else.
 */
static int hip_fb_resize(struct hip_file_buffer *fb)
{
    off_t file_size = 0;

    if (NULL == fb) {
        return 1;
    }

    if (fb->start != NULL) {
        free(fb->start);
        fb->start = NULL;
    }

    /* First, we try to determine the current file size for the new buffer size.
     * If that fails (it does, e.g., for proc files), we just increase the
     * current buffer size. */
    file_size = lseek(fb->_fd, 0, SEEK_END);
    if (file_size != -1) {
        fb->_size = file_size + HIP_FB_HEADROOM; // add a little head room
    } else {
        if (fb->_size < HIP_FB_HEADROOM) {
            fb->_size = HIP_FB_HEADROOM;
        } else {
            fb->_size *= 2;
        }
    }

    if (fb->_size <= HIP_FB_MAX_SIZE) {
        // allocate the buffer
        fb->start = (char *)malloc(fb->_size);
        if (NULL == fb->start) {
            fb->_size = 0;
        }
    }

    return (NULL == fb->start);
}

/**
 * Creates a file buffer that holds the specified file.
 *
 * This function allocates resources, in particular memory, for the returned
 * struct hip_line_parser object.
 * To free these resources and to avoid memory leaks, it is imperative to call
 * hip_lp_delete() when the object created here is no longer used.
 *
 * @param file_name the name of the file to buffer.
 * @return a file buffer instance if the file could be opened and successfully
 *  buffered.
 *  NULL on error.
 */
struct hip_file_buffer *hip_fb_create(const char *file_name)
{
    struct hip_file_buffer *fb = NULL;

    if (file_name != NULL) {
        fb = (struct hip_file_buffer *)calloc(1, sizeof(struct hip_file_buffer));
        if (fb != NULL) {
            fb->_fd = open(file_name, O_RDONLY);
            if (fb->_fd != -1) {
                // start, end, size are now NULL/0 thanks to calloc()
                // initialize file buffer
                if (hip_fb_reload(fb) == 0) {
                    return fb;
                }
            }
            hip_fb_delete(fb);
        }
    }

    return NULL;
}

/**
 * Deletes a file buffer and releases all resources associated with it.
 * After calling this function, the result of calling any other hip_fb_...()
 * function on the file buffer fb is undefined.
 *
 * @param fb the file buffer to delete.
 */
void hip_fb_delete(struct hip_file_buffer *fb)
{
    if (fb != NULL) {
        if (fb->_fd != -1) {
            close(fb->_fd);
        }
        if (fb->start != NULL) {
            free(fb->start);
        }
        free(fb);
    }
}

/**
 * Make modifications to the file since the last invocation of hip_fb_create() or
 * hip_fb_reload() visible in the buffer.
 *
 * @param fb the file buffer to use.
 * @return 0 if the file data was successfully re-read.
 *  1 if the file could not be read or not enough buffer space could be
 *  allocated.
 */
int hip_fb_reload(struct hip_file_buffer *fb)
{
    if (NULL == fb || -1 == fb->_fd) {
        return 1;
    }

    while (1) {
        ssize_t bytes = 0;

        // can we re-read the whole file into the memory buffer?
        lseek(fb->_fd, 0, SEEK_SET);
        bytes = read(fb->_fd, fb->start, fb->_size);
        if (bytes == -1) {
            // we can't read from the file at all -> return error
            break;
        } else if ((size_t)bytes == fb->_size) {
            // we can't fit the file into the memory buffer -> resize it
            if (hip_fb_resize(fb) == 0) {
                // successful resize -> retry reading
                continue;
            } else {
                // error resizing -> return error
                break;
            }
        } else {
            // successfully read the file contents into the buffer
            fb->end = fb->start + bytes;
            return 0;
        }
    }

    fb->end = NULL;

    return 1;
}
