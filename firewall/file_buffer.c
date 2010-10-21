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
static int hip_fb_resize(struct hip_file_buffer *const fb)
{
    off_t file_size = 0;

    if (NULL == fb) {
        return 1;
    }

    if (fb->ma.start != NULL) {
        free(fb->ma.start);
        fb->ma.start = NULL;
    }

    /* First, we try to determine the current file size for the new buffer size.
     * If that fails (it does, e.g., for proc files), we just increase the
     * current buffer size. */
    file_size = lseek(fb->fd, 0, SEEK_END);
    if (file_size != -1) {
        fb->buffer_size = file_size + HIP_FB_HEADROOM; // add a little head room
    } else {
        if (fb->buffer_size < HIP_FB_HEADROOM) {
            fb->buffer_size = HIP_FB_HEADROOM;
        } else {
            fb->buffer_size *= 2;
        }
    }

    if (fb->buffer_size <= HIP_FB_MAX_SIZE) {
        // allocate the buffer
        fb->ma.start = malloc(fb->buffer_size);
        if (NULL == fb->ma.start) {
            fb->buffer_size = 0;
        }
    }

    return (NULL == fb->ma.start);
}

/**
 * Creates a file buffer that holds the specified file.
 *
 * A file buffer is used to load and hold the contents of a file in
 * memory (for simplified access or improved performance).
 * The memory buffer is allocated so that the whole file fits in it.
 * Any changes to the memory buffer are not written back to the file and remain
 * local to the memory buffer.
 * Note that this is useful primarily with files that cannot be mapped into
 * memory via mmap(), such as files in /proc.
 * For regular files, using mmap() is vastly more efficient.
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
struct hip_file_buffer *hip_fb_create(const char *const file_name)
{
    struct hip_file_buffer *fb = NULL;

    if (file_name != NULL) {
        fb = calloc(1, sizeof(struct hip_file_buffer));
        if (fb != NULL) {
            fb->fd = open(file_name, O_RDONLY);
            if (fb->fd != -1) {
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
void hip_fb_delete(struct hip_file_buffer *const fb)
{
    if (fb != NULL) {
        if (fb->fd != -1) {
            close(fb->fd);
        }
        if (fb->ma.start != NULL) {
            free(fb->ma.start);
        }
        free(fb);
    }
}

/**
 * Make modifications to the file since the last invocation of hip_fb_create() or
 * hip_fb_reload() visible in the buffer.
 *
 * @warning
 * Note that this function may change the start and end pointers in the memory
 * area returned by hip_fb_get_mem_area()!
 *
 * @param fb the file buffer to use.
 * @return 0 if the file data was successfully re-read.
 *  1 if the file could not be read or not enough buffer space could be
 *  allocated.
 */
int hip_fb_reload(struct hip_file_buffer *const fb)
{
    if (NULL == fb || -1 == fb->fd) {
        return 1;
    }

    while (1) {
        ssize_t bytes = 0;

        // can we re-read the whole file into the memory buffer?
        lseek(fb->fd, 0, SEEK_SET);
        bytes = read(fb->fd, fb->ma.start, fb->buffer_size);
        if (bytes == -1) {
            // we can't read from the file at all -> return error
            break;
        } else if ((size_t)bytes == fb->buffer_size) {
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
            fb->ma.end = fb->ma.start + bytes;
            return 0;
        }
    }

    fb->ma.end = NULL;

    return 1;
}
