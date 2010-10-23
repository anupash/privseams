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
#include <string.h>     // memset()
#include <errno.h>      // errno

#include "lib/core/debug.h"     // HIP_ERROR()
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
 * (Re-)allocates the file buffer so that it can hold a complete copy of its
 * file in memory.
 * After the function completes successfully, the memory area associated with
 * the file buffer points to an allocated region of memory that is at least as
 * large as the size of the file buffer's file at the time of invocation.
 * The contents of the memory area are undefined.
 *
 * If the size of a file cannot be determined (lseek() does not work on proc
 * files), the buffer size is increased incrementally.
 *
 * @param fb the file buffer to use.
 * @return If the function completes successfully, it returns 0.
 *  If fb is NULL, -1 is returned.
 *  If internal errors occur, other negative values are returned.
 */
static int hip_fb_resize(struct hip_file_buffer *const fb)
{
    int err = 0;

    if (fb) {
        off_t file_size = 0;

        if (fb->ma.start != NULL) {
            free(fb->ma.start);
            fb->ma.start = NULL;
        }

        /* First, we try to determine the current file size for the new buffer size.
         * If that fails (it does, e.g., for proc files), we just increase the
         * current buffer size. */
        errno = 0;
        file_size = lseek(fb->fd, 0, SEEK_END);
        if (file_size != -1 || EINVAL == errno) {
            if (file_size != -1) {
                fb->buffer_size = file_size + HIP_FB_HEADROOM; // add a little head room
            } else if (EINVAL == errno) {
                if (fb->buffer_size < HIP_FB_HEADROOM) {
                    fb->buffer_size = HIP_FB_HEADROOM;
                } else {
                    fb->buffer_size *= 2;
                }
            }

            // fb->buffer_size is now adjusted, but maybe not positive or very large?
            if (fb->buffer_size > 0 && fb->buffer_size <= HIP_FB_MAX_SIZE) {
                // fb->buffer_size is now the size we want to allocate
                fb->ma.start = malloc(fb->buffer_size);
                if (fb->ma.start) {
                    return 0;
                } else {
                    HIP_ERROR("Allocating %d bytes of memory for file data failed\n",
                              fb->buffer_size);
                    err = -4;
                }
            } else {
                HIP_ERROR("The file buffer size %d is too large to be supported\n");
                err = -3;
            }
        } else {
            HIP_ERROR("Determining file size via lseek() failed: %s", strerror(errno));
            err = -2;
        }
        fb->buffer_size = 0;
    } else {
        err = -1;
    }

    return err;
}

/**
 * Initializes a file buffer that holds the specified file.
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
 * object.
 * To free these resources and to avoid memory leaks, it is imperative to call
 * hip_fb_delete() when the object created here is no longer used.
 *
 * @param fb a pointer to a valid, allocated instance of struct hip_file_buffer.
 *  Upon successful completion, the function writes file-specific context data
 *  to the location referenced by fb.
 * @param file_name the name of the file to open and load into memory.
 * @return a 0 if the file could be opened and successfully buffered.
 *  -1 is returned if fb is NULL or if file_name is NULL.
 *  -2 is returned if the specified file cannot be opened for reading.
 *  -3 is returned if an internal error occurs.
 */
int hip_fb_create(struct hip_file_buffer *const fb,
                  const char *const file_name)
{
    int err = 0;

    if (fb && file_name) {
        memset(fb, 0, sizeof(*fb)); // set all fields to 0/NULL
        fb->fd = open(file_name, O_RDONLY);
        if (fb->fd != -1) {
            if (hip_fb_reload(fb) == 0) {
                return 0;
            } else {
                err = -3;
            }
        } else {
            HIP_ERROR("Opening the file %s for reading via open() failed with the error %s\n",
                      file_name, strerror(errno));
            err = -2;
        }
        hip_fb_delete(fb);
    } else {
        err = -1;
    }

    return err;
}

/**
 * De-allocates the resources associated with a file buffer object in
 * hip_fb_create().
 * This function does not de-allocated the memory pointed to by fb.
 * After calling this function, the result of calling any other hip_fb_...()
 * function on the file buffer fb is undefined.
 *
 * @param fb the file buffer to delete. If fb is NULL, this function has no
 *  effect.
 */
void hip_fb_delete(struct hip_file_buffer *const fb)
{
    if (fb != NULL) {
        if (fb->fd != -1) {
            close(fb->fd);
            fb->fd = -1;
        }
        if (fb->ma.start != NULL) {
            free(fb->ma.start);
            fb->ma.start = NULL;
            fb->ma.end = NULL;
        }
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
 * @return 0 when the function completes successfully.
 *  If fb is NULL, -1 is returned.
 *  If an internal error occurs, -2 is returned.
 */
int hip_fb_reload(struct hip_file_buffer *const fb)
{
    if (NULL == fb) {
        return -1;
    }

    while (1) {
        ssize_t bytes;
        off_t seek_offset;

        // can we re-read the whole file into the memory buffer?
        seek_offset = lseek(fb->fd, 0, SEEK_SET);
        if (-1 == seek_offset) {
            HIP_ERROR("Resetting the read position on file descriptor %d via lseek() failed with the error %s",
                      fb->fd, errno, strerror(errno));
            break;
        }

        bytes = read(fb->fd, fb->ma.start, fb->buffer_size);
        if (bytes == -1) {
            HIP_ERROR("Reading the contents of the file descriptor %d via read() into a memory buffer of size %d failed with the error %s",
                      fb->fd, fb->buffer_size, strerror(errno));
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

    return -2;
}
