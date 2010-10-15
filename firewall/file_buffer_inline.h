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
#ifndef HIP_FIREWALL_FILE_BUFFER_INLINE_H
#define HIP_FIREWALL_FILE_BUFFER_INLINE_H

// On the one hand, the contents of this file are part of the public interface
// and thus only their declaration should go into the public header file.
// On the other hand, these functions should be inlineable so their definitions
// have to appear in a header file.
// To achieve inlineability and still hide the implementation, we use this
// secondary header file that is not part of the public interface.
#ifndef HIP_FIREWALL_FILE_BUFFER_H
#error This file must not be included directly because it contains implementation details. It may only be included by file_buffer.h.
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A file buffer object represents an open file and its associated memory
 * buffer.
 */
struct hip_file_buffer {
    /**
     * The memory area holding the file contents.
     * Its start field points to the first byte of file data and the beginning
     * of the allocated memory buffer.
     * Its end field points to the last byte of file data + 1.
     */
    struct hip_mem_area ma;
    /*
     * The number of bytes in the allocated buffer that ma.start points to.
     * buffer_size is equal to or greater than (ma.end - ma.start).
     */
    size_t buffer_size;
    /*
     * The file descriptor for the file backing the buffer.
     */
    int fd;
};

/**
 * Retrieve the memory area in which the file contents are stored.
 *
 * There is a 1:1 relationship between the passed in fb object and the returned
 * pointer.
 * That is, calling this function on the same fb object will always return the
 * same struct hip_mem_area pointer.
 * Thus, you may assume that the returned struct hip_mem_area pointer has the
 * same life time as its associated struct hip_file_buffer object.
 * However, hip_fb_reload() may change the start and end address in the
 * returned struct hip_mem_area object!
 *
 * @param fb the file buffer object holding the memory area to retrieve.
 * @return a pointer to the struct hip_mem_area object associated with the
 *  given file buffer object.
 *  If the passed in file buffer pointer is invalid, this function returns
 *  NULL.
 */
static inline const struct hip_mem_area *hip_fb_get_mem_area(const struct hip_file_buffer *const fb)
{
    if (fb != NULL) {
        return &fb->ma;
    }
    return NULL;
}

#ifdef __cplusplus
}
#endif

#endif
