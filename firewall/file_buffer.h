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
#ifndef HIP_FIREWALL_FILE_BUFFER_H
#define HIP_FIREWALL_FILE_BUFFER_H

#include <sys/types.h>  // size_t

#ifdef __cplusplus
extern "C" {
#endif

/**
 * File buffer objects are used to load and hold file contents into a memory
 * buffer.
 * The memory buffer is allocated so that the whole file fits in it.
 * Any changes to the memory buffer are not written back to the file and remain
 * local to the memory buffer.
 */
struct hip_file_buffer {
    /**
     * Points to the first byte of file data and the beginning of the buffer.
     */
    char *start;
    /**
     * Points to the last byte of file data + 1.
     */
    char *end;
    /*
     * The number of bytes in the allocated buffer.
     * _size is less than or equal to (end - start).
     * This field should not to be accessed by users of struct hip_file_buffer.
     */
    size_t _size;
    /*
     * The file descriptor for the file backing the buffer.
     * This field should not to be accessed by users of struct hip_file_buffer.
     */
    int _fd;
};

struct hip_file_buffer *hip_fb_create(const char *const file_name);
void hip_fb_delete(struct hip_file_buffer *const fb);
int hip_fb_reload(struct hip_file_buffer *const fb);

#ifdef __cplusplus
}
#endif

#endif
