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

#ifndef HIP_FIREWALL_FILE_BUFFER_H
#define HIP_FIREWALL_FILE_BUFFER_H

#include "firewall/mem_area.h"  // struct hip_mem_area

struct hip_file_buffer;

int hip_fb_create(struct hip_file_buffer *const fb,
                  const char *const file_name);
void hip_fb_delete(struct hip_file_buffer *const fb);
static inline const struct hip_mem_area *hip_fb_get_mem_area(const struct hip_file_buffer *const fb);
int hip_fb_reload(struct hip_file_buffer *const fb);

#include "firewall/file_buffer_inline.h"

#endif /* HIP_FIREWALL_FILE_BUFFER_H */
