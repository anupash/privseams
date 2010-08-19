/**
 * @file
 *
 * Copyright (c) 2010 Aalto University) and RWTH Aachen University.
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
 * @brief look for locators in hit-to-ip domain
 * @brief usually invoked by hip_map_id_to_addr
 *
 * @author Oleg Ponomarev <oleg.ponomarev@hiit.fi>
 */

#ifndef HIP_HIPD_HIT_TO_IP_H
#define HIP_HIPD_HIT_TO_IP_H

#include <netinet/in.h>

#include "lib/core/protodefs.h"

int hip_hit_to_ip(const hip_hit_t *hit, struct in6_addr *retval);

void hip_set_hit_to_ip_status(const int status);
int hip_get_hit_to_ip_status(void);
void hip_hit_to_ip_set(const char *zone);

#endif /* HIP_HIPD_HIT_TO_IP_H */
