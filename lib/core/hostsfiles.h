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
 */

#ifndef HIP_LIB_CORE_HOSTSFILES_H
#define HIP_LIB_CORE_HOSTSFILES_H

#include <netinet/in.h>

#include "protodefs.h"

int hip_map_lsi_to_hit_from_hosts_files(const hip_lsi_t *lsi, hip_hit_t *hit);
int hip_map_hit_to_lsi_from_hosts_files(const hip_hit_t *hit, hip_lsi_t *lsi);
int hip_map_id_to_ip_from_hosts_files(const hip_hit_t *hit,
                                      const hip_lsi_t *lsi,
                                      struct in6_addr *ip);
int hip_map_lsi_to_hostname_from_hosts(hip_lsi_t *lsi, char *hostname);
int hip_host_file_info_exists_lsi(hip_lsi_t *lsi);

#endif /* HIP_LIB_CORE_HOSTSFILES_H */
