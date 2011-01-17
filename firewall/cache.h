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

#ifndef HIP_FIREWALL_CACHE_H
#define HIP_FIREWALL_CACHE_H

#include <netinet/in.h>

#include "lib/core/protodefs.h"
#include "lib/core/icomm.h"

enum fw_cache_query_type { FW_CACHE_HIT, FW_CACHE_LSI, FW_CACHE_IP };

struct hip_hadb_user_info_state *hip_firewall_cache_db_match(const void *local,
                                                             const void *peer,
                                                             enum fw_cache_query_type type,
                                                             int query_daemon);

void hip_firewall_cache_db_del_entry(const void *local, const void *peer,
                                     enum fw_cache_query_type type);

void hip_firewall_cache_init_hldb(void);

void hip_firewall_cache_delete_hldb(int);

int hip_firewall_cache_set_bex_state(const struct in6_addr *hit_s,
                                     const struct in6_addr *hit_r,
                                     int state);

int hip_firewall_cache_update_entry(const struct in6_addr *ip_our,
                                    const struct in6_addr *ip_peer,
                                    const struct in6_addr *hit_our,
                                    const struct in6_addr *hit_peer,
                                    int state);

#endif /* HIP_FIREWALL_CACHE_H */
