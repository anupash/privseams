/** @file
 * oppipdb.h: A header file for oppipdb.c
 *
 * @author  Antti Partanen
 * @author  Alberto Garcia
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
 */

#ifndef HIP_HIPD_OPPIPDB_H
#define HIP_HIPD_OPPIPDB_H

#include "lib/core/debug.h"
#include "hidb.h"
#include "lib/core/hashtable.h"

typedef struct in6_addr hip_oppip_t;

int hip_for_each_oppip(void (*func)(hip_oppip_t *entry, void *opaq), void *opaque);
void hip_oppipdb_del_entry_by_entry(hip_oppip_t *entry, void *arg);
int hip_oppipdb_add_entry(const struct in6_addr *ip_peer);
int hip_init_oppip_db(void);
hip_oppip_t *hip_oppipdb_find_byip(const struct in6_addr *ip_peer);
void hip_oppipdb_delentry(const struct in6_addr *ip_peer);
void hip_oppipdb_uninit(void);

#endif /* HIP_HIPD_OPPIPDB_H */
