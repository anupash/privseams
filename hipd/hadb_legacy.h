/*
 * Copyright (c) 2010-2011 Aalto University and RWTH Aachen University.
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
 *
 * @author Stefan Götz <stefan.goetz@web.de>
 */

#ifndef HIP_HIPD_HADB_LEGACY_H
#define HIP_HIPD_HADB_LEGACY_H

#include <stdint.h>
#include <netinet/in.h>
#include <sys/time.h>

#include "lib/core/protodefs.h"


int hip_hadb_get_peer_addr_info_old(struct hip_hadb_state *entry,
                                    const struct in6_addr *addr);

void hip_hadb_delete_peer_addrlist_one_old(struct hip_hadb_state *ha,
                                           struct in6_addr *addr);

#endif /* HIP_HIPD_HADB_LEGACY_H */
