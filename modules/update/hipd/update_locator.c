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
 * This file contains legacy functions for mobility that should be rewritten for modularity.
 * They are still included in the code base due to locator dependencies with
 * base exchange code. See bugzilla ids 592195 and 592196.
 *
 * @author Baris Boyvat
 */

#include <stdlib.h>
#include <string.h>
#include <openssl/lhash.h>

#include "config.h"
#include "hipd/hipd.h"
#include "hipd/maintenance.h"
#include "lib/core/builder.h"
#include "lib/core/debug.h"
#include "lib/core/ife.h"
#include "lib/core/list.h"
#include "lib/core/prefix.h"
#include "lib/core/protodefs.h"
#include "update_builder.h"
#include "update.h"
#include "update_locator.h"


#define HIP_LOCATOR_TRAFFIC_TYPE_DUAL    0
#define HIP_LOCATOR_TRAFFIC_TYPE_SIGNAL  1

/**
 * build a LOCATOR parameter for an UPDATE packet
 *
 * @param msg the LOCATOR parameter will be appended to this UPDATE message
 * @return zero on success on negative on failure
 */
int hip_build_locators_old(struct hip_common *msg)
{
    int                                err = 0, i = 0, count = 0;
    int                                addr_max;
    struct netdev_address             *n;
    LHASH_NODE                        *item = NULL, *tmp = NULL;
    struct hip_locator_info_addr_item *locs = NULL;

    if (address_count == 0) {
        HIP_DEBUG("Host has only one or no addresses no point "
                  "in building LOCATOR2 parameters\n");
        goto out_err;
    }

    addr_max = address_count;

    HIP_IFEL(!(locs = calloc(addr_max, sizeof(struct hip_locator_info_addr_item))),
             -1, "Malloc for LOCATORS type1 failed\n");

    HIP_DEBUG("there are %d type 1 locator item\n", addr_max);

    list_for_each_safe(item, tmp, addresses, i) {
        n = list_entry(item);
        HIP_DEBUG_IN6ADDR("Add address:",
                          hip_cast_sa_addr(((struct sockaddr *) &n->addr)));
        HIP_ASSERT(!ipv6_addr_is_hit(hip_cast_sa_addr((struct sockaddr *) &n->addr)));
        memcpy(&locs[count].address, hip_cast_sa_addr((struct sockaddr *) &n->addr),
               sizeof(struct in6_addr));
        if (n->flags & HIP_FLAG_CONTROL_TRAFFIC_ONLY) {
            locs[count].traffic_type = HIP_LOCATOR_TRAFFIC_TYPE_SIGNAL;
        } else {
            locs[count].traffic_type = HIP_LOCATOR_TRAFFIC_TYPE_DUAL;
        }
        locs[count].locator_type   = HIP_LOCATOR_LOCATOR_TYPE_ESP_SPI;
        locs[count].locator_length = sizeof(struct in6_addr) / 4;
        locs[count].reserved       = 0;
        count++;
    }

    HIP_DEBUG("locator count %d\n", count);

    HIP_IFEL(count == 0, -1, "No locators to build\n");

    err = hip_build_param_locator(msg, locs, count);

out_err:
    free(locs);
    return err;
}

/**
 * This function stores the LOCATOR parameter into the hadb entry
 * of a connection in question. The whole LOCATOR is stored and
 * handled later as the LOCATOR is received before the connection
 * state has reached ESTABLISHED (UPDATEs are not allowed before
 * the state is ESTABLISHED) and the address verification is
 * handled later during the BEX (after receiving the R2).
 *
 * @param locator The received LOCATOR parameter.
 * @param entry Hadb entry where the LOCATOR is stored.
 *
 * @return Zero on success, non-zero else.
 */
int handle_locator(const struct hip_locator *locator,
                   struct hip_hadb_state *entry)
{
    int n_addrs = 0, loc_size = 0, err = 0;

    n_addrs  = hip_get_locator_addr_item_count(locator);
    loc_size = sizeof(struct hip_locator) +
               (n_addrs * sizeof(struct hip_locator_info_addr_item));
    HIP_IFEL(!(entry->locator = malloc(loc_size)),
             -1, "Malloc for entry->locators failed\n");
    memcpy(entry->locator, locator, loc_size);

out_err:
    return err;
}
