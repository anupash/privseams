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

#include "config.h"
#include "hipd/hipd.h"
#include "hipd/maintenance.h"
#include "hipd/oppipdb.h"
#include "lib/core/builder.h"
#include "lib/core/debug.h"
#include "lib/core/ife.h"
#include "lib/core/list.h"
#include "lib/core/prefix.h"
#include "lib/core/protodefs.h"
#include "update.h"
#include "update_legacy.h"

/**
 * build a LOCATOR parameter for an UPDATE packet
 *
 * @param msg the LOCATOR parameter will be appended to this UPDATE message
 * @return zero on success on negative on failure
 */
int hip_build_locators_old(struct hip_common *msg)
{
    int err                                 = 0, i = 0, count = 0;
    int addr_max;
    struct netdev_address *n;
    hip_list_t *item                        = NULL, *tmp = NULL;
    struct hip_locator_info_addr_item *locs = NULL;

    if (address_count == 0) {
        HIP_DEBUG("Host has only one or no addresses no point "
                  "in building LOCATOR2 parameters\n");
        goto out_err;
    }

    addr_max = address_count;

    HIP_IFEL(!(locs = malloc(addr_max *
                             sizeof(struct hip_locator_info_addr_item))),
             -1, "Malloc for LOCATORS type1 failed\n");

    memset(locs, 0, (addr_max *
                     sizeof(struct hip_locator_info_addr_item)));

    HIP_DEBUG("there are %d type 1 locator item\n", addr_max);

    list_for_each_safe(item, tmp, addresses, i) {
        n = (struct netdev_address *) list_entry(item);
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

    HIP_IFEL((count == 0), -1, "No locators to build\n");

    err = hip_build_param_locator(msg, locs, count);

out_err:

    if (locs) {
        free(locs);
    }

    return err;
}

/**
 * Flush the opportunistic mode blacklist at the firewall. It is required
 * when the host moves e.g. from one private address realm to another and
 * the IP-address based blacklist becomes unreliable
 */
void hip_empty_oppipdb_old(void)
{
#ifdef CONFIG_HIP_OPPORTUNISTIC
    hip_for_each_oppip(hip_oppipdb_del_entry_by_entry, NULL);
#endif
    if (hip_firewall_is_alive()) {
        int err;
        struct hip_common *msg;

        msg = hip_msg_alloc();
        HIP_IFEL(!msg, -1, "msg alloc failed\n");
        HIP_IFEL(hip_build_user_hdr(msg, HIP_MSG_FW_FLUSH_SYS_OPP_HIP, 0),
                 -1, "build hdr failed\n");

        err = hip_sendto_firewall(msg);
        err = err > 0 ? 0 : -1;

out_err:
        free(msg);
        if (err) {
            HIP_ERROR("Couldn't flush firewall chains\n");
        }
    }
}
