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
int hip_build_locators_old(struct hip_common *const msg)
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
 * build locators in an UPDATE message
 *
 * @param locator_msg the message where the LOCATOR should be appended
 * @param locators an extra pointer that will point to the LOCATOR
 * @return zero on success or negative on failure
 */
int hip_create_locators(struct hip_common *const locator_msg,
                        struct hip_locator_info_addr_item **locators)
{
    int                 err = 0;
    struct hip_locator *loc = NULL;

    hip_msg_init(locator_msg);
    HIP_IFEL(hip_build_user_hdr(locator_msg,
                                HIP_MSG_SET_LOCATOR_ON, 0), -1,
             "Failed to add user header\n");
    HIP_IFEL(hip_build_locators_old(locator_msg),
             -1,
             "Failed to build locators\n");
    loc = hip_get_param_readwrite(locator_msg, HIP_PARAM_LOCATOR);
    hip_print_locator_addresses(locator_msg);
    *locators = (struct hip_locator_info_addr_item *) (loc + 1);

out_err:
    return err;
}

/**
 * Retrieve a locator address item from a list.
 *
 * @param item_list a pointer to the first item in the list
 * @param idx       the index of the item in the list
 * @return          the locator addres item
 */
union hip_locator_info_addr *hip_get_locator_item(void *const item_list,
                                                  const int idx)
{
    int                                i = 0;
    struct hip_locator_info_addr_item *temp;
    char                              *result;
    result = item_list;


    for (i = 0; i <= idx - 1; i++) {
        temp = (struct hip_locator_info_addr_item *) result;
        if (temp->locator_type == HIP_LOCATOR_LOCATOR_TYPE_ESP_SPI ||
            temp->locator_type == HIP_LOCATOR_LOCATOR_TYPE_IPV6) {
            result += sizeof(struct hip_locator_info_addr_item);
        } else {
            result += sizeof(struct hip_locator_info_addr_item2);
        }
    }
    return (union hip_locator_info_addr *) result;
}

/**
 * retrieve a IP address from a locator item structure
 *
 * @param item      a pointer to the item
 * @return a pointer to the IP address
 */
struct in6_addr *hip_get_locator_item_address(void *const item)
{
    struct hip_locator_info_addr_item *temp = item;

    if (temp->locator_type == HIP_LOCATOR_LOCATOR_TYPE_ESP_SPI) {
        return &temp->address;
    } else if (temp->locator_type == HIP_LOCATOR_LOCATOR_TYPE_IPV6) {
        return &temp->address;
    } else {
        return &((struct hip_locator_info_addr_item2 *) temp)->address;
    }
}

/**
 * Retrieve the number of locators inside a LOCATOR parameter.
 * Type 1 and 2 parameters are supported.
 *
 * @param locator a LOCATOR parameter
 * @return the number of locators
 */
int hip_get_locator_addr_item_count(const struct hip_locator *const locator)
{
    const char *address_pointer = (const char *) (locator + 1);
    int         loc_count       = 0;
    uint8_t     type;

    while (address_pointer <
           ((const char *) locator) + hip_get_param_contents_len(locator)) {
        type = ((const struct hip_locator_info_addr_item *)
                address_pointer)->locator_type;

        if (type == HIP_LOCATOR_LOCATOR_TYPE_UDP) {
            address_pointer += sizeof(struct hip_locator_info_addr_item2);
            loc_count       += 1;
        } else if (type == HIP_LOCATOR_LOCATOR_TYPE_ESP_SPI
                   || type == HIP_LOCATOR_LOCATOR_TYPE_IPV6) {
            address_pointer += sizeof(struct hip_locator_info_addr_item);
            loc_count       += 1;
        } else {
            address_pointer += sizeof(struct hip_locator_info_addr_item);
        }
    }
    return loc_count;
}
