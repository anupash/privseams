/**
 * This file contains legacy functions for mobility that should be rewritten for modularity.
 * They are still included in the code base due to locator dependencies with DHT and
 * base exchange code.
 */

#include "update.h"
#include "update_legacy.h"

/* required for s6_addr32 */
#define _BSD_SOURCE

int hip_build_locators_old(struct hip_common *msg, uint32_t spi)
{
    int err                                 = 0, i = 0, count = 0;
    int addr_max;
    struct netdev_address *n;
    hip_list_t *item                        = NULL, *tmp = NULL;
    struct hip_locator_info_addr_item *locs = NULL;

    //TODO count the number of UDP relay servers.
    // check the control state of every hatb_state.

    if (address_count == 0) {
        HIP_DEBUG("Host has only one or no addresses no point "
                  "in building LOCATOR2 parameters\n");
        goto out_err;
    }

    //TODO check out the count for UDP and hip raw.
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
                          hip_cast_sa_addr(((const struct sockaddr *) &n->addr)));
        HIP_ASSERT(!ipv6_addr_is_hit(hip_cast_sa_addr((const struct sockaddr *) &n->addr)));
        memcpy(&locs[count].address, hip_cast_sa_addr((const struct sockaddr *) &n->addr),
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
