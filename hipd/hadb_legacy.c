/**
 * This file contains legacy functions for mobility that should be rewritten for modularity.
 * They are still included in the code base due to locator dependencies with DHT and
 * base exchange code.
 */

/* required for s6_addr32 */
#define _BSD_SOURCE

#include "hadb_legacy.h"

/**
 * Gets infomation on the given peer IPv6 address.
 *
 * @param entry         corresponding hadb entry of the peer.
 * @param addr          the IPv6 address for which the information is to be
 *                      retrieved.
 * @param lifetime      where the lifetime of @c addr is copied to.
 * @param modified_time where the time when @c addr was added or updated is
 *                      copied to.
 * @return              If @c entry has the address @c addr in its peer address
 *                      list parameters @c spi, @c lifetime, and
 *                      @c modified_time are assigned if they are non-NULL and 1
 *                      is returned, else @c interface_id and @c lifetime are
 *                      not assigned a value and 0 is returned.
 */
int hip_hadb_get_peer_addr_info_old(hip_ha_t *entry,
                                    const struct in6_addr *addr,
                                    uint32_t *lifetime,
                                    struct timeval *modified_time)
{
    // 99999: REMOVE
    /*struct hip_peer_addr_list_item *peer_addr_list_item;
     * int i = 1, ii;
     * struct hip_spi_out_item *spi_out;
     * hip_list_t *item, *tmp, *a_item, *a_tmp;*/

    struct hip_peer_addr_list_item *peer_addr_list_item;
    int i = 1, ii;
    hip_list_t *item, *tmp;

    list_for_each_safe(item, tmp, entry->peer_addresses_old, ii)
    {
        peer_addr_list_item = (struct hip_peer_addr_list_item *) list_entry(item);

        if (!ipv6_addr_cmp(&peer_addr_list_item->address, addr)) {
            _HIP_DEBUG("found\n");
            if (lifetime) {
                *lifetime = peer_addr_list_item->lifetime;
            }

            if (modified_time) {
                modified_time->tv_sec  = peer_addr_list_item->modified_time.tv_sec;
                modified_time->tv_usec = peer_addr_list_item->modified_time.tv_usec;
            }

            return 1;
        }

        i++;
    }

    // 99999: REMOVE
    /* assumes already locked entry */
/*	list_for_each_safe(item, tmp, entry->spis_out_old, ii)
 *      {
 *              spi_out = list_entry(item);
 *              list_for_each_safe(a_item, a_tmp, entry->peer_addresses_old, iii)
 *              {
 *                      s = list_entry(a_item);
 *                      if (!ipv6_addr_cmp(&s->address, addr))
 *                      {
 *                              _HIP_DEBUG("found\n");
 *                              if (lifetime)
 *lifetime = s->lifetime;
 *                              if (modified_time)
 *                              {
 *                                      modified_time->tv_sec = s->modified_time.tv_sec;
 *                                      modified_time->tv_usec = s->modified_time.tv_usec;
 *                              }
 *                              if (spi)
 *spi = spi_out->spi;
 *                              return 1;
 *                      }
 *                      i++;
 *              }
 *      }*/

    _HIP_DEBUG("not found\n");
    return 0;
}

/**
 * Deletes IPv6 address from the entry's list of peer addresses
 *
 * @param entry corresponding hadb entry of the peer
 * @param addr IPv6 address to be deleted
 */
void hip_hadb_delete_peer_addrlist_one_old(hip_ha_t *ha, struct in6_addr *addr)
{
    struct hip_peer_addr_list_item *peer_addr_list_item;
    int i;
    hip_list_t *item, *tmp;

    /* possibly deprecated function .. */

    list_for_each_safe(item, tmp, ha->peer_addresses_old, i)
    {
        peer_addr_list_item = (struct hip_peer_addr_list_item *) list_entry(item);
        if (!ipv6_addr_cmp(&peer_addr_list_item->address, addr)) {
            _HIP_DEBUG("deleting address\n");
            list_del(item, ha->peer_addresses_old);
            HIP_FREE(item);
            /* if address is on more than one spi list then do not goto out */
            goto out;
        }
    }

out:
    return;
}
