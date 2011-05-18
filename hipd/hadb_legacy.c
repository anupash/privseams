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
 * This file contains legacy functions for mobility that should be rewritten for modularity.
 * They are still included in the code base due to locator dependencies with
 * base exchange code. See bugzilla ids 592195 and 592196.
 *
 * @author Baris Boyvat
 * @author Miika Komu <miika@iki.fi>
 * @author Stefan Götz <stefan.goetz@web.de>
 */

#include <netinet/in.h>
#include <openssl/lhash.h>

#include "lib/core/list.h"
#include "lib/core/prefix.h"
#include "lib/core/protodefs.h"
#include "lib/core/state.h"
#include "hadb_legacy.h"

/**
 * Deletes IPv6 address from the entry's list of peer addresses
 *
 * @param ha corresponding hadb entry of the peer
 * @param addr IPv6 address to be deleted
 */
void hip_hadb_delete_peer_addrlist_one_old(struct hip_hadb_state *ha,
                                           struct in6_addr *addr)
{
    struct hip_peer_addr_list_item *peer_addr_list_item;
    int                             i;
    LHASH_NODE                     *item, *tmp;

    /* possibly deprecated function .. */

    list_for_each_safe(item, tmp, ha->peer_addresses_old, i)
    {
        peer_addr_list_item = list_entry(item);
        if (!ipv6_addr_cmp(&peer_addr_list_item->address, addr)) {
            list_del(item, ha->peer_addresses_old);
            free(item);
            /* if address is on more than one spi list then do not goto out */
            goto out;
        }
    }

out:
    return;
}
