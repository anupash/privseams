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
 * This file defines handling functions for opportunistic mode to remember
 * IP's which are not HIP capable. This means faster communication in second
 * connection attempts to these hosts. Otherwise it would always take the same
 * fallback timeout (about 5 secs) to make new connection to hosts which don't
 * support HIP.
 *
 * @author  Antti Partanen
 * @author  Alberto Garcia
 */

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "lib/core/builder.h"
#include "lib/core/common.h"
#include "lib/core/debug.h"
#include "lib/core/list.h"
#include "lib/core/prefix.h"
#include "oppipdb.h"

#define HIP_LOCK_OPPIP(entry)
#define HIP_UNLOCK_OPPIP(entry)

HIP_HASHTABLE *oppipdb;

/**
 * Generates the hash information that is used to index the table
 *
 * @param ptr: pointer to the ip address used to make the hash
 *
 * @return hash information
 */
static unsigned long hip_oppipdb_hash_ip(const void *ptr)
{
    uint8_t hash[HIP_AH_SHA_LEN];

    hip_build_digest(HIP_DIGEST_SHA1, ptr, sizeof(hip_oppip_t), hash);

    return *((unsigned long *) hash);
}

/**
 * Compares two ip addresses.
 *
 * Note that when this function is called, the hashes of the two hash table
 * entries provided as arguments are known to be equal.
 * The point of this function is to allow the hash table to determine whether
 * the entries (or rather the part used to calculate the hash) themselves are
 * equal or whether they are different and this is just a hash collision.
 *
 * @param ptr1: pointer to the first ip address to compare
 * @param ptr2: pointer to the second ip address to compare
 *
 * @return 0 if the ips are identical, 1 if they are different
 */
static int hip_oppipdb_match_ip(const void *ptr1, const void *ptr2)
{
    return memcmp(ptr1, ptr2, sizeof(hip_oppip_t));
}

/**
 * Map a function to every entry in the oppipdb hash table
 *
 * @param func mapper function to apply to all entries
 * @param opaque opaque data for the mapper function
 *
 * @return negative value if an error occurs. If an error occurs during traversal of
 * the oppipdb hash table, then the traversal is stopped and function returns.
 * Returns the last return value of applying the mapper function to the last
 * element in the hash table.
 */
int hip_for_each_oppip(void (*func)(hip_oppip_t *entry, void *opaq), void *opaque)
{
    int i = 0;
    hip_oppip_t *this;
    hip_list_t *item, *tmp;

    if (!func) {
        return -EINVAL;
    }

    HIP_LOCK_HT(&oppipdb);
    list_for_each_safe(item, tmp, oppipdb, i)
    {
        this = (hip_oppip_t *) list_entry(item);
        func(this, opaque);
    }

    HIP_UNLOCK_HT(&oppipdb);
    return 0;
}

/**
 * Deletes an entry that is present in oppipdb hash table
 *
 * @param entry pointer to the entry to delete
 * @param arg   needed because of the the iterator signature
 */
void hip_oppipdb_del_entry_by_entry(hip_oppip_t *entry, UNUSED void *arg)
{
    HIP_LOCK_OPPIP(entry);
    hip_ht_delete(oppipdb, entry);
    HIP_UNLOCK_OPPIP(entry);
    free(entry);
}

/**
 * Allocates and initilizes the node to store the information
 * in the oppipdb hash table
 *
 * @return pointer to the allocated structure
 */
static hip_oppip_t *hip_create_oppip_entry(void)
{
    hip_oppip_t *entry = NULL;

    entry = malloc(sizeof(hip_oppip_t));
    if (!entry) {
        HIP_ERROR("hip_oppip_t memory allocation failed.\n");
        return NULL;
    }

    memset(entry, 0, sizeof(*entry));

    return entry;
}

/**
 * Adds a new entry to the oppipdb hash table.
 * This table stores the ip addresses of the hosts that are not HIP capable.
 *
 * @param ip_peer: pointer to the ip of the non-HIP capable host
 *                 to be added to the table
 * @return 0 or the value being added on success; -ENOMEM on malloc failure
 */
int hip_oppipdb_add_entry(const struct in6_addr *ip_peer)
{
    int err               = 0;
    hip_oppip_t *new_item = NULL;

    new_item = hip_create_oppip_entry();
    if (!new_item) {
        HIP_ERROR("new_item malloc failed\n");
        err = -ENOMEM;
        return err;
    }

    ipv6_addr_copy(new_item, ip_peer);

    err = hip_ht_add(oppipdb, new_item);

    return err;
}

/**
 * Creates and initializes the oppipdb hash table
 *
 * @return 0 on success
 */
int hip_init_oppip_db(void)
{
    oppipdb = hip_ht_init(hip_oppipdb_hash_ip, hip_oppipdb_match_ip);
    return 0;
}

/**
 * Seeks an ip within the oppipdb hash table.
 * If the ip is found in the table, that host is not HIP capable.
 *
 * @param ip_peer: pointer to the ip of the host to check whether
 *                 it is HIP capable
 * @return pointer to the entry if the ip is found in the table; NULL otherwise
 */
hip_oppip_t *hip_oppipdb_find_byip(const struct in6_addr *ip_peer)
{
    hip_oppip_t *ret = NULL;

    ret = hip_ht_find(oppipdb, ip_peer);
    if (!ret) {
        HIP_DEBUG("The ip was not present in oppipdb. Peer HIP capable.\n");
    } else {
        HIP_DEBUG("The ip was found in oppipdb. Peer non-HIP capable.\n");
    }

    return ret;
}

/**
 * This function should be called after receiving an R1 from the peer and after
 * a successful base exchange in the opportunistic mode. It checks whether an
 * address of a HIP capable host is found from database. If the address is
 * found, it is deleted from the database; since the host is actually HIP capable.
 *
 * @param ip_peer: pointer to the ip of the HIP-capable host
 */
void hip_oppipdb_delentry(const struct in6_addr *ip_peer)
{
    hip_oppip_t *ret;

    if ((ret = hip_oppipdb_find_byip(ip_peer))) {
        HIP_DEBUG_IN6ADDR("HIP capable host found in oppipbd (non-HIP hosts database). Deleting it from oppipdb.", ip_peer);
        hip_oppipdb_del_entry_by_entry(ret, NULL);
    }
}
