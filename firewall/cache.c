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
 * Caches partial information about hadb entries (HITs, LSIs, locators and HA state). Operates
 * independently of the firewall connection tracking feature.
 *
 * @brief Cache implementation for local and peer HITs, LSIs and locators
 */

#define _BSD_SOURCE

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <openssl/lhash.h>

#include "lib/core/builder.h"
#include "lib/core/debug.h"
#include "lib/core/hashtable.h"
#include "lib/core/ife.h"
#include "lib/core/icomm.h"
#include "lib/core/list.h"
#include "lib/core/message.h"
#include "lib/core/prefix.h"
#include "lib/core/protodefs.h"

#include "firewall.h"
#include "user_ipsec_api.h"
#include "cache.h"

static HIP_HASHTABLE *firewall_cache_db = NULL;

/**
 * Allocate a cache entry. Caller must free the memory.
 *
 * @return the allocated cache entry
 */
static struct hip_hadb_user_info_state *hip_cache_create_hl_entry(void)
{
    struct hip_hadb_user_info_state *entry = NULL;

    if (!(entry = calloc(1, sizeof(struct hip_hadb_user_info_state)))) {
        HIP_ERROR("No memory available for firewall database entry.\n");
    }
    return entry;
}

/**
 * Add an cache entry into the firewall db.
 *
 * @param ha_entry cache database entry
 *
 * @return the new firewall db entry
 */
static struct hip_hadb_user_info_state *firewall_add_new_entry(const struct hip_hadb_user_info_state *ha_entry)
{
    struct hip_hadb_user_info_state *new_entry = NULL;

    HIP_DEBUG("\n");

    HIP_ASSERT(ha_entry != NULL);

    new_entry = hip_cache_create_hl_entry();
    ipv6_addr_copy(&new_entry->hit_our,  &ha_entry->hit_our);
    ipv6_addr_copy(&new_entry->hit_peer, &ha_entry->hit_peer);

    ipv4_addr_copy(&new_entry->lsi_our,  &ha_entry->lsi_our);
    ipv4_addr_copy(&new_entry->lsi_peer, &ha_entry->lsi_peer);

    ipv6_addr_copy(&new_entry->ip_our,  &ha_entry->ip_our);
    ipv6_addr_copy(&new_entry->ip_peer, &ha_entry->ip_peer);

    new_entry->state = ha_entry->state;

    hip_ht_add(firewall_cache_db, new_entry);

    return new_entry;
}

/**
 * Query HIPD for current HA information and try to match a pair of
 * HITs, LSIs or IPs. If a match is found, insert it in the firewall
 * cache and return the cache entry.
 *
 * @param local local identifier or locator (optional)
 * @param peer peer identifier or locator
 * @param type whether the parameters are HITs, LSIs or IPs
 * @return the cached entry on match, NULL otherwise
 */
static struct hip_hadb_user_info_state *hip_firewall_cache_hadb_match(const void *local,
                                                                      const void *peer,
                                                                      enum fw_cache_query_type type)
{
    struct       hip_hadb_user_info_state *err           = NULL;
    const struct hip_hadb_user_info_state *ha_curr       = NULL;
    struct       hip_common               *msg           = NULL;
    const struct hip_tlv_common           *current_param = NULL;

    HIP_IFEL(!(msg = malloc(HIP_MAX_PACKET)), NULL, "malloc failed\n");
    hip_msg_init(msg);
    HIP_IFEL(hip_build_user_hdr(msg, HIP_MSG_GET_HA_INFO, 0),
             NULL, "Building of daemon header failed\n");
    HIP_IFEL(hip_send_recv_daemon_info(msg, 0, hip_fw_sock),
             NULL, "send recv daemon info\n");

    while ((current_param = hip_get_next_param(msg, current_param))) {
        ha_curr = hip_get_param_contents_direct(current_param);

        if ((type == FW_CACHE_HIT && !ipv6_addr_cmp(peer, &ha_curr->hit_peer) &&
             (!local || !ipv6_addr_cmp(local,  &ha_curr->hit_our))) ||
            (type == FW_CACHE_LSI && !ipv4_addr_cmp(peer, &ha_curr->lsi_peer) &&
             (!local || !ipv4_addr_cmp(local, &ha_curr->lsi_our)))  ||
            (type == FW_CACHE_IP  && !ipv6_addr_cmp(peer, &ha_curr->ip_peer)  &&
             (!local || !ipv6_addr_cmp(local, &ha_curr->ip_our)))) {
            err = firewall_add_new_entry(ha_curr);
            break;
        }
    }

out_err:
    free(msg);
    return err;
}

/**
 * Search the cache database for an entry by HITs, LSIs or IPs
 *
 * @param local local identifier or locator (optional)
 * @param peer peer identifier or locator
 * @param type whether the parameters are HITs, LSIs or IPs
 * @param query_daemon whether to query the daemon for HA information
 *        if no entry is found in the cache
 * @return the entry on match, NULL otherwise
 */
struct hip_hadb_user_info_state *hip_firewall_cache_db_match(const void *local,
                                                             const void *peer,
                                                             enum fw_cache_query_type type,
                                                             int query_daemon)
{
    int                              i;
    struct hip_hadb_user_info_state *this = NULL, *ha_match = NULL;
    LHASH_NODE                      *item = NULL, *tmp = NULL;

    if (type == FW_CACHE_HIT) {
        ha_match = hip_ht_find(firewall_cache_db, peer);
        if (ha_match) {
            HIP_DEBUG("Matched using hash\n");
            goto out_err;
        }
    }

    HIP_DEBUG("Check firewall cache db\n");

    list_for_each_safe(item, tmp, firewall_cache_db, i) {
        this = list_entry(item);

        if (type == FW_CACHE_HIT &&
            !ipv6_addr_cmp(peer, &this->hit_peer) &&
            (!local || !ipv6_addr_cmp(local, &this->hit_our))) {
            ha_match = this;
            break;
        } else if (type == FW_CACHE_LSI &&
                   !ipv4_addr_cmp(peer, &this->lsi_peer) &&
                   (!local || !ipv4_addr_cmp(local, &this->lsi_our))) {
            ha_match = this;
            break;
        } else if (type == FW_CACHE_IP &&
                   !ipv6_addr_cmp(peer, &this->ip_peer) &&
                   (!local || !ipv6_addr_cmp(local, &this->ip_our))) {
            ha_match = this;
            break;
        }
    }

    if (!ha_match && query_daemon) {
        HIP_DEBUG("No match found in cache, querying daemon\n");
        ha_match = hip_firewall_cache_hadb_match(local, peer, type);
    }

out_err:
    if (!ha_match) {
        HIP_DEBUG("No match found\n");
    }

    return ha_match;
}

/**
 * Generate the hash information that is used to index the cache table
 *
 * @param ptr pointer to the hit used to make the hash
 *
 * @return the value of the hash
 */
static unsigned long hip_firewall_hash_hit_peer(const void *ptr)
{
    const struct in6_addr *hit_peer = &((const struct hip_hadb_user_info_state *) ptr)->hit_peer;
    uint8_t                hash[HIP_AH_SHA_LEN];

    hip_build_digest(HIP_DIGEST_SHA1, hit_peer, sizeof(*hit_peer), hash);
    return *((unsigned long *) hash);
}

/**
 * Compare two cache table entries to resolve hash collisions.
 *
 * Note that when this function is called, the hashes of the two hash table
 * entries provided as arguments are known to be equal.
 * The point of this function is to allow the hash table to determine whether
 * the entries (or rather the part used to calculate the hash) themselves are
 * equal or whether they are different and this is just a hash collision.
 *
 * @param ptr1: pointer to a struct hip_hadb_user_info_state
 * @param ptr2: pointer to a struct hip_hadb_user_info_state
 *
 * @return zero if the peer HITs in both table entries are identical, a non-zero value otherwise.
 */
static int hip_firewall_match_hit_peer(const void *ptr1, const void *ptr2)
{
    // stg: can one assume that there will always be at most one struct hip_hadb_user_info_state object per hit_peer?
    // If so, one could compare the pointers instead because if the hit_peers are the same, the pointers would be the same, and comparing the pointers is faster.
    const struct in6_addr *peer1 = &((const struct hip_hadb_user_info_state *) ptr1)->hit_peer;
    const struct in6_addr *peer2 = &((const struct hip_hadb_user_info_state *) ptr2)->hit_peer;
    return memcmp(peer1, peer2, sizeof(*peer1));
}

/**
 * Initialize cache database
 */
void hip_firewall_cache_init_hldb(void)
{
    firewall_cache_db = hip_ht_init(hip_firewall_hash_hit_peer,
                                    hip_firewall_match_hit_peer);
}

/**
 * Uninitialize cache database
 * @param exiting   1 if the firewall is exiting and the hashtable should be
 *                  freed or zero otherwise
 */
void hip_firewall_cache_delete_hldb(int exiting)
{
    int                              i;
    struct hip_hadb_user_info_state *this = NULL;
    LHASH_NODE                      *item = NULL, *tmp = NULL;

    HIP_DEBUG("Start hldb delete\n");

    if (firewall_cache_db) {
        list_for_each_safe(item, tmp, firewall_cache_db, i)
        {
            this = list_entry(item);
            hip_ht_delete(firewall_cache_db, this);
            free(this);
        }
    }

    /* Note: this function is also reached by "hipconf rst all"
     * so we don't want to uninitialize hash table here. Instead,
     * we handle it in firewall_exit(). */

    if (exiting) {
        hip_ht_uninit(firewall_cache_db);
    }
    HIP_DEBUG("End hldb delete\n");
}

/**
 * Update the state of a cached entry identified by HITs
 * @param  hit_our Local HIT (optional)
 * @param  hit_peer Peer HIT
 * @param state New state
 * @return 0 on success, negative on error
 */
int hip_firewall_cache_set_bex_state(const struct in6_addr *hit_our,
                                     const struct in6_addr *hit_peer,
                                     int state)
{
    int                              err = 0;
    struct hip_hadb_user_info_state *entry;

    HIP_IFEL(!hit_peer, -1, "Need peer HIT to search\n");

    entry = hip_firewall_cache_db_match(hit_our, hit_peer, FW_CACHE_HIT, 0);
    HIP_IFEL(!entry, -1, "No cache entry found\n");

    entry->state = state;

out_err:
    return err;
}
