/**
 * @file firewall/cache.c
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 *
 * Caches partial information about hadb entries (HITs, LSIs, locators and HA state). Operates
 * independently of the firewall connection tracking feature.
 *
 * @brief Cache implementation for local and peer HITs, LSIs and locators
 *
 * @author Miika Komu <miika@iki.fi>
 */

/* required for s6_addr32 */
#define _BSD_SOURCE

#include "cache.h"
#include "lib/core/debug.h"
#include "lib/core/misc.h"
#include "firewall.h"
#include "user_ipsec_api.h"

static HIP_HASHTABLE *firewall_cache_db = NULL;

/**
 * Allocate a cache entry. Caller must free the memory.
 *
 * @return the allocated cache entry
 */
firewall_cache_hl_t *hip_cache_create_hl_entry(void)
{
    firewall_cache_hl_t *entry = NULL;
    int err = 0;

    HIP_IFEL(!(entry = (firewall_cache_hl_t *) HIP_MALLOC(sizeof(firewall_cache_hl_t), 0)),
             -ENOMEM, "No memory available for firewall database entry\n");
    memset(entry, 0, sizeof(*entry));
out_err:
    return entry;
}

/**
 * Add an cache entry into the firewall db.
 *
 * @param h_entry cache database entry
 *
 * @return zero on success and non-zero on error
 */
static int firewall_add_new_entry(const firewall_cache_hl_t *ha_entry)
{
    firewall_cache_hl_t *new_entry = NULL;
    int err = 0;

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

    return err;
}

/**
 * Search the cache database for an entry. The search is based on HITs if they are given.
 * If HITs are NULL, then search with the LSIs.
 *
 * @param hit_our local HIT
 * @param hit_peer remote HIT
 * @param lsi_our local LSI
 * @param lsi_peer remote LSI
 * @param ip_our local (default) locator
 * @param ip_peer remote (default) locator
 * @param state output argument in which the function writes the state of the corresponding HIP association
 * @return
 */
int hip_firewall_cache_db_match(const struct in6_addr *hit_our,
                                const struct in6_addr *hit_peer,
                                hip_lsi_t       *lsi_our,
                                hip_lsi_t       *lsi_peer,
                                struct in6_addr *ip_our,
                                struct in6_addr *ip_peer,
                                int *state)
{
    int i, err = 0, entry_in_cache = 0;
    firewall_cache_hl_t *this            = NULL;
    hip_list_t *item                     = NULL;
    hip_list_t *tmp                      = NULL;
    struct hip_common *msg               = NULL;
    firewall_cache_hl_t *ha_curr         = NULL;
    firewall_cache_hl_t *ha_match        = NULL;
    struct hip_tlv_common *current_param = NULL;

    HIP_ASSERT((hit_our && hit_peer) ||
               (lsi_our && lsi_peer));

    if (hit_peer) {
        ha_match = (firewall_cache_hl_t *) hip_ht_find(
            firewall_cache_db,
            (void *) hit_peer);
        if (ha_match) {
            HIP_DEBUG("Matched using hash\n");
            entry_in_cache = 1;
            goto out_err;
        }
    }

    HIP_DEBUG("Check firewall cache db\n");

    HIP_LOCK_HT(&firewall_cache_db);

    list_for_each_safe(item, tmp, firewall_cache_db, i) {
        this = (firewall_cache_hl_t *) list_entry(item);

        if (lsi_our && lsi_peer) {
            HIP_DEBUG_INADDR("this->our", (hip_lsi_t *) &this->lsi_our.s_addr);
            HIP_DEBUG_INADDR("this->peer", (hip_lsi_t *) &this->lsi_peer.s_addr);
            HIP_DEBUG_INADDR("our", lsi_our);
            HIP_DEBUG_INADDR("peer", lsi_peer);
        }

        if (hit_our && hit_peer &&
            (ipv6_addr_cmp(hit_peer, &this->hit_peer) == 0) &&
            (ipv6_addr_cmp(hit_our,  &this->hit_our)  == 0)) {
            ha_match = this;
            break;
        }
        if (lsi_our && lsi_peer &&
            lsi_peer->s_addr == this->lsi_peer.s_addr &&
            lsi_our->s_addr  == this->lsi_our.s_addr) {
            ha_match = this;
            break;
        }
        if (ip_our && ip_peer &&
            ip_peer->s6_addr == this->ip_peer.s6_addr &&
            ip_our->s6_addr  == this->ip_our.s6_addr) {
            ha_match = this;
            break;
        }
    }
    HIP_UNLOCK_HT(&firewall_cache_db);

    if (ha_match) {
        entry_in_cache = 1;
        goto out_err;
    }

    HIP_DEBUG("No cache found, querying daemon\n");

    HIP_IFEL(!(msg = malloc(HIP_MAX_PACKET)), -1, "malloc failed\n");
    hip_msg_init(msg);
    HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_GET_HA_INFO, 0),
             -1, "Building of daemon header failed\n");
    HIP_IFEL(hip_send_recv_daemon_info(msg, 0, hip_fw_sock), -1,
             "send recv daemon info\n");

    while ((current_param = hip_get_next_param(msg, current_param)) != NULL) {
        ha_curr = hip_get_param_contents_direct(current_param);

        HIP_DEBUG_HIT("our1", &ha_curr->hit_our);
        HIP_DEBUG_HIT("peer1", &ha_curr->hit_peer);
        if (hit_our) {
            HIP_DEBUG_HIT("our2", hit_our);
        }
        if (hit_peer) {
            HIP_DEBUG_HIT("peer2", hit_peer);
        }
        if (hit_our && hit_peer &&
            (ipv6_addr_cmp(hit_peer, &ha_curr->hit_peer) == 0) &&
            (ipv6_addr_cmp(hit_our,  &ha_curr->hit_our)  == 0)) {
            HIP_DEBUG("Matched HITs\n");
            ha_match = ha_curr;
            break;
        }
        if (lsi_our && lsi_peer &&
            lsi_peer->s_addr == ha_curr->lsi_peer.s_addr &&
            lsi_our->s_addr  == ha_curr->lsi_our.s_addr) {
            HIP_DEBUG("Matched LSIs\n");
            ha_match = ha_curr;
            break;
        }
        if (ip_our && ip_peer &&
            ip_peer->s6_addr == ha_curr->ip_peer.s6_addr &&
            ip_our->s6_addr  == ha_curr->ip_our.s6_addr) {
            HIP_DEBUG("Matched IPs\n");
            ha_match = ha_curr;
            break;
        }
    }

out_err:
    if (ha_match) {
        if (!entry_in_cache) {
            firewall_add_new_entry(ha_match);
        }

        if (lsi_our) {
            ipv4_addr_copy(lsi_our, &ha_match->lsi_our);
        }

        if (lsi_peer) {
            ipv4_addr_copy(lsi_peer, &ha_match->lsi_peer);
        }

        if (ip_our) {
            ipv6_addr_copy(ip_our, &ha_match->ip_our);
        }

        if (ip_peer) {
            ipv6_addr_copy(ip_peer, &ha_match->ip_peer);
            HIP_DEBUG_IN6ADDR("peer ip", ip_peer);
        }

        if (state) {
            *state = ha_match->state;
        }
    } else {
        err = -1;
    }

    if (msg) {
        free(msg);
    }

    return err;
}

/**
 * Generate the hash information that is used to index the cache table
 *
 * @param ptr pointer to the hit used to make the hash
 *
 * @return the value of the hash
 */
unsigned long hip_firewall_hash_hit_peer(const void *ptr)
{
    struct in6_addr *hit_peer = &((firewall_cache_hl_t *) ptr)->hit_peer;
    uint8_t hash[HIP_AH_SHA_LEN];

    hip_build_digest(HIP_DIGEST_SHA1, hit_peer, sizeof(*hit_peer), hash);
    return *((unsigned long *) hash);
}

/**
 * Compare two HITs
 *
 * @param ptr1: pointer to a HIT
 * @param ptr2: pointer to a HIT
 *
 * @return zero if hashes are identical, or one otherwise
 */
int hip_firewall_match_hit_peer(const void *ptr1, const void *ptr2)
{
    return hip_firewall_hash_hit_peer(ptr1) != hip_firewall_hash_hit_peer(ptr2);
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
 *
 * @param exit 1 if the firewall is exiting and the hashtable should be
 *               freed or zero otherwise
 */
void hip_firewall_cache_delete_hldb(int exit)
{
    int i;
    firewall_cache_hl_t *this = NULL;
    hip_list_t *item          = NULL;
    hip_list_t *tmp           = NULL;

    HIP_DEBUG("Start hldb delete\n");
    HIP_LOCK_HT(&firewall_cache_db);

    list_for_each_safe(item, tmp, firewall_cache_db, i)
    {
        this = (firewall_cache_hl_t *) list_entry(item);
        hip_ht_delete(firewall_cache_db, this);
        free(this);
    }

    /* Note: this function is also reached by "hipconf rst all"
     * so we don't want to uninitialize hash table here. Instead,
     * we handle it in firewall_exit(). */

    HIP_UNLOCK_HT(&firewall_cache_db);
    if (exit)
        hip_ht_uninit(firewall_cache_db);
    HIP_DEBUG("End hldbdb delete\n");
}
