/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 *
 * @todo THIS DATABASE IS REDUDANT WITH CACHE.C AND CONTAINS ONLY A SUBSET OF IT. REWRITE AND TEST!!!
 * @note this code is linked to the use of hip_firewall_set_bex_data()
 * @todo move the raw socket initialization to somewhere else
 *
 * @brief Write a short summary
 *
 * @author another Author another@author.net
 */

#define _BSD_SOURCE

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "lib/core/builder.h"
#include "lib/core/debug.h"
#include "lib/core/hashtable.h"
#include "lib/core/icomm.h"
#include "lib/core/ife.h"
#include "lib/core/list.h"
#include "lib/core/prefix.h"
#include "lib/core/protodefs.h"
#include "lib/tool/checksum.h"
#include "cache.h"
#include "firewalldb.h"


HIP_HASHTABLE *firewall_hit_lsi_ip_db;


/**
 * display the contents of the database
 */
static void hip_firewall_hldb_dump(void)
{
    int i;
    firewall_hl_t *this;
    hip_list_t *item, *tmp;
    HIP_DEBUG("---------   Firewall db   ---------\n");
    HIP_LOCK_HT(&firewall_lsi_hit_db);

    list_for_each_safe(item, tmp, firewall_hit_lsi_ip_db, i) {
        this = list_entry(item);
        HIP_DEBUG_HIT("hit_our", &this->hit_our);
        HIP_DEBUG_HIT("hit_peer", &this->hit_peer);
        HIP_DEBUG_LSI("lsi", &this->lsi);
        HIP_DEBUG_IN6ADDR("ip", &this->ip_peer);
        HIP_DEBUG("bex_state %d \n", this->bex_state);
    }
    HIP_UNLOCK_HT(&firewall_lsi_hit_db);
}

/**
 * Search in the database the given peer ip
 *
 * @param ip_peer: entrance that we are searching in the db
 * @return NULL if not found and otherwise the firewall_hl_t structure
 */
firewall_hl_t *hip_firewall_ip_db_match(const struct in6_addr *ip_peer)
{
    hip_firewall_hldb_dump();
    HIP_DEBUG_IN6ADDR("peer ip", ip_peer);
    return (firewall_hl_t *) hip_ht_find(firewall_hit_lsi_ip_db,
                                         (void *) ip_peer);
}

/**
 * allocate memory for a new database entry
 *
 * @return the allocated database entry (caller responsible of freeing)
 */
static firewall_hl_t *hip_create_hl_entry(void)
{
    firewall_hl_t *entry = NULL;
    int err              = 0;
    HIP_IFEL(!(entry = malloc(sizeof(firewall_hl_t))),
             -ENOMEM, "No memory available for firewall database entry\n");
    memset(entry, 0, sizeof(*entry));
out_err:
    return entry;
}

/**
 * Add a default entry in the firewall db.
 *
 * @param ip    the only supplied field, the ip of the peer
 * @return      error if any
 */
int hip_firewall_add_default_entry(const struct in6_addr *ip)
{
    struct in6_addr all_zero_default_v6;
    struct in_addr all_zero_default_v4, in4;
    firewall_hl_t *new_entry  = NULL;
    firewall_hl_t *entry_peer = NULL;
    int err                   = 0;

    HIP_DEBUG("\n");

    HIP_ASSERT(ip != NULL);

    entry_peer = hip_firewall_ip_db_match(ip);

    if (!entry_peer) {
        HIP_DEBUG_IN6ADDR("ip ", ip);

        new_entry = hip_create_hl_entry();

        memset(&all_zero_default_v6, 0, sizeof(all_zero_default_v6));
        memset(&all_zero_default_v4, 0, sizeof(all_zero_default_v4));

        /* Check the lower bits of the address to make sure it is not
         * a zero address. Otherwise e.g. connections to multiple LSIs
         * don't work. */
        IPV6_TO_IPV4_MAP(ip, &in4);
        if (in4.s_addr == 0) {
            HIP_DEBUG("NULL default address\n");
            return 0;
        }

        ipv6_addr_copy(&new_entry->hit_our,  &all_zero_default_v6);
        ipv6_addr_copy(&new_entry->hit_peer, &all_zero_default_v6);
        ipv4_addr_copy(&new_entry->lsi,      &all_zero_default_v4);
        ipv6_addr_copy(&new_entry->ip_peer,  ip);
        new_entry->bex_state = FIREWALL_STATE_BEX_DEFAULT;

        hip_ht_add(firewall_hit_lsi_ip_db, new_entry);
    }

    return err;
}

/**
 * Update an existing entry. The entry is found based on the peer ip.
 * If any one of the first three params is null,
 * the corresponding field in the db entry is not updated.
 * The ip field is required so as to find the entry.
 *
 * @param *hit_our  our hit, optionally null
 * @param *hit_peer peer hit, optionally null
 * @param *lsi      peer lsi, optionally null
 * @param *ip       peer ip, NOT null
 * @param state     state of entry, required
 *
 * @return  error if any
 */
int hip_firewall_update_entry(const struct in6_addr *hit_our,
                              const struct in6_addr *hit_peer,
                              const hip_lsi_t       *lsi,
                              const struct in6_addr *ip,
                              int state)
{
    int err = 0;
    firewall_hl_t *entry_update = NULL;

    HIP_DEBUG("\n");

    HIP_ASSERT(ip != NULL &&
               (state == FIREWALL_STATE_BEX_DEFAULT        ||
                state == FIREWALL_STATE_BEX_NOT_SUPPORTED  ||
                state == FIREWALL_STATE_BEX_ESTABLISHED));

    if (ip) {
        HIP_DEBUG_IN6ADDR("ip", ip);
    }

    HIP_IFEL(!(entry_update = hip_firewall_ip_db_match(ip)), -1,
             "Did not find entry\n");

    //update the fields if new value value is not NULL
    if (hit_our) {
        ipv6_addr_copy(&entry_update->hit_our, hit_our);
    }
    if (hit_peer) {
        ipv6_addr_copy(&entry_update->hit_peer, hit_peer);
    }
    if (lsi) {
        ipv4_addr_copy(&entry_update->lsi, lsi);
    }
    entry_update->bex_state = state;

out_err:
    return err;
}

/**
 * Generate the hash information that is used to index the table
 *
 * @param ptr: pointer to the lsi used to make the hash
 *
 * @return hash information
 */
static unsigned long hip_firewall_hash_ip_peer(const void *ptr)
{
    struct in6_addr *ip_peer = &((firewall_hl_t *) ptr)->ip_peer;
    uint8_t hash[HIP_AH_SHA_LEN];

    hip_build_digest(HIP_DIGEST_SHA1, ip_peer, sizeof(*ip_peer), hash);
    return *((unsigned long *) hash);
}

/**
 * Compare two IPs
 *
 * @param ptr1: pointer to ip
 * @param ptr2: pointer to ip
 *
 * @return 0 if hashes identical, otherwise 1
 */
static int hip_firewall_match_ip_peer(const void *ptr1, const void *ptr2)
{
    return hip_firewall_hash_ip_peer(ptr1) != hip_firewall_hash_ip_peer(ptr2);
}

/**
 * Initialize the database
 */
void hip_firewall_init_hldb(void)
{
    firewall_hit_lsi_ip_db = hip_ht_init(hip_firewall_hash_ip_peer,
                                         hip_firewall_match_ip_peer);
}

/**
 * Update the state of a cached HADB entry denoted by the given HITs
 *
 * @param hit_s the source HIT of the HADB cache
 * @param hit_r the destination HIT of the HADB cache
 * @param state the new state of the HADB entry
 *
 * @return zero on success and non-zero on error
 */
int hip_firewall_set_bex_state(struct in6_addr *hit_s,
                               struct in6_addr *hit_r,
                               int state)
{
    struct in6_addr ip_src, ip_dst;
    hip_lsi_t lsi_our, lsi_peer;
    int err = 0;

    HIP_IFEL(hip_firewall_cache_db_match(hit_r, hit_s, &lsi_our, &lsi_peer,
                                         &ip_src, &ip_dst, NULL),
             -1, "Failed to query LSIs\n");
    HIP_IFEL(hip_firewall_update_entry(NULL, NULL, NULL, &ip_dst, state), -1,
             "Failed to update firewall entry\n");

out_err:
    return err;
}

/**
 * remove and deallocate the hadb cache
 *
 */
void hip_firewall_delete_hldb(void)
{
    int i;
    firewall_hl_t *this = NULL;
    hip_list_t *item, *tmp;

    HIP_DEBUG("Start hldb delete\n");
    HIP_LOCK_HT(&firewall_lsi_hit_db);

    list_for_each_safe(item, tmp, firewall_hit_lsi_ip_db, i)
    {
        this = (firewall_hl_t *) list_entry(item);
        hip_ht_delete(firewall_hit_lsi_ip_db, this);
        free(this);
    }
    HIP_UNLOCK_HT(&firewall_lsi_hit_db);
    HIP_DEBUG("End hldbdb delete\n");
}
