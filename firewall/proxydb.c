/** @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 *
 * HIP client-side proxy databases. Documented in detail in Weiwei's
 * thesis when it's finished.
 *
 * @author Weiwei Hu
 */

#include "proxydb.h"

HIP_HASHTABLE *hip_proxy_db = NULL;


/**
 * Create a hash of the given entry for the hash table
 *
 * @param p the connection entry
 * @return a hash calculated based on the given entry
 */
static unsigned long hip_proxy_db_hash(const hip_proxy_t *p)
{
    hip_hit_t hitpair[2];
    uint8_t hash[HIP_AH_SHA_LEN];

    if (p == NULL || &(p->addr_client) == NULL || &(p->addr_peer) == NULL) {
        return 0;
    }

    /* The HIT fields of an host association struct cannot be assumed to be
     * alligned consecutively. Therefore, we must copy them to a temporary
     * array. */
    memcpy(&hitpair[0], &(p->addr_client), sizeof(p->addr_client));
    memcpy(&hitpair[1], &(p->addr_peer), sizeof(p->addr_peer));

    hip_build_digest(HIP_DIGEST_SHA1, (void *) hitpair, sizeof(hitpair), hash);

    return *((unsigned long *) hash);
}

/** A callback wrapper of the prototype required by @c lh_new(). */
static IMPLEMENT_LHASH_HASH_FN(hip_proxy_db, const hip_proxy_t)


/**
 * Compare two hash keys
 *
 * @param ha1 first hash key
 * @param ha2 second hash key
 * @return zero if keys match or one otherwise
 */
static int hip_proxy_db_cmp(const hip_proxy_t *ha1, const hip_proxy_t *ha2)
{
    if (ha1 == NULL
            || &(ha1->addr_client) == NULL
            || &(ha1->addr_peer) == NULL
            || ha2 == NULL
            || &(ha2->addr_client) == NULL
            || &(ha2->addr_peer) == NULL) {
        return 1;
    }

    return hip_proxy_db_hash(ha1) != hip_proxy_db_hash(ha2);
}

/** A callback wrapper of the prototype required by @c lh_new(). */
static IMPLEMENT_LHASH_COMP_FN(hip_proxy_db, const hip_proxy_t)


/**
 * Initialize the proxy database
 */
void hip_init_proxy_db(void)
{
    hip_proxy_db = hip_ht_init(LHASH_HASH_FN(hip_proxy_db),
                               LHASH_COMP_FN(hip_proxy_db));
}

/**
 * Unitialize the proxy database
 */
void hip_uninit_proxy_db(void)
{
    int i = 0;
    hip_list_t *item, *tmp;
    hip_proxy_t *entry;

    list_for_each_safe(item, tmp, hip_proxy_db, i)
    {
        entry = (hip_proxy_t *) list_entry(item);
        hip_ht_delete(hip_proxy_db, entry);
    }
}

/**
 * Add an entry to the database of the HIP proxy
 *
 * @param addr_client Addess of the legacy client
 * @param addr_peer Address of the HIP server
 * @return zero on success or non-zero on failure
 */
int hip_proxy_add_entry(const struct in6_addr *addr_client,
                        const struct in6_addr *addr_peer)
{
    hip_proxy_t *new_item = NULL;
    int err               = 0;

    new_item = malloc(sizeof(hip_proxy_t));
    if (!new_item) {
        HIP_ERROR("new_item malloc failed\n");
        err = -ENOMEM;
        return err;
    }

    memset(new_item, 0, sizeof(hip_proxy_t));
    ipv6_addr_copy(&new_item->addr_client, addr_client);
    ipv6_addr_copy(&new_item->addr_peer, addr_peer);
    err = hip_ht_add(hip_proxy_db, new_item);
    HIP_DEBUG("Proxy adds connection state successfully!\n");
    HIP_DEBUG_IN6ADDR("source ip addr", &new_item->addr_client );
    HIP_DEBUG_IN6ADDR("destination ip addr", &new_item->addr_peer);

    return err;
}

/**
 * Find the proxy database entry corresponding to addresses
 *
 * @param addr the address of the legacy client
 * @param addr2 the address of the HIP server
 * @return the database entry if found or otherwise NULL
 */
hip_proxy_t *hip_proxy_find_by_addr(const struct in6_addr *addr,
                                    const struct in6_addr *addr2)
{
    hip_proxy_t p;
    memcpy(&p.addr_client, addr, sizeof(struct in6_addr));
    memcpy(&p.addr_peer, addr2, sizeof(struct in6_addr));

    return hip_ht_find(hip_proxy_db, &p);
}

/**
 * Update the entry state in the proxy database
 * Only for known clients
 *
 * @param entry the HIP database entry
 * @param client_addr the IP address of the client
 * @param peer_addr the IP address of the server
 * @param proxy_addr the IP address of the HIP proxy
 * @param proxy_hit the HIT of the HIP proxy
 * @param peer_hit the HIT of the server
 * @param state the state of the connection entry
 * @return zero on success or non-zero on failure
 */
static int hip_proxy_update_entry_state(hip_proxy_t *entry,
                                        struct in6_addr *client_addr,
                                        struct in6_addr *peer_addr,
                                        struct in6_addr *proxy_addr,
                                        hip_hit_t *proxy_hit,
                                        hip_hit_t *peer_hit,
                                        int state)
{
    HIP_ASSERT(entry);

    if (peer_hit) {
        ipv6_addr_copy(&entry->hit_peer, peer_hit);
    }
    if (client_addr) {
        ipv6_addr_copy(&entry->addr_client, client_addr);
    }
    if (peer_addr) {
        ipv6_addr_copy(&entry->addr_peer, peer_addr);
    }
    if (proxy_addr) {
        ipv6_addr_copy(&entry->addr_proxy, proxy_addr);
    }
    if (state) {
        entry->state = state;
    }

    return 0;
}

/**
 * The firewall receives R1 and does not know which client to serve.
 * Updates all clients.
 *
 * @param client_addr the IP address of the client
 * @param peer_addr the IP address of the server
 * @param proxy_addr the IP address of the HIP proxy
 * @param proxy_hit the HIT of the HIP proxy
 * @param peer_hit the HIT of the server
 * @param state the state of the connection entry
 *
 */
static int hip_proxy_update_state_no_client(struct in6_addr *client_addr,
                                            struct in6_addr *peer_addr,
                                            struct in6_addr *proxy_addr,
                                            hip_hit_t *proxy_hit,
                                            hip_hit_t *peer_hit,
                                            int state)
{
    int i = 0;
    hip_proxy_t *this;
    hip_list_t *item, *tmp;

    list_for_each_safe(item, tmp, hip_proxy_db, i)
    {
        this = (hip_proxy_t *) list_entry(item);
        if (ipv6_addr_cmp(&this->addr_peer, peer_addr) == 0) {
            return hip_proxy_update_entry_state(this, client_addr,
                                                peer_addr,
                                                proxy_addr,
                                                proxy_hit,
                                                peer_hit,
                                                state);
        }
    }
    return 0;
}


/**
 * Update the entry state in the proxy database for all cases.
 * Available for the known clients and unknow clients
 *
 * @param client_addr the IP address of the client
 * @param peer_addr the IP address of the server
 * @param proxy_addr the IP address of the HIP proxy
 * @param proxy_hit the HIT of the HIP proxy
 * @param peer_hit the HIT of the server
 * @param state the state of the connection entry
 *
 */
int hip_proxy_update_state(struct in6_addr *client_addr,
                           struct in6_addr *peer_addr,
                           struct in6_addr *proxy_addr,
                           hip_hit_t *proxy_hit,
                           hip_hit_t *peer_hit,
                           int state)
{
    hip_proxy_t *p;

    HIP_ASSERT(peer_addr);

    if (client_addr == NULL) {
        return hip_proxy_update_state_no_client(client_addr,
                                                peer_addr,
                                                proxy_addr,
                                                proxy_hit,
                                                peer_hit,
                                                state);
    }

    p = hip_proxy_find_by_addr(client_addr, peer_addr);
    if (p) {
        return hip_proxy_update_entry_state(p, client_addr,
                                            peer_addr,
                                            proxy_addr,
                                            proxy_hit,
                                            peer_hit,
                                            state);
    }
    return -1;
}
