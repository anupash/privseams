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
 * Host Association Database (HADB) is the heart of the hipd and it
 * contains state information about HIP connectivity with remote
 * hosts. It shouldn't be confused with Host Identity Data Base (HIDB)
 * which contains just the local host identities. The Host Association
 * is an implementation-speficic synonym for HIP association (RFC
 * terminology).
 *
 * HADB is a hash table. It is indexed by a local and remote HIT. For
 * opportunistic connections, the remote HIT is actually a "pseudo
 * HIT" at the Initiator side when sending I1. The pseudo HIT consists
 * of a HIT prefix and a part of the IP address (to avoid demuxing
 * problems with multiple simultaneous opportunistic connections at
 * the Initiator side. The Initiator deletes the "pseudo HA" and
 * creates a new one upon receiving the R1. At the Responder side,
 * this pseudo trick is not needed because the Responder can just
 * choose a real HIT when it receives the opportunistic I1.
 *
 * The hash table structure is located in lib/core/state.h and it is
 * called hip_hadb_state. As the structure contains sensitive
 * information (symmetric key material for IPsec), it should not be
 * exposed outside of hipd (use hip_hadb_user_info_state instead).
 *
 * You can use HADB to store information about negotiated extensions,
 * local or peer host capabilities, etc. Do not store there
 * information that is needed to process a single HIP packet, but
 * instead use the hip_context structure and pass in in function
 * arguments.
 *
 * @brief Host Association Database (HADB) for HIP
 */

#define _BSD_SOURCE

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/dsa.h>
#include <openssl/lhash.h>
#include <openssl/rsa.h>

#include "lib/core/builder.h"
#include "lib/core/crypto.h"
#include "lib/core/debug.h"
#include "lib/core/hashtable.h"
#include "lib/core/hip_udp.h"
#include "lib/core/hostid.h"
#include "lib/core/hostsfiles.h"
#include "lib/core/ife.h"
#include "lib/core/keylen.h"
#include "lib/core/list.h"
#include "lib/core/prefix.h"
#include "lib/core/protodefs.h"
#include "lib/core/solve.h"
#include "lib/core/straddr.h"
#include "lib/core/transform.h"
#include "lib/tool/pk.h"
#include "lib/tool/xfrmapi.h"
#include "config.h"
#include "accessor.h"
#include "hidb.h"
#include "hipd.h"
#include "input.h"
#include "keymat.h"
#include "netdev.h"
#include "output.h"
#include "hadb.h"


HIP_HASHTABLE *hadb_hit = NULL;

struct hip_peer_map_info {
    hip_hit_t       peer_hit;
    struct in6_addr peer_addr;
    hip_lsi_t       peer_lsi;
    struct in6_addr our_addr;
    uint8_t         peer_hostname[HIP_HOST_ID_HOSTNAME_LEN_MAX];
};

/**
 * The hash function of the hashtable. Calculates a hash from parameter host
 * assosiation HITs (hit_our and hit_peer).
 *
 * @param ha  rec a pointer to a host assosiation.
 * @return    the calculated hash or zero if ha, hit_our or hit_peer is NULL.
 */
static unsigned long hip_ha_hash(const struct hip_hadb_state *ha)
{
    hip_hit_t hitpair[2];
    uint8_t   hash[HIP_AH_SHA_LEN];

    if (ha == NULL || &ha->hit_our == NULL || &ha->hit_peer == NULL) {
        return 0;
    }

    /* The HIT fields of an host association struct cannot be assumed to be
     * alligned consecutively. Therefore, we must copy them to a temporary
     * array. */
    memcpy(&hitpair[0], &ha->hit_our, sizeof(ha->hit_our));
    memcpy(&hitpair[1], &ha->hit_peer, sizeof(ha->hit_peer));

    hip_build_digest(HIP_DIGEST_SHA1, hitpair, sizeof(hitpair),
                     hash);

    return *((unsigned long *) hash);
}

/** A callback wrapper of the prototype required by @c lh_new(). */
STATIC_IMPLEMENT_LHASH_HASH_FN(hip_ha, struct hip_hadb_state)

/**
 * a comparison function for the hash table algorithm to distinguish
 * two HAs from each other
 *
 * Note that when this function is called, the hashes of the two hash table
 * entries provided as arguments are known to be equal.
 * The point of this function is to allow the hash table to determine whether
 * the entries (or rather the part used to calculate the hash) themselves are
 * equal or whether they are different and this is just a hash collision.
 *
 * @param ha1 a HA to compare for equality
 * @param ha2 a HA to compare for equality
 * @return zero if the HAs match or non-zero otherwise
 */
static int hip_ha_cmp(const struct hip_hadb_state *ha1,
                      const struct hip_hadb_state *ha2)
{
    int result_hit_our = 0;

    if (ha1 == NULL || ha2 == NULL) {
        return 1;
    }

    result_hit_our = memcmp(&ha1->hit_our, &ha2->hit_our, sizeof(ha1->hit_our));
    if (result_hit_our != 0) {
        return result_hit_our;
    }
    return memcmp(&ha1->hit_peer, &ha2->hit_peer, sizeof(ha1->hit_peer));
}

/** A callback wrapper of the prototype required by @c lh_new(). */
STATIC_IMPLEMENT_LHASH_COMP_FN(hip_ha, struct hip_hadb_state)

/**
 * build a digest of a peer address
 *
 * @param ptr a pointer to hip_peer_addr_list_item structure
 * @return a digest of the address in the hip_peer_addr_list_item structure
 */
static unsigned long hip_hash_peer_addr(const void *ptr)
{
    const struct in6_addr *addr;
    uint8_t                hash[HIP_AH_SHA_LEN];

    addr = &((const struct hip_peer_addr_list_item *) ptr)->address;
    hip_build_digest(HIP_DIGEST_SHA1, addr, sizeof(*addr), hash);

    return *((unsigned long *) hash);
}

/**
 * test if two peer addresses match to detect and avoid hash collisions in the peer address list.
 *
 * Note that when this function is called, the hashes of the two hash table
 * entries provided as arguments are known to be equal.
 * The point of this function is to allow the hash table to determine whether
 * the entries (or rather the part used to calculate the hash) themselves are
 * equal or whether they are different and this is just a hash collision.
 *
 * @param ptr1 a pointer to a hip_peer_addr_list_item
 * @param ptr2 a pointer to a hip_peer_addr_list_item
 * @return zero if the addresses match or non-zero otherwise
 */
static int hip_match_peer_addr(const void *ptr1, const void *ptr2)
{
    const struct in6_addr *addr1 = &((const struct hip_peer_addr_list_item *) ptr1)->address;
    const struct in6_addr *addr2 = &((const struct hip_peer_addr_list_item *) ptr2)->address;
    return memcmp(addr1, addr2, sizeof(*addr1));
}

/* PRIMITIVES */

/**
 * assign local and peer LSI to the given host association
 *
 * @param entry the host association
 */
static void hip_hadb_set_lsi_pair(struct hip_hadb_state *entry)
{
    hip_lsi_t aux;
    //Assign value to lsi_our searching in hidb by the correspondent hit
    if (entry) {
        hip_hidb_get_lsi_by_hit(&entry->hit_our, &entry->lsi_our);
        //Assign lsi_peer
        if (hip_map_hit_to_lsi_from_hosts_files(&entry->hit_peer, &aux)) {
            hip_generate_peer_lsi(&aux);
        }
        memcpy(&entry->lsi_peer, &aux, sizeof(hip_lsi_t));
    }
}

/**
 * This function searches for a struct hip_hadb_state entry from the
 * hip_hadb_hit by a HIT pair (local,peer).
 *
 * @param hit_local local HIT
 * @param hit_remote peer HIT
 * @return the corresponding host association or NULL if not found
 */
struct hip_hadb_state *hip_hadb_find_byhits(const hip_hit_t *hit_local,
                                            const hip_hit_t *hit_remote)
{
    struct hip_hadb_state ha, *ret = NULL;

    memcpy(&ha.hit_our, hit_local, sizeof(hip_hit_t));
    memcpy(&ha.hit_peer, hit_remote, sizeof(hip_hit_t));
    HIP_DEBUG_HIT("Local HIT", hit_local);
    HIP_DEBUG_HIT("Remote HIT", hit_remote);

    ret = hip_ht_find(hadb_hit, &ha);
    if (!ret) {
        memcpy(&ha.hit_peer, hit_local, sizeof(hip_hit_t));
        memcpy(&ha.hit_our, hit_remote, sizeof(hip_hit_t));
        ret = hip_ht_find(hadb_hit, &ha);
    }

    return ret;
}

/**
 * Context information used during a search by
 * hip_hadb_try_to_find_by_peer_hit().
 */
struct ha_pattern {
    const hip_hit_t        peer_hit;
    struct hip_hadb_state *ha;
};

/**
 * A call-back function for finding a host association between a given peer HIT
 * and any of the iteratively provided local HIs.
 *
 * @param lhi     Points to a local_host_id object from which contains the
 *                local HIT of the HA to find.
 * @param context Points to a ha_pattern object which contains the peer HIT of
 *                the HA to find and where the result is stored if a HA is
 *                found.
 * @return        0 if no matching HA is found, 1 if a matching HA is found.
 */
static int find_ha_by_lhi(struct local_host_id *const lhi,
                          void *const context)
{
    struct ha_pattern *pattern = context;
    pattern->ha = hip_hadb_find_byhits(&pattern->peer_hit, &lhi->hit);
    return pattern->ha != NULL;
}

/**
 * This function simply goes through all local HIs and tries
 * to find a HADB entry that matches the current HI and
 * the given peer hit. First matching HADB entry is then returned.
 *
 * @param hit the peer HIT
 * @return the host association that matches the peer HIT or NULL if
 *         not found
 *
 * @todo Find a better solution, see the text below:
 * This function is needed because we index the HADB now by
 * key values calculated from <peer_hit,local_hit> pairs. Unfortunately, in
 * some functions like the ipv6 stack hooks hip_get_saddr() and
 * hip_handle_output() we just can't know the local_hit so we have to
 * improvise and just try to find some HA entry.
 *
 * @note This way of finding HA entries doesn't work properly if we have
 * multiple entries with the same peer_hit.
 * @note Don't use this function because it does not deal properly
 * with multiple source hits. Prefer hip_hadb_find_byhits() function.
 */
struct hip_hadb_state *hip_hadb_try_to_find_by_peer_hit(const hip_hit_t *hit)
{
    struct hip_hadb_state *entry = NULL;
    hip_hit_t              our_hit;
    struct ha_pattern      pattern = { *hit, NULL };

    /* Let's try with the default HIT first */
    hip_get_default_hit(&our_hit);

    if ((entry = hip_hadb_find_byhits(hit, &our_hit))) {
        return entry;
    }

    /* and then with rest (actually default HIT is here redundantly) */
    hip_for_each_hi(find_ha_by_lhi, &pattern);

    return pattern.ha;
}

/**
 * @brief Inserts a HIP association to HIP association hash table.
 *
 * Inserts a HIP association to HIP association hash table @c hadb_hit and
 * updates the the hastate of the HIP association @c ha. This function can be
 * called even if the @c ha is in the hash table already. <b>The peer address of
 * the host association must be set (i.e. @c ha->hit_peer must not be
 * ipv6_addr_any). </b> When @c ha is NULL or if @c ha->hit_peer is
 * ipv6_addr_any this function will kill the HIP daemon.
 *
 * @return The state of the HIP association (enum hip_hastate).
 * @note   For multithreaded model: this function assumes that @c ha is locked.
 */
int hip_hadb_insert_state(struct hip_hadb_state *ha)
{
    enum   hip_hastate     st  = 0;
    struct hip_hadb_state *tmp = NULL;

    /* assume already locked ha */

    HIP_ASSERT(!(ipv6_addr_any(&ha->hit_peer)));

    HIP_DEBUG("hip_hadb_insert_state() invoked. Inserting a new state to " \
              "the HIP association hash table.\n");

    if (ha == NULL) {
        HIP_DIE("Trying to insert a NULL HIP association to the HIP " \
                "association hash table.\n");
    } else if (ipv6_addr_any(&ha->hit_peer)) {
        HIP_DIE("Trying to insert a HIP association with zero " \
                "(ipv6_addr_any) peer HIT to the HIP association hash " \
                "table.\n");
    }

    st = ha->hastate;

#ifdef CONFIG_HIP_DEBUG /* Debug block. */
    {
        char hito[INET6_ADDRSTRLEN], hitp[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &ha->hit_our, hito, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &ha->hit_peer, hitp, INET6_ADDRSTRLEN);
        HIP_DEBUG("Trying to insert a new state to the HIP " \
                  "association database. Our HIT: %s," \
                  "Peer HIT: %s, HIP association state: %d\n",
                  hito, hitp, ha->hastate);
    }
#endif

    if (st != HIP_HASTATE_VALID) {
        tmp = hip_ht_find(hadb_hit, ha);

        if (tmp == NULL) {
            if ((ha->lsi_peer).s_addr == 0) {
                hip_hadb_set_lsi_pair(ha);
            }
            hip_ht_add(hadb_hit, ha);
            st = HIP_HASTATE_VALID;
            HIP_DEBUG("HIP association was inserted " \
                      "successfully.\n");
        } else {
            HIP_DEBUG("HIP association was NOT inserted because " \
                      "a HIP association with matching HITs was " \
                      "already present in the database.\n");
        }
    } else {
        HIP_DEBUG("HIP association was NOT inserted because the " \
                  "HIP association state is not OK.\n");
    }


    ha->hastate = st;
    return st;
}

/**
 * display debug information on information in host association
 *
 * @param local_addr local address
 * @param peer_addr peer address
 * @param local_hit local HIT
 * @param peer_hit peer HIT
 * @param peer_lsi peer LSI
 * @param peer_hostname peer host name
 * @param local_nat_udp_port local UDP port
 * @param peer_nat_udp_port peer UDP port
 *
 */
static void hip_print_debug_info(const struct in6_addr *local_addr,
                                 const struct in6_addr *peer_addr,
                                 const hip_hit_t *local_hit,
                                 const hip_hit_t *peer_hit,
                                 const hip_lsi_t *peer_lsi,
                                 const char *peer_hostname,
                                 const in_port_t *local_nat_udp_port,
                                 const in_port_t *peer_nat_udp_port)
{
    if (local_addr) {
        HIP_DEBUG_IN6ADDR("Our addr", local_addr);
    }
    if (peer_addr) {
        HIP_DEBUG_IN6ADDR("Peer addr", peer_addr);
    }
    if (local_hit) {
        HIP_DEBUG_HIT("Our HIT", local_hit);
    }
    if (peer_hit) {
        HIP_DEBUG_HIT("Peer HIT", peer_hit);
    }
    if (peer_lsi) {
        HIP_DEBUG_LSI("Peer LSI", peer_lsi);
    }
    if (peer_hostname) {
        HIP_DEBUG("Peer hostname: %s\n", peer_hostname);
    }

    if (local_nat_udp_port) {
        HIP_DEBUG("Local NAT traversal UDP port: %d\n", *local_nat_udp_port);
    }

    if (peer_nat_udp_port) {
        HIP_DEBUG("Peer NAT traversal UDP port: %d\n", *peer_nat_udp_port);
    }
}

/**
 * Practically called only by when adding a HIT-IP mapping before base exchange.
 *
 * @param  local_hit local HIT
 * @param  peer_hit peer HIT
 * @param  local_addr local address
 * @param  peer_addr peer address
 * @param  peer_lsi optional peer LSI (automatically generated if NULL)x
 * @param  peer_hostname peer hostname
 * @return zero on success or negative on error
 */
int hip_hadb_add_peer_info_complete(const hip_hit_t *local_hit,
                                    const hip_hit_t *peer_hit,
                                    const hip_lsi_t *peer_lsi,
                                    const struct in6_addr *local_addr,
                                    const struct in6_addr *peer_addr,
                                    const char *peer_hostname)
{
    struct hip_hadb_state *entry = NULL, *aux = NULL;
    hip_lsi_t              lsi_aux;
    in_port_t              nat_udp_port_local = hip_get_local_nat_udp_port();
    in_port_t              nat_udp_port_peer  = hip_get_peer_nat_udp_port();

    HIP_DEBUG_IN6ADDR("Local IP address ", local_addr);

    hip_print_debug_info(local_addr, peer_addr,
                         local_hit, peer_hit,
                         peer_lsi, peer_hostname,
                         &nat_udp_port_local,
                         &nat_udp_port_peer);

    entry = hip_hadb_find_byhits(local_hit, peer_hit);

    if (entry) {
        HIP_DEBUG_LSI("    Peer lsi   ", &entry->lsi_peer);
    } else {
        HIP_DEBUG("hip_hadb_create_state\n");
        entry = hip_hadb_create_state();
        if (!entry) {
            HIP_ERROR("Unable to create a new entry");
            return -1;
        }
        entry->peer_addr_list_to_be_added =
            hip_ht_init(hip_hash_peer_addr, hip_match_peer_addr);
    }

    ipv6_addr_copy(&entry->hit_peer, peer_hit);
    ipv6_addr_copy(&entry->hit_our, local_hit);
    ipv6_addr_copy(&entry->our_addr, local_addr);
    if (hip_hidb_get_lsi_by_hit(local_hit, &entry->lsi_our)) {
        HIP_ERROR("Unable to find local hit");
        return -1;
    }

    /* Copying peer_lsi */
    if (peer_lsi != NULL && peer_lsi->s_addr != 0) {
        ipv4_addr_copy(&entry->lsi_peer, peer_lsi);
    } else {
        /* Check if exists an entry in the hadb with the
         * peer_hit given */
        aux = hip_hadb_try_to_find_by_peer_hit(peer_hit);
        if (aux && &aux->lsi_peer.s_addr != 0) {
            /* Exists: Assign its lsi to the new entry created */
            ipv4_addr_copy(&entry->lsi_peer, &aux->lsi_peer);
        } else if (!hip_map_hit_to_lsi_from_hosts_files(peer_hit, &lsi_aux)) {
            ipv4_addr_copy(&entry->lsi_peer, &lsi_aux);
        } else if (hip_hidb_hit_is_our(peer_hit)) {
            /* When adding a map to hadb for a loopback HIT, the
             * destination LSI should be same as the local one (1.0.0.1). */
            entry->lsi_peer = entry->lsi_our;
        } else {
            /* Not exists: Call to the automatic generation */
            hip_generate_peer_lsi(&lsi_aux);
            ipv4_addr_copy(&entry->lsi_peer, &lsi_aux);
        }
    }

    /* If global NAT status is on, that is if the current host is behind
     * NAT, the NAT status of the host association is set on and the send
     * function set is set to "nat_xmit_func_set". */
    if (hip_nat_status && IN6_IS_ADDR_V4MAPPED(peer_addr) &&
        !ipv6_addr_is_teredo(peer_addr)) {
        entry->nat_mode       = hip_nat_status;
        entry->peer_udp_port  = hip_get_peer_nat_udp_port();
        entry->local_udp_port = hip_get_local_nat_udp_port();
    }

    if (hip_hidb_hit_is_our(peer_hit)) {
        HIP_DEBUG("Peer HIT is ours (loopback)\n");
        entry->is_loopback = 1;
    }

    HIP_DEBUG_LSI("entry->lsi_peer \n", &entry->lsi_peer);
    hip_hadb_insert_state(entry);

    /* Add initial HIT-IP mapping. */
    if (hip_hadb_add_peer_addr(entry, peer_addr)) {
        HIP_ERROR("error while adding a new peer address\n");
        return -2;
    }

    return 0;
}

/**
 * a wrapper to create a host association
 *
 * @param  entry a pointer to a preallocated host association
 * @param  peer_map_void a pointer to hip_peer_map_info
 * @return zero on success or negative on error
 */
static int hip_hadb_add_peer_info_wrapper(struct local_host_id *entry,
                                          void *peer_map_void)
{
    struct hip_peer_map_info *peer_map = peer_map_void;

    if (hip_hadb_add_peer_info_complete(&entry->hit,
                                        &peer_map->peer_hit,
                                        &peer_map->peer_lsi,
                                        &peer_map->our_addr,
                                        &peer_map->peer_addr,
                                        (char *) &peer_map->peer_hostname)) {
        HIP_ERROR("Failed to add peer info\n");
        return -1;
    }

    return 0;
}

/**
 * create a host association
 *
 * @param peer_hit the HIT of the remote host
 * @param peer_addr the address of the remote host
 * @param peer_lsi an optional LSI for the remote host
 * @param peer_hostname an optional host name for the remote host
 * @return zero on success or negative on error
 */
int hip_hadb_add_peer_info(const hip_hit_t *peer_hit,
                           const struct in6_addr *peer_addr,
                           const hip_lsi_t *peer_lsi,
                           const char *peer_hostname)
{
    struct hip_peer_map_info peer_map = { { { { 0 } } } };

    in_port_t nat_local_udp_port = hip_get_local_nat_udp_port();
    in_port_t nat_peer_udp_port  = hip_get_peer_nat_udp_port();
    hip_print_debug_info(NULL,
                         peer_addr,
                         NULL,
                         peer_hit,
                         peer_lsi,
                         peer_hostname,
                         &nat_local_udp_port,
                         &nat_peer_udp_port);

    if (!ipv6_addr_is_hit(peer_hit)) {
        HIP_ERROR("Not a HIT\n");
        return -1;
    }

    memcpy(&peer_map.peer_hit, peer_hit, sizeof(hip_hit_t));
    if (peer_addr) {
        memcpy(&peer_map.peer_addr, peer_addr, sizeof(struct in6_addr));
    }

    if (peer_lsi) {
        memcpy(&peer_map.peer_lsi, peer_lsi, sizeof(struct in6_addr));
    }

    if (peer_hostname) {
        memcpy(peer_map.peer_hostname, peer_hostname,
               HIP_HOST_ID_HOSTNAME_LEN_MAX - 1);
    }

    if (hip_select_source_address(&peer_map.our_addr, &peer_map.peer_addr)) {
        HIP_ERROR("Cannot find source address\n");
        return -1;
    }

    if (hip_for_each_hi(hip_hadb_add_peer_info_wrapper, &peer_map)) {
        HIP_ERROR("for_each_hi err.\n");
        return 0;
    }

    return 0;
}

/**
 * create a host association based on the parameter in a user message
 *
 * @param input an user message containing a HIT, optional LSI and hostname for
 *              the remote host
 * @return zero on success or negative on error
 */
int hip_add_peer_map(const struct hip_common *input)
{
    const struct in6_addr *hit           = NULL, *ip = NULL;
    const hip_lsi_t       *lsi           = NULL;
    const char            *peer_hostname = NULL;
    int                    err           = 0;

    hit = hip_get_param_contents(input, HIP_PARAM_HIT);

    lsi = hip_get_param_contents(input, HIP_PARAM_LSI);

    ip = hip_get_param_contents(input, HIP_PARAM_IPV6_ADDR);

    peer_hostname = hip_get_param_contents(input, HIP_PARAM_HOSTNAME);

    if (!ip && (!lsi || !hit)) {
        HIP_ERROR("handle async map: no ip and maybe no lsi or hit\n");
        return -ENODATA;
    }

    if (lsi) {
        HIP_DEBUG_LSI("lsi value is\n", lsi);
    }

    if (peer_hostname) {
        HIP_DEBUG("Peer hostname value is %s\n", peer_hostname);
    }

    err = hip_hadb_add_peer_info(hit, ip, lsi, peer_hostname);

    if (err) {
        HIP_ERROR("Failed to insert peer map (%d)\n", err);
        return err;
    }

    return 0;
}

/**
 * Inits a Host Association after memory allocation.
 *
 * @param  entry pointer to a host association
 */
static int hip_hadb_init_entry(struct hip_hadb_state *entry)
{
    if (!entry) {
        HIP_ERROR("HA is NULL\n");
        return -1;
    }

    entry->state         = HIP_STATE_UNASSOCIATED;
    entry->hastate       = HIP_HASTATE_INVALID;
    entry->purge_timeout = HIP_HA_PURGE_TIMEOUT;

    /* Initialize the peer host name */
    memset(entry->peer_hostname, '\0', HIP_HOST_ID_HOSTNAME_LEN_MAX);

    /* Randomize inbound SPI */
    get_random_bytes(&entry->spi_inbound_current,
                     sizeof(entry->spi_inbound_current));

    if (!(entry->hip_msg_retrans.buf = calloc(1, HIP_MAX_NETWORK_PACKET))) {
        return -ENOMEM;
    }

    entry->hip_msg_retrans.count = 0;

    /* Initialize module states */
    entry->hip_modular_state = lmod_init_state();
    lmod_init_state_items(entry->hip_modular_state);
    HIP_DEBUG("Modular state initialized.\n");

    return 0;
}

/**
 * Allocate and initialize a new HA structure.
 *
 * @return NULL if memory allocation failed, otherwise the HA.
 */
struct hip_hadb_state *hip_hadb_create_state(void)
{
    struct hip_hadb_state *entry = NULL;

    if (!(entry = calloc(1, sizeof(struct hip_hadb_state)))) {
        return NULL;
    }

    hip_hadb_init_entry(entry);

    return entry;
}

/* END OF PRIMITIVE FUNCTIONS */

/**
 * Gets some of the peer's usable IPv6 address.
 * @param entry corresponding hadb entry of the peer
 * @param addr where the selected IPv6 address of the peer is copied to
 *
 * Current destination address selection algorithm:
 * 1. use preferred address of the HA, if any (should be set)
 *
 * tkoponen: these are useless: ?
 * 2. use preferred address of the default outbound SPI, if any
 * (should be set, suspect bug if we get this far)
 *
 * 3. select among the active addresses of the default outbound SPI
 * (select the address which was added/updated last)
 *
 * @return 0 if some of the addresses was copied successfully, else < 0.
 */
int hip_hadb_get_peer_addr(struct hip_hadb_state *entry, struct in6_addr *addr)
{
    int err = 0;

    /* assume already locked entry */
    HIP_DEBUG_HIT("entry def addr", &entry->peer_addr);
    ipv6_addr_copy(addr, &entry->peer_addr);
    return err;
}

/**
 * Adds a new peer IPv6 address to the entry's list of peer addresses.
 * @param entry corresponding hadb entry of the peer
 * @param new_addr IPv6 address to be added
 *
 * @return zero on success and negative on error
 */
int hip_hadb_add_peer_addr(struct hip_hadb_state *entry,
                           const struct in6_addr *new_addr)
{
    struct hip_peer_addr_list_item *a_item;
    char                            addrstr[INET6_ADDRSTRLEN];

    /* assumes already locked entry */

    if (!ipv6_addr_any(&entry->peer_addr)) {
        hip_in6_ntop(&entry->peer_addr, addrstr);
        HIP_DEBUG("warning, overwriting existing preferred address %s\n",
                  addrstr);
    }
    ipv6_addr_copy(&entry->peer_addr, new_addr);
    HIP_DEBUG_IN6ADDR("entry->peer_address \n", &entry->peer_addr);

    if (entry->peer_addr_list_to_be_added) {
        /* Adding the peer address to the entry->peer_addr_list_to_be_added
         * so that later after base exchange it can be transferred to
         * SPI OUT's peer address list */
        a_item = malloc(sizeof(struct hip_peer_addr_list_item));
        if (!a_item) {
            HIP_ERROR("item malloc failed\n");
            return -ENOMEM;
        }
        ipv6_addr_copy(&a_item->address, new_addr);

        list_add(a_item, entry->peer_addr_list_to_be_added);
    }

    return 0;
}

/**
 * Delete a HA state (and deallocate memory), all associated IPSEC SAs
 * and free the memory occupied by the HA state.
 *
 * @param ha HA
 * @note     ASSERT: The HA must be unlinked from the global hadb hash tables
 *           (SPI and HIT). This function should only be called when absolutely
 *           sure that nobody else has a reference to it.
 */
static void hip_hadb_delete_state(struct hip_hadb_state *ha)
{
    LHASH_NODE                     *item    = NULL, *tmp = NULL;
    struct hip_peer_addr_list_item *addr_li = NULL;
    int                             i;

    HIP_DEBUG("ha=0x%p\n", ha);

    /* Delete SAs */

    free(ha->dh_shared_key);
    free(ha->hip_msg_retrans.buf);
    if (ha->peer_pub) {
        switch (hip_get_host_id_algo(ha->peer_pub)) {
        case HIP_HI_RSA:
            RSA_free(ha->peer_pub_key);
            break;
        case HIP_HI_ECDSA:
            EC_KEY_free(ha->peer_pub_key);
            break;
        case HIP_HI_DSA:
            DSA_free(ha->peer_pub_key);
            break;
        default:
            HIP_DEBUG("Could not free key, because algorithm is unknown.\n");
        }
        free(ha->peer_pub);
    }
    free(ha->our_priv);
    free(ha->our_pub);
    free(ha->rendezvous_addr);

    lmod_uninit_state(ha->hip_modular_state);

    free(ha->locator);

    if (ha->peer_addr_list_to_be_added) {
        list_for_each_safe(item, tmp, ha->peer_addr_list_to_be_added, i) {
            addr_li = list_entry(item);
            list_del(addr_li, ha->peer_addr_list_to_be_added);
            free(addr_li);
            HIP_DEBUG_HIT("SPI out address", &addr_li->address);
        }
        hip_ht_uninit(ha->peer_addr_list_to_be_added);
    }

    list_del(ha, hadb_hit);
    free(ha);
}

/**
 * delete a host association
 *
 * @param ha the ha to deinitiliaze and deallocate
 * @return zero on success and negative on error
 */
int hip_del_peer_info_entry(struct hip_hadb_state *ha)
{
    /* by now, if everything is according to plans, the refcnt
     * should be 1 */
    HIP_DEBUG_HIT("our HIT", &ha->hit_our);
    HIP_DEBUG_HIT("peer HIT", &ha->hit_peer);
    hip_delete_security_associations_and_sp(ha);

    hip_hadb_delete_state(ha);

    return 0;
}

/**
 * store a remote host identifier to a host association
 *
 * @param entry the host association
 * @param peer the remote host identifier
 * @return zero on success and negative on error
 */
int hip_init_peer(struct hip_hadb_state *entry,
                  const struct hip_host_id *peer)
{
    int             err = 0;
    int             len = hip_get_param_total_len(peer);
    struct in6_addr hit;

    /* public key and verify function might be initialized already in the
     * case of loopback */

    if (entry->peer_pub) {
        HIP_DEBUG("Not initializing peer host id, old exists\n");
        goto out_err;
    }

    HIP_IFEL(hip_host_id_to_hit(peer, &hit, HIP_HIT_TYPE_HASH100) ||
             ipv6_addr_cmp(&hit, &entry->hit_peer),
             -1, "Unable to verify sender's HOST_ID\n");

    HIP_IFEL(!(entry->peer_pub = malloc(len)),
             -ENOMEM, "Out of memory\n");

    memcpy(entry->peer_pub, peer, len);
    switch (hip_get_host_id_algo(entry->peer_pub)) {
    case HIP_HI_RSA:
        entry->verify       = hip_rsa_verify;
        entry->peer_pub_key = hip_key_rr_to_rsa((struct hip_host_id_priv *) entry->peer_pub, 0);
        break;
    case HIP_HI_DSA:
        entry->verify       = hip_dsa_verify;
        entry->peer_pub_key = hip_key_rr_to_dsa((struct hip_host_id_priv *) entry->peer_pub, 0);
        break;
    case HIP_HI_ECDSA:
        entry->verify       = hip_ecdsa_verify;
        entry->peer_pub_key = hip_key_rr_to_ecdsa((struct hip_host_id_priv *) entry->peer_pub, 0);
        break;
    default:
        HIP_OUT_ERR(-1, "Unkown algorithm");
    }

out_err:
    HIP_DEBUG_HIT("peer's hit", &hit);
    HIP_DEBUG_HIT("entry's hit", &entry->hit_peer);
    return err;
}

/**
 * Initializes a host association
 *
 * @param entry a pointer to a HIP association to be initialized.
 * @param hit_our a pointer to a HIT value that is to be bound with the HIP association
 *         @c entry
 * @return zero if success, negative otherwise.
 */
int hip_init_us(struct hip_hadb_state *entry, hip_hit_t *hit_our)
{
    int err = 0;

    free(entry->our_pub);
    entry->our_pub = NULL;

    /* Try to fetch our private host identity first using RSA then using DSA.
     * Note, that hip_get_host_id() allocates a new buffer and this buffer
     * must be freed in out_err if an error occurs. */

    if (!hip_get_host_id_and_priv_key(HIP_DB_LOCAL_HID,
                                      hit_our,
                                      HIP_HI_RSA,
                                      &entry->our_pub,
                                      &entry->our_priv_key)) {
        HIP_DEBUG("Found RSA host identity\n");
    } else if (!hip_get_host_id_and_priv_key(HIP_DB_LOCAL_HID,
                                             hit_our,
                                             HIP_HI_DSA,
                                             &entry->our_pub,
                                             &entry->our_priv_key)) {
        HIP_DEBUG("Found DSA host identity\n");
    } else if (!hip_get_host_id_and_priv_key(HIP_DB_LOCAL_HID,
                                             hit_our,
                                             HIP_HI_ECDSA,
                                             &entry->our_pub,
                                             &entry->our_priv_key)) {
        HIP_DEBUG("Found ECDSA host identity\n");
    } else {
        HIP_OUT_ERR(-1, "Local host identity not found\n");
    }

    /* RFC 4034 obsoletes RFC 2535 and flags field differ */
    /* Get RFC2535 3.1 KEY RDATA format algorithm (Integer value). */

    /* Calculate our HIT from our public Host Identifier (HI).
     * Note, that currently (06.08.2008) both of these functions use DSA
     *
     * Set the funciton pointer for signing our host identity. */
    switch (hip_get_host_id_algo(entry->our_pub)) {
    case HIP_HI_DSA:
        entry->sign = hip_dsa_sign;
        break;
    case HIP_HI_RSA:
        entry->sign = hip_rsa_sign;
        break;
    case HIP_HI_ECDSA:
        entry->sign = hip_ecdsa_sign;
        break;
    default:
        err = -1;
    }
    HIP_IFEL(hip_host_id_to_hit(entry->our_pub, &entry->hit_our, HIP_HIT_TYPE_HASH100),
             -1, "Unable to digest the HIT out of public key.");

out_err:
    if (err) {
        free(entry->our_pub);
        entry->our_pub = NULL;
    }

    return err;
}

/* ----------------- */

/**
 * initialize the host association database
 */
void hip_init_hadb(void)
{
    hadb_hit = hip_ht_init(LHASH_HASH_FN(hip_ha), LHASH_COMP_FN(hip_ha));
}

/**
 * Switches on a local control bit for a host assosiation entry.
 *
 * @param entry a pointer to a host assosiation.
 * @param mask  a bit mask representing the control value.
 * @note  mask is a single mask, not a logical AND or OR mask.
 * @note When modifying this function, remember that some control values may
 *       not be allowed to co-exist. Therefore the logical OR might not be enough
 *       for all controls.
 */
void hip_hadb_set_local_controls(struct hip_hadb_state *entry,
                                 hip_controls mask)
{
    if (entry != NULL) {
        switch (mask) {
        case HIP_HA_CTRL_NONE:
            entry->local_controls &= mask;
        case HIP_HA_CTRL_LOCAL_REQ_UNSUP:
        case HIP_HA_CTRL_LOCAL_REQ_RELAY:
        case HIP_HA_CTRL_LOCAL_REQ_FULLRELAY:
        case HIP_HA_CTRL_LOCAL_REQ_RVS:
        case HIP_HA_CTRL_LOCAL_GRANTED_FULLRELAY:
            entry->local_controls |= mask;
            break;
        default:
            HIP_ERROR("Unknown local controls given.\n");
        }
    }
}

/**
 * Switches on a peer control bit for a host assosiation entry.
 *
 * @param entry a pointer to a host assosiation.
 * @param mask  a bit mask representing the control value.
 * @note  mask is a single mask, not a logical AND or OR mask
 * @note When modifying this function, remember that some control values may
 *       not be allowed to co-exist. Therefore the logical OR might not be enough
 *       for all controls.
 */
void hip_hadb_set_peer_controls(struct hip_hadb_state *entry,
                                hip_controls mask)
{
    if (entry != NULL) {
        switch (mask) {
        case HIP_HA_CTRL_NONE:
            entry->peer_controls &= mask;
        case HIP_HA_CTRL_PEER_UNSUP_CAPABLE:
        case HIP_HA_CTRL_PEER_RVS_CAPABLE:
        case HIP_HA_CTRL_PEER_RELAY_CAPABLE:
        case HIP_HA_CTRL_PEER_FULLRELAY_CAPABLE:
        case HIP_HA_CTRL_PEER_GRANTED_UNSUP:
        case HIP_HA_CTRL_PEER_GRANTED_RVS:
        case HIP_HA_CTRL_PEER_GRANTED_RELAY:
        case HIP_HA_CTRL_PEER_GRANTED_FULLRELAY:
        case HIP_HA_CTRL_PEER_REFUSED_UNSUP:
        case HIP_HA_CTRL_PEER_REFUSED_RELAY:
        case HIP_HA_CTRL_PEER_REFUSED_RVS:
        case HIP_HA_CTRL_PEER_REFUSED_FULLRELAY:
            entry->peer_controls |= mask;
            break;
        default:
            HIP_ERROR("Unknown peer controls given.\n");
        }
    }
}

void hip_hadb_cancel_local_controls(struct hip_hadb_state *entry,
                                    hip_controls mask)
{
    if (entry != NULL) {
        entry->local_controls &= ~mask;
    }
}

static void hip_hadb_rec_free_doall(struct hip_hadb_state *rec)
{
    if (hadb_hit == NULL || rec == NULL) {
        return;
    }

    hip_del_peer_info_entry(rec);
}

/** A callback wrapper of the prototype required by @c lh_doall_arg(). */
STATIC_IMPLEMENT_LHASH_DOALL_FN(hip_hadb_rec_free, struct hip_hadb_state)

/**
 * Uninitialize host association database
 */
void hip_uninit_hadb(void)
{
    if (hadb_hit == NULL) {
        return;
    }

    hip_ht_doall(hadb_hit, (LHASH_DOALL_FN_TYPE) LHASH_DOALL_FN(hip_hadb_rec_free));
    hip_ht_uninit(hadb_hit);
    hadb_hit = NULL;
}

/**
 * flush all security policies
 *
 * @todo currently this function is a no-op
 */
void hip_delete_all_sp(void)
{
    HIP_DEBUG("\n");

    HIP_DEBUG("DEBUG: DUMP SPI LISTS\n");

    HIP_DEBUG("DELETING HA HT\n");
}

/**
 * Map function @c func to every HA in HIT hash table. The hash table is
 * LOCKED while we process all the entries. This means that the mapper function
 * MUST be very short and _NOT_ do any operations that might sleep!
 *
 * @param func a mapper function.
 * @param opaque opaque data for the mapper function.
 * @return       negative if an error occurs. If an error occurs during
 *               traversal of a the HIT hash table, then the traversal is
 *               stopped and function returns. Returns the last return value of
 *               applying the mapper function to the last element in the hash
 *               table.
 */
int hip_for_each_ha(int (*func)(struct hip_hadb_state *entry, void *opaq),
                    void *opaque)
{
    int                    i = 0, fail = 0;
    struct hip_hadb_state *this;
    LHASH_NODE            *item, *tmp;

    if (!func) {
        return -EINVAL;
    }

    list_for_each_safe(item, tmp, hadb_hit, i)
    {
        this = list_entry(item);
        /* @todo: lock ha when we have threads */
        fail = func(this, opaque);
        /* @todo: unlock ha when we have threads */
        if (fail) {
            goto out_err;
        }
    }

out_err:
    return fail;
}

/**
 * Enumeration for hip_count_open_connections
 *
 * @param entry a host association
 * @param cntr a counter used for counting open host associations
 * @return zero
 */
static int hip_count_one_entry(struct hip_hadb_state *entry, void *cntr)
{
    int *counter = cntr;
    if (entry->state == HIP_STATE_CLOSING ||
        entry->state == HIP_STATE_ESTABLISHED) {
        (*counter)++;
    }
    return 0;
}

/**
 * Return number of open host associations by calculating hadb entrys.
 *
 * @return the number of open host associations
 */
int hip_count_open_connections(void)
{
    int n = 0;

    hip_for_each_ha(hip_count_one_entry, &n);

    return n;
}

/**
 * an enumerator to find information on host associations
 *
 * @param entry the host association
 * @param opaq a preallocated HIP message where information on the given
 *             host association will be written
 * @return zero on success and negative on error
 */
int hip_handle_get_ha_info(struct hip_hadb_state *entry, void *opaq)
{
    int                             err = 0;
    struct hip_hadb_user_info_state hid = { { { { 0 } } } };
    struct hip_common              *msg = opaq;

    hid.state = entry->state;
    ipv6_addr_copy(&hid.hit_our, &entry->hit_our);
    ipv6_addr_copy(&hid.hit_peer, &entry->hit_peer);
    ipv6_addr_copy(&hid.ip_our, &entry->our_addr);
    ipv6_addr_copy(&hid.ip_peer, &entry->peer_addr);
    ipv4_addr_copy(&hid.lsi_our, &entry->lsi_our);
    ipv4_addr_copy(&hid.lsi_peer, &entry->lsi_peer);
    memcpy(&hid.peer_hostname, &entry->peer_hostname, HIP_HOST_ID_HOSTNAME_LEN_MAX);

    /** @todo Modularize heartbeat */
#if 0
    hid.heartbeats_on = hip_icmp_interval;
    calc_statistics(&entry->heartbeats_statistics, (uint32_t *) &hid.heartbeats_received, NULL, NULL,
                    &hid.heartbeats_mean, &hid.heartbeats_variance, STATS_IN_MSECS);
    hid.heartbeats_mean     = entry->heartbeats_mean;
    hid.heartbeats_variance = entry->heartbeats_variance;
    hid.heartbeats_received = entry->heartbeats_statistics.num_items;
    hid.heartbeats_sent     = entry->heartbeats_sent;
#endif

    hid.nat_udp_port_peer  = entry->peer_udp_port;
    hid.nat_udp_port_local = entry->local_udp_port;

    hid.broadcast_status = hip_broadcast_status;

    hid.peer_controls = entry->peer_controls;

    /* does not print heartbeat info, but I do not think it even should -Samu*/
    hip_print_debug_info(&hid.ip_our, &hid.ip_peer,
                         &hid.hit_our, &hid.hit_peer,
                         &hid.lsi_peer, (char *) &hid.peer_hostname,
                         &hid.nat_udp_port_local, &hid.nat_udp_port_peer);

    err = hip_build_param_contents(msg, &hid, HIP_PARAM_HA_INFO,
                                   sizeof(hid));
    if (err) {
        HIP_ERROR("Building ha info failed\n");
    }

    return err;
}

#ifdef CONFIG_HIP_RVS
/**
 * Finds a rendezvous server candidate host association entry.
 *
 * Finds a rendezvous server candidate host association entry matching the
 * parameter @c local_hit and @c rvs_ip. When asame as local one (1.0.0.1). relayed I1 packet arrives to the
 * responder, the packet has the initiators HIT as the source HIT, and the
 * responder HIT as the destination HIT. The responder needs the host
 * assosiation having RVS's HIT and the responder's HIT. This function gets that
 * host assosiation without using the RVS's HIT as searching key.
 *
 * @param  local_hit a pointer to rendezvous server HIT used as searching key.
 * @param  rvs_ip    a pointer to rendezvous server IPv6 or IPv4-in-IPv6 format
 *                   IPv4 address  used as searching key.
 * @return           a pointer to a matching host association or NULL if
 *                   a matching host association was not found.
 */
struct hip_hadb_state *hip_hadb_find_rvs_candidate_entry(const hip_hit_t *local_hit,
                                                         const hip_hit_t *rvs_ip)
{
    int                    i    = 0;
    struct hip_hadb_state *this = NULL, *result = NULL;
    LHASH_NODE            *item = NULL, *tmp = NULL; //

    list_for_each_safe(item, tmp, hadb_hit, i)
    {
        this = list_entry(item);
        /* @todo: lock ha when we have threads */
        if ((ipv6_addr_cmp(local_hit, &this->hit_our) == 0) &&
            (ipv6_addr_cmp(rvs_ip, &this->peer_addr) == 0)) {
            result = this;
            break;
        }
        /* @todo: unlock ha when we have threads */
    }

    return result;
}

#endif

/**
 * An iterator to find a matching remote LSI from HADB.
 *
 * @param entry the host association
 * @param lsi The LSI to match. Set to zero if a match was found.
 * @return zero
 * @note this function overwrites @c lsi, beware!
 */
static int hip_hadb_find_lsi(struct hip_hadb_state *entry, void *lsi)
{
    int exist_lsi;
    exist_lsi = hip_lsi_are_equal(&entry->lsi_peer, lsi);
    if (exist_lsi) {
        memset(lsi, 0, sizeof(lsi));
    }
    return 0;
}

/**
 * check if a remote LSI exists in the HADB
 *
 * @param lsi the LSI to check
 * @return one if it exists or zero otherwise
 */
static int hip_hadb_exists_lsi(hip_lsi_t *lsi)
{
    int       res = 0;
    hip_lsi_t lsi_aux;

    memcpy(&lsi_aux, lsi, sizeof(hip_lsi_t));
    hip_for_each_ha(hip_hadb_find_lsi, &lsi_aux);

    if (ipv4_addr_cmp(&lsi_aux, lsi) != 0) {
        res = 1;
        HIP_DEBUG("lsi exists\n");
    }
    return res;
}

/**
 * check if a remote LSI has been already assigned from
 * HADB and hosts files
 *
 * @param addr the LSI to check
 * @return one if the LSI exists or zero otherwise
 */
static int lsi_assigned(struct in_addr addr)
{
    int exist = 0;
    exist = hip_hidb_exists_lsi(&addr);
    if (!exist) {
        exist = hip_hadb_exists_lsi(&addr);
    }
    if (!exist) {
        exist = hip_host_file_info_exists_lsi(&addr);
    }
    return exist;
}

/**
 * allocate a free remote LSI
 *
 * @param lsi the LSI will be written here
 * @return zero
 */
int hip_generate_peer_lsi(hip_lsi_t *lsi)
{
    struct in_addr lsi_prefix;
    char           hostname[HOST_NAME_MAX];
    int            idx = 1;

    do {
        lsi_prefix.s_addr = htonl(HIP_LSI_PREFIX | idx++);
    } while (lsi_assigned(lsi_prefix) ||
             !hip_map_lsi_to_hostname_from_hosts(lsi, hostname));

    *lsi = lsi_prefix;
    return 0;
}

/**
 * This function simply goes through all HADB to find an entry that
 * matches the given lsi pair. First matching HADB entry is then returned.
 *
 * @param lsi_src the source LSI
 * @param lsi_dst the destination LSI
 * @return the host association corresponding to the LSIs
 *
 * @note This way of finding HA entries doesn't work properly if we have
 * multiple entries with the same tuple <lsi_src,lsi_dst>. Currently, that's not the case.
 * Our implementation doesn't allow repeated lsi tuples.
 */
struct hip_hadb_state *hip_hadb_try_to_find_by_pair_lsi(hip_lsi_t *lsi_src,
                                                        hip_lsi_t *lsi_dst)
{
    LHASH_NODE            *item, *aux;
    struct hip_hadb_state *tmp;
    int                    i;

    list_for_each_safe(item, aux, hadb_hit, i)
    {
        tmp = list_entry(item);
        if (!hip_lsi_are_equal(&tmp->lsi_peer, lsi_dst)) {
            continue;
        } else if (hip_lsi_are_equal(&tmp->lsi_our, lsi_src)) {
            return tmp;
        } else {
            continue;
        }
    }
    return NULL;
}

/**
 * find a remote LSI from from the HADB
 *
 * @param lsi_dst the remote LSI
 * @return the HADB entry or NULL if not found
 */
struct hip_hadb_state *hip_hadb_try_to_find_by_peer_lsi(const hip_lsi_t *lsi_dst)
{
    LHASH_NODE            *item, *aux;
    struct hip_hadb_state *tmp;
    int                    i;

    list_for_each_safe(item, aux, hadb_hit, i)
    {
        tmp = list_entry(item);
        if (hip_lsi_are_equal(&tmp->lsi_peer, lsi_dst)) {
            return tmp;
        }
    }
    return NULL;
}

/**
 * delete all security policies and associations related to the HA
 *
 * @param ha the host association
 */
void hip_delete_security_associations_and_sp(struct hip_hadb_state *const ha)
{
    int prev_spi_out = ha->spi_outbound_current;
    int prev_spi_in  = ha->spi_inbound_current;

    // Delete previous security policies
    hip_delete_hit_sp_pair(&ha->hit_our, &ha->hit_peer, 1);
    hip_delete_hit_sp_pair(&ha->hit_peer, &ha->hit_our, 1);

    // Delete the previous SAs
    HIP_DEBUG("Previous SPI out =0x%x\n", prev_spi_out);
    HIP_DEBUG("Previous SPI in =0x%x\n", prev_spi_in);

    HIP_DEBUG_IN6ADDR("Our current active addr", &ha->our_addr);
    HIP_DEBUG_IN6ADDR("Peer's current active addr", &ha->peer_addr);

    hip_delete_sa(prev_spi_out,
                  &ha->peer_addr,
                  HIP_SPI_DIRECTION_OUT,
                  ha);
    hip_delete_sa(prev_spi_in,
                  &ha->our_addr,
                  HIP_SPI_DIRECTION_IN,
                  ha);
}

/**
 * recreate the security policies and associations related to a HA
 *
 * @param ha the host association
 * @param src_addr the new source address for the SAs
 * @param dst_addr the new destination address for the SAs
 * @return zero on success and negative on error
 */
int hip_create_or_update_security_associations_and_sp(struct hip_hadb_state *const ha,
                                                      const struct in6_addr *const src_addr,
                                                      const struct in6_addr *const dst_addr)
{
    int err = 0;

    /* If we have old SAs with these HITs delete them */
    hip_delete_security_associations_and_sp(ha);

    // Create a new inbound SA
    HIP_DEBUG("Creating a new inbound SA, SPI=0x%x\n", ha->spi_inbound_current);
    HIP_IFEL(hip_add_sa(src_addr,
                        dst_addr,
                        &ha->hit_peer,
                        &ha->hit_our,
                        ha->spi_inbound_current,
                        ha->esp_transform,
                        &ha->esp_in,
                        &ha->auth_in,
                        HIP_SPI_DIRECTION_IN,
                        ha),
             -1, "Error while changing inbound security association\n");

    // Create a new outbound SA
    HIP_DEBUG("Creating a new outbound SA, SPI=0x%x\n", ha->spi_outbound_new);
    HIP_IFEL(hip_add_sa(dst_addr,
                        src_addr,
                        &ha->hit_our,
                        &ha->hit_peer,
                        ha->spi_outbound_new,
                        ha->esp_transform,
                        &ha->esp_out,
                        &ha->auth_out,
                        HIP_SPI_DIRECTION_OUT,
                        ha),
             -1, "Error while changing outbound security association\n");

    // Create a new security policy pointing to SAs after SA setup
    HIP_IFEL(hip_setup_hit_sp_pair(&ha->hit_peer,
                                   &ha->hit_our,
                                   src_addr,
                                   dst_addr,
                                   IPPROTO_ESP,
                                   1),
             -1, "Setting up SP pair failed\n");

out_err:
    if (err) {
        HIP_ERROR("Failed to setup IPsec SAs, removing IPsec state!");

        /* delete all IPsec related SPD/SA for this ctx->hadb_entry*/
        hip_delete_security_associations_and_sp(ha);
    }

    return err;
}
