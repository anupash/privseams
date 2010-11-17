/**
 * @file
 *
 * Copyright (c) 2010 Aalto University) and RWTH Aachen University.
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
 *
 * @author Henrik Ziegeldorf <henrik.ziegeldorf@rwth-aachen.de>
 *
 */

#include <string.h>
#include <stdlib.h>

#include "lib/core/builder.h"
#include "lib/core/debug.h"
#include "lib/core/ife.h"
#include "lib/core/common.h"

#include "firewall/hslist.h"
#include "signaling_cdb.h"

/* hash functions definitions used for calculating the entries' hashes
 * TODO use own function to hash hits to improve performance */
#define INDEX_HASH_FN           HIP_DIGEST_SHA1
#define INDEX_HASH_LENGTH       SHA_DIGEST_LENGTH

/* database storing the connection tracking entries, indexed by src _and_ dst hits */
HIP_HASHTABLE *scdb   = NULL;

/**
 * hashes the inner addresses (for now) to lookup the corresponding SA entry
 *
 * @param sa_entry  partial SA entry containing inner addresses and IPsec mode
 * @return          hash of inner addresses
 */
static unsigned long signaling_cdb_entry_hash(const signaling_cdb_entry_t *scdb_entry)
{
    struct in6_addr addr_pair[2];
    unsigned char hash[INDEX_HASH_LENGTH];
    int err = 0;

    memset(&hash, 0, INDEX_HASH_LENGTH);
    memcpy(&addr_pair[0], &scdb_entry->local_hit, sizeof(struct in6_addr));
    memcpy(&addr_pair[1], &scdb_entry->remote_hit, sizeof(struct in6_addr));
    HIP_IFEL(hip_build_digest(INDEX_HASH_FN, addr_pair, 2 * sizeof(struct in6_addr), hash),
            -1, "failed to hash addresses\n");

out_err:
    if (err) {
        memset(&hash, 0, INDEX_HASH_LENGTH);
    }

    // just consider sub-string of 4 bytes here
    return *((unsigned long *) hash);
}

/**
 * compares the hashes of 2 SA entries to check if they are the same
 *
 * @param sa_entry1     first SA entry to be compared with
 * @param sa_entry2     second SA entry to be compared with
 * @return              1 if different entries, else 0
 */
static int signaling_cdb_entries_cmp(const signaling_cdb_entry_t *scdb_entry1,
                                     const signaling_cdb_entry_t *scdb_entry2)
{
    int err             = 0;
    unsigned long hash1 = 0;
    unsigned long hash2 = 0;

    // values have to be present
    HIP_ASSERT(scdb_entry1 && scdb_entry2);

    HIP_IFEL(!(hash1 = signaling_cdb_entry_hash(scdb_entry1)), -1,
             "failed to hash scdb entry\n");
    HIP_IFEL(!(hash2 = signaling_cdb_entry_hash(scdb_entry2)), -1,
             "failed to hash scdb entry\n");

    err = (hash1 != hash2);

out_err:
    return err;
}

/**
 * callback wrappers providing per-variable casts before calling the
 * type-specific callbacks
 */
static IMPLEMENT_LHASH_HASH_FN(signaling_cdb_entry, signaling_cdb_entry_t)

/**
 * callback wrappers providing per-variable casts before calling the
 * type-specific callbacks
 */
static IMPLEMENT_LHASH_COMP_FN(signaling_cdb_entries, signaling_cdb_entry_t)


/**
 * frees an SCDB entry
 */
static void signaling_cdb_entry_free(UNUSED signaling_cdb_entry_t *entry)
{
    // TODO: Implement this
}

/**
 * deletes a single SCDB entry
 *
 * @param src_addr the source address
 * @param dst_addr the destination address
 */
UNUSED static int signaling_cdb_entry_delete(struct in6_addr *src_addr, struct in6_addr *dst_addr)
{
    signaling_cdb_entry_t *stored_entry = NULL;
    int err = 0;

    /* find entry in scdb and delete entry */
    HIP_IFEL(!(stored_entry = signaling_cdb_entry_find(src_addr, dst_addr)),
            -1, "failed to retrieve scdb entry\n");

    // delete the entry from the scdb
    hip_ht_delete(scdb, stored_entry);

    // free all entry members
    signaling_cdb_entry_free(stored_entry);

    // we still have to free the entry itself
    free(stored_entry);

    HIP_DEBUG("scdb entry deleted\n");

out_err:
    return err;
}


/** initializes the scdb
 *
 * @return -1, if error occurred, else 0
 */
int signaling_cdb_init(void)
{
    int err = 0;

    HIP_IFEL(!(scdb = hip_ht_init(LHASH_HASH_FN(signaling_cdb_entry), LHASH_COMP_FN(signaling_cdb_entries))),
            -1, "failed to initialize sadb\n");

    HIP_DEBUG("scdb initialized\n");

out_err:
    return err;
}

/**
 * uninits the scdb by deleting all entries stored in there
 *
 * @return -1, if error occurred, else 0
 */
int signaling_cdb_uninit(void)
{
    int err = 0;

    // TODO: implement this

    return err;
}

/**
 * searches the scdb for an entry
 */
signaling_cdb_entry_t *signaling_cdb_entry_find(const struct in6_addr *local_hit,
                                                const struct in6_addr *remote_hit)
{
    signaling_cdb_entry_t search_entry;
    signaling_cdb_entry_t *stored_entry = NULL;
    int err                      = 0;

    // fill search entry with information needed by the hash function
    memcpy(&search_entry.local_hit, local_hit, sizeof(struct in6_addr));
    memcpy(&search_entry.remote_hit, remote_hit, sizeof(struct in6_addr));

    /*HIP_DEBUG("looking up scdb entry with following index attributes:\n");
    HIP_DEBUG_HIT("inner_src_addr", &search_entry.local_hit);
    HIP_DEBUG_HIT("inner_dst_addr", &search_entry.remote_hit);*/

    // find entry in sadb db
    HIP_IFEL(!(stored_entry = hip_ht_find(scdb, &search_entry)),
            -1, "failed to retrieve sa entry\n");

out_err:
    if (err) {
        stored_entry = NULL;
    }

    return stored_entry;
}

static signaling_cdb_entry_t * signaling_cdb_add_new(const struct in6_addr *local_hit,
                      const struct in6_addr *remote_hit) {
    int err = 0;
    signaling_cdb_entry_t * entry = malloc(sizeof(signaling_cdb_entry_t));
    memcpy(&entry->local_hit, local_hit, sizeof(struct in6_addr));
    memcpy(&entry->remote_hit, remote_hit, sizeof(struct in6_addr));

    HIP_IFEL(hip_ht_add(scdb, entry), -1, "hash collision detected!\n");

out_err:
    if(err != 0)
        entry = NULL;

    return entry;
}

/* Adds or updates and entry */
int signaling_cdb_add(const struct in6_addr *local_hit,
                      const struct in6_addr *remote_hit,
                      signaling_cdb_connection_entry_t *conn,
                      signaling_cdb_applications_entry_t *app)
{
    int err = 0;
    signaling_cdb_entry_t *entry = NULL;
    entry = signaling_cdb_entry_find(local_hit, remote_hit);

    if(entry == NULL) {
        entry = signaling_cdb_add_new(local_hit, remote_hit);
    }

    entry->connections = append_to_slist(entry->connections, conn);
    entry->applications = append_to_slist(entry->applications, app);

//out_err:
    return err;
}

static void signaling_cdb_print_doall(signaling_cdb_entry_t * entry) {
    SList *listentry;

    HIP_DEBUG("\t----- ELEMENT START ------\n");
    HIP_DEBUG_HIT("\tLocal Hit", &entry->local_hit);
    HIP_DEBUG_HIT("\tRemote Hit", &entry->remote_hit);

    HIP_DEBUG("\tConnections\n");

    listentry = entry->connections;
    while(listentry) {
        HIP_DEBUG("\t  ->  local port: %d, remote port: %d\n",
                ((signaling_cdb_connection_entry_t *) listentry->data)->local_port,
                ((signaling_cdb_connection_entry_t *) listentry->data)->remote_port);
        listentry = listentry->next;
    }

    HIP_DEBUG("\tApplications\n");

    listentry = entry->applications;
    while(listentry) {
        HIP_DEBUG("\t  ->  appname (%d): %s\n",
                ((signaling_cdb_applications_entry_t *) listentry->data)->pid,
                ((signaling_cdb_applications_entry_t *) listentry->data)->application_dn);
        listentry = listentry->next;
    }
    HIP_DEBUG("\t----- ELEMENT END   ------\n");
}

/** A callback wrapper of the prototype required by @c lh_doall_arg(). */
static IMPLEMENT_LHASH_DOALL_FN(signaling_cdb_print, signaling_cdb_entry_t)

/* Print the contents of the database */
void signaling_cdb_print(void) {
    HIP_DEBUG("------------------ SCDB START ------------------\n");
    hip_ht_doall(scdb, (LHASH_DOALL_FN_TYPE) LHASH_DOALL_FN(signaling_cdb_print));
    HIP_DEBUG("------------------ SCDB END   ------------------\n");
}

