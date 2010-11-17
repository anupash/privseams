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

#include "modules/signaling/lib/signaling_prot_common.h"
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
 * searches for a port pair inside a given entry
 * returns -1 for error, 0 for not found, 1 for found.
 */
int signaling_cdb_ports_find(const uint16_t src_port, const uint16_t dest_port,
        signaling_cdb_entry_t * entry) {
    int err = 0;
    SList *listitem;
    signaling_cdb_connection_entry_t * conn;

    HIP_IFEL(entry == NULL,
            -1, "Entry is null.\n" );

    listitem = entry->connections;
    while(listitem) {
        conn = (signaling_cdb_connection_entry_t *) listitem->data;
        if((src_port == conn->local_port && dest_port == conn->remote_port) ||
           (dest_port == conn->local_port && src_port == conn->remote_port)) {
            err = 1;
            goto out_err;
        }
        listitem = listitem->next;
    }

out_err:
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
    stored_entry = hip_ht_find(scdb, &search_entry);

    if(!stored_entry) {
        memcpy(&search_entry.local_hit, remote_hit, sizeof(struct in6_addr));
        memcpy(&search_entry.remote_hit, local_hit, sizeof(struct in6_addr));
    }

    // find entry in sadb db
    HIP_IFEL(!(stored_entry = hip_ht_find(scdb, &search_entry)),
            -1, "No corresponding scdb entry found.\n");

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
    entry->connections = NULL;
    entry->applications = NULL;

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

    HIP_IFEL(!entry, -1, "Adding a new entry failed.\n");

    entry->connections = append_to_slist(entry->connections, conn);
    entry->applications = append_to_slist(entry->applications, app);

out_err:
    return err;
}

static void signaling_cdb_print_doall(signaling_cdb_entry_t * entry) {
    SList *listentry;

    HIP_DEBUG("\t----- ELEMENT START ------\n");
    HIP_DEBUG_HIT("\tLocal Hit", &entry->local_hit);
    HIP_DEBUG_HIT("\tRemote Hit", &entry->remote_hit);

    HIP_DEBUG("\tConnections\n");

    listentry = entry->connections;
    while(listentry != NULL) {
        if(listentry->data != NULL) {
            HIP_DEBUG("\t  ->  local port: %d, remote port: %d\n",
                ((signaling_cdb_connection_entry_t *) listentry->data)->local_port,
                ((signaling_cdb_connection_entry_t *) listentry->data)->remote_port);
        } else {
            HIP_DEBUG("\t  ->  <no port info available>\n");
        }
        listentry = listentry->next;
    }

    HIP_DEBUG("\tApplications\n");

    listentry = entry->applications;
    while(listentry != NULL) {
        if(listentry->data != NULL) {
            HIP_DEBUG("\t  ->  appname (%d): %s\n",
                ((signaling_cdb_applications_entry_t *) listentry->data)->pid,
                ((signaling_cdb_applications_entry_t *) listentry->data)->application_dn);
        } else {
            HIP_DEBUG("\t  ->  <no appdata available>\n");
        }
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

int signaling_cdb_handle_add_request(hip_common_t * msg) {
    int err = 0;
    const struct signaling_param_appinfo *appinfo;
    const struct hip_tlv_common *param   = NULL;
    const hip_hit_t *src_hit = NULL;
    const hip_hit_t *dst_hit = NULL;
    signaling_cdb_connection_entry_t * conn;

    HIP_DEBUG("Got request to add a connection to a scdb entry.\n");
    HIP_DUMP_MSG(msg);

    param      = hip_get_param(msg, HIP_PARAM_HIT);
    src_hit    = hip_get_param_contents_direct(param);

    param      = hip_get_next_param(msg, param);
    dst_hit    = hip_get_param_contents_direct(param);

    param = hip_get_param(msg, HIP_PARAM_SIGNALING_APPINFO);
    if(param) {
        signaling_param_appinfo_print((const struct signaling_param_appinfo *) param);
    }
    appinfo = (const struct signaling_param_appinfo *) param;

    conn = malloc(sizeof(signaling_cdb_connection_entry_t));
    conn->local_port = ntohs(appinfo->dest_port);
    conn->remote_port = ntohs(appinfo->src_port);

    signaling_cdb_add(src_hit, dst_hit, conn, NULL);

    signaling_cdb_print();

    return err;
}


