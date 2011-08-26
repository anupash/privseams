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

/* variable for storing the next free connection id */
static int next_conn_id;

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
static void signaling_cdb_entry_free(signaling_cdb_entry_t *entry)
{
    struct slist *element;
    element = entry->connections;
    while (element) {
        free(element->data);
        element = element->next;
    }
    free(entry);
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

    // free the entry and its members
    signaling_cdb_entry_free(stored_entry);

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
    next_conn_id = 0;

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
    hip_list_t *curr, *iter;
    struct signaling_cdb_entry *tmp;
    int count;

    list_for_each_safe(curr, iter, scdb, count) {
        tmp = (struct signaling_cdb_entry *) list_entry(curr);
        signaling_cdb_entry_free(tmp);
    }

    hip_ht_uninit(scdb);

    return err;
}

/**
 * Searches for connection for a sepcific destination port inside the given entry.
 *
 * @return < 0 for error, 0 for not found, > 0 for found.
 */
struct signaling_connection *signaling_cdb_entry_find_connection_by_dst_port(const struct in6_addr *src_hit,
                                                                             const struct in6_addr *dst_hit,
                                                                             const uint16_t dest_port) {
    int err = 0;
    int i = 0;
    struct slist *listitem;
    struct signaling_connection *conn = NULL;
    signaling_cdb_entry_t *entry = NULL;

    /* sanity checks */
    HIP_IFEL(!src_hit || !dst_hit, -1, "Need both source and destination hit. \n");

    if (!(entry = signaling_cdb_entry_find(src_hit, dst_hit))) {
        return NULL;
    }

    listitem = entry->connections;
    while(listitem) {
        conn = (struct signaling_connection *) listitem->data;
        for (i = 0; i < SIGNALING_MAX_SOCKETS; i++) {
            if (conn->sockets[i].src_port == 0 && conn->sockets[i].dst_port == 0) {
                break;
            } else if (conn->sockets[i].dst_port != dest_port) {
                break;
            }
        }
        if (conn->sockets[0].dst_port == dest_port) {
            return conn;
        }
        listitem = listitem->next;
    }

out_err:
    return NULL;
}

/**
 * Searches for a pair of ports inside the given entry.
 *
 * @return < 0 for error, 0 for not found, > 0 for found.
 */
int signaling_cdb_entry_find_connection(const uint16_t src_port, const uint16_t dest_port,
                                        signaling_cdb_entry_t * entry,
                                        struct signaling_connection **ret) {
    int err = 0;
    int i = 0;
    struct slist *listitem;
    struct signaling_connection *conn = NULL;

    HIP_IFEL(entry == NULL,
            -1, "Entry is null.\n" );

    listitem = entry->connections;
    while(listitem) {
        conn = (struct signaling_connection *) listitem->data;
        for (i = 0; i < SIGNALING_MAX_SOCKETS; i++) {
            if (conn->sockets[i].src_port == 0 && conn->sockets[i].dst_port == 0) {
                break;
            } else if ((conn->sockets[i].src_port == src_port && conn->sockets[i].dst_port == dest_port) ||
                       (conn->sockets[i].dst_port == src_port && conn->sockets[i].src_port == dest_port)) {
                *ret = conn;
                return 1;
            }
        }
        listitem = listitem->next;
    }

out_err:
    return err;
}

/**
 * Searches for a connection that has been put on wait.
 *
 * @return < 0 for error, 0 for not found, > 0 for found.
 */
struct signaling_connection *signaling_cdb_get_waiting(const struct in6_addr *src_hit,
                                                       const struct in6_addr *dst_hit) {
    int err                                  = 0;
    struct slist *listitem                   = NULL;
    signaling_cdb_entry_t *entry             = NULL;
    struct signaling_connection *conn        = NULL;

    HIP_IFEL(!(entry = signaling_cdb_entry_find(src_hit, dst_hit)),
             -1, "No CDB entry for given HIT Pair\n");

    listitem = entry->connections;
    while(listitem) {
        conn = (struct signaling_connection *) listitem->data;
        if (conn->status == SIGNALING_CONN_WAITING) {
            return conn;
        }
        listitem = listitem->next;
    }

out_err:
    return NULL;
}

struct signaling_connection *signaling_cdb_entry_get_connection(const struct in6_addr *local_hit,
                                                     const struct in6_addr *remote_hit,
                                                     const uint32_t id)
{
    struct slist *listitem;
    struct signaling_connection *conn = NULL;
    signaling_cdb_entry_t *entry = NULL;

    if ((entry = signaling_cdb_entry_find(local_hit, remote_hit))) {
        listitem = entry->connections;
        while(listitem) {
            conn = (struct signaling_connection *) listitem->data;
            if(conn->id == id) {
                return conn;
            }
            listitem = listitem->next;
        }
    } else {
        return NULL;
    }
    return NULL;
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
    signaling_cdb_entry_t * entry = NULL;

    HIP_IFEL(!(entry = malloc(sizeof(signaling_cdb_entry_t))),
             -1, "Could not allocate memory for new scdb entry \n");
    memcpy(&entry->local_hit, local_hit, sizeof(struct in6_addr));
    memcpy(&entry->remote_hit, remote_hit, sizeof(struct in6_addr));
    entry->connections = NULL;

    HIP_IFEL(hip_ht_add(scdb, entry), -1, "hash collision detected!\n");

out_err:
    if(err != 0)
        entry = NULL;

    return entry;
}

/*
 * Updates all fields in old with values from new.
 */
static int signaling_cdb_update_entry(struct signaling_connection *old,
                                      const struct signaling_connection *new) {

    old->status = new->status;
    old->ctx_in.flags  = new->ctx_in.flags;
    old->ctx_out.flags = new->ctx_out.flags;
    // TODO: update application context and user context

    return 0;
}

/* Adds or updates and entry.
 *
 * @param local_hit the hit of the local host
 * @param remote_hi the hit of the peer host
 * @param ctx the signaling connection context to add to the entry identified by local and remote hit
 *
 * @return 0 on success, negative otherwise
 * */
int signaling_cdb_add(const struct in6_addr *local_hit,
                      const struct in6_addr *remote_hit,
                      struct signaling_connection *conn)
{
    int err = 0;
    int i;
    int found;
    signaling_cdb_entry_t *entry = NULL;
    struct signaling_connection *new_conn;
    struct signaling_connection *existing_conn;

    HIP_IFEL(!local_hit || !remote_hit,
             -1, "Got local or remote hit NULL\n");

    entry = signaling_cdb_entry_find(local_hit, remote_hit);

    if(entry == NULL) {
        entry = signaling_cdb_add_new(local_hit, remote_hit);
    }

    HIP_IFEL(!entry, -1, "Adding a new empty entry failed.\n");

    for (i = 0; i < SIGNALING_MAX_SOCKETS; i++) {
        if (conn->sockets[i].src_port == 0 && conn->sockets[i].dst_port == 0) {
            found = 0;
            break;
        } else if ((found = signaling_cdb_entry_find_connection(conn->sockets[i].src_port, conn->sockets[i].dst_port, entry, &existing_conn))) {
            break;
        }
    }

    if (found > 0) {
        signaling_cdb_update_entry(existing_conn, conn);
    } else {
        new_conn = malloc(sizeof(struct signaling_connection));
        signaling_copy_connection(new_conn, conn);
        entry->connections = append_to_slist(entry->connections, new_conn);
        next_conn_id = new_conn->id + 1;
    }

out_err:
    return err;
}

uint32_t signaling_cdb_get_next_connection_id(void) {
    return next_conn_id;
}

/*
 * Prints one database entry.
 *
 * @return always returns 0 (but needs to be of type int to be able to use it with cdb_apply_func).
 */
int signaling_cdb_entry_print(signaling_cdb_entry_t * entry) {
    struct slist *listentry;
    struct signaling_connection *conn;

    HIP_DEBUG("\t----- SCDB ELEMENT START ------\n");
    HIP_DEBUG_HIT("\tLocal Hit:\t", &entry->local_hit);
    HIP_DEBUG_HIT("\tRemote Hit:\t", &entry->remote_hit);

    HIP_DEBUG("\tLocal application context:\n");

    listentry = entry->connections;
    while(listentry != NULL) {
        if(listentry->data != NULL) {
            conn = ((struct signaling_connection *) listentry->data);
            signaling_connection_print(conn, "\t");
        }
        listentry = listentry->next;
    }
    HIP_DEBUG("\t----- SCDB ELEMENT END   ------\n");
    return 0;
}

/*
 * Prints one database entry.
 */
static void signaling_cdb_apply_func_doall_arg(signaling_cdb_entry_t *entry, void *ptr) {
    int err = 0;
    int(**func)(signaling_cdb_entry_t *) = ptr;

    if ((err = (**func)(entry))) {
        HIP_DEBUG("Error evaluationg following entry: \n");
        signaling_cdb_entry_print(entry);
    } else {
        //HIP_DEBUG("Successfully evaluated following entry: \n");
        //signaling_cdb_print_doall(entry);
    }
}

/** A callback wrapper of the prototype required by @c lh_doall_arg(). */
static IMPLEMENT_LHASH_DOALL_ARG_FN(signaling_cdb_apply_func, signaling_cdb_entry_t, void *)

/* Apply a function to each element of the cdb. */
void signaling_cdb_apply_func(int(*func)(signaling_cdb_entry_t *)) {
    hip_ht_doall_arg(scdb, (LHASH_DOALL_ARG_FN_TYPE) LHASH_DOALL_ARG_FN(signaling_cdb_apply_func), &func);
}

/* Print the contents of the database */
void signaling_cdb_print(void) {
    HIP_DEBUG("------------------ SCDB START ------------------\n");
    signaling_cdb_apply_func(&signaling_cdb_entry_print);
    //hip_ht_doall(scdb, (LHASH_DOALL_FN_TYPE) LHASH_DOALL_FN(signaling_cdb_print));
    HIP_DEBUG("------------------ SCDB END   ------------------\n");
}

