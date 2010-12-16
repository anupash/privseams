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
static void signaling_cdb_entry_free(signaling_cdb_entry_t *entry)
{
    SList *element;
    element = entry->connection_contexts;
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
 * Searches for a pair of ports inside the given entry.
 *
 * @return < 0 for error, 0 for not found, > 0 for found.
 */
int signaling_cdb_entry_find_connection(const uint16_t src_port, const uint16_t dest_port,
                                        signaling_cdb_entry_t * entry,
                                        struct signaling_connection_context **ret) {
    int err = 0;
    SList *listitem;
    struct signaling_connection_context *ctx = NULL;

    HIP_IFEL(entry == NULL,
            -1, "Entry is null.\n" );

    listitem = entry->connection_contexts;
    while(listitem) {
        ctx = (struct signaling_connection_context *) listitem->data;
        if((src_port == ctx->src_port && dest_port == ctx->dest_port) ||
           (dest_port == ctx->src_port && src_port == ctx->dest_port)) {
            err = 1;
            *ret = ctx;
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
    signaling_cdb_entry_t * entry = NULL;

    HIP_IFEL(!(entry = malloc(sizeof(signaling_cdb_entry_t))),
             -1, "Could not allocate memory for new scdb entry \n");
    memcpy(&entry->local_hit, local_hit, sizeof(struct in6_addr));
    memcpy(&entry->remote_hit, remote_hit, sizeof(struct in6_addr));
    entry->connection_contexts = NULL;

    HIP_IFEL(hip_ht_add(scdb, entry), -1, "hash collision detected!\n");

out_err:
    if(err != 0)
        entry = NULL;

    return entry;
}

/*
 * Updates all fields in old with values from new.
 */
static int signaling_cdb_update_entry(struct signaling_connection_context *old,
                                      const struct signaling_connection_context *new) {
    old->src_port = new->src_port;
    old->dest_port = new->dest_port;
    old->connection_status = new->connection_status;
    // TODO: update application context and user context

    return 0;
}

/* Adds or updates and entry */
int signaling_cdb_add(const struct in6_addr *local_hit,
                      const struct in6_addr *remote_hit,
                      struct signaling_connection_context *ctx)
{
    int err = 0;
    int found;
    signaling_cdb_entry_t *entry = NULL;
    struct signaling_connection_context *existing_app_ctx;
    entry = signaling_cdb_entry_find(local_hit, remote_hit);

    if(entry == NULL) {
        entry = signaling_cdb_add_new(local_hit, remote_hit);
    }

    HIP_IFEL(!entry, -1, "Adding a new empty entry failed.\n");

    found = signaling_cdb_entry_find_connection(ctx->src_port, ctx->dest_port, entry, &existing_app_ctx);
    if (found > 0) {
        signaling_cdb_update_entry(existing_app_ctx, ctx);
    } else {
        entry->connection_contexts = append_to_slist(entry->connection_contexts, ctx);
    }

out_err:
    return err;
}

/*
 * Prints one database entry.
 */
static void signaling_cdb_print_doall(signaling_cdb_entry_t * entry) {
    SList *listentry;
    struct signaling_connection_context *ctx;

    HIP_DEBUG("\t----- SCDB ELEMENT START ------\n");
    HIP_DEBUG_HIT("\tLocal Hit", &entry->local_hit);
    HIP_DEBUG_HIT("\tRemote Hit", &entry->remote_hit);

    HIP_DEBUG("\tApplication contexts:\n");

    listentry = entry->connection_contexts;
    while(listentry != NULL) {
        if(listentry->data != NULL) {
            ctx = (struct signaling_connection_context *) listentry->data;
            HIP_DEBUG("\t  ->  appname (%d): %s\n",
                ctx->app_ctx.pid,
                ctx->app_ctx.application_dn);
            HIP_DEBUG("\t  ->  local port: %d, remote port: %d\n",
                ctx->src_port,
                ctx->dest_port);
        } else {
            HIP_DEBUG("\t  ->  <no port info available>\n");
        }
        listentry = listentry->next;
    }
    HIP_DEBUG("\t----- SCDB ELEMENT END   ------\n");
}

/** A callback wrapper of the prototype required by @c lh_doall_arg(). */
static IMPLEMENT_LHASH_DOALL_FN(signaling_cdb_print, signaling_cdb_entry_t)

/* Print the contents of the database */
void signaling_cdb_print(void) {
    HIP_DEBUG("------------------ SCDB START ------------------\n");
    hip_ht_doall(scdb, (LHASH_DOALL_FN_TYPE) LHASH_DOALL_FN(signaling_cdb_print));
    HIP_DEBUG("------------------ SCDB END   ------------------\n");
}

/*
 * Processes a message of type 'HIP_MSG_SIGNALING_CDB_ADD_CONN'
 * by adding information about completed BEX or Update to connection tracking db.
 *
 * Comment:
 *      For now, connection tracking is done only on port-basis.
 *      Thus, any application context inside 'msg' is discarded.
 *
 * @return -1 on error
 */
int signaling_cdb_handle_add_request(hip_common_t * msg) {
    int err = 0;
    const struct signaling_param_appinfo *appinfo;
    const struct hip_tlv_common *param   = NULL;
    const hip_hit_t *src_hit = NULL;
    const hip_hit_t *dst_hit = NULL;
    struct signaling_connection_context * ctx;

    HIP_IFEL(hip_get_msg_type(msg) != HIP_MSG_SIGNALING_CDB_ADD_CONN,
            -1, "Message has wrong type.\n");

    HIP_DEBUG("Got request to add a connection to a scdb entry.\n");
    HIP_DUMP_MSG(msg);

    param      = hip_get_param(msg, HIP_PARAM_HIT);
    src_hit    = hip_get_param_contents_direct(param);
    param      = hip_get_next_param(msg, param);
    dst_hit    = hip_get_param_contents_direct(param);
    HIP_IFEL(!(src_hit && dst_hit),
            -1, "Source- and/or destinationhit not given.\n");

    HIP_IFEL(!(param = hip_get_param(msg, HIP_PARAM_SIGNALING_APPINFO)),
            -1, "No appinfo parameter in message.\n");
    appinfo = (const struct signaling_param_appinfo *) param;
    HIP_IFEL(!(ctx = signaling_init_connection_context()),
             -1, "Failed to init app context \n");

    ctx->src_port = ntohs(appinfo->src_port);
    ctx->dest_port = ntohs(appinfo->dest_port);
    ctx->connection_status = SIGNALING_CONN_ALLOWED;

    signaling_cdb_add(src_hit, dst_hit, ctx);

    signaling_cdb_print();

out_err:
    return err;
}


