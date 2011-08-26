/*
 * signaling_hipd_state.c
 *
 *  Created on: Nov 4, 2010
 *      Author: ziegeldorf
 */

#include <string.h>
#include <stdlib.h>

#include "lib/core/ife.h"
#include "lib/core/debug.h"

#include "signaling_hipd_state.h"

#define INDEX_HASH_LENGTH      4
/**
 * hashes the inner addresses (for now) to lookup the corresponding SA entry
 *
 * @param sa_entry  partial SA entry containing inner addresses and IPsec mode
 * @return          hash of inner addresses
 */
static unsigned long signaling_connection_context_hash(const struct signaling_connection_context *ctx)
{
    HIP_DEBUG("Hash of entry: %d \n", ctx->id);
    return ctx->id;
}

/**
 * Compares the ids of two connection contexts.
 *
 * @param c1     first connection context entry to be compared with
 * @param c2     second connection context entry to be compared with
 * @return              1 if different entries, else 0
 */
static int signaling_connection_context_cmp(const struct signaling_connection_context *c1,
                                            const struct signaling_connection_context *c2)
{
    if(c1->id == c2->id) {
        return 0;
    } else {
        return 1;
    }
}

static IMPLEMENT_LHASH_HASH_FN(signaling_connection_context, struct signaling_connection_context);
static IMPLEMENT_LHASH_COMP_FN(signaling_connection_context, struct signaling_connection_context);

/*
 * Initialize an signaling_hipd_state instance.
 *
 * Allocates the required memory and sets the members to the start values.
 *
 *  @return Success = Index of the update state item in the global state. (>0)
 *          Error   = -1
 */
int signaling_hipd_init_state(struct modular_state *state)
{
    int err = 0;
    struct signaling_hipd_state *sig_state = NULL;

    HIP_IFEL(!(sig_state = (struct signaling_hipd_state *) malloc(sizeof(struct signaling_hipd_state))),
             -1, "Error on allocating memory for a signaling_hipd_state instance.\n");

    HIP_IFEL(!(sig_state->connection_contexts = hip_ht_init(LHASH_HASH_FN(signaling_connection_context),
                                                            LHASH_COMP_FN(signaling_connection_context))),
             -1, "failed to initialize hashtable for connection contexts\n");

    sig_state->pending_ctx = NULL;

    sig_state->user_cert_ctx.user_certificate_required    = 0;
    sig_state->user_cert_ctx.cert_chain                   = NULL;
    sig_state->user_cert_ctx.group                        = -1;
    signaling_init_user_context(&sig_state->user_cert_ctx.user_ctx);

    sig_state->update_in_progress = 0;

    err = lmod_add_state_item(state, sig_state, "signaling_hipd_state");

out_err:
    return err;
}

/**
 * return NULL if no such entry, or the matching entry
 */
struct signaling_connection_context *signaling_hipd_state_get_connection_context(struct signaling_hipd_state *state, uint32_t id)
{
    struct signaling_connection_context search_entry;
    search_entry.id = id;
    return hip_ht_find(state->connection_contexts, &search_entry);
}

/**
 * return NULL if no such entry, or the matching entry
 */
int signaling_hipd_state_add_connection_context(struct signaling_hipd_state *state, struct signaling_connection_context *ctx)
{
    struct signaling_connection_context *new_entry;

    /* reject new entry if one already exists */
    if ((new_entry = hip_ht_find(state->connection_contexts, ctx)) != NULL) {
        HIP_ERROR("Connection context with same hash already exists. Free it before you add a new one:\n");
        signaling_connection_context_print(new_entry, "\t");
        return -1;
    }

    /* allocate new entry and copy contents */
    if (!(new_entry = malloc(sizeof(struct signaling_connection_context)))) {
        HIP_ERROR("Could not allocate enough memory for new connection context\n");
        return -1;
    } else {
        signaling_copy_connection_context(new_entry, ctx);
    }

    /* Remember this for BEX */
    if (!state->pending_ctx) {
        state->pending_ctx = new_entry;
        HIP_DEBUG("Set pending context.. \n");
    }

    return hip_ht_add(state->connection_contexts, new_entry);
}

void signaling_hipd_state_delete_connection_context(struct signaling_hipd_state *state, struct signaling_connection_context *ctx) {
    hip_ht_delete(state->connection_contexts, ctx);
}

/*
 * Prints one database entry.
 */
static void connection_contexts_print_doall(struct signaling_connection_context *ctx) {
    signaling_connection_context_print(ctx, "\t");
}

/** A callback wrapper of the prototype required by @c lh_doall_arg(). */
static IMPLEMENT_LHASH_DOALL_FN(connection_contexts_print, struct signaling_connection_context);

/* Print the contents of the database */
void signaling_hipd_state_print(struct signaling_hipd_state *state) {
    HIP_DEBUG("------------------ HIPD SIGNALING STATE START ------------------\n");
    HIP_DEBUG("Update in progress: \t %s \n\n", state->update_in_progress == 1 ? "Yes" : "No");
    hip_ht_doall(state->connection_contexts, (LHASH_DOALL_FN_TYPE) LHASH_DOALL_FN(connection_contexts_print));
    HIP_DEBUG("------------------ HIPD SIGNALING STATE END   ------------------\n");
}
