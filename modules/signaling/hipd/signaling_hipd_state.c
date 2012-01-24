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


/*
 *  static unsigned long signaling_connection_hash(const struct signaling_connection *conn)
 *  {
 *      HIP_DEBUG("Hash of entry: %d \n", conn->id);
 *      return conn->id;
 *  }
 */


/**
 * Compares the ids of two connection contexts.
 *
 * @param c1     first connection context entry to be compared with
 * @param c2     second connection context entry to be compared with
 * @return              1 if different entries, else 0
 */


/*
 *  static int signaling_connection_cmp(const struct signaling_connection *c1,
 *  const struct signaling_connection *c2)
 *  {
 *      if (c1->id == c2->id) {
 *          return 0;
 *      } else {
 *          return 1;
 *      }
 *  }
 */


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
    int                          err       = 0;
    struct signaling_hipd_state *sig_state = NULL;

    HIP_IFEL(!(sig_state = (struct signaling_hipd_state *) malloc(sizeof(struct signaling_hipd_state))),
             -1, "Error on allocating memory for a signaling_hipd_state instance.\n");

    hip_ll_init(sig_state->connections);

    sig_state->pending_conn = NULL;

    sig_state->user_cert_ctx.cert_chain   = NULL;
    sig_state->user_cert_ctx.group        = -1;
    sig_state->user_cert_ctx.next_cert_id = 0;

    err = lmod_add_state_item(state, sig_state, "signaling_hipd_state");

out_err:
    return err;
}

/**
 * return NULL if no such entry, or the matching entry
 */
struct signaling_connection *signaling_hipd_state_get_connection(struct signaling_hipd_state *state, uint32_t id,
                                                                 uint16_t src_port, uint16_t dst_port)
{
    const struct hip_ll_node *iter = NULL;
    if (state->connections) {
        while ((iter = hip_ll_iterate(state->connections, iter))) {
            if ((((struct signaling_connection *) (iter->ptr))->id       == id) &&
                (((struct signaling_connection *) (iter->ptr))->src_port == src_port) &&
                (((struct signaling_connection *) (iter->ptr))->dst_port == dst_port)) {
                return (struct signaling_connection *) (iter->ptr);
            }
        }
    } else {
        return NULL;
    }
    return NULL;
}

struct signaling_connection *signaling_hipd_state_add_connection(struct signaling_hipd_state *state,
                                                                 const struct signaling_connection *const conn)
{
    int                          err       = 0;
    struct signaling_connection *new_entry = NULL;

    /* allocate new entry and copy contents */
    if (!(new_entry = malloc(sizeof(struct signaling_connection)))) {
        HIP_ERROR("Could not allocate enough memory for new connection context\n");
        return NULL;
    }

    signaling_copy_connection(new_entry, conn);
    HIP_IFEL(hip_ll_add_last(state->connections, new_entry), -1,
             "Could not add the connection context to the signaling state");

    /* Remember this for BEX */
    if (!state->pending_conn) {
        state->pending_conn = new_entry;
        HIP_DEBUG("Set pending context.. \n");
    }
    return new_entry;

out_err:
    return NULL;
}

void signaling_hipd_state_delete_connection(struct signaling_hipd_state *state, struct signaling_connection *conn)
{
    int                          idx       = 0;
    const struct hip_ll_node    *iter      = NULL;
    struct signaling_connection *temp_conn = NULL;

    if (state->connections) {
        while ((iter = hip_ll_iterate(state->connections, iter)) != NULL) {
            temp_conn = iter->ptr;

            if ((temp_conn->id == conn->id) &&
                (temp_conn->src_port == conn->src_port) &&
                (temp_conn->dst_port == conn->dst_port)) {
                HIP_DEBUG("Deleting and freeing a signaling connection context " \
                          "at index %u.\n", idx);
                hip_ll_del(state->connections, idx, free);
            }
            idx++;
        }
    }
}

/*
 * Prints one database entry.
 */

/*
 *  static void connections_print_doall(struct signaling_connection *conn)
 *  {
 *      signaling_connection_print(conn, "\t");
 *  }
 */

/** A callback wrapper of the prototype required by @c lh_doall_arg(). */
//static IMPLEMENT_LHASH_DOALL_FN(connections_print, struct signaling_connection);

/* Print the contents of the database */
void signaling_hipd_state_print(struct signaling_hipd_state *state)
{
    const struct hip_ll_node *iter = NULL;

    HIP_DEBUG("------------------ HIPD SIGNALING STATE START ------------------\n");
    if (state->connections) {
        while ((iter = hip_ll_iterate(state->connections, iter)) != NULL) {
            signaling_connection_print((struct signaling_connection *) (iter->ptr), "\t");
        }
    }
    //hip_ht_doall(state->connections, (LHASH_DOALL_FN_TYPE) LHASH_DOALL_FN(connections_print));
    HIP_DEBUG("------------------ HIPD SIGNALING STATE END   ------------------\n");
}
