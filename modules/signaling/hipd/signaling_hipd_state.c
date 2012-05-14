/*
 * signaling_hipd_state.c
 *
 *  Created on: Nov 4, 2010
 *     Authors: Henrik Ziegeldorf, <henrik.ziegeldorf@rwth-aachen.de>
 *              Anupam Ashish,     <anupam.ashish@rwth-aachen.de>
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
    int                          err       = 0, i = 0;
    struct signaling_hipd_state *sig_state = NULL;

    HIP_IFEL(!(sig_state = (struct signaling_hipd_state *) malloc(sizeof(struct signaling_hipd_state))),
             -1, "Error on allocating memory for a signaling_hipd_state instance.\n");

    if (!(sig_state->connections = malloc(sizeof(struct hip_ll)))) {
        HIP_ERROR("Could not allocate empty new list\n");
        free(sig_state);
        return -1;
    }
    hip_ll_init(sig_state->connections);

    sig_state->pending_conn               = NULL;
    sig_state->flag_user_sig              = 0;
    sig_state->flag_offer_type            = 0;
    sig_state->user_cert_ctx.cert_chain   = NULL;
    sig_state->user_cert_ctx.group        = -1;
    sig_state->user_cert_ctx.next_cert_id = 0;

    for (i = 0; i < 10; i++) {
        sig_state->service_ack[i]  = NULL;
        sig_state->service_nack[i] = 0;
        sig_state->offer_groups[i] = NULL;
        sig_state->mb_certs[i]     = NULL;
    }

    err = lmod_add_state_item(state, sig_state, "signaling_hipd_state");
    signaling_init_connection_context(&sig_state->pending_conn_context, OUT);
out_err:
    return err;
}

int signaling_hipd_state_initialize_service_ack(struct signaling_hipd_state    *state)
{
    int i = 0;
    for (i = 0; i < 10; i++) {
        if (state->service_ack[i]) {
            free(state->service_ack[i]);
        }
        state->service_ack[i] = NULL;
    }
    return 0;
}

int signaling_hipd_state_initialize_offer_groups(struct signaling_hipd_state    *state)
{
    int i = 0;
    for (i = 0; i < 10; i++) {
        if (state->offer_groups[i]) {
            free(state->offer_groups[i]);
        }
        state->offer_groups[i] = NULL;
    }
    return 0;
}

int signaling_hipd_state_initialize_mb_certs(struct signaling_hipd_state    *state)
{
    int i = 0;
    for (i = 0; i < 10; i++) {
        if (state->mb_certs[i]) {
            free(state->mb_certs[i]);
        }
        state->mb_certs[i] = NULL;
    }
    return 0;
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

/**
 * return NULL if no such entry, or the matching entry
 */
int signaling_hipd_state_get_connections_by_app_name(struct signaling_hipd_state *state,
                                                     char *app_name, struct hip_ll *ret_list)
{
    int                       err  = 0;
    const struct hip_ll_node *iter = NULL;
    hip_ll_init(ret_list);

    if (state->connections) {
        while ((iter = hip_ll_iterate(state->connections, iter))) {
            if (!strcmp(((struct signaling_connection *) (iter->ptr))->application_name, app_name)) {
                HIP_IFEL(hip_ll_add_last(ret_list, iter->ptr), -1,
                         "Could not add the connection context to the list");
            }
        }

        return 0;
    } else {
        return -1;
    }
    return -1;

out_err:
    return err;
}

struct signaling_connection *signaling_hipd_state_add_connection(struct signaling_hipd_state *state,
                                                                 const struct signaling_connection *const conn)
{
    struct signaling_connection *new_entry = NULL;

    HIP_ASSERT(conn);
    /* allocate new entry and copy contents */
    if (!(new_entry = malloc(sizeof(struct signaling_connection)))) {
        HIP_ERROR("Could not allocate enough memory for new connection context\n");
        return NULL;
    }

    signaling_copy_connection(new_entry, conn);
    if (hip_ll_add_last(state->connections, new_entry)) {
        HIP_ERROR("Could not add the connection context to the signaling state");
        return NULL;
    }
    HIP_DEBUG("Added new HIPD state to the HIP State DB.\n");

    /* Remember this for BEX */
//    if (!state->pending_conn) {
    state->pending_conn = new_entry;
    HIP_DEBUG("Set pending context.. \n");
//    }
    return new_entry;
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

void signaling_port_pairs_from_hipd_state_by_app_name(struct signaling_hipd_state *state, char *app_name, struct signaling_port_pair *ports)
{
    const struct hip_ll_node *iter = NULL;
    int                       i    = 0;
    if (!app_name) {
        HIP_DEBUG("No Application name provided. Can't add corresponding socket information\n");
        return;
    }

    HIP_DEBUG("------------------ HIPD SIGNALING STATE COPYING PORT PAIRS ------------------\n");
    if (state->connections) {
        while ((iter = hip_ll_iterate(state->connections, iter)) != NULL) {
            if (!strcmp(((struct signaling_connection *) (iter->ptr))->application_name, app_name)) {
                if (i < SIGNALING_MAX_SOCKETS) {
                    (ports + i)->src_port = ((struct signaling_connection *) iter->ptr)->src_port;
                    (ports + i)->dst_port = ((struct signaling_connection *) iter->ptr)->dst_port;
                    i++;
                } else {
                    return;
                }
            }
        }
    }

    HIP_DEBUG("Number of Port pairs copied = %d \n", i);
}
