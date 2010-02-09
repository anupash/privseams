/** @file
 * The main source file for libmodularization
 *
 * @author  Tim Just
 * @version 0.1
 * @date    04.02.2010
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 */
#include <stdlib.h>
#include <string.h>

#include "modularization.h"
#include "lib/core/debug.h"

/**
 * hip_init_state
 *
 * Initializes a new data structure for storage of references to state items.
 * This data structure consists of a pointer set and can be mentioned as global
 * state.
 *
 *  @return Success = Pointer to the new data structure
 *          Error   = NULL
 **/
struct modular_state *hip_init_state(void)
{
    struct modular_state *state;

    if ((state = (struct modular_state*) malloc(sizeof(struct modular_state))) == NULL) {
        HIP_ERROR("Error on allocating memory for a modular_state instance.\n");
        return NULL;
    }

    if ((state->item_list = (hip_ll_t*) malloc(sizeof(hip_ll_t))) == NULL) {
        HIP_ERROR("Error on allocating memory for a linked list.\n");
        return NULL;
    }

    hip_ll_init(state->item_list);
    state->item_names = NULL;
    state->num_items = 0;

    return state;
}

/**
 * hip_add_state_item
 *
 * Registers a new state item to the global state. The state item can be of any
 * type. This function stores a reference to the new state item.
 *
 * Afterwards the state item is retrievable by the provided @c item_name or the
 * returned id (unsigned int).
 *
 *  @param      state       Pointer to the global state.
 *  @param      state_item  Pointer to the new state information.
 *  @param      item_name   String for retrieving the state item by name.
 *  @return Success = id (unsigned int) for retrieving the state by number
 *          Error   = -1
 **/
int hip_add_state_item(struct modular_state *state, void *state_item, const char *item_name)
{
    /* Check if identifier already exists */
    if (-1 != hip_get_state_item_id(state, item_name)) {
        return -1;
    }

    hip_ll_add_last(state->item_list, state_item);

    state->item_names = (char **)realloc(state->item_names,
                             (state->num_items + 1) * sizeof(char *));

    state->item_names[state->num_items++] = strdup(item_name);

    return state->num_items-1;
}

/**
 * hip_get_state_item
 *
 * Returns a void pointer to a state item from the global state set using
 * the string identifier.
 *
 *  @param      state       Pointer to the global state.
 *  @param      item_name   String identifying the state.
 *  @return Success = Pointer to the requested state item (if exists)
 *          Error   = NULL
 **/
void *hip_get_state_item(struct modular_state *state, const char *item_name)
{
    unsigned int state_id;

    state_id = hip_get_state_item_id(state, item_name);

    return hip_get_state_item_by_id(state, state_id);
}

/**
 * hip_get_state_item_by_id
 *
 * Returns a void pointer to a state item from the global state set using
 * the id (index number).
 *
 *  @param      state       Pointer to the global state.
 *  @param      id          Index number of the requested state.
 *  @return Success = Pointer to the requested state item (if exists)
 *          Error   = NULL
 **/
void *hip_get_state_item_by_id(struct modular_state *state, const unsigned int id)
{
    return hip_ll_get(state->item_list, id);
}

/**
 * hip_get_state_item_id
 *
 * Retrieve a void pointer to a state variable from the global state set using
 * the state item name.
 *
 *  @param      state       Pointer to the global state.
 *  @param      item_name   String identifying a state.
 *  @return Success = id (index number) of the state item as unsigned int
 *          Error   = -1
 **/
int hip_get_state_item_id(struct modular_state *state, const char *item_name)
{
    unsigned int      i;

    for (i = 0; i < state->num_items; i++) {
       if (0 == strcmp(item_name, state->item_names[i])) {
           return i;
       }
    }

    return -1;
}

/**
 * hip_free_state
 *
 * Free all allocated memory for storage of the global state set.
 *
 *  @param      state       Pointer to the global state.
 **/
void hip_free_state(struct modular_state *state)
{
    unsigned int      i;

    hip_ll_uninit(state->item_list, NULL);
    free(state->item_list);

    for (i = 0; i < state->num_items; i++) {
        free(state->item_names[i]);
    }

    free(state->item_names);
    free(state);
}
