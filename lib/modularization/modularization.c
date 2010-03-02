/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 *
 * @brief The main source file for libmodularization.
 *
 * @author Tim Just <tim.just@rwth-aachen.de>
 *
 */
#include <stdlib.h>
#include <string.h>

#include "modularization.h"
#include "lib/core/debug.h"
#include "lib/core/protodefs.h"
#include "lib/core/state.h"

enum function_types {
    HANDLE_FUNCTION,
    MAINTENANCE_FUNCTION
};

struct handle_function {
    enum function_types type;
    uint32_t            priority;
    int               (*func_ptr)(const uint32_t packet_type,
                                  const uint32_t ha_state,
                                  struct hip_packet_context *ctx);
};

struct maint_function {
    enum function_types type;
    uint32_t            priority;
    int               (*func_ptr)(void);
};

/**
 * @todo add description
 */
static hip_ll_t *handle_functions[HIP_MAX_PACKET_TYPE][HIP_MAX_HA_STATE];

/**
 * @todo add description
 */
static hip_ll_t *maintenance_functions;

/**
 * @todo add description
 */
static hip_ll_t *state_init_functions;


/******************************************************************************
 * HANDLE FUNCTIONS                                                           *
 ******************************************************************************/

/**
 * hip_register_handle_function
 *
 * Register a function for handling of the specified combination from packet
 * type and host association state.
 *
 * @param packet_type The packet type of the control message (RFC 5201, 5.3.)
 * @param ha_state The host association state (RFC 5201, 4.4.1.)
 * @param *handle_function Pointer to the function which should be called
 *                         when the combination of packet type and host
 *                         association state is reached.
 * @param priority Execution priority for the handle function.
 *
 * @return Success =  0
 *         Error   = -1
 */
int hip_register_handle_function(const uint32_t packet_type,
                                 const uint32_t ha_state,
                                 int (*handle_function)(const uint32_t packet_type,
                                                        const uint32_t ha_state,
                                                        struct hip_packet_context *ctx),
                                 const uint32_t priority)
{
    int err = 0, index = 0;
    hip_ll_t               *new_func_list = NULL;
    hip_ll_node_t          *iter          = NULL;
    struct handle_function *new_entry     = NULL;

    HIP_IFEL(packet_type > HIP_MAX_PACKET_TYPE,
             -1,
             "Maximum packet type exceeded.\n");
    HIP_IFEL(ha_state    > HIP_MAX_HA_STATE,
             -1,
             "Maximum host association state exceeded.\n");

    HIP_IFEL(((new_entry = malloc(sizeof(struct handle_function))) == NULL),
             -1,
             "Error on allocating memory for a handle function entry.\n");

    new_entry->type        = HANDLE_FUNCTION;
    new_entry->priority    = priority;
    new_entry->func_ptr    = handle_function;

    if (!handle_functions[packet_type][ha_state]) {
        HIP_IFEL(((new_func_list = malloc(sizeof(hip_ll_t))) == NULL),
                 -1,
                 "Error on allocating memory for a linked list.\n");
        hip_ll_init(new_func_list);
        handle_functions[packet_type][ha_state] = new_func_list;
    }

    /* Iterate through function list until the desired position is found */
    while ((iter = hip_ll_iterate(handle_functions[packet_type][ha_state],
                                  iter)) != NULL)
    {
        if (priority < ((struct handle_function *) iter->ptr)->priority) {
            break;
        } else {
            index++;
        }
    }

    HIP_IFEL(hip_ll_add(handle_functions[packet_type][ha_state],
                        index,
                        new_entry),
             -1,
             "Error on adding handle function.\n");
out_err:
    return err;
}

/**
 * hip_unregister_handle_function
 *
 * Unregister a function for handling of the specified combination from packet
 * type and host association state.
 *
 * @param packet_type The packet type of the control message (RFC 5201, 5.3.)
 * @param ha_state The host association state (RFC 5201, 4.4.1.)
 * @param *handle_function Pointer to the function which should be unregistered.
 *
 * @return Success =  0
 *         Error   = -1
 */
int hip_unregister_handle_function(const uint32_t packet_type,
                                   const uint32_t ha_state,
                                   const void *handle_function)
{
    int       err, index    = 0;
    hip_ll_node_t *iter     = NULL;

    HIP_IFEL(packet_type > HIP_MAX_PACKET_TYPE,
             -1,
             "Maximum packet type exceeded.\n");
    HIP_IFEL(ha_state    > HIP_MAX_HA_STATE,
             -1,
             "Maximum host association state exceeded.\n");

    if(!handle_functions[packet_type][ha_state]) {
        HIP_ERROR("Bad combination of packet type and ha_state.\n");
        return -1;
    }

    /* Iterate through handle functions until the desired function is found */
    while ((iter = hip_ll_iterate(handle_functions[packet_type][ha_state], iter)) != NULL) {
        if (handle_function == ((struct handle_function *) iter->ptr)->func_ptr) {
            hip_ll_del(handle_functions[packet_type][ha_state], index, free);
            break;
        }
        index++;
    }

out_err:
    return err;
}

/**
 * hip_run_handle_functions
 *
 * Run all handle functions for specified combination from packet type and host
 * association state.
 *
 * @param packet_type The packet type of the control message (RFC 5201, 5.3.)
 * @param ha_state The host association state (RFC 5201, 4.4.1.)
 * @param *ctx The packet context containing the received message, source and
 *             destination address, the ports and the corresponding entry from
 *             the host association database.
 *
 * @return Success =  0
 *         Error   = -1
 */
int hip_run_handle_functions(const uint32_t packet_type,
                             const uint32_t ha_state,
                             struct hip_packet_context *ctx)
{
    int            err  = 0;
    hip_ll_node_t *iter = NULL;

    HIP_IFEL(packet_type > HIP_MAX_PACKET_TYPE,
             -1,
             "Maximum packet type exceeded.\n");
    HIP_IFEL(ha_state    > HIP_MAX_HA_STATE,
             -1,
             "Maximum host association state exceeded.\n");

    HIP_IFEL(!handle_functions[packet_type][ha_state],
             -1,
             "Error on running handle functions.\nPacket type: %d, HA state: %d\n",
             packet_type,
             ha_state);

    while ((iter = hip_ll_iterate(handle_functions[packet_type][ha_state],
                                  iter)) != NULL)
    {
        ((struct handle_function *) iter->ptr)->func_ptr(packet_type,
                                                         ha_state,
                                                         ctx);
    }

out_err:
    return err;
}

/**
 * hip_uninit_handle_functions
 *
 * Free the memory used for storage of handle functions.
 *
 */
void hip_uninit_handle_functions(void)
{
    int i,j;

    for (i = 0; i < HIP_MAX_PACKET_TYPE; i++) {
        for (j = 0; j < HIP_MAX_HA_STATE; j++) {
            if (handle_functions[i][j]) {
                hip_ll_uninit(handle_functions[i][j], free);
                free(handle_functions[i][j]);
            }
        }
    }
}



/******************************************************************************
 * MAINTENANCE FUNCTIONS                                                      *
 ******************************************************************************/

/**
 * hip_register_maint_function
 *
 */
int hip_register_maint_function(int (*maint_function)(void),
                                const uint32_t priority)
{
    int err = 0, index = 0;
    hip_ll_t               *new_func_list = NULL;
    hip_ll_node_t          *iter          = NULL;
    struct maint_function *new_entry     = NULL;

    HIP_IFEL(((new_entry = malloc(sizeof(struct maint_function))) == NULL),
             -1,
             "Error on allocating memory for a handle function entry.\n");

    new_entry->type        = MAINTENANCE_FUNCTION;
    new_entry->priority    = priority;
    new_entry->func_ptr    = maint_function;

    if (!maintenance_functions) {
        HIP_IFEL(((new_func_list = malloc(sizeof(hip_ll_t))) == NULL),
                 -1,
                 "Error on allocating memory for a linked list.\n");
        hip_ll_init(new_func_list);
        maintenance_functions = new_func_list;
    }

    /* Iterate through function list until the desired position is found */
    while ((iter = hip_ll_iterate(maintenance_functions, iter)) != NULL)
    {
        if (priority < ((struct maint_function *) iter->ptr)->priority) {
            break;
        } else {
            index++;
        }
    }

    HIP_IFEL(hip_ll_add(maintenance_functions,
                        index,
                        new_entry),
             -1,
             "Error on adding maintenance function.\n");
out_err:
    return err;
}

/**
 * hip_run_maint_functions
 *
 * Run all maintenance functions.
 *
 * @return Success =  0
 *         Error   = -1
 */
int hip_run_maint_functions(void)
{
    int            err  = 0;
    hip_ll_node_t *iter = NULL;

    HIP_IFEL(!maintenance_functions,
             -1,
             "Error on running maintenance functions.\n");

    while ((iter = hip_ll_iterate(maintenance_functions, iter)) != NULL) {
        ((struct maint_function*) iter->ptr)->func_ptr();
    }

out_err:
    return err;
}

/**
 * hip_uninit_maint_functions
 *
 * Free the memory used for storage of maintenance functions.
 *
 */
void hip_uninit_maint_functions(void)
{
    if (maintenance_functions) {
        hip_ll_uninit(maintenance_functions, free);
        free(maintenance_functions);
    }
}

/******************************************************************************
 * MODULAR STATE                                                              *
 ******************************************************************************/

/**
 * hip_init_state
 *
 * Initializes a new data structure for storage of references to state items.
 * This data structure consists of a pointer set and can be mentioned as global
 * state.
 *
 *  @return Success = Pointer to the new data structure
 *          Error   = NULL
 */
struct modular_state *hip_init_state(void)
{
    struct modular_state *state;

    if ((state = malloc(sizeof(struct modular_state))) == NULL) {
        HIP_ERROR("Error on allocating memory for a modular_state instance.\n");
        return NULL;
    }

    if ((state->item_list = malloc(sizeof(hip_ll_t))) == NULL) {
        HIP_ERROR("Error on allocating memory for a linked list.\n");
        return NULL;
    }

    hip_ll_init(state->item_list);
    state->item_names = NULL;
    state->num_items = 0;

    return state;
}

/**
 * hip_register_state_init_function
 *
 * Registers a new state initialization function. These functions are called,
 * when a new host association database entry is created.
 *
 * @param  Pointer to the state initialization function.
 *
 * @return Success = 0
 *         Error   = -1
 */
int hip_register_state_init_function(void *func)
{
    int err = 0;
    hip_ll_t *new_func_list = NULL;

    HIP_IFEL(!func, -1, "Invalid init function provided");

    if (!state_init_functions) {
        HIP_IFEL(((new_func_list = malloc(sizeof(hip_ll_t))) == NULL),
                 -1,
                 "Error on allocating memory for a linked list.\n");
        hip_ll_init(new_func_list);
        state_init_functions = new_func_list;
    }

    err = hip_ll_add_last(state_init_functions, func);

out_err:
    return err;
}

/**
 * hip_init_state_items
 *
 * Initialize all registered state items. This function is called, when a new
 * host association database entry is created.
 *
 * @note  Call hip_register_state_init_function to add an initialization
 *        function.
 *
 * @param *state    Pointer to the modular state data structure.
 */
void hip_init_state_items(struct modular_state *state)
{
    hip_ll_node_t *iter = NULL;
    int (*init_function)(struct modular_state *state) = NULL;

    while ((iter = hip_ll_iterate(state_init_functions, iter)) != NULL) {
        init_function = iter->ptr;
        init_function(state);
    }
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
int hip_add_state_item(struct modular_state *state,
                       void *state_item,
                       const char *item_name)
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
void *hip_get_state_item_by_id(struct modular_state *state,
                               const unsigned int id)
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

    hip_ll_uninit(state->item_list, free);
    free(state->item_list);

    for (i = 0; i < state->num_items; i++) {
        free(state->item_names[i]);
    }

    free(state->item_names);
    free(state);
}
