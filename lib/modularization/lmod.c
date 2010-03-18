/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 *
 * @brief The main source file for libmodularization (lmod).
 *
 * @author Tim Just <tim.just@rwth-aachen.de>
 *
 */
#include <stdlib.h>
#include <string.h>

#include "lmod.h"

/**
 * A generic struct for function pointer.
 */
struct function {
    uint16_t priority;
    void    *func_ptr;
};

struct packet_type {
    uint32_t    num;
    const char *identifier;
};


/**
 * List of initialization functions for the modular state.
 *
 * Call lmod_register_state_init_function to add a function to the list and
 * lmod_init_state_items to initialize all items of a modular state instance.
 *
 */
static hip_ll_t *state_init_functions;

/**
 * List of module identifier.
 *
 * Used to check, whether a certain module is loaded.
 *
 */
static char **module_list;

/**
 * List of packet types.
 *
 * Used to track all registered packet types. Each module which defines a new
 * packet type should register it using lmod_register_packet_type. So, two
 * independent modules cannot unintentionally use the same packet type number
 * for different purposes.
 *
 */
static hip_ll_t packet_types;

/**
 * Number of enabled modules.
 */
static uint16_t num_modules = 0;

/**
 * lmod_init_state
 *
 * Initializes a new data structure for storage of references to state items.
 * This data structure consists of a pointer set and can be mentioned as global
 * state.
 *
 *  @return Success = Pointer to the new data structure
 *          Error   = NULL
 */
struct modular_state *lmod_init_state(void)
{
    struct modular_state *state;

    if (!(state = malloc(sizeof(struct modular_state)))) {
        return NULL;
    }

    if (!(state->item_list = malloc(sizeof(hip_ll_t)))) {
        return NULL;
    }

    hip_ll_init(state->item_list);
    state->item_names = NULL;
    state->num_items = 0;

    return state;
}

/**
 * lmod_register_state_init_function
 *
 * Registers a new state initialization function. These functions are called,
 * when a new host association database entry is created.
 *
 * @param  Pointer to the state initialization function.
 *
 * @return Success = 0
 *         Error   = -1
 */
int lmod_register_state_init_function(void *func)
{
    int err = 0;
    hip_ll_t *new_func_list = NULL;

    if (!func) {
        return -1;
    }

    if (!state_init_functions) {

        if (!(new_func_list = malloc(sizeof(hip_ll_t)))) {
            return -1;
        }

        hip_ll_init(new_func_list);
        state_init_functions = new_func_list;
    }

    err = hip_ll_add_last(state_init_functions, func);

    return err;
}

/**
 * lmod_init_state_items
 *
 * Initialize all registered state items. This function is called, when a new
 * host association database entry is created.
 *
 * @note  Call lmod_register_state_init_function to add an initialization
 *        function.
 *
 * @param *state    Pointer to the modular state data structure.
 */
void lmod_init_state_items(struct modular_state *state)
{
    hip_ll_node_t *iter = NULL;
    int (*init_function)(struct modular_state *state) = NULL;

    while ((iter = hip_ll_iterate(state_init_functions, iter))) {
        init_function = iter->ptr;
        init_function(state);
    }
}

/**
 * lmod_add_state_item
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
 */
int lmod_add_state_item(struct modular_state *state,
                        void *state_item,
                        const char *item_name)
{

    /* Check if identifier already exists */
    if (-1 != lmod_get_state_item_id(state, item_name)) {
        return -1;
    }

    hip_ll_add_last(state->item_list, state_item);

    state->item_names = (char **)realloc(state->item_names,
                             (state->num_items + 1) * sizeof(char *));

    state->item_names[state->num_items++] = strdup(item_name);

    return state->num_items-1;
}

/**
 * lmod_get_state_item
 *
 * Returns a void pointer to a state item from the global state set using
 * the string identifier.
 *
 *  @param      state       Pointer to the global state.
 *  @param      item_name   String identifying the state.
 *  @return Success = Pointer to the requested state item (if exists)
 *          Error   = NULL
 */
void *lmod_get_state_item(struct modular_state *state, const char *item_name)
{
    unsigned int state_id;

    state_id = lmod_get_state_item_id(state, item_name);

    return lmod_get_state_item_by_id(state, state_id);
}

/**
 * lmod_get_state_item_by_id
 *
 * Returns a void pointer to a state item from the global state set using
 * the id (index number).
 *
 *  @param      state       Pointer to the global state.
 *  @param      id          Index number of the requested state.
 *  @return Success = Pointer to the requested state item (if exists)
 *          Error   = NULL
 */
void *lmod_get_state_item_by_id(struct modular_state *state,
                                const unsigned int id)
{
    return hip_ll_get(state->item_list, id);
}

/**
 * lmod_get_state_item_id
 *
 * Retrieve a void pointer to a state variable from the global state set using
 * the state item name.
 *
 *  @param      state       Pointer to the global state.
 *  @param      item_name   String identifying a state.
 *  @return Success = id (index number) of the state item as unsigned int
 *          Error   = -1
 */
int lmod_get_state_item_id(struct modular_state *state, const char *item_name)
{
    unsigned int i;

    for (i = 0; i < state->num_items; i++) {
       if (0 == strcmp(item_name, state->item_names[i])) {
           return i;
       }
    }

    return -1;
}

/**
 * lmod_uninit_state
 *
 * Free all allocated memory for storage of the global state set.
 *
 *  @param      state       Pointer to the global state.
 */
void lmod_uninit_state(struct modular_state *state)
{
    unsigned int i;

    hip_ll_uninit(state->item_list, free);
    free(state->item_list);

    for (i = 0; i < state->num_items; i++) {
        free(state->item_names[i]);
    }

    free(state->item_names);
    free(state);
}

/**
 * lmod_register_function
 *
 * Register a function to the specified list according their priority.
 *
 * @param *list Pointer to the list if already exist, NULL otherwise.
 * @param *entry Pointer to the data structure containing the function pointer.
 * @param priority Execution priority for the function.
 *
 * @note If there already exists a function with the same priority, this
 *       function will return NULL as error value. Functions need to have unique
 *       priority values.
 *
 * @return Success = Pointer to the function list.
 *         Error   = NULL
 */
hip_ll_t *lmod_register_function(hip_ll_t *list,
                                 void *entry,
                                 const uint16_t priority)
{
    int            index    = 0;
    hip_ll_t      *new_list = NULL;
    hip_ll_node_t *iter     = NULL;

    if (!list) {
        if (!(new_list = malloc(sizeof(hip_ll_t)))) {
            return NULL;
        }
        hip_ll_init(new_list);
        list = new_list;
    }

    if (!entry) {
        return NULL;
    }

    while ((iter = hip_ll_iterate(list, iter))) {
        if (priority == ((struct function *) iter->ptr)->priority) {
            return NULL;
        } else if (priority < ((struct function *) iter->ptr)->priority) {
            break;
        } else {
            index++;
        }
    }

    hip_ll_add(list, index, entry);

    return list;
}

/**
 * lmod_unregister_function
 *
 * Unregister a function from the specified list.
 *
 * @param *list Pointer to the list from which the function should be removed.
 * @param *function Pointer to the function to remove.
 *
 * @return Success =  0
 *         Error   = -1
 */
int lmod_unregister_function(hip_ll_t *list, const void *function)
{
    int            index = 0;
    hip_ll_node_t *iter  = NULL;

    if (!list) {
        return -1;
    }

    while ((iter = hip_ll_iterate(list, iter))) {
        if (function == ((struct function *) iter->ptr)->func_ptr) {
            hip_ll_del(list, index, free);
            break;
        }
        index++;
    }

    return 0;
}

/**
 * lmod_register_module
 *
 * Add an identifier to the module list. All modules should register an id.
 * So everyone else can check, if a certain module is loaded.
 *
 * @note Call lmod_uninit_module_list() to free the allocated memory!
 *
 * @param *module_id String identifier for the module to register.
 *
 * @return Success =  0
 *         Error   = -1 (if the identifier already exists)
 */
int lmod_register_module(const char *module_id)
{
    if (lmod_module_exists(module_id)) {
        return -1;
    }

    module_list = (char **)realloc(module_list,
                                   (num_modules + 1) * sizeof(char *));

    module_list[num_modules++] = strdup(module_id);

    return 0;
}

/**
 * lmod_module_exists
 *
 * Check whether a certain module is enabled.
 *
 * @note This function uses string compares. Therefore you should call this
 *       function only once and cache the result to improve performance.
 *
 * @param *module_id String identifier for the module to check.
 *
 * @return 0, if module with this id is NOT registered
 *         1, if module with this id is registered
 */
int lmod_module_exists(const char *module_id)
{
    unsigned int i;

    for (i = 0; i < num_modules; i++) {
       if (0 == strcmp(module_id, module_list[i])) {
           return 1;
       }
    }

    return 0;
}

/**
 * lmod_uninit_module_list
 *
 * Free all allocated memory for storage of the module list.
 *
 * @note Call this function, if you have added module id's.
 *
 */
void lmod_uninit_module_list(void)
{
    int i;

    if (module_list) {
        for (i = 0; i < num_modules; i++) {
            if (module_list[i]) {
                free(module_list[i]);
            }
        }
        free(module_list);
    }
}

/**
 * lmod_register_packet_type
 *
 * Register a new packet type and the corresponding identifier. Each module
 * introducing a new packet type should register it using this function.
 *
 * @note Call lmod_uninit_packet_types() to free the allocated memory!
 *
 * @param packet_type The packet type number to register.
 * @param *identifier A name for the packet type.
 *
 * @return Success =  0
 *         Error   = -1
 */
int lmod_register_packet_type(const uint16_t packet_type,
                              const char *identifier)
{
    int                 index     = 0;
    hip_ll_node_t      *iter      = NULL;
    struct packet_type *new_entry = NULL;

    if (!identifier || (lmod_packet_type_exists(packet_type) != -1)) {
        return -1;
    }

    if (!(new_entry = malloc(sizeof(struct packet_type)))) {
        return -1;
    }

    new_entry->num = packet_type;
    new_entry->identifier = identifier;

    while ((iter = hip_ll_iterate(&packet_types, iter))) {
        if (packet_type == ((struct packet_type *) iter->ptr)->num) {
            return -1;
        } else if (packet_type < ((struct packet_type *) iter->ptr)->num) {
            break;
        } else {
            index++;
        }
    }

    hip_ll_add(&packet_types, index, new_entry);

    return 0;
}

/**
 * lmod_packet_type_exists
 *
 * Check whether a certain packet type was already registered.
 *
 * @param packet_type The packet type number to search for.
 *
 * @return The index of the packet type, if existing or
 *         -1, if the packet type not exists
 */
int lmod_packet_type_exists(const uint16_t packet_type)
{
    int            index = 0;
    hip_ll_node_t *iter  = NULL;

    while ((iter = hip_ll_iterate(&packet_types, iter))) {
        if (packet_type == ((struct packet_type *) iter->ptr)->num) {
            return index;
        } else {
            index++;
        }
    }

    return -1;
}

/**
 * lmod_get_packet_type_identifier
 *
 * Get the identifier corresponding to the provided packet type number.
 *
 * @param packet_type The packet type number to search for.
 *
 * @return The corresponding identifier, if exists or
 *         NULL, if the packet type is not registered.
 */
const char *lmod_get_packet_type_identifier(const uint16_t packet_type)
{
    int index;
    struct packet_type *entry = NULL;

    index = lmod_packet_type_exists(packet_type);

    if ((index != -1)) {
        entry = hip_ll_get(&packet_types, index);
        return entry->identifier;
    }

    return NULL;
}

/**
 * lmod_uninit_packet_types
 *
 * Free all allocated memory for storage of the packet type list.
 *
 * @note Call this function, if you have added packet types.
 *
 */
void lmod_uninit_packet_types(void)
{
    hip_ll_uninit(&packet_types, free);
}
