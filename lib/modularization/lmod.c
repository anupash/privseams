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
 * @brief The main source file for libmodularization (lmod).
 *
 * @author Tim Just <tim.just@rwth-aachen.de>
 *
 */
#include <stdio.h>
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
    uint16_t    num;
    char *identifier;
};


/**
 * List of initialization functions for the modular state.
 *
 * Call lmod_register_state_init_function to add a function to the list and
 * lmod_init_state_items to initialize all items of a modular state instance.
 *
 */
static hip_ll_t state_init_functions;

/**
 * List of module identifier.
 *
 * Used to check, whether a certain module is loaded.
 *
 */
static char **disabled_modules;

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
static uint16_t num_disabled_modules = 0;

/**
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
 * Registers a new state initialization function. These functions are called,
 * when a new host association database entry is created.
 *
 * @param  func Pointer to the state initialization function.
 *
 * @return Success = 0
 *         Error   = -1
 */
int lmod_register_state_init_function(void *func)
{
    if (!func) {
        return -1;
    }

    return hip_ll_add_last(&state_init_functions, func);
}

/**
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

    while ((iter = hip_ll_iterate(&state_init_functions, iter))) {
        init_function = iter->ptr;
        init_function(state);
    }
}

/**
 * Retrieve a void pointer to a state variable from the global state set using
 * the state item name.
 *
 *  @param      state       Pointer to the global state.
 *  @param      item_name   String identifying a state.
 *  @return Success = id (index number) of the state item as unsigned int
 *          Error   = -1
 */
static int lmod_get_state_item_id(struct modular_state *state,
                                  const char *item_name)
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
 * Returns a void pointer to a state item from the global state set using
 * the id (index number).
 *
 *  @param      state       Pointer to the global state.
 *  @param      id          Index number of the requested state.
 *  @return Success = Pointer to the requested state item (if exists)
 *          Error   = NULL
 */
static void *lmod_get_state_item_by_id(struct modular_state *state,
                                       const unsigned int id)
{
    return hip_ll_get(state->item_list, id);
}

/**
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
 * Disable the module with the provide name. The initialization functions of
 * disabled modules will not be executed. Therefore the functionality of these
 * modules should be completely disabled.
 *
 * @note Call lmod_uninit_disabled_modules() to free the allocated memory!
 *
 * @param *module_name String identifier for the module to disable.
 *
 * @return Success =  0
 *         Error   = -1 (if the module was already disabled)
 */
int lmod_disable_module(const char *module_name)
{
    if (lmod_module_disabled(module_name)) {
        return -1;
    }

    disabled_modules = (char **)realloc(disabled_modules,
                                        (num_disabled_modules + 1) * sizeof(char *));

    disabled_modules[num_disabled_modules++] = strdup(module_name);

    return 0;
}

/**
 * Check whether a certain module is disabled.
 *
 * @note This function uses string compares. Therefore you should call this
 *       function only once and cache the result to improve performance.
 *
 * @param *module_name String identifier for the module to check.
 *
 * @return 0, if module with this name is ENABLED
 *         1, if module with this name is DISABLED
 */
int lmod_module_disabled(const char *module_name)
{
    unsigned int i;

    for (i = 0; i < num_disabled_modules; i++) {
       if (0 == strcmp(module_name, disabled_modules[i])) {
           return 1;
       }
    }

    return 0;
}

/**
 * Free all allocated memory for storage of disabled modules.
 *
 */
void lmod_uninit_disabled_modules(void)
{
    int i;

    if (disabled_modules) {
        for (i = 0; i < num_disabled_modules; i++) {
            if (disabled_modules[i]) {
                free(disabled_modules[i]);
            }
        }
        free(disabled_modules);
    }
}

/**
 * Check whether a certain packet type was already registered.
 *
 * @note The return value is not 0 (FALSE), if the packet type not exists.
 *       Therefore you have to check, if the return value is equal to -1, if you
 *       want to check whether a packet type exists or not.
 *
 * @param packet_type The packet type number to search for.
 *
 * @return The index of the packet type, if existing or
 *         -1, if the packet type not exists
 */
static int lmod_packet_type_exists(const uint16_t packet_type)
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
    int                 index          = 0;
    size_t              identifier_len = 0;
    hip_ll_node_t      *iter           = NULL;
    struct packet_type *new_entry      = NULL;

    if (!identifier || (lmod_packet_type_exists(packet_type) != -1)) {
        return -1;
    }

    if (!(new_entry = malloc(sizeof(struct packet_type)))) {
        return -1;
    }

    new_entry->num = packet_type;

    identifier_len = strlen(identifier);
    if (!(new_entry->identifier = malloc(identifier_len))) {
        return -1;
    }
    strncpy(new_entry->identifier, identifier, identifier_len);

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
 * Free allocated memory for one entry of the packet type list.
 *
 */
static void lmod_free_packet_entry(void *entry)
{
    struct packet_type *packte_type_entry = entry;
    free(packte_type_entry->identifier);
    free(packte_type_entry);
}

/**
 * Free all allocated memory for storage of the packet type list.
 *
 * @note Call this function, if you have added packet types.
 *
 */
void lmod_uninit_packet_types(void)
{
    hip_ll_uninit(&packet_types, lmod_free_packet_entry);
}
