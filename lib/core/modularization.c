/*
 * Copyright (c) 2010 Aalto University and RWTH Aachen University.
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
 */

/**
 * @file
 * @brief Allow modularized features that can be enabled as required.
 *
 * @author Tim Just <tim.just@rwth-aachen.de>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "debug.h"
#include "modularization.h"
#include "ife.h"


/**
 * A generic struct for function pointer.
 */
struct function {
    uint16_t priority;
    void    *func_ptr;
};

struct packet_type {
    uint8_t num;
    char   *identifier;
};

struct parameter_type {
    uint16_t num;
    char    *identifier;
};

/**
 * List of initialization functions for the modular state.
 *
 * Call lmod_register_state_init_function to add a function to the list and
 * lmod_init_state_items to initialize all items of a modular state instance.
 *
 */
static struct hip_ll state_init_functions;

/**
 * List of uninitialization functions for the modular states.
 * These functions free memory that was allocated for their respective state item.
 *
 * Call lmod_register_state_uninit_function to add a function the list and
 * lmod_uninit_state_items to uninitialize the items of a modular state instance.
 */
static struct hip_ll state_uninit_functions;

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
static struct hip_ll packet_types;

/**
 * List of parameter types.
 *
 * Used to track all registered parameter types. Each module which defines a new
 * parameter type must register it using lmod_register_parameter_type.
 */
static struct hip_ll parameter_types;

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

    if (!(state->item_list = malloc(sizeof(struct hip_ll)))) {
        return NULL;
    }

    hip_ll_init(state->item_list);
    state->item_names = NULL;
    state->num_items  = 0;

    return state;
}

/**
 * Registers a new state initialization function. These functions are called,
 * when a new host association database entry is created.
 *
 * @note   Call lmod_uninit_state_init_functions() to free all memory allocated
 *         for state initialization functions.
 *
 * @param  func Pointer to the state initialization function.
 *
 * @return Success = 0
 *         Error   = -1
 */
int lmod_register_state_init_function(void *const func)
{
    return hip_ll_add_last(&state_init_functions, func);
}

/**
 * Register a new state uninitialization function. These functions are called,
 * when a host association database entry is purged.
 *
 * @note    Call lmod_uninit_state_uninit_functions() to free all memory
 *          allocated for the state uninitialization functions.
 *
 * @param  func Pointer to the state uninitialization function.
 * @return Success =  0
 *         Error   = -1
 */
int lmod_register_state_uninit_function(void *const func)
{
    return hip_ll_add_last(&state_uninit_functions, func);
}

/**
 * Free all memory allocated for storage of the state initialization functions.
 */
void lmod_uninit_state_init_functions(void)
{
    hip_ll_uninit(&state_init_functions, NULL);
}

/**
 * Free all memory allocated for storage of the state uninitialization functions.
 */
void lmod_uninit_state_uninit_functions()
{
    hip_ll_uninit(&state_uninit_functions, NULL);
}

/**
 * Run all functions specified in @c list with @c state as parameter.
 * Use this function to initialize or uninitialize state items.
 * Behaviour for lists that do not contain function pointers is undefined.
 *
 * @param state Pointer to the modular state data structure.
 * @param list  Pointer to the list of functions that are supposed to be called
 *              with the modular state as parameter.
 */
static void lmod_run_functions_on_state(struct modular_state *const state,
                                        struct hip_ll *const list)
{
    const struct hip_ll_node *iter = NULL;
    int                       (*function)(struct modular_state *state) = NULL;

    while ((iter = hip_ll_iterate(list, iter))) {
        function = iter->ptr;
        function(state);
    }
}

/**
 * Initialize all registered state items. This function is called, when a new
 * host association database entry is created.
 *
 * @note  Call lmod_register_state_init_function to add an initialization
 *        function.
 *
 * @param state Pointer to the modular state data structure.
 */
void lmod_init_state_items(struct modular_state *state)
{
    lmod_run_functions_on_state(state, &state_init_functions);
}

/**
 * Uninitialize all registered state items. This function is called when a host
 * association database entry is purged.
 *
 * @param state Pointer to the modular state data structure.
 */
void lmod_uninit_state_items(struct modular_state *const state)
{
    lmod_run_functions_on_state(state, &state_uninit_functions);
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
        if (strcmp(item_name, state->item_names[i]) == 0) {
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
    if (lmod_get_state_item_id(state, item_name) != -1) {
        return -1;
    }

    hip_ll_add_last(state->item_list, state_item);

    state->item_names = realloc(state->item_names,
                                (state->num_items + 1) * sizeof(char *));

    state->item_names[state->num_items++] = strdup(item_name);

    return state->num_items - 1;
}

/**
 * Free all allocated memory for storage of the global state set.
 *
 *  @param      state       Pointer to the global state.
 */
void lmod_uninit_state(struct modular_state *state)
{
    unsigned int i;

    lmod_uninit_state_items(state);
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
 * @param list     Pointer to the list if already exist, NULL otherwise.
 * @param entry    Pointer to the data structure containing the function pointer.
 * @param priority Execution priority for the function.
 *
 * @note If there already exists a function with the same priority, this
 *       function will return NULL as error value. Functions need to have unique
 *       priority values.
 *
 * @return Success = Pointer to the function list.
 *         Error   = NULL
 */
struct hip_ll *lmod_register_function(struct hip_ll *list,
                                      void *entry,
                                      const uint16_t priority)
{
    int                       idx      = 0;
    struct hip_ll            *new_list = NULL;
    const struct hip_ll_node *iter     = NULL;

    if (!list) {
        if (!(new_list = malloc(sizeof(struct hip_ll)))) {
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
            idx++;
        }
    }

    hip_ll_add(list, idx, entry);

    return list;
}

/**
 * Unregister a function from the specified list.
 *
 * @param list     Pointer to the list from which the function should be removed.
 * @param function Pointer to the function to remove.
 *
 * @return Success =  0
 *         Error   = -1
 */
int lmod_unregister_function(struct hip_ll *list, const void *function)
{
    int                       idx  = 0;
    const struct hip_ll_node *iter = NULL;

    if (!list) {
        return -1;
    }

    while ((iter = hip_ll_iterate(list, iter))) {
        if (function == ((struct function *) iter->ptr)->func_ptr) {
            hip_ll_del(list, idx, free);
            break;
        }
        idx++;
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
 * @param module_name String identifier for the module to disable.
 *
 * @return Success =  0
 *         Error   = -1 (if the module was already disabled)
 */
int lmod_disable_module(const char *module_name)
{
    if (lmod_module_disabled(module_name)) {
        return -1;
    }

    disabled_modules = realloc(disabled_modules,
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
 * @param module_name String identifier for the module to check.
 *
 * @return 0, if module with this name is ENABLED
 *         1, if module with this name is DISABLED
 */
int lmod_module_disabled(const char *module_name)
{
    unsigned int i;

    for (i = 0; i < num_disabled_modules; i++) {
        if (strcmp(module_name, disabled_modules[i]) == 0) {
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
            free(disabled_modules[i]);
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
int lmod_packet_type_exists(const uint8_t packet_type)
{
    int                       idx  = 0;
    const struct hip_ll_node *iter = NULL;

    while ((iter = hip_ll_iterate(&packet_types, iter))) {
        if (packet_type == ((struct packet_type *) iter->ptr)->num) {
            return idx;
        } else {
            idx++;
        }
    }

    return -1;
}

/**
 * Get the identifier of the packet type.
 *
 * @return parameter name or UNDEFINED if parameter type was not found.
 */
const char *lmod_get_packet_identifier(const uint8_t packet_type)
{
    const struct hip_ll_node *iter = NULL;
    HIP_DEBUG("Name search for packet type %d \n", packet_type);

    while ((iter = hip_ll_iterate(&packet_types, iter))) {
        HIP_DEBUG("Packet type in list %d \n", ((struct packet_type *) iter->ptr)->num);
        if (packet_type == ((struct packet_type *) iter->ptr)->num) {
            return ((struct packet_type *) iter->ptr)->identifier;
        }
    }

    return "UNDEFINED";
}

/**
 * Register a new packet type and the corresponding identifier. Each module
 * introducing a new packet type should register it using this function.
 *
 * @note Call lmod_uninit_packet_types() to free the allocated memory!
 *
 * @param packet_type The packet type number to register.
 * @param identifier  A name for the packet type.
 *
 * @return Success =  0
 *         Error   = -1
 */
int lmod_register_packet_type(const uint8_t packet_type,
                              const char *const identifier)
{
    int                       idx       = 0;
    const struct hip_ll_node *iter      = NULL;
    struct packet_type       *new_entry = NULL;

    if (!identifier || (lmod_packet_type_exists(packet_type) != -1)) {
        return -1;
    }

    if (!(new_entry = malloc(sizeof(struct packet_type)))) {
        return -1;
    }

    new_entry->num = packet_type;

    if (!(new_entry->identifier = strdup(identifier))) {
        return -1;
    }

    while ((iter = hip_ll_iterate(&packet_types, iter))) {
        if (packet_type == ((struct packet_type *) iter->ptr)->num) {
            return -1;
        } else if (packet_type < ((struct packet_type *) iter->ptr)->num) {
            break;
        } else {
            idx++;
        }
    }

    hip_ll_add(&packet_types, idx, new_entry);

    return 0;
}

/**
 * Free allocated memory for one entry of the packet type list.
 *
 * @param entry packet type entry to be freed
 */
static void lmod_free_packet_entry(void *entry)
{
    struct packet_type *packet_type_entry = entry;
    free(packet_type_entry->identifier);
    free(packet_type_entry);
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

/**
 * Check whether a certain parameter type was already registered.
 *
 * @note The return value is not 0 (FALSE), if the packet type does not exist.
 *       Therefore you have to check, if the return value is equal to -1, if you
 *       want to check whether a parameter type exists or not.
 *
 * @param parameter_type The parameter type number to search for.
 *
 * @return The index of the parameter type, if existing or
 *         -1, if the parameter type does not exist
 */
int lmod_parameter_type_exists(const uint16_t parameter_type)
{
    int                       index = 0;
    const struct hip_ll_node *iter  = NULL;

    while ((iter = hip_ll_iterate(&parameter_types, iter))) {
        if (parameter_type == ((struct parameter_type *) iter->ptr)->num) {
            return index;
        } else {
            index++;
        }
    }

    return -1;
}

/**
 * Register a new parameter type and the corresponding identifier. Each module
 * introducing a new parameter type must register it using this function.
 *
 * @note Call lmod_uninit_parameter_types() to free all memory allocated for
 *       parameter types.
 *
 * @param parameter_type The parameter type number to register.
 * @param identifier     A name for the parameter type.
 *
 * @return Success =  0
 *         Error   = -1
 */
int lmod_register_parameter_type(const uint16_t parameter_type,
                                 const char *const identifier)
{
    int                       index     = 0;
    const struct hip_ll_node *iter      = NULL;
    struct parameter_type    *new_entry = NULL;
    int                       err       = 0;

    HIP_IFEL(!identifier || (lmod_parameter_type_exists(parameter_type) != -1),
             -1, "Missing identifier or parameter type already registered.\n");

    HIP_IFEL(!(new_entry = malloc(sizeof(struct parameter_type))),
             -1, "Failed to allocate memory.\n");

    new_entry->num = parameter_type;

    HIP_IFEL(!(new_entry->identifier = strdup(identifier)),
             -1, "Failed to copy parameter type identifier.\n");

    while ((iter = hip_ll_iterate(&parameter_types, iter))) {
        if (parameter_type < ((struct parameter_type *) iter->ptr)->num) {
            break;
        } else {
            index++;
        }
    }

    HIP_IFEL(hip_ll_add(&parameter_types, index, new_entry) == -1,
             -1, "Failed to register parameter type.\n");

    return 0;

out_err:
    if (new_entry) {
        free(new_entry->identifier);
        free(new_entry);
    }
    return err;
}

/**
 * Get the identifier of the parameter type.
 *
 * @return Parameter name or UNDEFINED if parameter type was not found.
 */
const char *lmod_get_parameter_identifier(const uint16_t parameter_type)
{
    const struct hip_ll_node *iter = NULL;
    HIP_DEBUG("Name search for parameter type %d \n", parameter_type);

    while ((iter = hip_ll_iterate(&parameter_types, iter))) {
        HIP_DEBUG("Parameter type in list %d \n", ((struct parameter_type *) iter->ptr)->num);
        if (parameter_type == ((struct parameter_type *) iter->ptr)->num) {
            return ((struct parameter_type *) iter->ptr)->identifier;
        }
    }

    return "UNDEFINED";
}

/**
 * Free allocated memory for one entry of the packet type list.
 *
 * @param entry parameter type entry to be freed
 */
static void lmod_free_parameter_entry(void *entry)
{
    struct packet_type *parameter_type_entry = entry;
    free(parameter_type_entry->identifier);
    free(parameter_type_entry);
}

/**
 * Free all allocated memory for storage of the parameter type list.
 *
 * @note Call this function, if you have added parameter types.
 */
void lmod_uninit_parameter_types(void)
{
    hip_ll_uninit(&parameter_types, lmod_free_parameter_entry);
}
