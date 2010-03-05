/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 *
 * @brief The main header file for libmodularization.
 *
 * @author Tim Just <tim.just@rwth-aachen.de>
 *
 */
#ifndef HIP_LIB_MODULARIZATION_MODULARIZATION_H
#define HIP_LIB_MODULARIZATION_MODULARIZATION_H

#include <stdint.h>

#include "lib/core/linkedlist.h"

/**
 * @todo add description
 */
struct modular_state {
    hip_ll_t        *item_list;
    char           **item_names;
    unsigned int     num_items;
};

hip_ll_t *lmod_register_function(hip_ll_t *list, void *entry, const uint16_t priority);
int lmod_unregister_function(hip_ll_t *list, const void *function);

int lmod_register_state_init_function(void *func);

void lmod_init_state_items(struct modular_state *state);

struct modular_state *lmod_init_state(void);

int   lmod_add_state_item(struct modular_state *state,
                         void *state_item,
                         const char *item_name);

void *lmod_get_state_item(struct modular_state *state,
                         const char *item_name);

void *lmod_get_state_item_by_id(struct modular_state *state,
                               const unsigned int index);

int   lmod_get_state_item_id(struct modular_state *state,
                            const char *item_name);

void  lmod_uninit_state(struct modular_state *state);

#endif /* HIP_LIB_MODULARIZATION_MODULARIZATION_H */
