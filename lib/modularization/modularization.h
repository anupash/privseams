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
#ifndef HIP_MODULARIZATION_H
#define HIP_MODULARIZATION_H

#include "lib/core/linkedlist.h"

struct modular_state {
    hip_ll_t        *item_list;
    char           **item_names;
    unsigned int     num_items;
};

struct modular_state *hip_init_state(void);
int   hip_add_state_item(struct modular_state *state, void *state_item, const char *item_name);
void *hip_get_state_item(struct modular_state *state, const char *item_name);
void *hip_get_state_item_by_id(struct modular_state *state, const unsigned int index);
int   hip_get_state_item_id(struct modular_state *state, const char *item_name);
void  hip_free_state(struct modular_state *state);

#endif /* HIP_MODULARIZATION_H */
