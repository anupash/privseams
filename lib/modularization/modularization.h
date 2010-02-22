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
struct hip_packet_context {
    struct hip_common         *msg;
    struct in6_addr           *src_addr;
    struct in6_addr           *dst_addr;
    struct hip_stateless_info *msg_info;
    struct hip_hadb_state     *hadb_entry;
};

/**
 * @todo add description
 */
struct modular_state {
    hip_ll_t        *item_list;
    char           **item_names;
    unsigned int     num_items;
};

int hip_register_handle_function(uint32_t packet_type,
                                 uint32_t ha_state,
                                 void *handle_function,
                                 uint32_t priority);

int hip_run_handle_functions(uint32_t packet_type,
                             uint32_t ha_state,
                             struct hip_packet_context *ctx);

void hip_uninit_handle_functions(void);

struct modular_state *hip_init_state(void);

int   hip_add_state_item(struct modular_state *state,
                         void *state_item,
                         const char *item_name);

void *hip_get_state_item(struct modular_state *state,
                         const char *item_name);

void *hip_get_state_item_by_id(struct modular_state *state,
                               const unsigned int index);

int   hip_get_state_item_id(struct modular_state *state,
                            const char *item_name);

void  hip_free_state(struct modular_state *state);

#endif /* HIP_LIB_MODULARIZATION_MODULARIZATION_H */
