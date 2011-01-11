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
 * @author Tim Just <tim.just@rwth-aachen.de>
 */

#ifndef HIP_LIB_CORE_MODULARIZATION_H
#define HIP_LIB_CORE_MODULARIZATION_H

#include <stdint.h>

#include "linkedlist.h"

/**
 * @todo add description
 */
struct modular_state {
    struct hip_ll *item_list;
    char         **item_names;
    unsigned int   num_items;
};

struct hip_ll *lmod_register_function(struct hip_ll *list, void *entry,
                                      const uint16_t priority);
int lmod_unregister_function(struct hip_ll *list, const void *function);

int lmod_register_state_init_function(void *func);

void lmod_init_state_items(struct modular_state *state);

struct modular_state *lmod_init_state(void);

int   lmod_add_state_item(struct modular_state *state,
                          void *state_item,
                          const char *item_name);

void *lmod_get_state_item(struct modular_state *state,
                          const char *item_name);

void  lmod_uninit_state(struct modular_state *state);

int lmod_disable_module(const char *module_id);

int lmod_module_disabled(const char *module_id);

void lmod_uninit_disabled_modules(void);

int lmod_register_packet_type(const uint16_t packet_type,
                              const char *identifier);

void lmod_uninit_packet_types(void);

#endif /* HIP_LIB_CORE_MODULARIZATION_H */
