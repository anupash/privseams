/** @file
 * The header file for libmodularization
 *
 * @author  Tim Just
 * @version 0.1
 * @date    04.02.2010
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>.
 */
#ifndef HIP_MODULARIZATION_H
#define HIP_MODULARIZATION_H

#ifdef HAVE_CONFIG_H
  #include "config.h"
#endif /* HAVE_CONFIG_H */

void *hip_init_state(void);
int   hip_add_state_item(void *state, void *state_item, const char *item_name);
void *hip_get_state_item(void *state, const char *item_name);
void *hip_get_state_item_by_id(void *state, const unsigned int index);
int   hip_get_state_item_id(void *state, const char *item_name);
void  hip_free_state(void *state);

#endif /* HIP_MODULARIZATION_H */
