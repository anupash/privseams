/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 *
 * Provides messaging functionality required for HHL-based anchor
 * element updates.
 *
 * @brief Messaging required for HHL-based anchor element updates
 *
 * @author Rene Hummen <rene.hummen@rwth-aachen.de>
 *
 */

#ifndef HIP_HIPD_ESP_PROT_LIGHT_UPDATE_H
#define HIP_HIPD_ESP_PROT_LIGHT_UPDATE_H

#include "lib/core/protodefs.h"

int esp_prot_send_light_update(hip_ha_t *entry,
                               const int anchor_offset[],
                               unsigned char *secret[MAX_NUM_PARALLEL_HCHAINS],
                               const int secret_length[],
                               unsigned char *branch_nodes[MAX_NUM_PARALLEL_HCHAINS],
                               const int branch_length[]);
int esp_prot_receive_light_update(hip_common_t *msg,
                                  const in6_addr_t *src_addr,
                                  const in6_addr_t *dst_addr,
                                  hip_ha_t *entry);

#endif /* HIP_HIPD_ESP_PROT_LIGHT_UPDATE_H */
