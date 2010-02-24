/**
 * @file firewall/esp_prot_light_update.c
 *
 * <LICENSE TEMLPATE LINE - LEAVE THIS LINE INTACT>
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
#include "lib/modularization/modularization.h"

int esp_prot_send_light_update(hip_ha_t *entry,
                               const int anchor_offset[],
                               unsigned char *secret[MAX_NUM_PARALLEL_HCHAINS],
                               const int secret_length[],
                               unsigned char *branch_nodes[MAX_NUM_PARALLEL_HCHAINS],
                               const int branch_length[]);
int esp_prot_handle_light_update(const uint32_t packet_type,
                                 const uint32_t ha_state,
                                 struct hip_packet_context *ctx);

#endif /* HIP_HIPD_ESP_PROT_LIGHT_UPDATE_H */
