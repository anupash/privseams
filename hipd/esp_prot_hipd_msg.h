/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 *
 * hipd messages to the hipfw and additional parameters for BEX and
 * UPDATE messages.
 *
 * @brief Messaging with hipfw and other HIP instances
 *
 * @author Rene Hummen <rene.hummen@rwth-aachen.de>
 *
 */

#ifndef HIP_HIPD_ESP_PROT_HIPD_MSG_H
#define HIP_HIPD_ESP_PROT_HIPD_MSG_H

#include "lib/core/protodefs.h"
#include "lib/core/state.h"

int esp_prot_set_preferred_transforms(const struct hip_common *msg);
int esp_prot_handle_trigger_update_msg(const struct hip_common *msg);
int esp_prot_handle_anchor_change_msg(const struct hip_common *msg);
int esp_prot_sa_add(hip_ha_t *entry, struct hip_common *msg, const int direction,
                    const int update);
int esp_prot_r1_add_transforms(hip_common_t *msg);
int esp_prot_r1_handle_transforms(hip_ha_t *entry, struct hip_context *ctx);
int esp_prot_i2_add_anchor(hip_common_t *i2,
                           hip_ha_t *entry,
                           const struct hip_context *ctx);
int esp_prot_i2_handle_anchor(hip_ha_t *entry, const struct hip_context *ctx);
int esp_prot_r2_add_anchor(hip_common_t *r2, hip_ha_t *entry);
int esp_prot_r2_handle_anchor(hip_ha_t *entry, const struct hip_context *ctx);
int esp_prot_handle_update(const hip_common_t *recv_update, hip_ha_t *entry,
                           const in6_addr_t *src_ip, const in6_addr_t *dst_ip);
int esp_prot_update_add_anchor(hip_common_t *update, hip_ha_t *entry);
int esp_prot_update_handle_anchor(const hip_common_t *recv_update,
                                  hip_ha_t *entry,
                                  const in6_addr_t *src_ip,
                                  const in6_addr_t *dst_ip,
                                  uint32_t *spi);

#endif /*HIP_HIPD_ESP_PROT_HIPD_MSG_H*/
