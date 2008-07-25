#ifndef ESP_PROT_HIPD_MSG_H_
#define ESP_PROT_HIPD_MSG_H_

#include "misc.h"

int esp_prot_set_preferred_transforms(struct hip_common *msg);
int esp_prot_sa_add(hip_ha_t *entry, struct hip_common *msg, int direction);
int esp_prot_r1_add_transform(hip_common_t *msg);
int esp_prot_i2_add_transform(hip_common_t *i2, hip_ha_t *entry, struct hip_context *ctx);
int esp_prot_i2_add_anchor(hip_common_t *i2, hip_ha_t *entry);
int esp_prot_i2_handle_transform(hip_ha_t *entry, struct hip_context *ctx);
int esp_prot_i2_handle_anchor(hip_ha_t *entry, struct hip_context *ctx);
int esp_prot_r2_add_anchor(hip_common_t *r2, hip_ha_t *entry);
int esp_prot_r2_handle_anchor(hip_ha_t *entry, struct hip_context *ctx);

#endif /*ESP_PROT_HIPD_MSG_H_*/
