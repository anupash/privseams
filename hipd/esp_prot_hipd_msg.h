#ifndef ESP_PROT_HIPD_MSG_H_
#define ESP_PROT_HIPD_MSG_H_

#include "misc.h"

int hip_set_esp_prot_transform(struct hip_common *msg);
int esp_prot_add_sa(hip_ha_t *entry, struct hip_common *msg, int direction);
int add_esp_prot_transform_r1(hip_common_t *msg);
int add_esp_prot_transform_i2(hip_common_t *i2, hip_ha_t *entry, struct hip_context *ctx);
int add_esp_prot_anchor_i2(hip_common_t *i2, hip_ha_t *entry);
int handle_esp_prot_transform_i2(hip_ha_t *entry, struct hip_context *ctx);
int handle_esp_prot_anchor_i2(hip_ha_t *entry, struct hip_context *ctx);
int add_esp_prot_anchor_r2(hip_common_t *r2, hip_ha_t *entry);
int handle_esp_prot_anchor_r2(hip_ha_t *entry, struct hip_context *ctx);

#endif /*ESP_PROT_HIPD_MSG_H_*/
