/*
 * esp_prot_conntrack.h
 *
 *  Created on: Sep 10, 2008
 *      Author: chilli
 */

#ifndef ESP_PROT_CONNTRACK_H_
#define ESP_PROT_CONNTRACK_H_

#include "builder.h"
#include "conntrack.h"

typedef struct esp_prot_conntrack_tfm
{
	hash_function_t hash_function;
	int hash_length;
} esp_prot_conntrack_tfm_t;

int esp_prot_conntrack_init();
int esp_prot_conntrack_uninit();
esp_prot_conntrack_tfm_t * esp_prot_conntrack_resolve_transform(uint8_t transform);
int esp_prot_conntrack_R1_tfms(struct hip_common * common, const struct tuple * tuple);
int esp_prot_conntrack_I2_anchor(const struct hip_common *common,
		struct tuple *tuple);
struct esp_tuple * esp_prot_conntrack_R2_esp_tuple(SList *other_dir_esps);
int esp_prot_conntrack_R2_anchor(const struct hip_common *common,
		struct tuple *tuple);
int esp_prot_conntrack_update(const hip_common_t *update, struct tuple * tuple);
int esp_prot_conntrack_cache_anchor(struct tuple * tuple, struct hip_seq *seq,
		struct esp_prot_anchor *esp_anchor);
int esp_prot_conntrack_update_anchor(struct tuple *tuple, struct hip_ack *ack,
		struct hip_esp_info *esp_info);
int esp_prot_conntrack_verify(struct esp_tuple *esp_tuple, struct hip_esp *esp);




#endif /* ESP_PROT_CONNTRACK_H_ */
