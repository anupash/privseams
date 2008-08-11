/*
 * esp_prot_msg.h
 *
 *  Created on: Jul 20, 2008
 *      Author: Rene Hummen <rene.hummen@rwth-aachen.de>
 */

#ifndef ESP_PROT_FW_MSG_H_
#define ESP_PROT_FW_MSG_H_

#include <inttypes.h>
#include "builder.h"
#include "hashchain_store.h"
#include "user_ipsec_sadb.h"
#include "conntrack.h"

int send_esp_prot_to_hipd(int active);
int send_bex_store_update_to_hipd(hchain_store_t *hcstore);
hip_common_t *create_bex_store_update_msg(hchain_store_t *hcstore);
int send_trigger_update_to_hipd(hip_sa_entry_t *entry);
int send_anchor_change_to_hipd(hip_sa_entry_t *entry);
unsigned char * esp_prot_handle_sa_add_request(struct hip_common *msg,
		uint8_t *esp_prot_transform);
int esp_prot_conntrack_R1_tfms(struct hip_common * common, const struct tuple * tuple);
int esp_prot_conntrack_I2_anchor(const struct hip_common * common,
		struct tuple * tuple);
struct esp_tuple * esp_prot_conntrack_R2_esp_tuple(SList *other_dir_esps);
int esp_prot_conntrack_R2_anchor(const struct hip_common * common,
		struct tuple * tuple);
int esp_prot_conntrack_update_anchor(const hip_common_t * update, struct tuple * tuple);
int esp_prot_conntrack_update_esp_info(const hip_common_t *update,
		struct tuple * other_dir_tuple);

#endif /* ESP_PROT_FW_MSG_H_ */
