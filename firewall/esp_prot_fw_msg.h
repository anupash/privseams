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

int send_esp_prot_to_hipd(int active);
int send_bex_store_update_to_hipd(hchain_store_t *hcstore, int use_hash_trees);
hip_common_t *create_bex_store_update_msg(hchain_store_t *hcstore, int use_hash_trees);
int send_trigger_update_to_hipd(hip_sa_entry_t *entry, int soft_update,
		int anchor_offset, unsigned char *secret, int secret_length,
		unsigned char *branch_nodes, int branch_length, unsigned char * root,
		int root_length);
int send_anchor_change_to_hipd(hip_sa_entry_t *entry);
unsigned char * esp_prot_handle_sa_add_request(struct hip_common *msg,
		uint8_t *esp_prot_transform, uint32_t * hash_item_length);

#endif /* ESP_PROT_FW_MSG_H_ */
