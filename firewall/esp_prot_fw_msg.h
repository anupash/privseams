/**
 * @file firewall/esp_prot_fw_msg.h
 *
 * <LICENSE TEMLPATE LINE - LEAVE THIS LINE INTACT>
 *
 * API for the communication with the hipd.
 *
 * @brief TPA and HHL-specific inter-process communication with the hipd
 *
 * @author Rene Hummen <rene.hummen@rwth-aachen.de>
 *
 */

#ifndef ESP_PROT_FW_MSG_H_
#define ESP_PROT_FW_MSG_H_

#include "lib/core/hashchain_store.h"
#include "user_ipsec_sadb.h"
#include "lib/core/protodefs.h"

int send_esp_prot_to_hipd(const int active);
int send_bex_store_update_to_hipd(hchain_store_t *hcstore,
                       const int use_hash_trees);
int send_trigger_update_to_hipd(const hip_sa_entry_t *entry,
                       const unsigned char *anchors[MAX_NUM_PARALLEL_HCHAINS],
                       const int hash_item_length,
                       const int soft_update,
                       const int *anchor_offset,
                       hash_tree_t *link_trees[MAX_NUM_PARALLEL_HCHAINS]);
int send_anchor_change_to_hipd(const hip_sa_entry_t *entry);
int esp_prot_handle_sa_add_request(const struct hip_common *msg,
                       uint8_t *esp_prot_transform,
                       uint16_t *num_anchors,
                       unsigned char (*esp_prot_anchors)[MAX_HASH_LENGTH],
                       uint32_t *hash_item_length);

#endif /* ESP_PROT_FW_MSG_H_ */
