/*
 * Copyright (c) 2010 Aalto University and RWTH Aachen University.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

/**
 * @file
 * API for the communication with the hipd.
 *
 * @brief TPA and HHL-specific inter-process communication with the hipd
 *
 * @author Rene Hummen <rene.hummen@rwth-aachen.de>
 */

#ifndef HIP_FIREWALL_ESP_PROT_FW_MSG_H
#define HIP_FIREWALL_ESP_PROT_FW_MSG_H

#include <stdint.h>

#include "lib/core/hashchain_store.h"
#include "lib/core/hashtree.h"
#include "lib/core/protodefs.h"
#include "user_ipsec_sadb.h"

int send_esp_prot_to_hipd(const int active);
int send_bex_store_update_to_hipd(struct hchain_store *hcstore,
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

#endif /* HIP_FIREWALL_ESP_PROT_FW_MSG_H */
