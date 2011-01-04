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
 * API for adding and verifying tokens to ESP data packets for the
 * different modes, in order to allow middleboxes to inspect and
 * verify the validity of ESP packets.
 *
 * @brief Provides API to token-based ESP protection for middleboxes
 *
 * @author Rene Hummen <rene.hummen@rwth-aachen.de>
 */

#ifndef HIP_FIREWALL_ESP_PROT_API_H
#define HIP_FIREWALL_ESP_PROT_API_H

#include <stdint.h>

#include "lib/core/hashchain.h"
#include "user_ipsec_sadb.h"

/* maps from the transform_id defined above to the hash-function id
 * and hash length id
 *
 * NOTE: this ensures, we don't use uninitialized
 *       (hash_function, hash_length)-combinations in the array
 */
struct esp_prot_tfm {
    int is_used;     /* indicates if the transform is configured */
    int hash_func_id;     /* index of the hash function used by the transform */
    int hash_length_id;     /* index of the hash length used by the transform */
};


extern int token_transform;
extern int num_parallel_hchains;
extern int ring_buffer_size;
extern int num_linear_elements;
extern int num_random_elements;
extern int hash_length_g;
extern int hash_structure_length;
extern int num_hchains_per_item;
extern int num_hierarchies;
extern double refill_threshold;
extern double update_threshold;

extern int hash_lengths[NUM_HASH_FUNCTIONS][NUM_HASH_LENGTHS];
extern hash_function hash_functions[NUM_HASH_FUNCTIONS];

int esp_prot_init(void);
int esp_prot_uninit(void);
int esp_prot_sa_entry_set(hip_sa_entry_t *entry,
                          const uint8_t esp_prot_transform,
                          const uint32_t hash_item_length,
                          const uint16_t esp_num_anchors,
                          unsigned char (*esp_prot_anchors)[MAX_HASH_LENGTH],
                          const int update);
void esp_prot_sa_entry_free(hip_sa_entry_t *entry);
int esp_prot_cache_packet_hash(unsigned char *esp_packet,
                               const uint16_t esp_length,
                               hip_sa_entry_t *entry);
int esp_prot_add_hash(unsigned char *esp_packet,
                      int *out_length,
                      hip_sa_entry_t *entry);
int esp_prot_verify_hchain_element(const hash_function hash_function,
                                   const int hash_length,
                                   unsigned char *active_anchor,
                                   const unsigned char *next_anchor,
                                   const unsigned char *hash_value,
                                   const int tolerance,
                                   const unsigned char *active_root,
                                   const int active_root_length,
                                   const unsigned char *next_root,
                                   const int next_root_length);
int esp_prot_verify_htree_element(const hash_function hash_function,
                                  const int hash_length,
                                  const uint32_t hash_tree_depth,
                                  const unsigned char *active_root,
                                  const unsigned char *next_root,
                                  const unsigned char *active_uroot,
                                  const int active_uroot_length,
                                  const unsigned char *next_uroot,
                                  const int next_uroot_length,
                                  const unsigned char *hash_value);
struct esp_prot_tfm *esp_prot_resolve_transform(const uint8_t transform);
int esp_prot_get_hash_length(const uint8_t transform);
int esp_prot_get_data_offset(const hip_sa_entry_t *entry);
int esp_prot_sadb_maintenance(hip_sa_entry_t *entry);

#endif /* HIP_FIREWALL_ESP_PROT_API_H */
