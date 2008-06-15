/*
 * Lightweight HIP hash chain store
 * 
 * structs and functions to store hash chains
 *
 * Authors:
 * - Tobias Heer <heer@tobibox.de>
 * - René Hummen
 *
 * Licence: GNU/GPL
 */
#ifndef HASHCHAIN_STORE_H
#define HASHCHAIN_STORE_H

#include "builder.h"
#include "hashchain.h"

int hip_hchain_store_init(int* lengths, int lengths_count);
int hip_hchain_bexstore_set_item_length(int item_length);
int hip_hchain_store_fill(int num_new_items, int item_length);
int hip_hchain_bexstore_fill(int num_new_items);
int hip_hchain_stores_refill(void);
int hip_hchain_store_get_hchain(int item_length, hash_chain_t *stored_hchain);
int hip_hchain_bexstore_get_hchain(unsigned char *anchor, hash_chain_t *stored_hchain);
int hip_hchain_store_get_store(int item_length);
int hip_hchain_store_remaining(int item_length);
int create_bexstore_anchors_message(struct hip_common *msg);

#endif /* HASHCHAIN_STORE_H */
