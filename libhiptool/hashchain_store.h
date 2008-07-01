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

#include "hashchain.h"
#include "builder.h"

int hip_hchain_store_init(int* hchain_lengths, int lengths_count);
int hip_hchain_bexstore_set_item_length(int hchain_length);
int hip_hchain_store_fill(int num_new_items, int hchain_length, int hash_length);
int hip_hchain_bexstore_fill(int num_new_items, int hash_length);
int hip_hchain_stores_refill(int hash_length);
int hip_hchain_store_get_hchain(int hchain_length, hash_chain_t *stored_hchain);
int hip_hchain_bexstore_get_hchain(unsigned char *anchor, int hash_length,
		hash_chain_t *stored_hchain);
int hip_hchain_store_get_store(int hchain_length);
int hip_hchain_store_remaining(int hchain_length);
int create_bexstore_anchors_message(struct hip_common *msg, int hash_length);

#endif /* HASHCHAIN_STORE_H */
