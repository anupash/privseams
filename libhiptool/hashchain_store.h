/*
 * Lightweight HIP hash chain store
 * 
 * structs and functions to store hash chains
 *
 * Authors:
 * - Tobias Heer <heer@tobibox.de>
 *
 * Licence: GNU/GPL
 */
#ifndef HASHCHAIN_STORE_H
#define HASHCHAIN_STORE_H

#include "hashchain.h"

int hip_hchain_store_init(int* lengths, int lengths_count);
int hip_hchain_store_fill(int num_new_items, int item_length);
hash_chain_t *hip_hchain_store_get(int item_length);
int hip_hchain_store_remaining(int item_length);

#endif /* HASHCHAIN_STORE_H */
