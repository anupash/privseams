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


// max amount of different hash-functions that can be stored
#define MAX_FUNCTIONS			5
// max amount of different hash lengths that can be stored
#define MAX_NUM_HASH_LENGTH		5
// this includes the BEX-item
#define MAX_NUM_HCHAIN_LENGTH	5
// max amount of hchains that can be stored per hchain_item
#define MAX_HCHAINS_PER_ITEM	5

// determines when to refill a store
#define ITEM_THRESHOLD 0.5


typedef struct hchain_store
{
	/* amount of currently used hash-functions */
	int num_functions;
	/* pointer to the hash-function used to create and verify the hchain
	 *
	 * @note params: (in_buffer, in_length, out_buffer)
	 * @note out_buffer should be size MAX_HASH_LENGTH */
	hash_funtion_t hash_functions[MAX_FUNCTIONS];
	/* amount of different hash_lengths per hash-function */
	int num_hash_length[MAX_FUNCTIONS];
	/* length of the hashes, of which the respective hchain items consist */
	int hash_length[MAX_FUNCTIONS][MAX_NUM_HASH_LENGTH];
	/* contains hchains and meta-information about how to process them */
	hchain_shelf_t hchain_shelves[MAX_FUNCTIONS][MAX_NUM_HASH_LENGTH];
} hchain_store_t;

typedef struct hchain_shelf
{
	/* number of different hchain lengths currently used for this
	 * (hash-function, hash_length)-combination */
	int num_hchain_length;
	/* the different hchain lengths */
	int hchain_length[MAX_NUM_HCHAIN_LENGTH];
	/* hchains with the respective length */
	hchain_item_t hchain_items[MAX_NUM_HCHAIN_LENGTH];
} hchain_shelf_t;

typedef struct hchain_item
{
	/* amount of currently used hchains */
	int num_hchains;
	/* the hchains themselves */
	hash_chain_t *hchains[MAX_HCHAINS_PER_ITEM];
} hchain_item_t;

int hcstore_init(hchain_store_t *hcstore);
int hcstore_register_function(hchain_store_t *hcstore, hash_function_t hash_function);
int hcstore_register_hash_length(hchain_store_t *hcstore, int function_id,
		int hash_length);
int hcstore_register_hchain_length(hchain_store_t *hcstore, int function_id,
		int hash_length_id, int hchain_length);
int hcstore_refill(hchain_store_t *hcstore);
hash_chain_t * hcstore_get_hchain(hchain_store_t *hcstore, int function_id,
		int hash_length_id, int hchain_length);
hash_chain_t * hcstore_get_hchain_by_anchor(hchain_store_t *hcstore, int function_id,
		int hash_length_id, unsigned char *anchor);
hash_function_t hcstore_get_hash_function(hchain_store_t *hcstore, int hash_function_id);
int hcstore_get_hash_length(hchain_store_t *hcstore, int hash_function_id,
		int hash_length_id);
void hcstore_uninit(hchain_store_t *hcstore);
struct hip_common *create_anchors_message(hchain_store_t *hcstore);


#if 0
int hip_hchain_store_init(int* hchain_lengths, int lengths_count);
int hip_hchain_bexstore_set_item_length(int hchain_length);
int hip_hchain_store_fill(int num_new_items, int hchain_length, int hash_length);
int hip_hchain_bexstore_fill(int num_new_items, int hash_length);
int hip_hchain_stores_refill(int hash_length);
hash_chain_t * hip_hchain_store_get_hchain(int hchain_length);
hash_chain_t * hip_hchain_bexstore_get_hchain(unsigned char *anchor, int hash_length);
int hip_hchain_store_get_store(int hchain_length);
int hip_hchain_store_remaining(int hchain_length);


#endif

#endif /* HASHCHAIN_STORE_H */
