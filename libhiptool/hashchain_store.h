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

/* IDs for all supported transforms
 *
 * NOTE: if you change these, make sure to also change the helper defines
 *       NUM_*
 */
#define SHA1_8_TRANSFORM		0
#define SHA1_16_TRANSFORM		1
#define SHA1_20_TRANSFORM		2
#define MD5_8_TRANSFORM			3
#define MD5_20_TRANSFORM		4

/* maps from the transform_id defined above to the hash-function id
 * and hash length id
 *
 * NOTE: this ensures, we don't use uninitialised
 *       (hash_function, hash_length)-combinations
 */
typedef struct hchain_transform
{
	int hash_func_id;
	int hash_length_id;
} hchain_transform_t;

// stores the mapping transform_id -> (function_id, hash_length_id)
hchain_transform_t hchain_transforms[NUM_TRANSFORMS];



// max amount of different hash-functions that can be stored
#define MAX_FUNCTIONS			5
// max amount of different hash lengths that can be stored
#define MAX_NUM_HASH_LENGTH		5
// this includes the BEX-item
#define MAX_NUM_HCHAIN_LENGTH	5
// max amount of hchains that can be stored per hchain_item
#define MAX_HCHAINS_PER_ITEM	10

typedef struct hchain_store
{
	/* amount of currently used hash-functions */
	int num_functions;
	/* amount of different hash_lengths per hash-function */
	int num_hash_length[MAX_FUNCTIONS];
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


int hip_hchain_store_init(int* hchain_lengths, int lengths_count);
int hip_hchain_bexstore_set_item_length(int hchain_length);
int hip_hchain_store_fill(int num_new_items, int hchain_length, int hash_length);
int hip_hchain_bexstore_fill(int num_new_items, int hash_length);
int hip_hchain_stores_refill(int hash_length);
hash_chain_t * hip_hchain_store_get_hchain(int hchain_length);
hash_chain_t * hip_hchain_bexstore_get_hchain(unsigned char *anchor, int hash_length);
int hip_hchain_store_get_store(int hchain_length);
int hip_hchain_store_remaining(int hchain_length);
struct hip_common *create_bexstore_anchors_message(int hash_length);

#endif /* HASHCHAIN_STORE_H */
