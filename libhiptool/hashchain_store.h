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
#include "linkedlist.h"


// max amount of different hash-functions that can be stored
#define MAX_FUNCTIONS			5
// max amount of different hash lengths that can be stored
#define MAX_NUM_HASH_LENGTH		5
// this includes the BEX-item
#define MAX_NUM_HCHAIN_LENGTH	5
/* max amount of hchains that can be stored per hchain_item
 *
 * @note we are using a list here, so we might also use some other
 *       mechanism to stop the hcstore_refill() */
// TODO move this to esp_prot_api
#define MAX_HCHAINS_PER_ITEM	2

#if 0
#define MAX_HCHAINS_PER_ITEM	5
#endif

/* determines when to refill a store
 *
 * @note this is a reverse threshold -> 1 - never refill, 0 - always
 */
#define ITEM_THRESHOLD 1

typedef struct hchain_shelf
{
	/* number of different hchain lengths currently used for this
	 * (hash-function, hash_length)-combination */
	int num_hchain_lengths;
	/* the different hchain lengths */
	int hchain_lengths[MAX_NUM_HCHAIN_LENGTH];
	/* hchains with the respective hchain length */
	hip_ll_t hchains[MAX_NUM_HCHAIN_LENGTH];
} hchain_shelf_t;

typedef struct hchain_store
{
	/* amount of currently used hash-functions */
	int num_functions;
	/* pointer to the hash-function used to create and verify the hchain
	 *
	 * @note params: (in_buffer, in_length, out_buffer)
	 * @note out_buffer should be size MAX_HASH_LENGTH */
	hash_function_t hash_functions[MAX_FUNCTIONS];
	/* amount of different hash_lengths per hash-function */
	int num_hash_lengths[MAX_FUNCTIONS];
	/* length of the hashes, of which the respective hchain items consist */
	int hash_lengths[MAX_FUNCTIONS][MAX_NUM_HASH_LENGTH];
	/* contains hchains and meta-information about how to process them */
	hchain_shelf_t hchain_shelves[MAX_FUNCTIONS][MAX_NUM_HASH_LENGTH];
} hchain_store_t;


int hcstore_init(hchain_store_t *hcstore);
void hcstore_uninit(hchain_store_t *hcstore);
void hcstore_free_hchain(void *hchain);
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
hash_function_t hcstore_get_hash_function(hchain_store_t *hcstore, int function_id);
int hcstore_get_hash_length(hchain_store_t *hcstore, int function_id, int hash_length_id);

#endif /* HASHCHAIN_STORE_H */
