/*
*  Hash chain functions for packet authentication and
*  packet signatures
*
* Description:
* 
*
* Authors: 
*   - Tobias Heer <heer@tobobox.de> 2006
*  * Licence: GNU/GPL
*
*/

#include "hashchain_store.h"
#include <stdlib.h>			// malloc & co
#include <string.h>			// memcpy
#include "debug.h"
#include "ife.h"

#define hchain_store_lock() {}
#define hchain_store_unlock() {}
// offset of store holding hchains used for BEX
#define MAX_STORE_COUNT 10
#define STORE_THRESHOLD 0.5

/* these structs and typedefs are just for internal use.
   they shouldn't be accessed directly */
typedef struct hip_hchain_storage    hip_hchain_storage_t;
typedef struct hip_hchain_store_item hip_hchain_store_item_t;
typedef struct hip_hchain_anchor_list hip_hchain_anchor_list_t;

/* a struct which holds a number of hash chains of different lengths.
   the hash chains are stored in different stores. Every store stores
   hash chains with the same legth. The number of available hash chains
   per store is indicated by store_count */
struct hip_hchain_storage
{
	/* the number of different hash chain lengths */
	int	num_stores;
	
	/* holds hchains shared with hipd and used during BEX,
	 * treated specially to make sure that is in sync with hipd */
	int bex_store;
	
	/* the length for the respective hash chain store (array) */
	int *store_hchain_length;
	
	/* the number of hash chains for each store (array) */
	int	*store_count;
	
	/* the hash chain stores (array of pointers to store items) */
	struct hip_hchain_store_item **hchain_store;
	
};

/* each item contains a pointer to the next item in the store
 * and a hash chain */
struct hip_hchain_store_item
{
	struct hip_hchain_store_item *previous;
	struct hip_hchain_store_item *next;
	hash_chain_t *hchain;		
};




/* globally defined. There is only one storage per execution instance*/
hip_hchain_storage_t hip_hchain_storage;




/** 
 * hip_hchain_store_init - allocate memory for the hash chain store.
 * The hash chain store will provide @lengths_count hash chain storage
 * slots for hash chains of length given by @lengths.
 * @lengths: array of integers which defines lengths for each hash chain
 * @lengths_count: number of entries in lengths
 * @return: zero on success, negative values on failure
**/
int hip_hchain_store_init(int* lengths, int lengths_count, int bex_store){
	int err = 0, i;
	
	HIP_DEBUG("Initialize hash chain storage for %d chain lengths.\n", lengths_count);
	for(i = 0; i < lengths_count; i++){
		HIP_DEBUG("Store %d: %d\n", i, lengths[i]);	
	}
	
	hip_hchain_storage.num_stores = lengths_count;
	hip_hchain_storage.bex_store = bex_store;
	
	/* allocate memory for the variable fields and copy */
	HIP_IFEL(!(hip_hchain_storage.store_hchain_length =
		(int *)malloc(lengths_count * sizeof(int))), -1,
		"Can't allocate memory for hchain storage.\n");
	memcpy(hip_hchain_storage.store_hchain_length, lengths, lengths_count * sizeof(int));	

	/* right now each store has 0 hash chains */
	HIP_IFEL(!(hip_hchain_storage.store_count =
		(int *)malloc(lengths_count * sizeof(int))), -1,
		"Can't allocate memory for hchain storage.\n");
	memset(hip_hchain_storage.store_count, 0, lengths_count * sizeof(int));

	/* set pointers to first element of each store to 0/NULL */
	HIP_IFEL(!(hip_hchain_storage.hchain_store = (hip_hchain_store_item_t **)
		malloc(lengths_count * sizeof(hip_hchain_store_item_t *))), -1,
		"Can't allocate memory for hchain storage.\n");
	memset(hip_hchain_storage.hchain_store, 0,
			lengths_count * sizeof(hip_hchain_store_item_t *));

out_err:
	return err;
}

int hip_hchain_store_fill_by_offset(int num_new_items, int store_offset)
{
	return hip_hchain_store_fill_by_length(num_new_items,
			hip_hchain_storage.store_hchain_length[store_offset]);
}

/**
 * hip_hchain_store_fill - fill up the store with hash chains of length
 * @item_length. @num_new_items new hash chains will be created and put to
 * the appropriate store.
 * @num_new_items: number of hash chains to be created
 * @item_length: length of the new hash chains
 * @return: zero on success, negative values on failure and 1 if bex_store was updated
**/
int hip_hchain_store_fill_by_length(int num_new_items, int item_length){
	
	int store = 0, err = 0, i;
	int remaining_items = 0;
	hip_hchain_store_item_t *new_store_item = NULL;
	
	// make sure that store is does not contain more than MAX_STORE_COUNT items
	remaining_items = hip_hchain_store_remaining(item_length);
	if (remaining_items + num_new_items > MAX_STORE_COUNT)
		num_new_items = MAX_STORE_COUNT - remaining_items;
	
	/* find the appropriate store */
	HIP_IFEL((store = hip_hchain_store_get_store(item_length) == -1), -1,
		"No store found for length %d\n", item_length);
	
	if (num_new_items > 0 && store == hip_hchain_storage.bex_store)
		err = 1;
	
	hchain_store_lock()
	
	/* create num_new_items new hash chains and add them to the store */
	for(i = 0; i < num_new_items; i++){
		
		HIP_IFEL(!(new_store_item = (hip_hchain_store_item_t *)
				malloc(sizeof(hip_hchain_store_item_t))), -1,
			"Not enough memory to fill hash chain storage.\n");
		
		new_store_item->hchain = hchain_create(item_length);
		HIP_DEBUG("Stored new item of length: %d\n", item_length);
		// hchain_print(new_store_item->hchain);
		
		// add new item to list
		new_store_item->previous = NULL;
		new_store_item->next = hip_hchain_storage.hchain_store[store];
		new_store_item->next->previous = new_store_item;
		hip_hchain_storage.hchain_store[store] = new_store_item;
		hip_hchain_storage.store_count[store]++;
	}
	
out_err:
	hchain_store_unlock()

	return err;
}

/* refills all stores to MAX_STORE_COUNT */
int hip_hchain_stores_refill(void)
{
	int err = 0, i;
	int remaining_items = 0;
	int item_length = 0;
	
	for (i = 0; i < hip_hchain_storage.num_stores; i++)
	{
		item_length = hip_hchain_storage.store_hchain_length[i];
		
		remaining_items = hip_hchain_store_remaining(item_length);
		if (remaining_items < MAX_STORE_COUNT * STORE_THRESHOLD)
			err = hip_hchain_store_fill(MAX_STORE_COUNT - remaining_items, item_length);
	}
	
	// TODO refill bex store

  out_err:
	return err;
}

/**
 * hip_hchain_store_get - get a hash chain from the store.
 * a pointer to a new hash chain will be returned, This pointer will
 * be taken from the store if hash chains with the desired length are
 * present. Otherwise a new hash chain will be created.
 * @item_length: length of the desired hash chain
 * @return pointer to a hash chain of length @item_length, NULL on error
**/
int hip_hchain_store_get_hchain(int item_length, hash_chain_t *stored_hchain){

	int store = 0, err = 0;
	hip_hchain_store_item_t *stored_item = NULL;
	stored_hchain = NULL;
	
	/* find the appropriate store */
	store = hip_hchain_store_get_store(item_length);
	
	hchain_store_lock();
	if(store >= 0 && hip_hchain_storage.store_count[store] > 0){
		HIP_DEBUG("Taking hash chain from the store:\n");
		/* we have enough items of the selected length in the store */
		stored_item = hip_hchain_storage.hchain_store[store];
		stored_hchain = stored_item->hchain;
		hip_hchain_storage.hchain_store[store] = stored_item->next;
		free(stored_item);
		hip_hchain_storage.store_count[store]--;
		hchain_print(stored_hchain);
		return stored_hchain;
	}
	
	// TODO delete from avail list
	hchain_store_unlock();
	
 	HIP_DEBUG("No stored hash chains of length %d. Creating new hash chain.\n", item_length);
	/* we don't have items of the selected length left */
	return hchain_create(item_length);
}

int hip_hchain_bexstore_get_hchain(unsigned char *anchor, hash_chain_t *stored_hchain)
{
	int err = -1;
	hip_hchain_store_item_t *stored_item = NULL;
	stored_hchain = NULL;
	
	hchain_store_lock();
	
	// walk through the bex store looking for the correct hash
	stored_item = hip_hchain_storage->hchain_store[hip_hchain_storage.bex_store];
	while (stored_item)
	{
		if (!memcmp(stored_item->hchain->anchor_element, anchor,
				hip_hchain_storage->store_hchain_length[hip_hchain_storage.bex_store]))
		{
			HIP_DEBUG("Taking hash chain from the BEX store\n");
			stored_hchain = stored_item->hchain;
			
			// clean up the list
			if (stored_item->previous && stored_item->next)
			{
				// we are somewhere in the middle
				stored_item->next->previous = stored_item->previous;
				stored_item->previous->next = stored_item->next;
				
			} else if (!(stored_item->previous) && stored_item->next)
			{
				// this is the first element, but there are more
				stored_item->next->previous = NULL;
				hip_hchain_storage->hchain_store[hip_hchain_storage.bex_store] = stored_item->next;
				
			} else if (stored_item->previous && !(stored_item->next))
			{
				// this is the last element, but there are more
				stored_item->previous->next = NULL;
				
			} else
			{
				// we are the only element
				hip_hchain_storage->hchain_store[hip_hchain_storage.bex_store] = NULL;
			}
			free(stored_item);
			hip_hchain_storage.store_count[hip_hchain_storage.bex_store]--;
			hchain_print(stored_hchain);

			err = 0;
			break;
		} else
		{
			stored_item = stored_item->next;
		}
	}

  out_err:
	hchain_store_unlock();
  
  	return err;
}

/**
 * hip_hchain_store_get_store - get the index of store for hash chains
 * of length @item_lengt.
 * @item_length: the length of the hash chains for which the store index should be retrieved
 * @return: the index of the matching store, -1 if no matching store was found
**/

int hip_hchain_store_get_store(int item_length){
	int i;

	/* check all stores for the given length */
	for(i = 0; i < hip_hchain_storage.num_stores; i++){
		if(hip_hchain_storage.store_hchain_length[i] == item_length){
			/* we found a matching store - return the index */
			return i;
		}
	}
	/* no store with the given length found */
	return -1;
}

/**
 * hip_hchain_store_remaining - return the number of hash chains
 * of length @item_length which are stored in the hash chain storage.
 * @item_length: length of the hash chains which need to be checked
 * @return: number of remaining hash chains of length @item_length or -1 if
 *          there is no store for hash chains of length @item_length
**/
int hip_hchain_store_remaining(int item_length){
	int err = 0;
	int store = 0;
	
	HIP_IFEL((store = hip_hchain_store_get_store(item_length)) == -1, -1,
		"No store found for length %d\n", item_length);
	_HIP_DEBUG("Store: %d\n", item_length);
	
	return hip_hchain_storage.store_count[store];
	
out_err:
	return err;
}

int create_message_bexstore_anchors()
{
	
}
