/*
*  Hash chain functions for packet authentication and
*  packet signatures
*
* Description:
* 
*
* Authors: 
*   - Tobias Heer <heer@tobobox.de> 2006
* 	- Rene Hummen <rene.hummen@rwth-aachen.de> 2008 (see UPDATE)
*  * Licence: GNU/GPL
*
*/

/* UPDATE: store with offset 0 is a special store with hash-chains
 * only for BEX and is shared with the hipd.
 * it is treated seperately to make sure that firewall and hipd
 * are in sync.
 * 
 * the hash length can be specified now. however we only support one
 * single length for all items at the moment */

#include "hashchain_store.h"
#include <stdlib.h>			// malloc & co
#include <string.h>			// memcpy
#include "debug.h"
#include "ife.h"

#define hchain_store_lock() {}
#define hchain_store_unlock() {}

#define MAX_STORE_COUNT 10
#define STORE_THRESHOLD 0.5

/* these structs and typedefs are just for internal use.
   they shouldn't be accessed directly */
typedef struct hip_hchain_storage    hip_hchain_storage_t;
typedef struct hip_hchain_store_item hip_hchain_store_item_t;

/* a struct which holds a number of hash chains of different lengths.
   the hash chains are stored in different stores. Every store stores
   hash chains with the same legth. The number of available hash chains
   per store is indicated by store_count */
struct hip_hchain_storage
{
	/* the number of different hash chain lengths */
	int	num_stores;
	
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
int hip_hchain_store_init(int* hchain_lengths, int lengths_count)
{
	int err = 0, i;
	int num_stores = 0;
	
	HIP_DEBUG("Initialize hash chain storage for %d chain lengths.\n", lengths_count);
	for(i = 0; i < lengths_count; i++){
		HIP_DEBUG("Store %d: %d\n", i + 1, hchain_lengths[i]);	
	}
	
	// + BEX_STORE
	num_stores = lengths_count + 1;
	
	hip_hchain_storage.num_stores = num_stores;
	
	HIP_IFEL(!(hip_hchain_storage.store_hchain_length =
		(int *)malloc(num_stores * sizeof(int))), -1,
		"Can't allocate memory for hchain storage.\n");

	// set BEX_STORE hchain length to 0
	memset(hip_hchain_storage.store_hchain_length, 0, sizeof(int));
	// ...and copy for the rest
	memcpy(hip_hchain_storage.store_hchain_length + 1, hchain_lengths,
			lengths_count * sizeof(int));

	/* right now each store has 0 hash chains */
	HIP_IFEL(!(hip_hchain_storage.store_count =
		(int *)malloc(num_stores * sizeof(int))), -1,
		"Can't allocate memory for hchain storage.\n");
	memset(hip_hchain_storage.store_count, 0, num_stores * sizeof(int));

	/* set pointers to first element of each store to 0/NULL */
	HIP_IFEL(!(hip_hchain_storage.hchain_store = (hip_hchain_store_item_t **)
		malloc(num_stores * sizeof(hip_hchain_store_item_t *))), -1,
		"Can't allocate memory for hchain storage.\n");
	memset(hip_hchain_storage.hchain_store, 0,
			num_stores * sizeof(hip_hchain_store_item_t *));

out_err:
	return err;
}

int hip_hchain_bexstore_set_item_length(int hchain_length)
{
	int err = 0;
	
	hip_hchain_storage.store_hchain_length[0] = hchain_length;
	
	return err;
}

/**
 * hip_hchain_store_fill - fill up the store with hash chains of length
 * @item_length. @num_new_items new hash chains will be created and put to
 * the appropriate store.
 * @num_new_items: number of hash chains to be created
 * @item_length: length of the new hash chains
 * @return: zero on success, negative values on failure
**/
int hip_hchain_store_fill(int num_new_items, int hchain_length, int hash_length)
{
	int store = 0, err = 0, i;
	int remaining_hchains = 0;
	hip_hchain_store_item_t *new_store_item = NULL;
	
	/* find the appropriate store */
	HIP_IFEL((store = hip_hchain_store_get_store(hchain_length) == -1), -1,
		"No store found for length %d\n", hchain_length);
	
	// make sure that store is does not contain more than MAX_STORE_COUNT items
	remaining_hchains = hip_hchain_store_remaining(hchain_length);
	if (remaining_hchains + num_new_items > MAX_STORE_COUNT)
		num_new_items = MAX_STORE_COUNT - remaining_hchains;
	
	hchain_store_lock()
	
	/* create num_new_items new hash chains and add them to the store */
	for(i = 0; i < num_new_items; i++){
		
		HIP_IFEL(!(new_store_item = (hip_hchain_store_item_t *)
				malloc(sizeof(hip_hchain_store_item_t))), -1,
			"Not enough memory to fill hash chain storage.\n");
		
		HIP_IFEL(hchain_create(hchain_length, hash_length, new_store_item->hchain), -1,
				"failed to create new hash-chain\n");
		HIP_DEBUG("Stored new item of length: %d\n", hchain_length);
		// hchain_print(new_store_item->hchain, hash_length);
		
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

/**
 * hip_hchain_bexstore_fill - fill up the store with hash chains of length
 * @item_length. @num_new_items new hash chains will be created and put to
 * the appropriate store.
 * @num_new_items: number of hash chains to be created
 * @item_length: length of the new hash chains
 * @return: count if inserts on success, negative values on failure
**/
int hip_hchain_bexstore_fill(int num_new_items, int hash_length)
{
	int err = 0, i;
	int hchain_length = 0;
	int remaining_hchains = 0;
	hip_hchain_store_item_t *new_store_item = NULL;
	
	// make sure that store is does not contain more than MAX_STORE_COUNT items
	remaining_hchains = hip_hchain_storage.store_count[0];
	if (remaining_hchains + num_new_items > MAX_STORE_COUNT)
		num_new_items = MAX_STORE_COUNT - remaining_hchains;
	
	hchain_length = hip_hchain_storage.store_hchain_length[0];
	
	// set positive value here, may be overwritten on error
	err = num_new_items;
	
	hchain_store_lock()
	
	/* create num_new_items new hash chains and add them to the store */
	for(i = 0; i < num_new_items; i++){
		
		HIP_IFEL(!(new_store_item = (hip_hchain_store_item_t *)
				malloc(sizeof(hip_hchain_store_item_t))), -1,
			"Not enough memory to fill hash chain storage.\n");
		
		HIP_IFEL(hchain_create(hchain_length, hash_length, new_store_item->hchain), -1,
				"failed to create new hash-chain");
		HIP_DEBUG("Stored new item of length: %d\n", hchain_length);
		// hchain_print(new_store_item->hchain, hash_length);
		
		// add new item to list
		new_store_item->previous = NULL;
		new_store_item->next = hip_hchain_storage.hchain_store[0];
		new_store_item->next->previous = new_store_item;
		hip_hchain_storage.hchain_store[0] = new_store_item;
		hip_hchain_storage.store_count[0]++;
	}
	
out_err:
	hchain_store_unlock()

	return err;
}

/* refills all stores to MAX_STORE_COUNT */
int hip_hchain_stores_refill(int hash_length)
{
	int err = 0, bex_store_update = 0, i;
	int remaining_hchains = 0;
	int hchain_length = 0;
	
	for (i = 0; i < hip_hchain_storage.num_stores; i++)
	{
		if (i != 0)
		{
			hchain_length = hip_hchain_storage.store_hchain_length[i];
			
			remaining_hchains = hip_hchain_store_remaining(hchain_length);
			if (remaining_hchains < MAX_STORE_COUNT * STORE_THRESHOLD)
				err = hip_hchain_store_fill(MAX_STORE_COUNT - remaining_hchains,
						hchain_length, hash_length);
			
		} else
		{
			remaining_hchains = hip_hchain_storage.store_count[0];
			if (remaining_hchains < MAX_STORE_COUNT * STORE_THRESHOLD)
				bex_store_update = hip_hchain_bexstore_fill(MAX_STORE_COUNT - remaining_hchains,
						hash_length);
		}
	}
	
	// if no error occured and the bex store was updated, we have to tell that to hipd
	if (err == 0)
		err = bex_store_update;

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
int hip_hchain_store_get_hchain(int hchain_length, hash_chain_t *stored_hchain)
{
	int store = 0, err = 0;
	hip_hchain_store_item_t *stored_item = NULL;
	stored_hchain = NULL;
	
	/* find the appropriate store */
	store = hip_hchain_store_get_store(hchain_length);
	
	hchain_store_lock();
	
	// make sure the store cointains sth to return
	if(store >= 1 && hip_hchain_storage.store_count[store] > 0)
	{
		HIP_DEBUG("Taking hash chain from the store\n");
		/* we have enough items of the selected length in the store */
		stored_item = hip_hchain_storage.hchain_store[store];
		stored_hchain = stored_item->hchain;
		
		// some clean-up
		hip_hchain_storage.hchain_store[store] = stored_item->next;
		hip_hchain_storage.hchain_store[store]->previous = NULL;
		free(stored_item);
		hip_hchain_storage.store_count[store]--;
		//hchain_print(stored_hchain);
	} else
	{
	 	HIP_DEBUG("No stored hash chains of length %d in storage.\n", hchain_length);
	 	err = -1;
	}
	
  out_err:
	hchain_store_unlock();
	
	return err;
}

int hip_hchain_bexstore_get_hchain(unsigned char *anchor, int hash_length,
		hash_chain_t *stored_hchain)
{
	int i, err = 0;
	hip_hchain_store_item_t *stored_item = NULL;
	int remaining_hchains = 0;
	stored_hchain = NULL;
	
	hchain_store_lock();
	
	// walk through the bex store looking for the correct hash-chain
	remaining_hchains = hip_hchain_storage.store_count[0];
	stored_item = hip_hchain_storage.hchain_store[0];
	for (i = 0; i < remaining_hchains; i++)
	{
		// compare passed anchor to anchor element of each hchain in the bex store
		if (!memcmp(stored_item->hchain->anchor_element->hash, anchor, hash_length))
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
				// we are the first element, but there are more
				stored_item->next->previous = NULL;
				hip_hchain_storage.hchain_store[0] = stored_item->next;
				
			} else if (stored_item->previous && !(stored_item->next))
			{
				// this is the last element, but there are more
				stored_item->previous->next = NULL;
				
			} else
			{
				// we are the only element
				hip_hchain_storage.hchain_store[0] = NULL;
			}
			free(stored_item);
			hip_hchain_storage.store_count[0]--;
			//hchain_print(stored_hchain, hash_length);

			goto out_err;
		}
		
		stored_item = stored_item->next;
	}
	
	HIP_DEBUG("No stored hash chain with requested anchor in bex store.\n");
	err = -1;

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
int hip_hchain_store_get_store(int hchain_length)
{
	// assume no store found
	int i, err = -1;

	/* check all stores for the given length excluding the BEX_STORE */
	for(i = 1; i < hip_hchain_storage.num_stores; i++)
	{
		if(hip_hchain_storage.store_hchain_length[i] == hchain_length){
			/* we found a matching store - return the index */
			err = i;
			break;
		}
	}

  out_err:
	return err;
}

/**
 * hip_hchain_store_remaining - return the number of hash chains
 * of length @item_length which are stored in the hash chain storage.
 * @item_length: length of the hash chains which need to be checked
 * @return: number of remaining hash chains of length @item_length or -1 if
 *          there is no store for hash chains of length @item_length
**/
int hip_hchain_store_remaining(int hchain_length)
{
	int err = 0;
	int store = 0;
	
	store = hip_hchain_store_get_store(hchain_length);
	if (store < 0)
	{
		HIP_ERROR("No store found for length %d\n", hchain_length);
		err = -1;
	} else
	{
		_HIP_DEBUG("Store: %d\n", hchain_length);
		err = hip_hchain_storage.store_count[store];
	}
	
  out_err:
	return err;
}

int create_bexstore_anchors_message(struct hip_common *msg, int hash_length)
{
	hip_hchain_store_item_t *stored_item = NULL;
	unsigned char *anchor = NULL;
	int err = 0;
	
	HIP_IFEL(!(msg = HIP_MALLOC(HIP_MAX_PACKET, 0)), -1,
		 "alloc memory for adding sa entry\n");
	
	hip_msg_init(msg);
	
	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_IPSEC_UPDATE_ANCHOR_LIST, 0), -1, 
		 "build hdr failed\n");
	
	stored_item = hip_hchain_storage.hchain_store[0];
	// make sure there are some anchors to send
	if (stored_item)
	{
		HIP_DEBUG("adding anchors to message...\n");
		
		do
		{
			anchor = stored_item->hchain->anchor_element->hash;
			
			HIP_HEXDUMP("anchor: ", anchor, hash_length);
			HIP_IFEL(hip_build_param_contents(msg, (void *)anchor,
					HIP_PARAM_HCHAIN_ANCHOR, hash_length),
					-1, "build param contents failed\n");
			
		} while(stored_item = stored_item->next);
		
	} else
	{
		HIP_ERROR("bex store anchor message issued, but no anchors\n");
		
		err = 1;
		goto out_err;
	}	
	
  out_err:
  	return err;
}
