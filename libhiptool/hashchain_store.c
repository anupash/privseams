/*
*  Hash chain functions for packet authentication and
*  packet signatures
*
* Description:
*
*
* Authors:
*   - Tobias Heer <heer@tobobox.de> 2006 (original hash-chain store)
* 	- Rene Hummen <rene.hummen@rwth-aachen.de> 2008 (extension and
* 	  complete reimplemtation)
*
*  * Licence: GNU/GPL
*/

#include "hashchain_store.h"

// sets all hash-chain store members and their dependencies to 0 / NULL
int hcstore_init(hchain_store_t *hcstore)
{
	int err = 0, i, j, g, h;

	HIP_ASSERT(hcstore != NULL);

	hcstore->num_functions = 0;

	for (i = 0; i < MAX_FUNCTIONS; i++)
	{
		hcstore->hash_functions[i] = NULL;
		hcstore->num_hash_length[i] = 0;

		for (j = 0; j < MAX_NUM_HASH_LENGTH; j++)
		{
			hcstore->hash_length[i][j] = 0;
			hcstore->hchain_shelves[i][j].num_hchain_length = 0;

			for (g = 0; g < MAX_NUM_HCHAIN_LENGTH; g++)
			{
				hcstore->hchain_shelves[i][j].hchain_length[g] = 0;
				hcstore->hchain_shelves[i][j].hchain_items[g].num_hchains = 0;

				for (h = 0; h < MAX_HCHAINS_PER_ITEM; h++)
				{
					hcstore->hchain_shelves[i][j].hchain_items[g].hchains[h] = NULL;
				}
			}

		}
	}

	HIP_DEBUG("hash-chain store initialized\n");

  out_err:
	return err;
}

/* >= 0 - function id in store
 * < 0 - store full
 */
int hcstore_register_function(hchain_store_t *hcstore, hash_function_t hash_function)
{
	int err = 0, i;

	HIP_ASSERT(hcstore != NULL);
	HIP_ASSERT(hash_function != NULL);

	// first check that there's still some space left
	HIP_IFEL(hcstore->num_functions == MAX_FUNCTIONS, -1,
			"space for function-storage is full\n");

	// also check if the function is already stored
	for (i = 0; i < hcstore->num_functions; i++)
	{
		if (hcstore->hash_functions[i] == hash_function)
		{
			HIP_DEBUG("hchain store already contains this function\n");

			err = i;
			goto out_err;
		}
	}

	// store the hash-function
	err = hcstore->num_functions;
	hcstore->hash_functions[hcstore->num_functions];
	hcstore->num_functions++;

	HIP_DEBUG("hash function successfully registered\n");

  out_err:
	return err;
}

/* >= 0 - hash_length id in store
 * < 0 - store full
 */
int hcstore_register_hash_length(hchain_store_t *hcstore, int function_id,
		int hash_length)
{
	int err = 0, i;

	HIP_ASSERT(hcstore != NULL);
	HIP_ASSERT(function_id >= 0 && function_id < hcstore->num_functions);
	HIP_ASSERT(hash_length > 0);

	// first check that there's still some space left
	HIP_IFEL(hcstore->num_hash_length[function_id] == MAX_NUM_HASH_LENGTH, -1,
			"space for hash_length-storage is full\n");

	// also check if the hash length is already stored for this function
	for (i = 0; i < hcstore->num_hash_length[function_id]; i++)
	{
		if (hcstore->hash_length[function_id][i] == hash_length)
		{
			HIP_DEBUG("hchain store already contains this hash length\n");

			err = i;
			goto out_err;
		}
	}

	// store the hash length
	err = hcstore->num_hash_length[function_id];
	hcstore->hash_length[function_id][hcstore->num_hash_length[function_id]] = hash_length;
	hcstore->num_hash_length[function_id]++;

	HIP_DEBUG("hash length successfully registered\n");

  out_err:
	return err;
}

/* >= 0 - hchain_length id in store
 * < 0 - store full
 */
int hcstore_register_hchain_length(hchain_store_t *hcstore, int function_id,
		int hash_length_id, int hchain_length)
{
	int err = 0, i;

	HIP_ASSERT(hcstore != NULL);
	HIP_ASSERT(function_id >= 0 && function_id < hcstore->num_functions);
	HIP_ASSERT(hash_length_id >= 0
			&& hash_length_id < hcstore->num_hash_length[function_id]);
	HIP_ASSERT(hchain_length > 0);

	// first check that there's still some space left
	HIP_IFEL(hcstore->hchain_shelves[function_id][hash_length_id].num_hchain_length
			== MAX_NUM_HCHAIN_LENGTH, -1, "space for hchain_length-storage is full\n");

	// also check if the hash length is already stored for this function
	for (i = 0; i < hcstore->hchain_shelves[function_id][hash_length_id].num_hchain_length;
			i++)
	{
		if (hcstore->hchain_shelves[function_id][hash_length_id].hchain_length[i]
			  == hchain_length)
		{
			HIP_DEBUG("hchain store already contains this hchain length\n");

			err = i;
			goto out_err;
		}
	}

	// store the hchain length
	err = hcstore->hchain_shelves[function_id][hash_length_id].num_hchain_length;
	hcstore->hchain_shelves[function_id][hash_length_id].hchain_length[hcstore->hchain_shelves[function_id][hash_length_id].num_hchain_length]
			  = hchain_length;
	hcstore->hchain_shelves[function_id][hash_length_id].num_hchain_length++;

	HIP_DEBUG("hchain length successfully registered\n");

  out_err:
	return err;
}

int hcstore_refill(hchain_store_t *hcstore)
{
	int hash_length, hchain_length, err = 0;
	hash_function_t hash_function = NULL;

	HIP_ASSERT(hcstore != NULL);

	/* go through the store setting up information neccessary for creating a new
	 * hchain in the respective item */
	for (i = 0; i < hcstore->num_functions; i++)
	{
		hash_function = hcstore->hash_functions[i];

		for (j = 0; j < hcstore->num_hash_length[i]; j++)
		{
			hash_length = hcstore->hash_length[i][j];

			for (g = 0; g < hcstore->hchain_shelves[i][j].num_hchain_length; g++)
			{
				hchain_length = hcstore->hchain_shelves[i][j].hchain_length[g];

				// how many hchains are missing to fill up the item again
				create_hchains = MAX_HCHAINS_PER_ITEM
					- hcstore->hchain_shelves[i][j].hchain_items[g].num_hchains;

				if (create_hchains >= ITEM_THRESHHOLD * MAX_HCHAINS_PER_ITEM)
				{
					// count the overall amount of created hchains
					err += create_hchains;

					for (h = 0; h < create_hchains; h++)
					{
						/* hchains are taken from the beginning of the array, so here
						 * we can safely put the new hchains in the first free slots */
						HIP_IFEL(!(hcstore->hchain_shelves[i][j].hchain_items[g].hchains[h]
							 = hchain_create(hash_function, hash_length, hchain_length)),
							 -1, "failed to create new hchain\n");
					}
				}
			}
		}
	}

	HIP_DEBUG("total amount of created hash-chains: %i\n", err);

  out_err:
	return err;
}

hash_chain_t * hcstore_get_hchain(hchain_store_t *hcstore, int function_id,
		int hash_length_id, int hchain_length)
{
	int err = 0, item_offset = 0, hchain_offset = 0, i;
	hash_chain_t *stored_hchain = NULL;

	HIP_ASSERT(hcstore != NULL);
	HIP_ASSERT(function_id >= 0 && function_id < hcstore->num_functions);
	HIP_ASSERT(hash_length_id >= 0
			&& hash_length_id < hcstore->num_hash_length[function_id]);
	HIP_ASSERT(hchain_length > 0);

	// first find the correct hchain item
	for (i = 0; i < hcstore->hchain_shelves[function_id][hash_length_id].num_hchain_length;
			i++)
	{
		if (hcstore->hchain_shelves[function_id][hash_length_id].hchain_length[i]
				== hchain_length)
		{
			found = 1;
			break;
		}
	}

	// handle unknow hchain length
	if (!item_offset)
	{
		HIP_DEBUG("hchain length not registered yet: %i\n", hchain_length);

		err = -1;
		goto out_err;
	}

	// calculate offset of next hchain with the requested length
	hchain_offset = MAX_HCHAINS_PER_ITEM
				- hcstore->hchain_shelves[function_id][hash_length_id].hchain_items[item_offset].num_hchains;

	stored_hchain = hcstore->hchain_shelves[function_id][hash_length_id].hchain_items[item_offset].hchains[hchain_offset];

	// remove this hchain from the store
	hcstore->hchain_shelves[function_id][hash_length_id].hchain_items[item_offset].hchains[hchain_offset] = NULL;

  out_err:
	if (err)
	{
		if (stored_hchain)
			hchain_free(stored_hchain);

		stored_hchain = NULL;
	}

	return stored_hchain;
}

hash_chain_t * hcstore_get_hchain_by_anchor(hchain_store_t *hcstore, int function_id,
		int hash_length_id, unsigned char *anchor)
{
	hash_chain_t *stored_hchain = NULL;
	int err = 0, i, j;

	HIP_ASSERT(hcstore != NULL);
	HIP_ASSERT(function_id >= 0 && function_id < hcstore->num_functions);
	HIP_ASSERT(hash_length_id >= 0
			&& hash_length_id < hcstore->num_hash_length[function_id]);
	HIP_ASSERT(anchor != NULL);

	for (i = 0; i < hcstore->hchain_shelves[function_id][hash_length_id].num_hchain_length;
			i++)
	{
		for (j = 0; j < hcstore->hchain_shelves[function_id][hash_length_id].hchain_items[i].num_hchains;
				j++)
		{
			if (!memcmp(anchor,
					hcstore->hchain_shelves[function_id][hash_length_id].hchain_items[i].hchains[j]->anchor_element.hash,
					hash_length))
			{
				stored_hchain = hcstore->hchain_shelves[function_id][hash_length_id].hchain_items[i].hchains[j];

				// remove this hchain from the store
				hcstore->hchain_shelves[function_id][hash_length_id].hchain_items[i].hchains[j] = NULL;

				HIP_ERROR("hash-chain matching the anchor found\n");
				HIP_HEXDUMP("anchor: ", anchor, hash_length);
				//hchain_print(stored_hchain);

				goto out_err;
			}
		}
	}

	HIP_ERROR("hash-chain matching the anchor NOT found\n");
	HIP_HEXDUMP("anchor: ", anchor, hash_length);
	err = -1;

  out_err:
	if (err)
	{
		if (stored_hchain)
			hchain_free(stored_hchain);

		stored_hchain = NULL;
	}

	return stored_hchain;
}

// this does the same as init but additionally destructs the hchains
void hcstore_uninit(hchain_store_t *hcstore)
{
	int err = 0, i, j, g, h;

	HIP_ASSERT(hcstore != NULL);

	hcstore->num_functions = 0;

	for (i = 0; i < MAX_FUNCTIONS; i++)
	{
		hcstore->hash_functions[i] = NULL;
		hcstore->num_hash_length[i] = 0;

		for (j = 0; j < MAX_NUM_HASH_LENGTH; j++)
		{
			hcstore->hash_length[i][j] = 0;
			hcstore->hchain_shelves[i][j].num_hchain_length = 0;

			for (g = 0; g < MAX_NUM_HCHAIN_LENGTH; g++)
			{
				hcstore->hchain_shelves[i][j].hchain_length[g] = 0;
				hcstore->hchain_shelves[i][j].hchain_items[g].num_hchains = 0;

				for (h = 0; h < MAX_HCHAINS_PER_ITEM; h++)
				{
					// free each hchain in the store
					hchain_free(hcstore->hchain_shelves[i][j].hchain_items[g].hchains[h]);
					hcstore->hchain_shelves[i][j].hchain_items[g].hchains[h] = NULL;
				}
			}

		}
	}

	HIP_DEBUG("hash-chain store uninitialized\n");
}

/* this will only consider the first hchain item in each shelf, as only
 * this should be set up for the store containing the hchains for the BEX */
struct hip_common *create_anchors_message(hchain_store_t *hcstore)
{
	struct hip_common *msg = NULL;
	hash_chain_t *bex_hchain = NULL;
	unsigned char *anchor = NULL;
	int err = 0, i, num_hchains = 0;

	HIP_ASSERT(hcstore != NULL);

	HIP_IFEL(!(msg = HIP_MALLOC(HIP_MAX_PACKET, 0)), -1,
		 "alloc memory for adding sa entry\n");

	hip_msg_init(msg);

	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_IPSEC_UPDATE_ANCHOR_LIST, 0), -1,
		 "build hdr failed\n");

	// make sure there are some anchors to send
	num_hchains = hip_ll_get_size(&hip_hchain_storage.hchain_store[0]);
	if (num_hchains > 0)
	{
		HIP_DEBUG("adding anchors to message...\n");

		for (i = 0; i < num_hchains; i++)
		{
			HIP_IFEL(!(bex_hchain = (hash_chain_t *)
					hip_ll_get(&hip_hchain_storage.hchain_store[0], i)), -1,
					"failed to get first hchain from bex store\n");

			//hchain_print(bex_hchain, hash_length);

			anchor = bex_hchain->anchor_element->hash;
			HIP_HEXDUMP("anchor: ", anchor, hash_length);

			HIP_IFEL(hip_build_param_contents(msg, (void *)anchor,
					HIP_PARAM_HCHAIN_ANCHOR, hash_length),
					-1, "build param contents failed\n");
		}
	} else
	{
		HIP_ERROR("bex store anchor message issued, but no anchors\n");

		err = 1;
		goto out_err;
	}

  out_err:
  	if (err)
  	{
  		free(msg);
  		msg = NULL;
  	}

  	return msg;
}






#if 0

#define hchain_store_lock() {}
#define hchain_store_unlock() {}

#define MAX_STORE_COUNT 10
#define STORE_THRESHOLD 0.5

/* these structs and typedefs are just for internal use.
   they shouldn't be accessed directly */
typedef struct hip_hchain_storage    hip_hchain_storage_t;

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

	/* the hash chain stores (array of lists storing the hashchains of
	 * the respective length) */
	hip_ll_t *hchain_store;
};

#if 0
struct hip_hchain_storage
{
	int num_hash_func;

	/* the number of different hash chain lengths */
	int	num_stores;

	/* the length for the respective hash chain store (array) */
	int *store_hchain_length;

	/* the hash chain stores (array of lists storing the hashchains of
	 * the respective length) */
	hip_ll_t *hchain_store;
};
#endif




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

	HIP_DEBUG("Initializing %i hash chain stores with following lengths:\n", lengths_count);

	// + BEX_STORE
	num_stores = lengths_count + 1;
	hip_hchain_storage.num_stores = num_stores;

	// allocate memory
	HIP_IFEL(!(hip_hchain_storage.store_hchain_length =
			(int *)malloc(num_stores * sizeof(int))), -1,
			"Can't allocate memory for hchain storage.\n");
	HIP_IFEL(!(hip_hchain_storage.hchain_store = (hip_ll_t *)
				malloc(num_stores * sizeof(hip_ll_t))), -1,
				"Can't allocate memory for hchain storage.\n");

	// set BEX_STORE hchain length to 0
	hip_hchain_storage.store_hchain_length[0] = 0;
	HIP_DEBUG("BEX Store (0): %i\n", hip_hchain_storage.store_hchain_length[0]);
	/* initialized the hchain list for this store */
	hip_ll_init(&hip_hchain_storage.hchain_store[0]);

	// ...and copy for the rest
	for(i = 0; i < lengths_count; i++)
	{
		hip_hchain_storage.store_hchain_length[i + 1] = hchain_lengths[i];
		HIP_DEBUG("Store %i: %i\n", i + 1, hip_hchain_storage.store_hchain_length[i + 1]);

		hip_ll_init(&hip_hchain_storage.hchain_store[i + 1]);
	}

  out_err:
	return err;
}

int hip_hchain_bexstore_set_item_length(int hchain_length)
{
	int err = 0;

	hip_hchain_storage.store_hchain_length[0] = hchain_length;
	HIP_DEBUG("bex store length: %i\n", hip_hchain_storage.store_hchain_length[0]);

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
	hash_chain_t *new_hchain = NULL;

	/* find the appropriate store */
	HIP_IFEL((store = hip_hchain_store_get_store(hchain_length)) <= 0, -1,
			"No store found for length %i\n", hchain_length);

	// make sure that store is does not contain more than MAX_STORE_COUNT items
	remaining_hchains = hip_ll_get_size(&hip_hchain_storage.hchain_store[store]);
	if (remaining_hchains + num_new_items > MAX_STORE_COUNT)
		num_new_items = MAX_STORE_COUNT - remaining_hchains;

	hchain_store_lock()

	/* create num_new_items new hash chains and add them to the store */
	for(i = 0; i < num_new_items; i++)
	{
		HIP_IFEL(!(new_hchain = hchain_create(hchain_length, hash_length)), -1,
				"failed to create new hash-chain\n");
		hchain_print(new_hchain, hash_length);
		HIP_IFEL(hchain_verify(new_hchain->source_element->hash,
				new_hchain->anchor_element->hash, hash_length, hchain_length) <= 0, -1,
				"failed to verify created hchain\n");
		HIP_DEBUG("hchain successfully verfied\n");

		HIP_IFEL(hip_ll_add_first(&hip_hchain_storage.hchain_store[store], new_hchain), -1,
				"failed to store new hchain in store\n");
		HIP_DEBUG("Stored new hchain of length: %i\n", hchain_length);
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
	hash_chain_t *new_hchain = NULL;

	// make sure that store is does not contain more than MAX_STORE_COUNT items
	remaining_hchains = hip_ll_get_size(&hip_hchain_storage.hchain_store[0]);
	if (remaining_hchains + num_new_items > MAX_STORE_COUNT)
		num_new_items = MAX_STORE_COUNT - remaining_hchains;

	hchain_length = hip_hchain_storage.store_hchain_length[0];

	// set positive value here, may be overwritten on error
	err = num_new_items;

	hchain_store_lock()

	/* create num_new_items new hash chains and add them to the store */
	for(i = 0; i < num_new_items; i++)
	{
		HIP_IFEL(!(new_hchain = hchain_create(hchain_length, hash_length)), -1,
				"failed to create new hash-chain\n");
		HIP_IFEL(hchain_verify(new_hchain->source_element->hash,
				new_hchain->anchor_element->hash, hash_length, hchain_length) <= 0, -1,
				"failed to verify created hchain\n");
		HIP_DEBUG("hchain successfully verfied\n");

		HIP_IFEL(hip_ll_add_first(&hip_hchain_storage.hchain_store[0], new_hchain), -1,
				"failed to store new hchain in store\n");
		HIP_DEBUG("Stored new hchain of length: %i\n", hchain_length);
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
			{
				err = hip_hchain_store_fill(MAX_STORE_COUNT - remaining_hchains,
						hchain_length, hash_length);
			}

		} else
		{
			remaining_hchains = hip_ll_get_size(&hip_hchain_storage.hchain_store[0]);
			if (remaining_hchains < MAX_STORE_COUNT * STORE_THRESHOLD)
			{
				bex_store_update =
					hip_hchain_bexstore_fill(MAX_STORE_COUNT - remaining_hchains,
						hash_length);
			}
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
hash_chain_t * hip_hchain_store_get_hchain(int hchain_length)
{
	hash_chain_t *stored_hchain = NULL;
	int store = 0, err = 0;

	/* find the appropriate store */
	HIP_IFEL((store = hip_hchain_store_get_store(hchain_length)) <= 0, -1,
				"No store found for length %i\n", hchain_length);

	hchain_store_lock();

	// make sure the store cointains sth to return
	if(store > 0 && hip_ll_get_size(&hip_hchain_storage.hchain_store[store]) > 0)
	{
		HIP_DEBUG("Taking hash chain from the store\n");

		// take first element and delete it from the list
		HIP_IFEL(!(stored_hchain = (hash_chain_t *)
			hip_ll_del_first(&hip_hchain_storage.hchain_store[store], NULL)), -1,
			"failed to fetch hchain from store\n");

	} else
	{
	 	HIP_DEBUG("No stored hash chains of length %d in storage.\n", hchain_length);
	 	err = -1;
	}

  out_err:
	hchain_store_unlock();

	if (err)
		stored_hchain = NULL;

	return stored_hchain;
}

hash_chain_t * hip_hchain_bexstore_get_hchain(unsigned char *anchor, int hash_length)
{
	hash_chain_t *stored_hchain = NULL;
	int i, err = 0;
	int num_hchains = 0;

	HIP_DEBUG("hash_length: %i\n", hash_length);
	HIP_HEXDUMP("search_anchor: ", anchor, hash_length);

	hchain_store_lock();

	// walk through the bex store looking for the correct hash-chain
	num_hchains = hip_ll_get_size(&hip_hchain_storage.hchain_store[0]);
	for (i = 0; i < num_hchains; i++)
	{
		HIP_IFEL(!(stored_hchain = (hash_chain_t *)
				hip_ll_get(&hip_hchain_storage.hchain_store[0], i)), -1,
				"failed to get hchain from bex store\n");

		HIP_DEBUG("anchor elements:\n");
		HIP_HEXDUMP("> ", stored_hchain->anchor_element->hash, hash_length);

		// compare passed anchor to anchor element of each hchain in the bex store
		if (!memcmp(stored_hchain->anchor_element->hash, anchor, hash_length))
		{
			HIP_DEBUG("requested hchain found, remove from list\n");

			stored_hchain = (hash_chain_t *)
				hip_ll_del(&hip_hchain_storage.hchain_store[0], i, NULL);

			hchain_print(stored_hchain, hash_length);

			goto out_err;
		}
	}

	HIP_DEBUG("No stored hash chain with requested anchor in bex store.\n");
	err = -1;

  out_err:
	hchain_store_unlock();

	if (err)
		stored_hchain = NULL;

  	return stored_hchain;
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
		if(hip_hchain_storage.store_hchain_length[i] == hchain_length)
		{
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
	int err = 0, store = 0;

	/* find the appropriate store */
	HIP_IFEL((store = hip_hchain_store_get_store(hchain_length)) <= 0, -1,
				"No store found for length %i\n", hchain_length);

	err = hip_ll_get_size(&hip_hchain_storage.hchain_store[store]);

  out_err:
	return err;
}

#endif
