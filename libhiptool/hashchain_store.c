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
#include "misc.h"
#include "linkedlist.h"

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

struct hip_common *create_bexstore_anchors_message(int hash_length)
{
	struct hip_common *msg = NULL;
	hash_chain_t *bex_hchain = NULL;
	unsigned char *anchor = NULL;
	int err = 0, i, num_hchains = 0;

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
