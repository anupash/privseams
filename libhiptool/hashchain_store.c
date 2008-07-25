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
		hcstore->num_hash_lengths[i] = 0;

		for (j = 0; j < MAX_NUM_HASH_LENGTH; j++)
		{
			hcstore->hash_lengths[i][j] = 0;
			hcstore->hchain_shelves[i][j].num_hchain_lengths = 0;

			for (g = 0; g < MAX_NUM_HCHAIN_LENGTH; g++)
			{
				hcstore->hchain_shelves[i][j].hchain_lengths[g] = 0;
				hip_ll_init(&hcstore->hchain_shelves[i][j].hchains[g]);
			}

		}
	}

	HIP_DEBUG("hash-chain store initialized\n");

  out_err:
	return err;
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
		hcstore->num_hash_lengths[i] = 0;

		for (j = 0; j < MAX_NUM_HASH_LENGTH; j++)
		{
			hcstore->hash_lengths[i][j] = 0;
			hcstore->hchain_shelves[i][j].num_hchain_lengths = 0;

			for (g = 0; g < MAX_NUM_HCHAIN_LENGTH; g++)
			{
				hcstore->hchain_shelves[i][j].hchain_lengths[g] = 0;
				hip_ll_uninit(&hcstore->hchain_shelves[i][j].hchains[g],
						hcstore_free_hchain);
			}
		}
	}

	HIP_DEBUG("hash-chain store uninitialized\n");
}

void hcstore_free_hchain(void *hchain)
{
	hchain_free((hash_chain_t *) hchain);
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
	hcstore->hash_functions[hcstore->num_functions] = hash_function;
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
	HIP_IFEL(hcstore->num_hash_lengths[function_id] == MAX_NUM_HASH_LENGTH, -1,
			"space for hash_length-storage is full\n");

	// also check if the hash length is already stored for this function
	for (i = 0; i < hcstore->num_hash_lengths[function_id]; i++)
	{
		if (hcstore->hash_lengths[function_id][i] == hash_length)
		{
			HIP_DEBUG("hchain store already contains this hash length\n");

			err = i;
			goto out_err;
		}
	}

	// store the hash length
	err = hcstore->num_hash_lengths[function_id];
	hcstore->hash_lengths[function_id][hcstore->num_hash_lengths[function_id]] =
				hash_length;
	hcstore->num_hash_lengths[function_id]++;

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
			&& hash_length_id < hcstore->num_hash_lengths[function_id]);
	HIP_ASSERT(hchain_length > 0);

	// first check that there's still some space left
	HIP_IFEL(hcstore->hchain_shelves[function_id][hash_length_id].num_hchain_lengths
			== MAX_NUM_HCHAIN_LENGTH, -1, "space for hchain_length-storage is full\n");

	// also check if the hash length is already stored for this function
	for (i = 0; i < hcstore->hchain_shelves[function_id][hash_length_id].
			num_hchain_lengths; i++)
	{
		if (hcstore->hchain_shelves[function_id][hash_length_id].hchain_lengths[i]
			  == hchain_length)
		{
			HIP_DEBUG("hchain store already contains this hchain length\n");

			err = i;
			goto out_err;
		}
	}

	// store the hchain length
	err = hcstore->hchain_shelves[function_id][hash_length_id].num_hchain_lengths;
	hcstore->hchain_shelves[function_id][hash_length_id].
			hchain_lengths[hcstore->hchain_shelves[function_id][hash_length_id].
			        num_hchain_lengths] = hchain_length;
	hcstore->hchain_shelves[function_id][hash_length_id].num_hchain_lengths++;

	HIP_DEBUG("hchain length successfully registered\n");

  out_err:
	return err;
}

int hcstore_refill(hchain_store_t *hcstore)
{
	hash_function_t hash_function = NULL;
	int hash_length = 0, hchain_length = 0;
	int create_hchains = 0;
	hash_chain_t *hchain = NULL;
	int err = 0, i, j, g, h;

	HIP_ASSERT(hcstore != NULL);

	/* go through the store setting up information neccessary for creating a new
	 * hchain in the respective item */
	for (i = 0; i < hcstore->num_functions; i++)
	{
		hash_function = hcstore->hash_functions[i];

		for (j = 0; j < hcstore->num_hash_lengths[i]; j++)
		{
			hash_length = hcstore->hash_lengths[i][j];

			for (g = 0; g < hcstore->hchain_shelves[i][j].num_hchain_lengths; g++)
			{
				hchain_length = hcstore->hchain_shelves[i][j].hchain_lengths[g];

				// how many hchains are missing to fill up the item again
				create_hchains = MAX_HCHAINS_PER_ITEM
					- hip_ll_get_size(&hcstore->hchain_shelves[i][j].hchains[g]);

				if (create_hchains >= ITEM_THRESHOLD * MAX_HCHAINS_PER_ITEM)
				{
					// count the overall amount of created hchains
					err += create_hchains;

					for (h = 0; h < create_hchains; h++)
					{
						// create a new hchain
						HIP_IFEL(!(hchain = hchain_create(hash_function, hash_length,
								hchain_length)), -1, "failed to create new hchain\n");

						// add it as last element to have some circulation
						HIP_IFEL(hip_ll_add_last(&hcstore->hchain_shelves[i][j].hchains[g],
								hchain), -1, "failed to store new hchain\n");
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
	// offsets of 3rd and 4th dimension, inited to invalid values
	int item_offset = -1;
	hash_chain_t *stored_hchain = NULL;
	int err = 0, i;

	HIP_ASSERT(hcstore != NULL);
	HIP_ASSERT(function_id >= 0 && function_id < hcstore->num_functions);
	HIP_ASSERT(hash_length_id >= 0
			&& hash_length_id < hcstore->num_hash_lengths[function_id]);
	HIP_ASSERT(hchain_length > 0);

	// first find the correct hchain item
	for (i = 0; i < hcstore->hchain_shelves[function_id][hash_length_id].
			num_hchain_lengths; i++)
	{
		if (hcstore->hchain_shelves[function_id][hash_length_id].hchain_lengths[i]
				== hchain_length)
		{
			// set item_offset
			item_offset = i;

			break;
		}
	}

	// handle unregistered hchain length
	HIP_IFEL(item_offset < 0, -1, "hchain with unregistered hchain length requested\n");

	HIP_IFEL(!(stored_hchain = hip_ll_del_first(&hcstore->hchain_shelves[function_id]
	        [hash_length_id].hchains[item_offset], NULL)), -1,
			"no hchain available\n");

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
	int hash_length = 0;
	hash_chain_t *stored_hchain = NULL;
	int err = 0, i, j;

	HIP_ASSERT(hcstore != NULL);
	HIP_ASSERT(function_id >= 0 && function_id < hcstore->num_functions);
	HIP_ASSERT(hash_length_id >= 0
			&& hash_length_id < hcstore->num_hash_lengths[function_id]);
	HIP_ASSERT(anchor != NULL);

	hash_length = hcstore_get_hash_length(hcstore, function_id, hash_length_id);

	HIP_ASSERT(hash_length > 0);

	HIP_HEXDUMP("searching hchain with anchor: ", anchor, hash_length);

	for (i = 0; i < hcstore->hchain_shelves[function_id][hash_length_id].
			num_hchain_lengths; i++)
	{
		for (j = 0; j < hip_ll_get_size(&hcstore->hchain_shelves[function_id]
		        [hash_length_id].hchains[i]); j++)
		{
			stored_hchain = (hash_chain_t *) hip_ll_get(&hcstore->hchain_shelves[function_id]
		        [hash_length_id].hchains[i], j);

			if (!memcmp(anchor, stored_hchain->anchor_element->hash, hash_length))
			{
				stored_hchain = (hash_chain_t *) hip_ll_del(&hcstore->hchain_shelves[function_id]
					[hash_length_id].hchains[i], j, NULL);

				HIP_DEBUG("hash-chain matching the anchor found\n");
				//hchain_print(stored_hchain);

				goto out_err;
			}
		}
	}

	HIP_ERROR("hash-chain matching the anchor NOT found\n");
	stored_hchain = NULL;
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

hash_function_t hcstore_get_hash_function(hchain_store_t *hcstore, int function_id)
{
	HIP_ASSERT(hcstore != NULL);
	HIP_ASSERT(function_id >= 0 && function_id < hcstore->num_functions);

	return hcstore->hash_functions[function_id];
}

int hcstore_get_hash_length(hchain_store_t *hcstore, int function_id, int hash_length_id)
{
	HIP_ASSERT(hcstore != NULL);
	HIP_ASSERT(function_id >= 0 && function_id < hcstore->num_functions);
	HIP_ASSERT(hash_length_id >= 0
			&& hash_length_id < hcstore->num_hash_lengths[function_id]);

	return hcstore->hash_lengths[function_id][hash_length_id];
}
