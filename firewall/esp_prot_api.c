#include "esp_prot_api.h"
#include "esp_prot_fw_msg.h"
#include "firewall_defines.h"


static const hash_function_t hash_functions[NUM_HASH_FUNCTIONS] = {SHA1};
static const int hash_lengths[NUM_HASH_FUNCTIONS][NUM_HASH_LENGTHS] = {{8}};

#if 0
static const hash_function_t hash_functions[NUM_HASH_FUNCTIONS]
				   = {SHA1, MD5};
static const int hash_lengths[NUM_HASH_FUNCTIONS][NUM_HASH_LENGTHS]
				   = {{8, 16, 20}, {8, 16, 0}};
#endif

// stores the mapping transform_id -> (function_id, hash_length_id)
esp_prot_tfm_t esp_prot_transforms[NUM_TRANSFORMS];

// this store only contains hchains used when negotiating esp protection in BEX
hchain_store_t bex_store;
// this stores hchains used during UPDATE
hchain_store_t update_store;


int esp_prot_init()
{
	int bex_function_id = 0, update_function_id = 0;
	int bex_hash_length_id = 0, update_hash_length_id = 0;
	int transform_id = 0;
	int err = 0, i, j, g;

	HIP_DEBUG("Initializing the esp protection extension...\n");

	/* init the hash-chain stores */

	HIP_IFEL(hcstore_init(&bex_store), -1, "failed to initialize the bex-store\n");
	HIP_IFEL(hcstore_init(&update_store), -1, "failed to initialize the update-store\n");

	/* set up meta-info for each store and init the esp protection transforms */
	for (i = 0; i < NUM_HASH_FUNCTIONS; i++)
	{
		// first we have to register the function
		HIP_IFEL((bex_function_id = hcstore_register_function(&bex_store,
				hash_functions[i])) < 0, -1,
				"failed to register hash-function in bex-store\n");
		HIP_IFEL((update_function_id = hcstore_register_function(&update_store,
				hash_functions[i])) < 0, -1,
				"failed to register hash-function in update-store\n");

		// ensure the 2 stores are in sync
		HIP_ASSERT(bex_function_id == update_function_id);

		for (j = 0; j < NUM_HASH_LENGTHS; j++)
		{
			if (hash_lengths[i][j] > 0)
			{
				// ensure correct boundaries
				HIP_ASSERT(transform_id < NUM_TRANSFORMS);

				// now we can register the hash lengths for this function
				HIP_IFEL((bex_hash_length_id = hcstore_register_hash_length(&bex_store,
						bex_function_id, hash_lengths[i][j])) < 0, -1,
						"failed to register hash-length in bex-store\n");
				HIP_IFEL((update_hash_length_id = hcstore_register_hash_length(
						&update_store, update_function_id, hash_lengths[i][j])) < 0, -1,
						"failed to register hash-length in update-store\n");

				// ensure the 2 stores are in sync
				HIP_ASSERT(bex_hash_length_id == update_hash_length_id);

				// store these IDs in the transforms array
				HIP_DEBUG("adding transform: %i\n", transform_id + 1);
				esp_prot_transforms[transform_id].hash_func_id = bex_function_id;
				esp_prot_transforms[transform_id].hash_length_id = bex_hash_length_id;
				transform_id++;

				/* also register the the hchain lengths for this function and this
				 * hash length */
				HIP_IFEL(hcstore_register_hchain_length(&bex_store, bex_function_id,
						bex_hash_length_id, bex_hchain_length) < 0, -1,
						"failed to register hchain-length in bex-store\n");

				for (g = 0; g < NUM_UPDATE_HCHAIN_LENGTHS; g++)
				{
					HIP_IFEL(hcstore_register_hchain_length(&update_store,
							update_function_id, update_hash_length_id,
							update_hchain_lengths[g]) < 0, -1,
							"failed to register hchain-length in update-store\n");
				}
			} else
			{
				// for this hash-function we have already processed all hash-lengths
				break;
			}
		}
	}

	/* finally we can fill the stores */
	HIP_IFEL(hcstore_refill(&bex_store) < 0, -1, "failed to fill the bex-store\n");
	HIP_IFEL(hcstore_refill(&update_store) < 0, -1, "failed to fill the update-store\n");

  out_err:
  	return err;
}

int esp_prot_set_sadb(hip_sa_entry_t *entry, uint8_t esp_prot_transform,
		unsigned char *esp_prot_anchor, int direction)
{
	int hash_length = 0, err = 0;

	HIP_ASSERT(entry != 0);
	HIP_ASSERT(esp_prot_transform >= 0 && esp_prot_transform <= NUM_TRANSFORMS);
	HIP_ASSERT(direction == 1 || direction == 2);

	// only set up the anchor or hchain, if esp extension is used
	if (esp_prot_transform > ESP_PROT_TFM_UNUSED)
	{
		// TODO add update support

		// if the extension is used, an anchor should be provided by the peer
		HIP_ASSERT(esp_prot_anchor != NULL);

		HIP_DEBUG("setting up ESP extension parameters...\n");

		// set the esp protection extension transform
		entry->esp_prot_transform = esp_prot_transform;
		HIP_DEBUG("entry->esp_prot_transform: %u\n", entry->esp_prot_transform);

		/* set up hash chains or anchors depending on the direction */
		if (direction == HIP_SPI_DIRECTION_IN)
		{
			// we have to get the hash_length
			hash_length = esp_prot_get_hash_length(esp_prot_transform);

			HIP_IFEL(!(entry->active_anchor = (unsigned char *)
					malloc(hash_length)), -1, "failed to allocate memory\n");

			// set anchor for inbound SA
			memcpy(entry->active_anchor, esp_prot_anchor, hash_length);

			entry->esp_prot_tolerance = DEFAULT_VERIFY_WINDOW;
		} else
		{
			// set hchain for outbound SA
			HIP_IFEL(!(entry->active_hchain =
				esp_prot_get_bex_hchain_by_anchor(esp_prot_anchor, esp_prot_transform)),
				-1, "corresponding hchain not found\n");
		}
	} else
	{
		entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;
	}

  out_err:
  	return err;
}

int add_esp_prot_hash(unsigned char *out_hash, int *out_length, hip_sa_entry_t *entry)
{
	unsigned char *tmp_hash = NULL;
	int err = 0;

	HIP_ASSERT(out_hash != NULL);
	HIP_ASSERT(*out_length == 0);
	HIP_ASSERT(entry != NULL);

	if (entry->esp_prot_transform > ESP_PROT_TFM_UNUSED)
	{
		HIP_ASSERT(entry->esp_prot_transform > 0
				&& entry->esp_prot_transform <= NUM_TRANSFORMS);

		HIP_DEBUG("adding hash chain element to outgoing packet...\n");

		// first determine hash length
		*out_length = entry->active_hchain->hash_length;
		HIP_DEBUG("hash length is %i\n", *out_length);

		HIP_IFEL(!(tmp_hash = hchain_pop(entry->active_hchain)), -1,
				"unable to retrieve hash element from hash-chain\n");

		/* don't send anchor as it could be known to third party
		 * -> other end-host will not accept it */
		if (!memcmp(tmp_hash, entry->active_hchain->anchor_element->hash,
				*out_length))
		{
			HIP_DEBUG("this is the hchain anchor -> get next element\n");

			// get next element
			HIP_IFEL(!(tmp_hash = hchain_pop(entry->active_hchain)), -1,
					"unable to retrieve hash element from hash-chain\n");
		}

		memcpy(out_hash, tmp_hash, *out_length);

		HIP_HEXDUMP("added esp protection hash: ", out_hash, *out_length);

		// now do some maintenance operations
		HIP_IFEL(esp_prot_sadb_maintenance(entry), -1,
				"esp protection extension maintenance operations failed\n");
	} else
	{
		HIP_DEBUG("esp prot extension UNUSED, not adding hash\n");
	}

  out_err:
    return err;
}

/* verifies received hchain-elements */
int verify_esp_prot_hash(hip_sa_entry_t *entry, unsigned char *hash_value)
{
	hash_function_t hash_function = NULL;
	int hash_length = 0;
	int err = 0;

	HIP_ASSERT(entry != NULL);

	if (entry->esp_prot_transform > ESP_PROT_TFM_UNUSED)
	{
		HIP_ASSERT(hash_value != NULL);
		HIP_ASSERT(entry->esp_prot_transform > 0
				&& entry->esp_prot_transform <= NUM_TRANSFORMS);

		hash_function = esp_prot_get_hash_function(entry->esp_prot_transform);
		hash_length = esp_prot_get_hash_length(entry->esp_prot_transform);
		HIP_DEBUG("hash length is %i\n", hash_length);

		HIP_DEBUG("hchain element of incoming packet to be verified:\n");
		HIP_HEXDUMP("-> ", hash_value, hash_length);

		HIP_DEBUG("checking active_anchor...\n");
		if (hchain_verify(hash_value, entry->active_anchor, hash_function,
				hash_length, entry->esp_prot_tolerance))
		{
			// this will allow only increasing elements to be accepted
			memcpy(entry->active_anchor, hash_value, hash_length);

			HIP_DEBUG("hash matches element in active hash-chain\n");

		} else
		{
			if (entry->next_anchor)
			{
				/* there might still be a chance that we have to switch to the
				 * next hchain implicitly */
				HIP_DEBUG("checking next_anchor...\n");
				if (hchain_verify(hash_value, entry->next_anchor, hash_function,
						hash_length, entry->esp_prot_tolerance))
				{
					HIP_DEBUG("hash matches element in next hash-chain\n");

					free(entry->active_anchor);
					entry->active_anchor = entry->next_anchor;
					entry->next_anchor = NULL;
				}
				else
				{
					// handle incorrect elements -> drop packet
					err = 1;
					goto out_err;
				}

			} else
			{
				// handle incorrect elements -> drop packet
				err = 1;
				goto out_err;
			}
		}
	} else
	{
		HIP_DEBUG("esp protection extension UNUSED\n");
	}

  out_err:
	if (err == 1)
	{
		HIP_DEBUG("INVALID hash-chain element!\n");
	}

    return err;
}

/* returns NULL for UNUSED transform */
esp_prot_tfm_t * esp_prot_resolve_transform(uint8_t transform)
{
	HIP_ASSERT(transform >= 0 && transform <= NUM_TRANSFORMS);

	HIP_DEBUG("resolving transform: %u\n", transform);

	if (transform > ESP_PROT_TFM_UNUSED)
		return &esp_prot_transforms[transform - 1];
	else
		return NULL;
}

/* returns NULL for UNUSED transform */
hash_function_t esp_prot_get_hash_function(uint8_t transform)
{
	esp_prot_tfm_t *prot_transform = NULL;
	hash_function_t hash_function = NULL;
	int err = 0;

	HIP_ASSERT(transform >= 0 && transform <= NUM_TRANSFORMS);

	HIP_IFEL(!(prot_transform = esp_prot_resolve_transform(transform)), 1,
			"tried to resolve UNUSED transform\n");

	// as both stores' meta-data are in sync, we can use any
	hash_function = hcstore_get_hash_function(&bex_store, prot_transform->hash_func_id);

  out_err:
	if (err)
		hash_function = NULL;

	return hash_function;
}

/* returns length of hash, 0 for UNUSED */
int esp_prot_get_hash_length(uint8_t transform)
{
	esp_prot_tfm_t *prot_transform = NULL;
	int err = 0;

	HIP_ASSERT(transform >= 0 && transform <= NUM_TRANSFORMS);

	// return length 0 for UNUSED transform
	HIP_IFEL(!(prot_transform = esp_prot_resolve_transform(transform)), 0,
			"tried to resolve UNUSED transform\n");

	// as both stores' meta-data are in sync, we can use any
	err = hcstore_get_hash_length(&bex_store, prot_transform->hash_func_id,
			prot_transform->hash_length_id);

  out_err:
	return err;
}

/* returns corresponding hash-chain, refills bex_store and sends update
 * message to hipd
 */
hash_chain_t * esp_prot_get_bex_hchain_by_anchor(unsigned char *hchain_anchor,
		uint8_t transform)
{
	esp_prot_tfm_t *prot_transform = NULL;
	hash_chain_t *return_hchain = NULL;
	int err = 0;

	HIP_ASSERT(hchain_anchor != NULL);
	HIP_ASSERT(transform >= 0 && transform <= NUM_TRANSFORMS);

	HIP_IFEL(!(prot_transform = esp_prot_resolve_transform(transform)), 1,
			"tried to resolve UNUSED transform\n");

	HIP_IFEL(!(return_hchain = hcstore_get_hchain_by_anchor(&bex_store,
			prot_transform->hash_func_id, prot_transform->hash_length_id, hchain_anchor)),
			-1, "unable to retrieve hchain from bex store\n");

	// refill bex-store if necessary
	HIP_IFEL((err = hcstore_refill(&bex_store)) < 0, -1,
			"failed to refill the bex-store\n");

	// some elements have been added, tell hipd about them
	if (err > 0)
	{
		HIP_IFEL(send_bex_store_update_to_hipd(&bex_store), -1,
				"unable to send bex-store update to hipd\n");

		// this is not an error condition
		err = 0;
	}

  out_err:
	if (err)
		return_hchain = NULL;

  	return return_hchain;
}

int get_esp_data_offset(hip_sa_entry_t *entry)
{
	HIP_ASSERT(entry != NULL);

	return (sizeof(struct hip_esp) + esp_prot_get_hash_length(entry->esp_prot_transform));
}

/* sets entry->next_hchain, if necessary
 * changes to next_hchain
 * refills the update_store
 */
int esp_prot_sadb_maintenance(hip_sa_entry_t *entry)
{
	esp_prot_tfm_t *prot_transform = NULL;
	int err = 0;

	HIP_ASSERT(entry != NULL);

	// first check the extension is used for this connection
	if (entry->esp_prot_transform > ESP_PROT_TFM_UNUSED)
	{
		HIP_ASSERT(entry->esp_prot_transform > 0
				&& entry->esp_prot_transform <= NUM_TRANSFORMS);

		/* make sure that the next hash-chain is set up before the active one
		 * depletes */
		if (!entry->next_hchain && entry->active_hchain->remaining
					<= entry->active_hchain->hchain_length * REMAIN_ELEMENTS_TRESHOLD)
		{
			HIP_IFEL(!(prot_transform = esp_prot_resolve_transform(entry->esp_prot_transform)),
					1, "tried to resolve UNUSED transform\n");

			/* set next hchain with DEFAULT_HCHAIN_LENGTH_ID
			 *
			 * @note this needs to be extended when implementing usage of different
			 *       hchain lengths
			 */
			HIP_IFEL(!(entry->next_hchain = hcstore_get_hchain(&update_store,
					prot_transform->hash_func_id, prot_transform->hash_length_id,
					update_hchain_lengths[DEFAULT_HCHAIN_LENGTH_ID])),
					-1, "unable to retrieve hchain from store\n");

			// issue UPDATE message to be sent by hipd
			HIP_IFEL(trigger_update(entry), -1,
					"unable to trigger update at hipd\n");

			// refill update-store
			HIP_IFEL((err = hcstore_refill(&update_store)) < 0, -1,
					"failed to refill the update-store\n");
		}

		// activate next hchain if current one is depleted
		if (entry->next_hchain && entry->active_hchain->remaining == 0)
		{
			// this will free all linked elements in the hchain
			hchain_free(entry->active_hchain);

			HIP_DEBUG("changing to next_hchain\n");
			entry->active_hchain = entry->next_hchain;
			entry->next_hchain = NULL;
		}
	}

  out_err:
    return err;
}
