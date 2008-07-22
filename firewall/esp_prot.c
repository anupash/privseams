#include "esp_prot.h"
#include "esp_prot_fw_msg.h"
#include "firewall_defines.h"


// stores the mapping transform_id -> (function_id, hash_length_id)
esp_prot_transform_t esp_prot_transforms[NUM_TRANSFORMS];

// this store only contains hchains used when negotiating esp protection in BEX
hchain_store_t bex_store;
// this stores hchains used during UPDATE
hchain_store_t update_store;


int esp_prot_init()
{
	int bex_function_id = 0, update_function_id = 0;
	int bex_hash_length_id = 0, update_hash_length_id = 0;
	int transform_id = 0;
	int err = 0, i, j;

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
				// now we can register the hash lengths for this function
				HIP_IFEL((bex_hash_length_id = hcstore_register_hash_length(&bex_store,
						function_id, hash_lengths[i][j])) < 0, -1,
						"failed to register hash-length in bex-store\n");
				HIP_IFEL((update_hash_length_id = hcstore_register_hash_length(
						&update_store, function_id, hash_lengths[i][j])) < 0, -1,
						"failed to register hash-length in update-store\n");

				// ensure the 2 stores are in sync
				HIP_ASSERT(bex_hash_length_id == update_hash_length_id);

				// store these IDs in the transforms array
				HIP_DEBUG("adding transform: %i\n", transform_id);
				esp_prot_transforms[transform_id].hash_func_id = function_id;
				esp_prot_transforms[transform_id].hash_length_id = hash_length_id;
				transform_id++;

				/* also register the the hchain lengths for this function and this
				 * hash length */
				for (g = 0; g < NUM_BEX_HCHAIN_LENGTHS; g++)
				{
					HIP_IFEL(hcstore_register_hchain_length(&bex_store, function_id,
							hash_length_id, bex_hchain_lengths[g]) < 0, -1,
							"failed to register hchain-length in bex-store\n");
				}
				for (g = 0; g < NUM_UPDATE_HCHAIN_LENGTHS; g++)
				{
					HIP_IFEL(hcstore_register_hchain_length(&update_store, function_id,
							hash_length_id, update_hchain_lengths[g]) < 0, -1,
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


#if 0
	int hc_element_lengths[] = {HC_LENGTH_STEP1};

	HIP_IFEL(hip_hchain_store_init(hc_element_lengths, 1), -1,
			"failed to initialize the hchain stores\n");

	HIP_IFEL(hip_hchain_bexstore_set_item_length(HC_LENGTH_BEX_STORE), -1,
			"failed to set item length for bex store\n");

	// ... and fill it with elements
	HIP_DEBUG("filling the hchain stores...\n");
	err = hip_hchain_stores_refill(esp_prot_transforms[ESP_PROT_TRANSFORM_DEFAULT]);
	if (err < 0)
	{
		HIP_ERROR("error refilling the stores\n");
		goto out_err;
	} else if (err > 0)
	{
		// this means the bex store was updated
		HIP_DEBUG("sending anchor list update to hipd...\n");
		HIP_IFEL(send_anchor_list_update_to_hipd(ESP_PROT_TRANSFORM_DEFAULT), -1,
				"unable to send anchor list update to hipd\n");

		err = 0;
	}
#endif

  out_err:
  	return err;
}

int esp_prot_set_sadb(hip_sa_entry_t *entry, uint8_t esp_prot_transform,
		unsigned char *esp_prot_anchor, int direction)
{
	int hash_length = 0, err = 0;

	// only set up the anchor or hchain, if esp extension is used
	if (esp_prot_transform > ESP_PROT_TFM_UNUSED)
	{
		// TODO add update support

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
				esp_prot_get_hchain_by_anchor(esp_prot_anchor, esp_prot_transform)),
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

	if (entry->esp_prot_transform > ESP_PROT_TFM_UNUSED)
	{
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
		HIP_IFEL(esp_prot_ext_maintenance(entry), -1,
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

	if (entry->esp_prot_transform > ESP_PROT_TFM_UNUSED)
	{
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
						hash_length, entry->tolerance))
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

// TODO handle UNUSED case
esp_prot_transform_t * esp_prot_resolve_transform(uint8_t transform)
{
	HIP_DEBUG("resolving transform: %u\n", transform);

	return &esp_prot_transforms[transform - 1];
}

// TODO handle UNUSED case
hash_function_t esp_prot_get_hash_function(uint8_t transform)
{
	esp_prot_transform_t *prot_transform = NULL;
	int err = 0;

	HIP_IFEL(!(prot_transform = esp_prot_resolve_transform(transform)),
			-1, "failed to resolve transform\n");

	// as both stores' meta-data are in sync, we can use any
	err = hcstore_get_hash_function(bex_store, prot_transform->hash_func_id);

  out_err:
	return err;
}

// TODO handle UNUSED case
int esp_prot_get_hash_length(uint8_t transform)
{
	esp_prot_transform_t *prot_transform = NULL;
	int err = 0;

	HIP_IFEL(!(prot_transform = esp_prot_resolve_transform(transform)),
			-1, "failed to resolve transform\n");

	// as both stores' meta-data are in sync, we can use any
	err = hcstore_get_hash_length(bex_store, prot_transform->hash_func_id,
			prot_transform->hash_length_id);

  out_err:
	return err;
}

// TODO check
hash_chain_t * esp_prot_get_hchain_by_anchor(unsigned char *hchain_anchor,
		uint8_t transform)
{
	int err = 0;
	hash_chain_t *return_hchain = NULL;

	HIP_IFEL(!(return_hchain = hip_hchain_bexstore_get_hchain(hchain_anchor,
			esp_prot_transforms[transform])), -1,
			"unable to retrieve hchain from bex store\n");

  out_err:
	if (err)
		return_hchain = NULL;

  	return return_hchain;
}

// TODO check
int get_esp_data_offset(hip_sa_entry_t *entry)
{
	return (sizeof(struct hip_esp) + esp_prot_transforms[entry->active_transform]);
}

// TODO check
int esp_prot_ext_maintainance(hip_sa_entry_t *entry)
{
	int err = 0, decreased_store_count = 0;

	// first check the extension is used
	if (entry->active_transform > ESP_PROT_TRANSFORM_UNUSED)
	{

		/* make sure that the next hash-chain is set up before the active one
		 * depletes */
		if (!entry->next_hchain && entry->active_hchain->remaining
					<= entry->active_hchain->hchain_length * REMAIN_THRESHOLD)
		{
			// set next hchain
			HIP_IFEL(entry->next_hchain = hip_hchain_store_get_hchain(HC_LENGTH_STEP1),
					-1, "unable to retrieve hchain from store\n");
			// issue UPDATE message to be sent by hipd
			HIP_IFEL(send_next_anchor_to_hipd(entry->next_hchain->anchor_element->hash,
					entry->active_transform), -1,
					"unable to send next anchor message to hipd\n");

			decreased_store_count = 1;
		}

		// activate next hchain if current one is depleted
		if (entry->next_hchain && entry->active_hchain->remaining == 0)
		{
			// this will free all linked elements in the hchain
			hchain_destruct(entry->active_hchain);

			HIP_DEBUG("changing to next_hchain\n");
			entry->active_hchain = entry->next_hchain;
			entry->next_hchain = NULL;
		}

		// check if we should refill the stores
		if (decreased_store_count)
		{
			err = hip_hchain_stores_refill(esp_prot_transforms[entry->active_transform]);
			if (err < 0)
			{
				HIP_ERROR("error refilling the stores\n");
				goto out_err;
			} else if (err > 0)
			{
				// this means the bex store was updated
				HIP_DEBUG("sending anchor update...\n");
				HIP_IFEL(send_anchor_list_update_to_hipd(entry->active_transform), -1,
						"unable to send anchor list update to hipd\n");

				err = 0;
			}
		}
	}

  out_err:
    return err;
}
