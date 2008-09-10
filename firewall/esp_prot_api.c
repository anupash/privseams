#include "esp_prot_api.h"
#include "esp_prot_fw_msg.h"
#include "firewall_defines.h"


/* preference of the supported transforms in decreasing order
 *
 * @note make sure to always include ESP_PROT_TFM_UNUSED
 */
extern const uint8_t preferred_transforms[NUM_TRANSFORMS + 1] =
		{ESP_PROT_TFM_SHA1_20, ESP_PROT_TFM_SHA1_16, ESP_PROT_TFM_MD5_16,
				ESP_PROT_TFM_SHA1_8, ESP_PROT_TFM_MD5_8, ESP_PROT_TFM_UNUSED};

extern const hash_function_t hash_functions[NUM_HASH_FUNCTIONS]
				   = {SHA1, MD5};
extern const int hash_lengths[NUM_HASH_FUNCTIONS][NUM_HASH_LENGTHS]
				   = {{8, 16, 20}, {8, 16, 0}};


static const int bex_hchain_length = 100000;
static const int update_hchain_lengths[NUM_UPDATE_HCHAIN_LENGTHS] = {100000};


/* stores the mapping transform_id -> (function_id, hash_length_id)
 *
 * @note no mapping for UNUSED transform */
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
	int activate = 1;

	HIP_DEBUG("Initializing the esp protection extension...\n");

	/* activate the extension in hipd
	 *
	 * @note this has to be set first, otherwise hipd won't understand the
	 *       anchor message */
	HIP_DEBUG("activating esp prot in hipd...\n");
	HIP_IFEL(send_esp_prot_to_hipd(activate), -1,
			"failed to activate the esp protection in hipd\n");

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

	/* ...and send the bex-store anchors to hipd */
	HIP_IFEL(send_bex_store_update_to_hipd(&bex_store), -1,
		"failed to send bex-store update to hipd\n");

  out_err:
  	return err;
}

int esp_prot_uninit()
{
	int err = 0, i;
	int activate = 0;

	// uninit hcstores
	hcstore_uninit(&bex_store);
	hcstore_uninit(&update_store);
	// ...and set transforms to 0/NULL
	for (i = 0; i < NUM_TRANSFORMS; i++)
	{
		esp_prot_transforms[i].hash_func_id = 0;
		esp_prot_transforms[i].hash_length_id = 0;
	}

	// also deactivate the extension in hipd
	HIP_IFEL(send_esp_prot_to_hipd(activate), -1,
			"failed to activate the esp protection in hipd\n");

  out_err:
	return err;
}

int esp_prot_sa_entry_set(hip_sa_entry_t *entry, uint8_t esp_prot_transform,
		unsigned char *esp_prot_anchor, int update)
{
	int hash_length = 0, err = 0;

	HIP_ASSERT(entry != 0);
	// esp_prot_transform >= 0 due to datatype
	HIP_ASSERT(esp_prot_transform <= NUM_TRANSFORMS);
	HIP_ASSERT(entry->direction == 1 || entry->direction == 2);

	// only set up the anchor or hchain, if esp extension is used
	if (esp_prot_transform > ESP_PROT_TFM_UNUSED)
	{
		// if the extension is used, an anchor should be provided by the peer
		HIP_ASSERT(esp_prot_anchor != NULL);

		// distinguish the creation of a new entry and the update of an old one
		if (update)
		{
			HIP_DEBUG("updating ESP prot parameters...\n");

			// check if current and next transform are matching
			HIP_IFEL(entry->esp_prot_transform != esp_prot_transform, 1,
					"transform for active esp prot and next do NOT match\n");
			HIP_DEBUG("found matching esp prot transforms\n");

			// we have to get the hash_length
			hash_length = esp_prot_get_hash_length(esp_prot_transform);

			/* set up hash chains or anchors depending on the direction */
			if (entry->direction == HIP_SPI_DIRECTION_IN)
			{
				HIP_IFEL(!(entry->next_anchor = (unsigned char *)
						malloc(hash_length)), -1, "failed to allocate memory\n");

				// set anchor for inbound SA
				memcpy(entry->next_anchor, esp_prot_anchor, hash_length);

				HIP_DEBUG("next_anchor set for inbound SA\n");

			} else
			{
				HIP_ASSERT(entry->next_hchain != NULL);

				/* esp_prot_sadb_maintenance should have already set up the next_hchain,
				 * check that the anchor belongs to the one that is set */
				HIP_IFEL(memcmp(esp_prot_anchor, entry->next_hchain->anchor_element->hash,
						hash_length), -1,
						"received a non-matching anchor from hipd for next_hchain\n");

				HIP_DEBUG("next_hchain-anchor and received anchor from hipd match\n");
			}
		} else
		{
			HIP_DEBUG("setting up ESP prot parameters for new entry...\n");

			// set the esp protection transform
			entry->esp_prot_transform = esp_prot_transform;
			HIP_DEBUG("entry->esp_prot_transform: %u\n", entry->esp_prot_transform);

			/* set up hash chains or anchors depending on the direction */
			if (entry->direction == HIP_SPI_DIRECTION_IN)
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
		}
	} else
	{
		HIP_DEBUG("no esp prot related params set, as UNUSED\n");

		entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;
	}

  out_err:
  	return err;
}

void esp_prot_sa_entry_free(hip_sa_entry_t *entry)
{
	if (entry->active_anchor)
		free(entry->active_anchor);
	if (entry->next_anchor)
		free(entry->next_anchor);
	if (entry->active_hchain)
		hchain_free(entry->active_hchain);
	if (entry->next_hchain)
		hchain_free(entry->next_hchain);
}

int esp_prot_add_hash(unsigned char *out_hash, int *out_length,
		hip_sa_entry_t *entry)
{
	unsigned char *tmp_hash = NULL;
	int err = 0;

	HIP_ASSERT(out_hash != NULL);
	HIP_ASSERT(*out_length == 0);
	HIP_ASSERT(entry != NULL);

	if (entry->esp_prot_transform > ESP_PROT_TFM_UNUSED)
	{
		// esp_prot_transform >= 0 due to data-type
		HIP_ASSERT(entry->esp_prot_transform <= NUM_TRANSFORMS);

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

int esp_prot_verify(hip_sa_entry_t *entry, unsigned char *hash_value)
{
	hash_function_t hash_function = NULL;
	int hash_length = 0;
	int err = 0;

	HIP_ASSERT(entry != NULL);
	HIP_ASSERT(hash_value != NULL);
	// esp_prot_transform >= 0 due to data-type
	HIP_ASSERT(entry->esp_prot_transform <= NUM_TRANSFORMS);

	if (entry->esp_prot_transform > ESP_PROT_TFM_UNUSED)
	{
		hash_function = esp_prot_get_hash_function(entry->esp_prot_transform);
		hash_length = esp_prot_get_hash_length(entry->esp_prot_transform);

		HIP_IFEL((err = esp_prot_verify_hash(hash_function, hash_length,
				entry->active_anchor, entry->next_anchor, hash_value,
				entry->esp_prot_tolerance)) < 0, -1, "failed to verify hash\n");

		// anchors have changed, tell hipd about it
		if (err > 0)
		{
			HIP_DEBUG("anchor change occurred, handled now\n");

			memcpy(entry->active_anchor, entry->next_anchor, hash_length);
			free(entry->next_anchor);
			entry->next_anchor = NULL;

			/* notify hipd about the switch to the next hash-chain for
			 * consistency reasons */
			HIP_IFEL(send_anchor_change_to_hipd(entry), -1,
					"unable to notify hipd about hchain change\n");

			err = 0;
		}
	}

  out_err:
	return err;
}

/* verifies received hchain-elements - should only be called with ESP
 * extension in use
 *
 * returns 0 - ok or UNUSED, < 0 err, > 0 anchor change */
int esp_prot_verify_hash(hash_function_t hash_function, int hash_length,
		unsigned char *active_anchor, unsigned char *next_anchor,
		unsigned char *hash_value, int tolerance)
{
	int err = 0;

	HIP_ASSERT(hash_function != NULL);
	HIP_ASSERT(hash_length > 0);
	HIP_ASSERT(active_anchor != NULL);
	// next_anchor may be NULL
	HIP_ASSERT(hash_value != NULL);
	HIP_ASSERT(tolerance >= 0);

	HIP_DEBUG("hash length is %i\n", hash_length);
	HIP_HEXDUMP("active_anchor: ", active_anchor, hash_length);
	HIP_DEBUG("hchain element of incoming packet to be verified:\n");
	HIP_HEXDUMP("-> ", hash_value, hash_length);

	HIP_DEBUG("checking active_anchor...\n");
	if (hchain_verify(hash_value, active_anchor, hash_function,
			hash_length, tolerance))
	{
		// this will allow only increasing elements to be accepted
		memcpy(active_anchor, hash_value, hash_length);

		HIP_DEBUG("hash matches element in active hash-chain\n");

	} else
	{
		if (next_anchor != NULL)
		{
			/* there might still be a chance that we have to switch to the
			 * next hchain implicitly */
			HIP_DEBUG("checking next_anchor...\n");
			HIP_HEXDUMP("next_anchor: ", next_anchor, hash_length);

			if (hchain_verify(hash_value, next_anchor, hash_function,
					hash_length, tolerance))
			{
				HIP_DEBUG("hash matches element in next hash-chain\n");

				// we have to notify about the change
				err = 1;

			} else
			{
				// handle incorrect elements -> drop packet
				err = -1;
				goto out_err;
			}

		} else
		{
			// handle incorrect elements -> drop packet
			err = -1;
			goto out_err;
		}
	}

  out_err:
	if (err == -1)
	{
		HIP_DEBUG("INVALID hash-chain element!\n");
	}

    return err;
}

/* returns NULL for UNUSED transform */
esp_prot_tfm_t * esp_prot_resolve_transform(uint8_t transform)
{
	// esp_prot_transform >= 0 due to data-type
	HIP_ASSERT(transform <= NUM_TRANSFORMS);

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

	// esp_prot_transform >= 0 due to data-type
	HIP_ASSERT(transform <= NUM_TRANSFORMS);

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

	// esp_prot_transform >= 0 due to data-type
	HIP_ASSERT(transform <= NUM_TRANSFORMS);

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
	// esp_prot_transform >= 0 due to data-type
	HIP_ASSERT(transform <= NUM_TRANSFORMS);

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

int esp_prot_get_data_offset(hip_sa_entry_t *entry)
{
	HIP_ASSERT(entry != NULL);
	// esp_prot_transform >= 0 due to data-type
	HIP_ASSERT(entry->esp_prot_transform <= NUM_TRANSFORMS);

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
	// esp_prot_transform >= 0 due to data-type
	HIP_ASSERT(entry->esp_prot_transform <= NUM_TRANSFORMS);

	// first check the extension is used for this connection
	if (entry->esp_prot_transform > ESP_PROT_TFM_UNUSED)
	{
		HIP_ASSERT(entry->esp_prot_transform > 0
				&& entry->esp_prot_transform <= NUM_TRANSFORMS);

		/* make sure that the next hash-chain is set up before the active one
		 * depletes */
		if (!entry->next_hchain && entry->active_hchain->remaining
					<= entry->active_hchain->hchain_length * REMAIN_HASHES_TRESHOLD)
		{
			HIP_IFEL(!(prot_transform = esp_prot_resolve_transform(entry->esp_prot_transform)),
					1, "tried to resolve UNUSED transform\n");

			//printf("next_hchain should be set now...\n");

			/* set next hchain with DEFAULT_HCHAIN_LENGTH_ID
			 *
			 * @note this needs to be extended when implementing usage of different
			 *       hchain lengths
			 */
			HIP_IFEL(!(entry->next_hchain = hcstore_get_hchain(&update_store,
					prot_transform->hash_func_id, prot_transform->hash_length_id,
					update_hchain_lengths[DEFAULT_HCHAIN_LENGTH_ID])),
					-1, "unable to retrieve hchain from store\n");

			//printf("is set\n");

			// issue UPDATE message to be sent by hipd
			HIP_IFEL(send_trigger_update_to_hipd(entry), -1,
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

			/* notify hipd about the switch to the next hash-chain for
			 * consistency reasons */
			HIP_IFEL(send_anchor_change_to_hipd(entry), -1,
					"unable to notify hipd about hchain change\n");
		}
	}

  out_err:
    return err;
}
