/*
 * esp_prot_conntrack.c
 *
 * Author: Rene Hummen <rene.hummen@rwth-aachen.de>
 */

#include "esp_prot_conntrack.h"
#include "esp_prot_api.h"
#include "linkedlist.h"
#include "hslist.h"
#include "hip_statistics.h"

esp_prot_conntrack_tfm_t esp_prot_conntrack_tfms[NUM_TRANSFORMS];

#ifdef CONFIG_HIP_MEASUREMENTS
// for measuring the amount of hashes calculated during a connection
statistics_data_t hash_distance;
// for measuring the amount of failed hashes (reordering)
statistics_data_t subsequent_failed_hashes;
uint64_t subseq_failed_hashes;
#endif


int esp_prot_conntrack_init()
{
	int transform_id = 0;
	extern const hash_function_t hash_functions[NUM_HASH_FUNCTIONS];
	extern const int hash_lengths[NUM_HASH_FUNCTIONS][NUM_HASH_LENGTHS];
	int err = 0, i, j, g;

	HIP_DEBUG("Initializing conntracking of esp protection extension...\n");

#ifdef CONFIG_HIP_MEASUREMENTS
	memset(&hash_distance, 0, sizeof(statistics_data_t));
	memset(&subsequent_failed_hashes, 0, sizeof(statistics_data_t));
	subseq_failed_hashes = 0;
#endif

	/* set up mapping of esp protection transforms to hash functions and lengths */
	for (i = 0; i < NUM_HASH_FUNCTIONS; i++)
	{
		for (j = 0; j < NUM_HASH_LENGTHS; j++)
		{
			if (hash_lengths[i][j] > 0)
			{
				// ensure correct boundaries
				HIP_ASSERT(transform_id < NUM_TRANSFORMS);

				// store these IDs in the transforms array
				HIP_DEBUG("adding transform: %i\n", transform_id + 1);

				esp_prot_conntrack_tfms[transform_id].hash_function = hash_functions[i];
				esp_prot_conntrack_tfms[transform_id].hash_length = hash_lengths[i][j];

				transform_id++;
			}
		}
	}

  out_err:
	return err;
}

int esp_prot_conntrack_uninit()
{
	int err = 0, i;
#ifdef CONFIG_HIP_MEASUREMENTS
	uint32_t num_items = 0;
	double min = 0.0, max = 0.0, avg = 0.0, std_dev = 0.0;
#endif

	// set transforms to 0/NULL
	for (i = 0; i < NUM_TRANSFORMS; i++)
	{
		esp_prot_conntrack_tfms[i].hash_function = NULL;
		esp_prot_conntrack_tfms[i].hash_length = 0;
	}

#ifdef CONFIG_HIP_MEASUREMENTS
	//calculate statistics for distance measurements
	calc_statistics(&hash_distance, &num_items, &min, &max, &avg, &std_dev,
			STATS_NO_CONV);
	printf("hash distance - num_data_items: %u, min: %.3f, max: %.3f, avg: %.3f, std_dev: %.3f\n",
			num_items, min, max, avg, std_dev);

	// calculate failed hashes measurements
	calc_statistics(&subsequent_failed_hashes, &num_items, &min, &max, &avg, &std_dev,
			STATS_NO_CONV);
	printf("subsequent failed hashes - num_data_items: %u, min: %.3f, max: %.3f, avg: %.3f, std_dev: %.3f\n",
			num_items, min, max, avg, std_dev);

	printf("total hashes - failed: %u, seen: %u, ",
			subsequent_failed_hashes.added_values, hash_distance.num_items);
	if (hash_distance.num_items > 0)
	{
		printf("failed (in percent): %.3f\n",
				((subsequent_failed_hashes.added_values * 100.0) / hash_distance.num_items));
	} else
	{
		printf("failed (in percent): 0.000\n");
	}

#endif

  out_err:
	return err;
}

/* returns NULL for UNUSED transform */
esp_prot_conntrack_tfm_t * esp_prot_conntrack_resolve_transform(uint8_t transform)
{
	// esp_prot_transform >= 0 due to data-type
	HIP_ASSERT(transform <= NUM_TRANSFORMS);

	HIP_DEBUG("resolving transform: %u\n", transform);

	if (transform > ESP_PROT_TFM_UNUSED)
		return &esp_prot_conntrack_tfms[transform - 1];
	else
		return NULL;
}

int esp_prot_conntrack_R1_tfms(struct hip_common * common, const struct tuple * tuple)
{
	struct hip_param *param = NULL;
	struct esp_prot_preferred_tfms *prot_transforms = NULL;
	int err = 0, i;

	// initialize the ESP protection params in the connection
	tuple->connection->num_esp_prot_tfms = 0;
	memset(tuple->connection->esp_prot_tfms, 0, NUM_TRANSFORMS + 1);

	// check if message contains optional ESP protection transforms
	if (param = hip_get_param(common, HIP_PARAM_ESP_PROT_TRANSFORMS))
	{
		HIP_DEBUG("ESP protection extension transforms found\n");

		prot_transforms = (struct esp_prot_preferred_tfms *) param;

		// make sure we only process as many transforms as we can handle
		if (prot_transforms->num_transforms > NUM_TRANSFORMS + 1)
		{
			HIP_DEBUG("received more transforms than we can handle, " \
					"processing max\n");

			// transforms + UNUSED
			tuple->connection->num_esp_prot_tfms = NUM_TRANSFORMS + 1;

		} else
		{
			tuple->connection->num_esp_prot_tfms = prot_transforms->num_transforms;
		}

		HIP_DEBUG("adding %i transforms...\n", tuple->connection->num_esp_prot_tfms);

		// store the transforms
		for (i = 0; i < tuple->connection->num_esp_prot_tfms; i++)
		{
			// only store transforms we support, >= UNUSED true to data-type
			if (prot_transforms->transforms[i] <= NUM_TRANSFORMS)
			{
				tuple->connection->esp_prot_tfms[i] = prot_transforms->transforms[i];

				HIP_DEBUG("added transform %i: %u\n", i + 1,
							tuple->connection->esp_prot_tfms[i]);

			} else
			{
				tuple->connection->esp_prot_tfms[i] = ESP_PROT_TFM_UNUSED;

				HIP_DEBUG("unknown transform, set to UNUSED\n");
			}
		}
	}

  out_err:
	return err;
}

int esp_prot_conntrack_I2_anchor(const struct hip_common *common,
		struct tuple *tuple)
{
	struct hip_param *param = NULL;
	struct esp_prot_anchor *prot_anchor = NULL;
	struct esp_tuple *esp_tuple = NULL;
	esp_prot_conntrack_tfm_t * conntrack_tfm = NULL;
	int hash_length = 0;
	int err = 0;

	HIP_ASSERT(common != NULL);
	HIP_ASSERT(tuple != NULL);

	// check if message contains optional ESP protection anchor
	if (param = hip_get_param(common, HIP_PARAM_ESP_PROT_ANCHOR))
	{
		prot_anchor = (struct esp_prot_anchor *) param;

		/* create esp_tuple for direction of this message only storing
		 * the sent anchor, no SPI known yet -> will be sent in R2
		 *
		 * @note this needs to be done as SPIs are signaled in one direction
		 *       but used in the other while anchors are signaled and used
		 *       in the same direction
		 */

		/* check esp_tuple count for this direction, should be 0 */
		HIP_IFEL(tuple->esp_tuples, -1,
				"expecting empty esp_tuple list, but it is NOT\n");

		HIP_IFEL(!(esp_tuple = malloc(sizeof(struct esp_tuple))), 0,
						"failed to allocate memory\n");
		memset(esp_tuple, 0, sizeof(struct esp_tuple));

		// check if the anchor has a supported transform
		if (esp_prot_check_transform(tuple->connection->num_esp_prot_tfms,
				tuple->connection->esp_prot_tfms,
				prot_anchor->transform) >= 0)
		{
			// it's one of the supported and advertised transforms
			esp_tuple->esp_prot_tfm = prot_anchor->transform;
			HIP_DEBUG("using esp prot transform: %u\n", esp_tuple->esp_prot_tfm);

			if (esp_tuple->esp_prot_tfm > ESP_PROT_TFM_UNUSED)
			{
				conntrack_tfm = esp_prot_conntrack_resolve_transform(
						esp_tuple->esp_prot_tfm);
				hash_length = conntrack_tfm->hash_length;

				// store the anchor
				HIP_IFEL(!(esp_tuple->active_anchor = (unsigned char *)
						malloc(hash_length)), -1, "failed to allocate memory\n");
				memcpy(esp_tuple->active_anchor, &prot_anchor->anchors[0],
						hash_length);

				// ...and make a backup of it for later verification of UPDATEs
				HIP_IFEL(!(esp_tuple->first_active_anchor = (unsigned char *)
						malloc(hash_length)), -1, "failed to allocate memory\n");
				memcpy(esp_tuple->first_active_anchor, &prot_anchor->anchors[0],
						hash_length);

				HIP_HEXDUMP("received anchor: ", esp_tuple->active_anchor,
						hash_length);

				// add the tuple to this direction's esp_tuple list
				HIP_IFEL(!(tuple->esp_tuples = append_to_slist(tuple->esp_tuples,
						esp_tuple)), -1, "failed to insert esp_tuple\n");

			} else
			{
				HIP_DEBUG("received anchor with non-matching transform, DROPPING\n");

				err = 1;
				goto out_err;
			}
		} else
		{
			HIP_ERROR("received anchor with unknown transform, DROPPING\n");

			err = 1;
			goto out_err;
		}

		// finally init the anchor cache needed for tracking UPDATEs
		hip_ll_init(&esp_tuple->anchor_cache);
	}

  out_err:
	if (err)
	{
		if (esp_tuple)
		{
			if (esp_tuple->active_anchor)
				free(esp_tuple->active_anchor);

			free(esp_tuple);
			esp_tuple = NULL;
		}
	}

	return err;
}

struct esp_tuple * esp_prot_conntrack_R2_esp_tuple(SList *other_dir_esps)
{
	struct esp_tuple *esp_tuple = NULL;
	int err = 0;

	/* normally there should NOT be any esp_tuple for the other direction yet,
	 * but when tracking anchor elements, the other one was already set up
	 * when handling the I2 */
	if (other_dir_esps)
	{
		/* there should only be one esp_tuple in the other direction's esp_tuple
		 * list */
		HIP_IFEL(other_dir_esps->next, -1,
				"expecting 1 esp_tuple in the list, but there are several\n");

		// get the esp_tuple for the other direction
		HIP_IFEL(!(esp_tuple = (struct esp_tuple *) other_dir_esps->data), -1,
				"expecting 1 esp_tuple in the list, but there is NONE\n");

	}

  out_err:
	if (err)
	{
		esp_tuple = NULL;
	}

	return esp_tuple;
}

int esp_prot_conntrack_R2_anchor(const struct hip_common *common,
		struct tuple *tuple)
{
	struct hip_param *param = NULL;
	struct esp_prot_anchor *prot_anchor = NULL;
	struct esp_tuple *esp_tuple = NULL;
	esp_prot_conntrack_tfm_t * conntrack_tfm = NULL;
	int hash_length = 0;
	int err = 0;

	HIP_ASSERT(common != NULL);
	HIP_ASSERT(tuple != NULL);

	// check if message contains optional ESP protection anchor
	if (param = hip_get_param(common, HIP_PARAM_ESP_PROT_ANCHOR))
	{
		prot_anchor = (struct esp_prot_anchor *) param;

		// check if the anchor has a supported transform
		if (esp_prot_check_transform(tuple->connection->num_esp_prot_tfms,
				tuple->connection->esp_prot_tfms,
				prot_anchor->transform) >= 0)
		{
			// for BEX there should be only one ESP tuple for this direction
			HIP_IFEL(tuple->esp_tuples->next, -1,
					"expecting 1 esp_tuple in the list, but there are several\n");

			HIP_IFEL(!(esp_tuple = (struct esp_tuple *) tuple->esp_tuples->data), -1,
					"expecting 1 esp_tuple in the list, but there is NONE\n");

			esp_tuple->esp_prot_tfm = prot_anchor->transform;
			HIP_DEBUG("using esp prot transform: %u\n", esp_tuple->esp_prot_tfm);

			if (esp_tuple->esp_prot_tfm > ESP_PROT_TFM_UNUSED)
			{
				conntrack_tfm = esp_prot_conntrack_resolve_transform(
						esp_tuple->esp_prot_tfm);
				hash_length = conntrack_tfm->hash_length;

				// store the anchor
				HIP_IFEL(!(esp_tuple->active_anchor = (unsigned char *)
						malloc(hash_length)), -1, "failed to allocate memory\n");
				memcpy(esp_tuple->active_anchor, &prot_anchor->anchors[0],
						hash_length);

				// ...and make a backup of it for later verification of UPDATEs
				HIP_IFEL(!(esp_tuple->first_active_anchor = (unsigned char *)
						malloc(hash_length)), -1, "failed to allocate memory\n");
				memcpy(esp_tuple->first_active_anchor, &prot_anchor->anchors[0],
						hash_length);

				HIP_HEXDUMP("received anchor: ", esp_tuple->active_anchor,
						hash_length);

			} else
			{
				HIP_DEBUG("received anchor with non-matching transform, DROPPING\n");

				err = 1;
				goto out_err;
			}
		} else
		{
			HIP_ERROR("received anchor with unknown transform, DROPPING\n");

			err = 1;
			goto out_err;
		}

		// finally init the anchor cache needed for tracking UPDATEs
		hip_ll_init(&esp_tuple->anchor_cache);
	}

  out_err:
	return err;
}

int esp_prot_conntrack_update(const hip_common_t *update, struct tuple * tuple)
{
	struct hip_seq *seq = NULL;
	struct hip_ack *ack = NULL;
	struct hip_esp_info *esp_info = NULL;
	struct esp_prot_anchor *esp_anchor = NULL;
	struct esp_prot_root *esp_root = NULL;
	int err = 0;

	HIP_ASSERT(update != NULL);
	HIP_ASSERT(tuple != NULL);

	seq = (struct hip_seq *) hip_get_param(update, HIP_PARAM_SEQ);
	esp_info = (struct hip_esp_info *) hip_get_param(update, HIP_PARAM_ESP_INFO);
	ack = (struct hip_ack *) hip_get_param(update, HIP_PARAM_ACK);
	esp_anchor = (struct esp_prot_anchor *) hip_get_param(update,
			HIP_PARAM_ESP_PROT_ANCHOR);

	// distinguish packet types and process accordingly
	if (seq && !ack && !esp_info && esp_anchor)
	{
		HIP_DEBUG("received 1. UPDATE packet of ANCHOR UPDATE\n");

		esp_root = (struct esp_prot_root *) hip_get_param(update,
				HIP_PARAM_ESP_PROT_ROOT);

		// cache ANCHOR
		HIP_IFEL(esp_prot_conntrack_cache_anchor(tuple, seq, esp_anchor, esp_root), -1,
				"failed to cache ANCHOR parameter\n");

	} else if (seq && ack && esp_info && esp_anchor)
	{
		/* either 2. UPDATE packet of mutual ANCHOR UPDATE or LOCATION UPDATE */
		// TODO implement

		HIP_ERROR("not implemented yet\n");
		err = -1;

	} else if (!seq && ack && esp_info && !esp_anchor)
	{
		HIP_DEBUG("either received 2. UPDATE packet of ANCHOR UPDATE or 3. of mutual one\n");

		// lookup cached ANCHOR and update corresponding esp_tuple
		HIP_IFEL(esp_prot_conntrack_update_anchor(tuple, ack, esp_info), -1,
				"failed to update anchor\n");

	} else if (!seq && ack && esp_info && esp_anchor)
	{
		/* 3. UPDATE packet of LOCATION UPDATE */
		// TODO implement

		HIP_ERROR("not implemented yet\n");
		err = -1;

	} else
	{
		HIP_DEBUG("unknown HIP-parameter combination, unhandled\n");
	}

  out_err:
	return err;
}

/* caches an anchor found in a update message in the current direction's
 * tuple indexed with the SEQ number for reference reasons with consecutive
 * update replies */
int esp_prot_conntrack_cache_anchor(struct tuple * tuple, struct hip_seq *seq,
		struct esp_prot_anchor *esp_anchor, struct esp_prot_root *esp_root)
{
	struct esp_anchor_item *anchor_item = NULL;
	unsigned char *cmp_value = NULL;
	struct esp_tuple *esp_tuple = NULL;
	esp_prot_conntrack_tfm_t * conntrack_tfm = NULL;
	int hash_length = 0;
	int err = 0;

	HIP_ASSERT(tuple != NULL);
	HIP_ASSERT(seq != NULL);
	HIP_ASSERT(esp_anchor != NULL);

	HIP_DEBUG("caching update anchor...\n");

	// needed for allocating and copying the anchors
	conntrack_tfm = esp_prot_conntrack_resolve_transform(
			esp_anchor->transform);
	hash_length = conntrack_tfm->hash_length;

	HIP_IFEL(!(esp_tuple = esp_prot_conntrack_find_esp_tuple(tuple,
			&esp_anchor->anchors[0], hash_length)), -1,
			"failed to look up matching esp_tuple\n");

	HIP_IFEL(!(anchor_item = (struct esp_anchor_item *)
			malloc(sizeof(struct esp_anchor_item))), -1,
			"failed to allocate memory\n");

	// active_anchor has to be present at least
	HIP_IFEL(!(anchor_item->active_anchor = (unsigned char *)
			malloc(hash_length)), -1, "failed to allocate memory\n");

	HIP_DEBUG("setting active_anchor\n");
	anchor_item->seq = seq->update_id;
	anchor_item->transform = esp_anchor->transform;
	memcpy(anchor_item->active_anchor, &esp_anchor->anchors[0], hash_length);

	// malloc and set cmp_value to be 0
	HIP_IFEL(!(cmp_value = (unsigned char *)
			malloc(hash_length)), -1, "failed to allocate memory\n");
	memset(cmp_value, 0, hash_length);

	// check if next_anchor is set
	if (memcmp(&esp_anchor->anchors[hash_length], cmp_value, hash_length))
	{
		HIP_HEXDUMP("setting cache->next_anchor: ", &esp_anchor->anchors[hash_length],
				hash_length);

		// also copy this anchor as it is set
		HIP_IFEL(!(anchor_item->next_anchor = (unsigned char *)
				malloc(hash_length)), -1, "failed to allocate memory\n");

		memcpy(anchor_item->next_anchor, &esp_anchor->anchors[hash_length],
				hash_length);

	} else
	{
		HIP_DEBUG("setting next_anchor to NULL\n");

		anchor_item->next_anchor = NULL;
	}

	// also set the root for the link_tree of the next hchain, if provided
	if (esp_root)
	{
		HIP_HEXDUMP("setting cache->root: ", esp_root->root, esp_root->root_length);

		HIP_IFEL(!(anchor_item->root = (unsigned char *)
				malloc(esp_root->root_length)), -1, "failed to allocate memory\n");

		anchor_item->root_length = esp_root->root_length;
		memcpy(anchor_item->root, esp_root->root, esp_root->root_length);
	}

	// add this anchor to the list for this direction's tuple
	HIP_DEBUG("adding anchor_item to cache for matching tuple\n");

	HIP_IFEL(hip_ll_add_first(&esp_tuple->anchor_cache, anchor_item), -1,
			"failed to add anchor_item to anchor_cache\n");

  out_err:
	return err;
}

/* returns -1 on err, 1 if not found, 0 if ok */
int esp_prot_conntrack_update_anchor(struct tuple *tuple, struct hip_ack *ack,
		struct hip_esp_info *esp_info)
{
	struct esp_anchor_item *anchor_item = NULL;
	struct tuple *other_dir_tuple = NULL;
	struct esp_tuple *esp_tuple = NULL;
	esp_prot_conntrack_tfm_t * conntrack_tfm = NULL;
	int hash_length = 0;
	// assume not found
	int err = 0, i;

	HIP_ASSERT(tuple != NULL);
	HIP_ASSERT(ack != NULL);
	HIP_ASSERT(esp_info != NULL);

	HIP_DEBUG("checking anchor cache for this direction...\n");

	if(tuple->direction == ORIGINAL_DIR)
	{
		other_dir_tuple = &tuple->connection->reply;

	} else
	{
		other_dir_tuple = &tuple->connection->original;
	}

	// get corresponding esp_tuple by spi
	HIP_IFEL(!(esp_tuple = find_esp_tuple(other_dir_tuple->esp_tuples,
			ntohl(esp_info->old_spi))), -1,
			"failed to look up esp_tuple\n");
	HIP_DEBUG("found esp_tuple for received ESP_INFO\n");

	for (i = 0; i < hip_ll_get_size(&esp_tuple->anchor_cache); i++)
	{
		HIP_IFEL(!(anchor_item = (struct esp_anchor_item *)
				hip_ll_get(&esp_tuple->anchor_cache, i)), -1,
				"failed to look up anchor_item\n");

		if (anchor_item->seq == ack->peer_update_id)
		{
			HIP_DEBUG("found match in the cache\n");

			// needed for allocating and copying the anchors
			conntrack_tfm = esp_prot_conntrack_resolve_transform(
					esp_tuple->esp_prot_tfm);
			hash_length = conntrack_tfm->hash_length;

			HIP_HEXDUMP("esp_tuple->active_anchor: ",
					esp_tuple->first_active_anchor, hash_length);
			HIP_HEXDUMP("anchor_item->active_anchor: ", anchor_item->active_anchor,
					hash_length);

			// delete cached item from the list
			HIP_IFEL(!(anchor_item = (struct esp_anchor_item *)
					hip_ll_del(&esp_tuple->anchor_cache, i, NULL)), -1,
					"failed to remove anchor_item from list\n");

			// update the esp_tuple
			esp_tuple->next_anchor = anchor_item->next_anchor;
			esp_tuple->next_root_length = anchor_item->root_length;
			esp_tuple->next_root = anchor_item->root;

			HIP_HEXDUMP("anchor_item->next_anchor: ", anchor_item->next_anchor,
					hash_length);
			HIP_HEXDUMP("anchor_item->root: ", anchor_item->root,
					anchor_item->root_length);

			// free the cached item, but NOT next_anchor and root as in use now
			free(anchor_item->active_anchor);
			free(anchor_item);

			HIP_DEBUG("next_anchor of esp_tuple updated\n");

			err = 0;
			goto out_err;
		}
	}

	HIP_DEBUG("no matching ANCHOR UPDATE cached\n");
	err = -1;

  out_err:
	return err;
}

int esp_prot_conntrack_verify(struct esp_tuple *esp_tuple, struct hip_esp *esp)
{
	esp_prot_conntrack_tfm_t * conntrack_tfm = NULL;
	uint32_t num_verify = 0;
	int err = 0;

	// esp_prot_transform >= 0 due to data-type
	HIP_ASSERT(esp_tuple->esp_prot_tfm <= NUM_TRANSFORMS);

	if (esp_tuple->esp_prot_tfm > ESP_PROT_TFM_UNUSED)
	{
		conntrack_tfm = esp_prot_conntrack_resolve_transform(
				esp_tuple->esp_prot_tfm);

		_HIP_DEBUG("stored seq no: %u\n", esp_tuple->seq_no);
		_HIP_DEBUG("received seq no: %u\n", ntohl(esp->esp_seq));

		/* calculate difference of SEQ no in order to determine how many hashes
		 * we have to calculate */
		if (ntohl(esp->esp_seq) - esp_tuple->seq_no > 0 &&
				ntohl(esp->esp_seq) - esp_tuple->seq_no <= DEFAULT_VERIFY_WINDOW)
		{
			num_verify = ntohl(esp->esp_seq) - esp_tuple->seq_no;
		} else
		{
			/* either we received a previous packet (-> dropped) or the difference is
			 * so big that the packet would not be verified */
			HIP_DEBUG("seq no difference < 0 or too high\n");

			err = -1;
			goto out_err;
		}

		/* check ESP protection anchor if extension is in use */
		HIP_IFEL((err = esp_prot_verify_hash(conntrack_tfm->hash_function,
				conntrack_tfm->hash_length,
				esp_tuple->active_anchor, esp_tuple->next_anchor,
				((unsigned char *) esp) + sizeof(struct hip_esp),
				num_verify, esp_tuple->active_root, esp_tuple->active_root_length,
				esp_tuple->next_root, esp_tuple->next_root_length)) < 0, -1,
				"failed to verify ESP protection hash\n");

		// this means there was a change in the anchors
		if (err > 0)
		{
			HIP_DEBUG("anchor change occurred, handled now\n");

			// don't copy the next anchor, but the already verified hash
			memcpy(esp_tuple->active_anchor, ((unsigned char *) esp) + sizeof(struct hip_esp),
					conntrack_tfm->hash_length);
			memcpy(esp_tuple->first_active_anchor, esp_tuple->next_anchor,
					conntrack_tfm->hash_length);

			// change roots
			/* the BEX-store does not have hierarchies, so no root is used for
			 * the first hchain */
			if (esp_tuple->active_root)
			{
				HIP_ASSERT(0);
				free(esp_tuple->active_root);
			}
			HIP_ASSERT(0);
			esp_tuple->active_root = esp_tuple->next_root;
			esp_tuple->next_root = NULL;
			esp_tuple->active_root_length = esp_tuple->next_root_length;
			esp_tuple->next_root_length = 0;

			free(esp_tuple->next_anchor);
			esp_tuple->next_anchor = NULL;

			// no error case
			err = 0;
		}
	} else
	{
		HIP_DEBUG("esp protection extension UNUSED\n");

		// this explicitly is no error condition
		err = 0;
	}

  out_err:
#ifdef CONFIG_HIP_MEASUREMENTS
	// count how many subsequent packets could not be verified
	if (err)
		subseq_failed_hashes++;
	else if (subseq_failed_hashes > 0)
		add_statistics_item(&subsequent_failed_hashes, subseq_failed_hashes);
#endif

	return err;
}

struct esp_tuple * esp_prot_conntrack_find_esp_tuple(struct tuple * tuple,
		unsigned char *active_anchor, int hash_length)
{
	struct esp_tuple *esp_tuple = NULL;
	SList *list = NULL;
	struct esp_anchor_item *anchor_item = NULL;
	int err = 0;

	HIP_ASSERT(tuple != NULL);

	HIP_HEXDUMP("received active anchor: ", active_anchor, hash_length);

	list = tuple->esp_tuples;

	while(list)
	{
		esp_tuple = (struct esp_tuple *) list->data;

		// check if last installed anchor equals the one in the packet
		if (!memcmp(esp_tuple->first_active_anchor, active_anchor, hash_length))
		{
			HIP_DEBUG("found matching active anchor in esp_tuples\n");

			HIP_HEXDUMP("stored active anchor: ", esp_tuple->first_active_anchor,
					hash_length);

			goto out_err;
		}

		list = list->next;
	}

	HIP_DEBUG("no esp_tuple with matching anchor found\n");
	err = -1;

  out_err:
	if (err)
		esp_tuple = NULL;

	return esp_tuple;
}
