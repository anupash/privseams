/*
 * esp_prot_fw_msg.c
 *
 *  Created on: Jul 20, 2008
 *      Author: Rene Hummen <rene.hummen@rwth-aachen.de>
 */

#include "esp_prot_fw_msg.h"
#include "esp_prot_common.h"
#include "esp_prot_api.h"
#include "hslist.h"

/* this sends the preferred transform to hipd implicitely turning on
 * the esp protection extension there */
int send_esp_prot_to_hipd(int activate)
{
	struct hip_common *msg = NULL;
	int num_transforms = 0;
	uint8_t transform = 0;
	int err = 0, i;
	extern const uint8_t preferred_transforms[];

	HIP_ASSERT(activate >= 0);

	HIP_IFEL(!(msg = HIP_MALLOC(HIP_MAX_PACKET, 0)), -1,
		 "failed to allocate memory\n");

	hip_msg_init(msg);

	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_ESP_PROT_TFM, 0), -1,
		 "build hdr failed\n");

	if (activate > 0)
	{
		/*** activation case ***/
		HIP_DEBUG("sending preferred esp prot transforms to hipd...\n");

		// all "in use" transforms + UNUSED
		num_transforms = NUM_TRANSFORMS + 1;

		HIP_DEBUG("adding num_transforms: %i\n", num_transforms);
		HIP_IFEL(hip_build_param_contents(msg, (void *)&num_transforms,
				HIP_PARAM_INT, sizeof(int)), -1,
				"build param contents failed\n");

		for (i = 0; i < num_transforms; i++)
		{
			HIP_DEBUG("adding transform %i: %u\n", i + 1, preferred_transforms[i]);
			HIP_IFEL(hip_build_param_contents(msg, (void *)&preferred_transforms[i],
					HIP_PARAM_ESP_PROT_TFM, sizeof(uint8_t)), -1,
					"build param contents failed\n");
		}
	} else
	{
		/*** deactivation case ***/
		HIP_DEBUG("sending esp prot transform ESP_PROT_TFM_UNUSED to hipd...\n");

		// we are only sending ESP_PROT_TFM_UNUSED
		num_transforms = 1;
		transform = ESP_PROT_TFM_UNUSED;

		HIP_DEBUG("adding num_transforms: %i\n", num_transforms);
		HIP_IFEL(hip_build_param_contents(msg, (void *)&num_transforms,
				HIP_PARAM_INT, sizeof(int)), -1,
				"build param contents failed\n");

		HIP_DEBUG("adding transform ESP_PROT_TFM_UNUSED: %u\n", transform);
		HIP_IFEL(hip_build_param_contents(msg, (void *)&transform,
				HIP_PARAM_ESP_PROT_TFM, sizeof(uint8_t)), -1,
				"build param contents failed\n");
	}

	HIP_DUMP_MSG(msg);

	/* send msg to hipd and receive corresponding reply */
	HIP_IFEL(hip_send_recv_daemon_info(msg), -1, "send_recv msg failed\n");

	/* check error value */
	HIP_IFEL(hip_get_msg_err(msg), -1, "hipd returned error message!\n");

	HIP_DEBUG("send_recv msg succeeded\n");

 out_err:
	if (msg)
		free(msg);

	return err;
}

/* sends a list of all available anchor elements in the bex store
 * to the hipd, which then draws the element used in the bex from
 * this list */
int send_bex_store_update_to_hipd(hchain_store_t *hcstore)
{
	struct hip_common *msg = NULL;
	int hash_length = 0;
	int err = 0;

	HIP_ASSERT(hcstore != NULL);

	HIP_DEBUG("sending bex-store update to hipd...\n");

	HIP_IFEL(!(msg = (struct hip_common *)create_bex_store_update_msg(hcstore)),
			-1, "failed to create bex store anchors update message\n");

	HIP_DUMP_MSG(msg);

	/* send msg to hipd and receive corresponding reply */
	HIP_IFEL(hip_send_recv_daemon_info(msg), -1, "send_recv msg failed\n");

	/* check error value */
	HIP_IFEL(hip_get_msg_err(msg), -1, "hipd returned error message!\n");

	HIP_DEBUG("send_recv msg succeeded\n");

 out_err:
	if (msg)
		free(msg);

	return err;
}

/* @note this will only consider the first hchain item in each shelf, as only
 *       this should be set up for the store containing the hchains for the BEX
 * @note the created message contains hash_length and anchors for each transform
 */
hip_common_t *create_bex_store_update_msg(hchain_store_t *hcstore)
{
	struct hip_common *msg = NULL;
	int hash_length = 0, num_hchains = 0;
	esp_prot_tfm_t *transform = NULL;
	hash_chain_t *hchain = NULL;
	unsigned char *anchor = NULL;
	int err = 0, j;
	uint8_t i;

	HIP_ASSERT(hcstore != NULL);

	HIP_IFEL(!(msg = HIP_MALLOC(HIP_MAX_PACKET, 0)), -1,
		 "failed to allocate memory\n");

	hip_msg_init(msg);

	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_BEX_STORE_UPDATE, 0), -1,
		 "build hdr failed\n");

	// first add hash_length and num_hchain for each transform
	for (i = 1; i <= NUM_TRANSFORMS; i++)
	{
		HIP_DEBUG("transform %i:\n", i);

		HIP_IFEL(!(transform = esp_prot_resolve_transform(i)), -1,
				"failed to resolve transform\n");

		HIP_IFEL((hash_length = esp_prot_get_hash_length(i)) <= 0, -1,
				"hash_length <= 0, expecting something bigger\n");

		HIP_IFEL((num_hchains = hip_ll_get_size(&hcstore->hchain_shelves[transform->hash_func_id]
		        [transform->hash_length_id].hchains[DEFAULT_HCHAIN_LENGTH_ID])) <= 0, -1,
				"num_hchains <= 0, expecting something bigger\n");

		// add num_hchains for this transform, needed on receiver side
		HIP_IFEL(hip_build_param_contents(msg, (void *)&num_hchains,
				HIP_PARAM_INT, sizeof(int)), -1,
				"build param contents failed\n");
		HIP_DEBUG("added num_hchains: %i\n", num_hchains);

		// add the hash_length for this transform, needed on receiver side
		HIP_IFEL(hip_build_param_contents(msg, (void *)&hash_length,
				HIP_PARAM_INT, sizeof(int)), -1,
				"build param contents failed\n");
		HIP_DEBUG("added hash_length: %i\n", hash_length);
	}

	// now add the hchain anchors
	for (i = 1; i <= NUM_TRANSFORMS; i++)
	{
		HIP_DEBUG("transform %i:\n", i);

		HIP_IFEL(!(transform = esp_prot_resolve_transform(i)), -1,
				"failed to resolve transform\n");

		HIP_IFEL((hash_length = esp_prot_get_hash_length(i)) <= 0, -1,
				"hash_length <= 0, expecting something bigger\n");

		// ensure correct boundaries
		HIP_ASSERT(transform->hash_func_id >= 0
				&& transform->hash_func_id < NUM_HASH_FUNCTIONS);
		HIP_ASSERT(transform->hash_length_id >= 0
				&& transform->hash_length_id < NUM_HASH_LENGTHS);

		// add anchor with this transform
		for (j = 0; j <  hip_ll_get_size(&hcstore->hchain_shelves[transform->hash_func_id]
				[transform->hash_length_id].hchains[DEFAULT_HCHAIN_LENGTH_ID]); j++)
		{
			HIP_IFEL(!(hchain = hip_ll_get(&hcstore->hchain_shelves[transform->hash_func_id]
				[transform->hash_length_id].hchains[DEFAULT_HCHAIN_LENGTH_ID], j)), -1,
				"failed to retrieve hchain\n");

			anchor = hchain->anchor_element->hash;
			HIP_IFEL(hip_build_param_contents(msg, (void *)anchor,
					HIP_PARAM_HCHAIN_ANCHOR, hash_length),
					-1, "build param contents failed\n");
			HIP_HEXDUMP("added anchor: ", anchor, hash_length);
		}
	}

  out_err:
  	if (err)
  	{
  		free(msg);
  		msg = NULL;
  	}

  	return msg;
}

/* invoke an UPDATE message containing the an anchor element as a hook to
 * entry->next_hchain to be used when the active one depletes
 *
 * sends src_hit, dst_hit, transform, hash_length and hash
 */
int send_trigger_update_to_hipd(hip_sa_entry_t *entry)
{
	int err = 0;
	struct hip_common *msg = NULL;
	int hash_length = 0;

	HIP_ASSERT(entry != NULL);

	// esp_prot_transform >= 0 due to datatype
	HIP_ASSERT(entry->esp_prot_transform <= NUM_TRANSFORMS);

	HIP_IFEL((hash_length = esp_prot_get_hash_length(entry->esp_prot_transform)) <= 0,
			-1, "error or tried to resolve UNUSED transform\n");

	HIP_IFEL(!(msg = HIP_MALLOC(HIP_MAX_PACKET, 0)), -1,
		 "failed to allocate memory\n");

	hip_msg_init(msg);

	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_TRIGGER_UPDATE, 0), -1,
		 "build hdr failed\n");

	HIP_DEBUG_HIT("src_hit", entry->inner_src_addr);
	HIP_IFEL(hip_build_param_contents(msg, (void *)entry->inner_src_addr,
			HIP_PARAM_HIT, sizeof(struct in6_addr)), -1, "build param contents failed\n");

	HIP_DEBUG_HIT("dst_hit", entry->inner_dst_addr);
	HIP_IFEL(hip_build_param_contents(msg, (void *)entry->inner_dst_addr,
			HIP_PARAM_HIT, sizeof(struct in6_addr)), -1, "build param contents failed\n");

	HIP_DEBUG("esp_prot_transform: %u\n", entry->esp_prot_transform);
	HIP_IFEL(hip_build_param_contents(msg, (void *)&entry->esp_prot_transform,
			HIP_PARAM_ESP_PROT_TFM, sizeof(uint8_t)), -1,
			"build param contents failed\n");

	HIP_HEXDUMP("anchor: ", entry->next_hchain->anchor_element->hash, hash_length);
	HIP_IFEL(hip_build_param_contents(msg, (void *)entry->next_hchain->anchor_element->hash,
			HIP_PARAM_HCHAIN_ANCHOR, hash_length), -1,
			"build param contents failed\n");

	HIP_DUMP_MSG(msg);

	/* send msg to hipd and receive corresponding reply */
	HIP_IFEL(hip_send_recv_daemon_info(msg), -1, "send_recv msg failed\n");

	/* check error value */
	HIP_IFEL(hip_get_msg_err(msg), -1, "hipd returned error message!\n");

	HIP_DEBUG("send_recv msg succeeded\n");

 out_err:
	if (msg)
		free(msg);

	return err;
}

int send_anchor_change_to_hipd(hip_sa_entry_t *entry)
{
	int err = 0;
	struct hip_common *msg = NULL;
	int hash_length = 0;
	int direction = 0;
	unsigned char *anchor = NULL;

	HIP_ASSERT(entry != NULL);

	// esp_prot_transform >= 0 due to datatype
	HIP_ASSERT(entry->esp_prot_transform <= NUM_TRANSFORMS);

	HIP_IFEL((hash_length = esp_prot_get_hash_length(entry->esp_prot_transform)) <= 0,
			-1, "error or tried to resolve UNUSED transform\n");

	if (entry->direction == HIP_SPI_DIRECTION_OUT)
	{
		anchor = entry->active_hchain->anchor_element->hash;

	} else
	{
		anchor = entry->active_anchor;
	}

	HIP_IFEL(!(msg = HIP_MALLOC(HIP_MAX_PACKET, 0)), -1,
		 "failed to allocate memory\n");

	hip_msg_init(msg);

	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_ANCHOR_CHANGE, 0), -1,
		 "build hdr failed\n");

	HIP_DEBUG_HIT("src_hit", entry->inner_src_addr);
	HIP_IFEL(hip_build_param_contents(msg, (void *)entry->inner_src_addr,
			HIP_PARAM_HIT, sizeof(struct in6_addr)), -1, "build param contents failed\n");

	HIP_DEBUG_HIT("dst_hit", entry->inner_dst_addr);
	HIP_IFEL(hip_build_param_contents(msg, (void *)entry->inner_dst_addr,
			HIP_PARAM_HIT, sizeof(struct in6_addr)), -1, "build param contents failed\n");

	HIP_DEBUG("direction: %i\n", entry->direction);
	HIP_IFEL(hip_build_param_contents(msg, (void *)&entry->direction,
			HIP_PARAM_INT, sizeof(int)), -1, "build param contents failed\n");

	HIP_DEBUG("esp_prot_transform: %u\n", entry->esp_prot_transform);
	HIP_IFEL(hip_build_param_contents(msg, (void *)&entry->esp_prot_transform,
			HIP_PARAM_ESP_PROT_TFM, sizeof(uint8_t)), -1,
			"build param contents failed\n");

	// the anchor change has already occured on fw-side
	HIP_HEXDUMP("anchor: ", anchor, hash_length);
	HIP_IFEL(hip_build_param_contents(msg, (void *)anchor,
			HIP_PARAM_HCHAIN_ANCHOR, hash_length), -1,
			"build param contents failed\n");

	HIP_DUMP_MSG(msg);

	/* send msg to hipd and receive corresponding reply */
	HIP_IFEL(hip_send_recv_daemon_info(msg), -1, "send_recv msg failed\n");

	/* check error value */
	HIP_IFEL(hip_get_msg_err(msg), -1, "hipd returned error message!\n");

	HIP_DEBUG("send_recv msg succeeded\n");

 out_err:
	if (msg)
		free(msg);

	return err;
}

unsigned char * esp_prot_handle_sa_add_request(struct hip_common *msg,
		uint8_t *esp_prot_transform)
{
	struct hip_tlv_common *param = NULL;
	unsigned char *esp_prot_anchor = NULL;
	int hash_length = 0, err = 0;
	*esp_prot_transform = 0;

	HIP_ASSERT(msg != NULL);
	HIP_ASSERT(esp_prot_transform != NULL);

	HIP_IFEL(!(param = (struct hip_tlv_common *)hip_get_param(msg, HIP_PARAM_ESP_PROT_TFM)),
			-1, "esp prot transform missing\n");
	*esp_prot_transform = *((uint8_t *) hip_get_param_contents_direct(param));
	HIP_DEBUG("esp protection transform is %u\n", *esp_prot_transform);

	// esp_prot_transform >= 0 due to datatype
	HIP_ASSERT(*esp_prot_transform <= NUM_TRANSFORMS);

	// this parameter is only included, if the esp extension is used
	if (*esp_prot_transform > ESP_PROT_TFM_UNUSED)
	{
		// retrieve hash length for the received transform
		HIP_IFEL((hash_length = esp_prot_get_hash_length(*esp_prot_transform)) <= 0,
				-1, "error or tried to resolve UNUSED transform\n");

		HIP_IFEL(!(param = (struct hip_tlv_common *) hip_get_param(msg, HIP_PARAM_HCHAIN_ANCHOR)),
				-1, "transform suggests anchor, but it is NOT included in msg\n");
		esp_prot_anchor = (unsigned char *) hip_get_param_contents_direct(param);
		HIP_HEXDUMP("esp protection anchor is ", esp_prot_anchor, hash_length);

	} else
	{
		esp_prot_anchor = NULL;
	}

  out_err:
	if (err)
	{
		esp_prot_anchor = NULL;
		*esp_prot_transform = 0;
	}

	return esp_prot_anchor;
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
				hash_length = esp_prot_get_hash_length(esp_tuple->esp_prot_tfm);

				// store the anchor
				HIP_IFEL(!(esp_tuple->active_anchor = (unsigned char *)
						malloc(hash_length)), -1, "failed to allocate memory\n");
				memcpy(esp_tuple->active_anchor, &prot_anchor->anchors[0], hash_length);

				HIP_HEXDUMP("received anchor: ", esp_tuple->active_anchor,
						hash_length);

				// add the tuple to this direction's esp_tuple list
				HIP_IFEL(!(tuple->esp_tuples =  append_to_slist(tuple->esp_tuples,
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
		hip_ll_init(&tuple->anchor_cache);
	}

  out_err:
	if (err)
	{
		if (esp_tuple)
		{
			if (esp_tuple->active_anchor)
				free(esp_tuple->active_anchor);

			free(esp_tuple);
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
				hash_length = esp_prot_get_hash_length(esp_tuple->esp_prot_tfm);

				// store the anchor
				HIP_IFEL(!(esp_tuple->active_anchor = (unsigned char *)
						malloc(hash_length)), -1, "failed to allocate memory\n");
				memcpy(esp_tuple->active_anchor, &prot_anchor->anchors[0], hash_length);

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
		hip_ll_init(&tuple->anchor_cache);
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
		/* 1. UPDATE packet of ANCHOR UPDATE */

		// cache ANCHOR
		HIP_IFEL(esp_prot_conntrack_cache_anchor(tuple, seq, esp_anchor), -1,
				"failed to cache ANCHOR parameter\n");

		HIP_DEBUG("getting here\n");

	} else if (seq && ack && esp_info && esp_anchor)
	{
		/* either 2. UPDATE packet of mutual ANCHOR UPDATE or LOCATION UPDATE */
		// TODO implement

		HIP_ERROR("not implemented yet\n");
		err = -1;

	} else if (!seq && ack && esp_info && !esp_anchor)
	{
		/* either 2. UPDATE packet of ANCHOR UPDATE or 3. of mutual one */

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
		struct esp_prot_anchor *esp_anchor)
{
	struct esp_anchor_item *anchor_item = NULL;
	unsigned char *cmp_value = NULL;
	int hash_length = 0;
	int err = 0;

	HIP_ASSERT(tuple != NULL);
	HIP_ASSERT(seq != NULL);
	HIP_ASSERT(esp_anchor != NULL);

	// needed for allocating and copying the anchors
	hash_length = esp_prot_get_hash_length(esp_anchor->transform);

	HIP_IFEL(!(anchor_item = (struct esp_anchor_item *)
			malloc(sizeof(struct esp_anchor_item))), -1,
			"failed to allocate memory\n");

	// active_anchor has to be present at least
	HIP_IFEL(!(anchor_item->active_anchor = (unsigned char *)
			malloc(hash_length)), -1, "failed to allocate memory\n");

	// malloc and set cmp_value to be 0
	HIP_IFEL(!(cmp_value = (unsigned char *)
			malloc(hash_length)), -1, "failed to allocate memory\n");
	memset(cmp_value, 0, hash_length);

	anchor_item->seq = seq->update_id;
	anchor_item->transform = esp_anchor->transform;
	memcpy(anchor_item->active_anchor, &esp_anchor->anchors[0], hash_length);

	// check if next_anchor is set
	if (memcmp(&esp_anchor->anchors[hash_length], cmp_value, hash_length))
	{
		// also copy this anchor as it is set
		HIP_IFEL(!(anchor_item->next_anchor = (unsigned char *)
				malloc(hash_length)), -1, "failed to allocate memory\n");

		memcpy(anchor_item->next_anchor, &esp_anchor->anchors[hash_length],
				hash_length);

	} else
	{
		anchor_item->next_anchor = NULL;
	}

	HIP_DEBUG("getting here\n");

	// add this anchor to the list for this direction's tuple
	HIP_IFEL(hip_ll_add_first(&tuple->anchor_cache, anchor_item), -1,
			"failed to add anchor_item to anchor_cache\n");

  out_err:
	return err;
}

/* returns -1 on err, 1 if not found, 0 if ok */
int esp_prot_conntrack_update_anchor(struct tuple *tuple, struct hip_ack *ack,
		struct hip_esp_info *esp_info)
{
	struct esp_anchor_item *anchor_item = NULL;
	struct esp_tuple *esp_tuple = NULL;
	int hash_length = 0;
	// assume not found
	int err = 1, i;

	HIP_ASSERT(tuple != NULL);
	HIP_ASSERT(ack != NULL);
	HIP_ASSERT(esp_info != NULL);

	for (i = 0; i < hip_ll_get_size(&tuple->anchor_cache); i++)
	{
		HIP_IFEL(!(anchor_item = (struct esp_anchor_item *)
				hip_ll_get(&tuple->anchor_cache, i)), -1,
				"failed to look up anchor_item\n");

		if (anchor_item->seq == ack->peer_update_id)
		{
			HIP_IFEL(!(esp_tuple = find_esp_tuple(tuple->esp_tuples,
					ntohl(esp_info->old_spi))), -1,
					"failed to look up esp_tuple\n");

			// needed for allocating and copying the anchors
			hash_length = esp_prot_get_hash_length(esp_tuple->esp_prot_tfm);

			// check if active_anchors are the same, further REPLAY PROTECTION
			if (!memcmp(esp_tuple->active_anchor, anchor_item->active_anchor,
					hash_length))
			{
				// TODO delete cached item from the list
				HIP_IFEL(!(anchor_item = (struct esp_anchor_item *)
						hip_ll_del(&tuple->anchor_cache, i, NULL)), -1,
						"failed to remove anchor_item from list\n");

				// update the esp_tuple
				esp_tuple->next_anchor = anchor_item->next_anchor;

				// free the cached item, but NOT next_anchor as in use now
				free(anchor_item->active_anchor);
				free(anchor_item);

				HIP_DEBUG("next_anchor of esp_tuple updated\n");

				err = 0;
				goto out_err;

			} else
			{
				HIP_DEBUG("matching UPDATE found, but anchors do NOT match\n");

				err = -1;
				goto out_err;
			}
		}
	}

	HIP_DEBUG("no matching ANCHOR UPDATE cached\n");

  out_err:
	return err;
}

#if 0
int esp_prot_conntrack_update_esp_info(const hip_common_t *update,
		struct tuple * other_dir_tuple)
{
	struct hip_ack *ack = NULL;
	struct hip_esp_info *esp_info = NULL;
	struct anchor_tuple *anchors = NULL;
	struct esp_tuple *esp_tuple = NULL;
	// assume no matching anchor
	int err = 1, i;

	/* the update reply to an anchor in anchor message contains the ESP_INFO
	 * parameter with the SPI number of the esp_tuple to be update with the
	 * anchor sent before */
	// XX TODO check for each ACK in case of aggregated ACKs
	HIP_IFEL(!(ack = (struct hip_ack *) hip_get_param(update, HIP_PARAM_ACK)), -1,
			"expecting ACK param, but UPDATE msg does NOT contain it\n");
	HIP_IFEL(!(esp_info = (struct hip_esp_info *) hip_get_param(update,
			HIP_PARAM_ESP_INFO)), -1,
			"expecting ESP_INFO param, but UPDATE msg does NOT contain it\n");

	// search for corresponding anchor in other direction's anchor cache
	for (i = 0; i < hip_ll_get_size(&other_dir_tuple->anchor_cache); i++)
	{
		anchors = (struct anchor_tuple *) hip_ll_get(&other_dir_tuple->anchor_cache, i);

		if (anchors->update_id == ack->peer_update_id)
		{
			HIP_DEBUG("matching SEQ and ACK for anchor update found\n");

			// remove from cache
			anchors = (struct anchor_tuple *) hip_ll_del(&other_dir_tuple->anchor_cache,
					i, NULL);

			// update corresponding esp_tuple
			// TODO distinguish the different update cases
			/* esp_tuple = find_esp_tuple(other_dir_esps, ntohl(esp_info->old_spi));
			esp_tuple->esp_prot_tfm
			esp_tuple->active_anchor
			esp_tuple->next_anchor

			esp_tuple = find_esp_tuple(other_dir_esps, ntohl(esp_info->new_spi));
			esp_tuple->esp_prot_tfm
			esp_tuple->active_anchor
			esp_tuple->next_anchor */

			err = 0;
			break;
		}
	}

  out_err:
	return err;
}
#endif
