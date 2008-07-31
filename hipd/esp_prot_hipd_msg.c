#include "esp_prot_hipd_msg.h"
#include "esp_prot_anchordb.h"
#include "esp_prot_common.h"

/**
 * activates the esp protection extension in the hipd
 *
 * NOTE: this is called by the hipd when receiving the respective message
 * from the firewall
 **/
int esp_prot_set_preferred_transforms(struct hip_common *msg)
{
	struct hip_tlv_common *param = NULL;
	extern int esp_prot_num_transforms;
	extern uint8_t esp_prot_transforms[NUM_TRANSFORMS];
	int err = 0, i;

	// process message and store the preferred transforms
	param = (struct hip_tlv_common *)hip_get_param(msg, HIP_PARAM_INT);
	esp_prot_num_transforms = *((int *)hip_get_param_contents_direct(param));
	HIP_DEBUG("esp protection num_transforms: %i\n", esp_prot_num_transforms);

	for (i = 0; i < NUM_TRANSFORMS; i++)
	{
		if (i < esp_prot_num_transforms)
		{
			param = (struct hip_tlv_common *)hip_get_next_param(msg, param);
			esp_prot_transforms[i] = *((uint8_t *)hip_get_param_contents_direct(param));
			HIP_DEBUG("esp protection transform %i: %u\n", i + 1, esp_prot_transforms[i]);

		} else
		{
			esp_prot_transforms[i] = 0;
		}
	}

	// this works as we always have to send at least ESP_PROT_TFM_UNUSED
	if (esp_prot_num_transforms > 1)
		HIP_DEBUG("switched to esp protection extension\n");
	else
		HIP_DEBUG("switched to normal esp mode\n");

	/* we have to make sure that the precalculated R1s include the esp
	 * protection extension transform */
	HIP_DEBUG("recreate all R1s\n");
	HIP_IFEL(hip_recreate_all_precreated_r1_packets(), -1, "failed to recreate all R1s\n");

  out_err:
  	return err;
}

int esp_prot_handle_trigger_update_msg(struct hip_common *msg)
{
	struct hip_tlv_common *param = NULL;
	hip_hit_t *local_hit = NULL, *peer_hit = NULL;
	uint8_t esp_prot_tfm = 0;
	int hash_length = 0;
	unsigned char *esp_prot_anchor = NULL;
	hip_ha_t *entry = NULL;
	int err = 0;

	param = hip_get_param(msg, HIP_PARAM_HIT);
	local_hit = (hip_hit_t *) hip_get_param_contents_direct(param);
	HIP_DEBUG_HIT("src_hit", local_hit);

	param = hip_get_next_param(msg, param);
	peer_hit = (hip_hit_t *) hip_get_param_contents_direct(param);
	HIP_DEBUG_HIT("dst_hit", peer_hit);

	param = hip_get_param(msg, HIP_PARAM_ESP_PROT_TFM);
	esp_prot_tfm = *((uint8_t *) hip_get_param_contents_direct(param));
	HIP_DEBUG("esp_prot_transform: %u\n", esp_prot_tfm);

	param = hip_get_param(msg, HIP_PARAM_HCHAIN_ANCHOR);
	esp_prot_anchor = (unsigned char *) hip_get_param_contents_direct(param);
	HIP_HEXDUMP("anchor: ", esp_prot_anchor, hash_length);


	// get matching entry from hadb for HITs provided above
	HIP_IFEL(!(entry = hip_hadb_find_byhits(local_hit, peer_hit)), -1,
			"failed to retrieve requested HA entry\n");

	// check if transforms are matching and add anchor as new local_anchor
	HIP_IFEL(entry->esp_prot_transform != esp_prot_tfm, -1,
			"esp prot transform changed without new BEX\n");
	HIP_DEBUG("esp prot transforms match\n");

	// we need to know the hash_length for this transform
	hash_length = anchor_db_get_anchor_length(entry->esp_prot_transform);

	// make sure that the update-anchor is not set yet
	HIP_IFEL(*(entry->esp_update_anchor) != 0, -1,
			"next hchain changed in fw, but we still have the last update-anchor set!");

	// set the update anchor
	memset(entry->esp_update_anchor, 0, MAX_HASH_LENGTH);
	memcpy(entry->esp_update_anchor, esp_prot_anchor, hash_length);

	/* this should send an update only containing the mandatory params
	 * HMAC and HIP_SIGNATURE as well as the ESP_PROT_ANCHOR and the
	 * SEQ param (to garanty freshness of the ANCHOR) in the signed part
	 * of the message
	 *
	 * params used for this call:
	 * - hadb entry matching the HITs passed in the trigger msg
	 * - not sending locators -> list = NULL and count = 0
	 * - no interface triggers this event -> -1
	 * - bitwise telling about which params to add to UPDATE -> set 3rd bit to 1
	 * - UPDATE not due to adding of a new addresses
	 * - not setting any address, as none is updated */
	HIP_IFEL(hip_send_update(entry, NULL, 0, -1, SEND_UPDATE_ESP_ANCHOR, 0, NULL),
			-1, "failed to send anchor update\n");

  out_err:
	return err;
}

int esp_prot_handle_hchain_change_msg(struct hip_common *msg)
{
	struct hip_tlv_common *param = NULL;
	hip_hit_t *local_hit = NULL, *peer_hit = NULL;
	uint8_t esp_prot_tfm = 0;
	int hash_length = 0;
	unsigned char *esp_prot_anchor = NULL;
	hip_ha_t *entry = NULL;
	int err = 0;

	param = hip_get_param(msg, HIP_PARAM_HIT);
	local_hit = (hip_hit_t *) hip_get_param_contents_direct(param);
	HIP_DEBUG_HIT("src_hit", local_hit);

	param = hip_get_next_param(msg, param);
	peer_hit = (hip_hit_t *) hip_get_param_contents_direct(param);
	HIP_DEBUG_HIT("dst_hit", peer_hit);

	param = hip_get_param(msg, HIP_PARAM_ESP_PROT_TFM);
	esp_prot_tfm = *((uint8_t *) hip_get_param_contents_direct(param));
	HIP_DEBUG("esp_prot_transform: %u\n", esp_prot_tfm);

	param = hip_get_param(msg, HIP_PARAM_HCHAIN_ANCHOR);
	esp_prot_anchor = (unsigned char *) hip_get_param_contents_direct(param);
	HIP_HEXDUMP("anchor: ", esp_prot_anchor, hash_length);


	// get matching entry from hadb for HITs provided above
	HIP_IFEL(!(entry = hip_hadb_find_byhits(local_hit, peer_hit)), -1,
			"failed to retrieve requested HA entry\n");

	// check if transforms are matching and add anchor as new local_anchor
	HIP_IFEL(entry->esp_prot_transform != esp_prot_tfm, -1,
			"esp prot transform changed without new BEX\n");
	HIP_DEBUG("esp prot transforms match\n");

	// we need to know the hash_length for this transform
	hash_length = anchor_db_get_anchor_length(entry->esp_prot_transform);

	// make sure that the update-anchor is set
	HIP_IFEL(memcmp(entry->esp_update_anchor, esp_prot_anchor, hash_length), -1,
			"hchain-anchors used for outbound connections NOT in sync\n");

	// set update anchor as new active local anchor
	memset(entry->esp_local_anchor, 0, MAX_HASH_LENGTH);
	memcpy(entry->esp_local_anchor, entry->esp_update_anchor, hash_length);
	memset(entry->esp_update_anchor, 0, MAX_HASH_LENGTH);

	HIP_DEBUG("changed local_anchor to update_anchor\n");

  out_err:
	return err;
}

int esp_prot_sa_add(hip_ha_t *entry, struct hip_common *msg, int direction,
		int update)
{
	unsigned char *hchain_anchor = NULL;
	int hash_length = 0;
	int err = 0;

	HIP_DEBUG("direction: %i\n", direction);

	// we always tell the negotiated transform to the firewall
	HIP_DEBUG("esp protection extension transform is %u \n", entry->esp_prot_transform);
	HIP_IFEL(hip_build_param_contents(msg, (void *)&entry->esp_prot_transform,
			HIP_PARAM_ESP_PROT_TFM, sizeof(uint8_t)), -1,
			"build param contents failed\n");

	// but we only transmit the anchor to the firewall, if the esp extension is used
	if (entry->esp_prot_transform > ESP_PROT_TFM_UNUSED)
	{
		hash_length = anchor_db_get_anchor_length(entry->esp_prot_transform);

		// choose the anchor depending on the direction and update or add
		if (direction == HIP_SPI_DIRECTION_OUT && update)
		{
			HIP_IFEL(!(hchain_anchor = entry->esp_update_anchor), -1,
					"hchain anchor expected, but not present\n");

		} else if (direction == HIP_SPI_DIRECTION_OUT)
		{
			HIP_IFEL(!(hchain_anchor = entry->esp_local_anchor), -1,
					"hchain anchor expected, but not present\n");

		} else
		{
			HIP_IFEL(!(hchain_anchor = entry->esp_peer_anchor), -1,
					"hchain anchor expected, but not present\n");
		}

		HIP_HEXDUMP("esp protection anchor is ", hchain_anchor, hash_length);

		HIP_IFEL(hip_build_param_contents(msg, (void *)hchain_anchor,
				HIP_PARAM_HCHAIN_ANCHOR, hash_length), -1,
				"build param contents failed\n");
	} else
	{
		HIP_DEBUG("no anchor added, transform UNUSED\n");
	}

  out_err:
	return err;
}

int esp_prot_r1_add_transforms(hip_common_t *msg)
{
	extern int esp_prot_num_transforms;
	extern uint8_t esp_prot_transforms[NUM_TRANSFORMS];
	int err = 0, i;

	/* only supported in usermode and optional there
 	 *
 	 * add the transform only when usermode is active */
 	if (hip_use_userspace_ipsec)
 	{
 		HIP_DEBUG("userspace IPsec hint: esp protection extension might be in use\n");

 		/* send the stored transforms */
		HIP_IFEL(hip_build_param_esp_prot_transform(msg, esp_prot_num_transforms,
				esp_prot_transforms), -1,
				"Building of ESP protection mode failed\n");

		HIP_DEBUG("ESP prot transforms param built\n");

 	} else
 	{
 		HIP_DEBUG("userspace IPsec hint: esp protection extension UNUSED, skip\n");
 	}

 	_HIP_DUMP_MSG(msg);

  out_err:
 	return err;
}

int esp_prot_r1_handle_transforms(hip_ha_t *entry, struct hip_context *ctx)
{
	struct hip_param *param = NULL;
	struct esp_prot_preferred_tfms *prot_transforms = NULL;
	int err = 0;

	/* this is only handled if we are using userspace ipsec,
	 * otherwise we just ignore it */
	if (hip_use_userspace_ipsec)
	{
		HIP_DEBUG("userspace IPsec hint: ESP extension might be in use\n");

		param = hip_get_param(ctx->input, HIP_PARAM_ESP_PROT_TRANSFORMS);

		// check if the transform parameter was sent
		if (param)
		{
			HIP_DEBUG("received preferred transforms from peer\n");

			// store that we received the param for further processing
			ctx->esp_prot_param = 1;

			prot_transforms = (struct esp_prot_preferred_tfms *) param;

			// select transform and store it for this connection
			entry->esp_prot_transform = esp_prot_select_transform(prot_transforms->num_transforms,
					prot_transforms->transforms);

			// transform >= 0 due to data-type
			HIP_ASSERT(entry->esp_prot_transform <= NUM_TRANSFORMS);

		} else
		{
			HIP_DEBUG("R1 does not contain preferred ESP protection transforms, " \
					"locally setting UNUSED\n");

			// store that we didn't received the param
			ctx->esp_prot_param = 0;

			// if the other end-host does not want to use the extension, we don't either
			entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;
		}
	} else
	{
		HIP_DEBUG("no userspace IPsec hint for ESP extension, locally setting UNUSED\n");

		// make sure we don't add the anchor now and don't add any transform or anchor
		entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;
	}

  out_err:
	return err;
}

#if 0
// TODO check
int esp_prot_i2_add_transform(hip_common_t *i2, hip_ha_t *entry, struct hip_context *ctx)
{
	extern int esp_prot_num_transforms;
	int err = 0;

	/* this is only handled if we are using userspace ipsec,
	 * otherwise we just ignore it */
	if (hip_use_userspace_ipsec)
	{
		// check if we are using the extension locally
		if (esp_prot_num_transforms > 1)
		{
			HIP_DEBUG("sending transform: u%\n", entry->esp_prot_transform);

			HIP_IFEL(hip_build_param_esp_prot_transform(i2, entry->esp_prot_transform),
					-1, "Building of ESP protection mode failed\n");

		} else
		{
			HIP_DEBUG("ESP extension switched off locally, sending UNUSED transform...\n");

			// advertise that we are not using the extension
			HIP_IFEL(hip_build_param_esp_prot_transform(i2, ESP_PROT_TFM_UNUSED),
					-1, "Building of ESP protection mode failed\n");
		}
	}

  out_err:
 	return err;
}
#endif

int esp_prot_i2_add_anchor(hip_common_t *i2, hip_ha_t *entry, struct hip_context *ctx)
{
	struct hip_param *param = NULL;
	unsigned char *anchor = NULL;
	int hash_length = 0;
	int err = 0;

	/* only add, if extension in use and we agreed on a transform
	 *
	 * @note the transform was selected in handle R1 */
	if (entry->esp_prot_transform > ESP_PROT_TFM_UNUSED)
	{
		if (anchor_db_has_more_anchors(entry->esp_prot_transform))
		{
			hash_length = anchor_db_get_anchor_length(entry->esp_prot_transform);

			HIP_IFEL(!(anchor = anchor_db_get_anchor(entry->esp_prot_transform)), -1,
					"no anchor elements available, threading?\n");
			HIP_IFEL(hip_build_param_esp_prot_anchor(i2, entry->esp_prot_transform,
					anchor, hash_length), -1,
					"Building of ESP protection anchor failed\n");

			// store local_anchor
			memset(entry->esp_local_anchor, 0, MAX_HASH_LENGTH);
			memcpy(entry->esp_local_anchor, anchor, hash_length);

			HIP_HEXDUMP("stored local anchor: ", entry->esp_local_anchor, hash_length);

		} else
		{
			// fall back
			HIP_ERROR("agreed on using esp hchain protection, but no elements");

			entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;

			// inform our peer
			HIP_IFEL(hip_build_param_esp_prot_anchor(i2, entry->esp_prot_transform,
					NULL, 0), -1,
					"Building of ESP protection anchor failed\n");
		}
	} else
	{
		// only reply, if transforms param in R1; send UNUSED param
		if (ctx->esp_prot_param)
		{
			HIP_DEBUG("R1 contained transforms, but agreed not to use the extension\n");

			entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;

			HIP_IFEL(hip_build_param_esp_prot_anchor(i2, entry->esp_prot_transform,
					NULL, 0), -1,
					"Building of ESP protection anchor failed\n");
		} else
		{
			HIP_DEBUG("peer didn't send transforms in R1, locally setting UNUSED\n");

			entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;
		}
	}

  out_err:
	if (anchor)
		free(anchor);

 	return err;
}

#if 0
int esp_prot_i2_handle_transform(hip_ha_t *entry, struct hip_context *ctx)
{
	struct hip_param *param = NULL;
	struct esp_prot_transform *prot_transform = NULL;
	uint8_t transform = 0;
	extern uint8_t hip_esp_prot_ext_transform;
	int err = 0;

	/* only supported in usermode and optional there
 	 *
 	 * process the transform only when usermode is active */
 	HIP_DEBUG("hip_use_userspace_ipsec is %i\n", hip_use_userspace_ipsec);
 	if (hip_use_userspace_ipsec)
 	{
 		HIP_DEBUG("userspace IPsec hint: esp protection extension might be in use\n");

 		if (hip_esp_prot_ext_transform > ESP_PROT_TFM_UNUSED)
 		{
 			param = hip_get_param(ctx->input, HIP_PARAM_ESP_PROT_TRANSFORM);
			/* process this if the other end-host supports the extension
			 * (parameter incl in R1) */
			if (param)
			{
				prot_transform = (struct esp_prot_transform *) param;
				transform = prot_transform->transform;

				// TODO agree on transform
				// right now we only support 2 transform, so we can just copy
				entry->esp_prot_transform = transform;

				HIP_DEBUG("esp protection transform in I2: %u \n", transform);
			} else
			{
				HIP_DEBUG("esp protection extension active, but not used by peer host -> setting UNUSED\n");
				entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;
			}
 		} else
 		{
 			HIP_DEBUG("esp protection extension not active, setting UNUSED\n");
 			entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;
 		}
 	} else
 	{
 		HIP_DEBUG("userspace IPsec hint: esp protection extension UNUSED, skipped\n");
 		entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;
 	}

  out_err:
 	return err;
}
#endif

int esp_prot_i2_handle_anchor(hip_ha_t *entry, struct hip_context *ctx)
{
	extern int esp_prot_num_transforms;
	struct hip_param *param = NULL;
	struct esp_prot_anchor *prot_anchor = NULL;
	int hash_length = 0;
	int err = 0;

	/* only supported in user-mode ipsec and optional there */
 	if (hip_use_userspace_ipsec && esp_prot_num_transforms > 1)
 	{
 		HIP_DEBUG("userspace IPsec hint: esp protection extension might be in use\n");

		if (param = hip_get_param(ctx->input, HIP_PARAM_ESP_PROT_ANCHOR))
		{
			prot_anchor = (struct esp_prot_anchor *) param;

			// check if the anchor has a supported transform
			if (esp_prot_check_transform(prot_anchor->transform) >= 0)
			{
				// we know this transform
				entry->esp_prot_transform = prot_anchor->transform;

				if (entry->esp_prot_transform == ESP_PROT_TFM_UNUSED)
				{
					HIP_DEBUG("agreed not to use esp protection extension\n");

				} else
				{
					hash_length = anchor_db_get_anchor_length(entry->esp_prot_transform);

					// store peer_anchor
					memset(entry->esp_peer_anchor, 0, MAX_HASH_LENGTH);
					memcpy(entry->esp_peer_anchor, prot_anchor->anchor, hash_length);

					HIP_HEXDUMP("received anchor: ", entry->esp_peer_anchor, hash_length);
				}
			} else
			{
				HIP_ERROR("received anchor with unknown transform, falling back\n");

				entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;
			}
		} else
		{
			HIP_DEBUG("NO esp anchor sent, locally setting UNUSED\n");

			entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;
		}
	} else
	{
		HIP_DEBUG("userspace IPsec hint: esp protection extension NOT in use\n");

		entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;
	}

  out_err:
 	return err;
}

int esp_prot_r2_add_anchor(hip_common_t *r2, hip_ha_t *entry)
{
	unsigned char *anchor = NULL;
	int hash_length = 0;
	int err = 0;

	// only add, if extension in use, we agreed on a transform and no error until now
	if (entry->esp_prot_transform > ESP_PROT_TFM_UNUSED)
	{
		if (anchor_db_has_more_anchors(entry->esp_prot_transform))
		{
			hash_length = anchor_db_get_anchor_length(entry->esp_prot_transform);

			HIP_IFEL(!(anchor = anchor_db_get_anchor(entry->esp_prot_transform)),
					-1, "no anchor elements available, threading?\n");
			HIP_IFEL(hip_build_param_esp_prot_anchor(r2, entry->esp_prot_transform,
					anchor, hash_length), -1,
					"Building of ESP protection anchor failed\n");

			// store local_anchor
			memset(entry->esp_local_anchor, 0, MAX_HASH_LENGTH);
			memcpy(entry->esp_local_anchor, anchor, hash_length);

			HIP_HEXDUMP("stored local anchor: ", entry->esp_local_anchor, hash_length);
		} else
		{
			// fall back
			HIP_ERROR("agreed on using esp hchain protection, but no elements");

			entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;

			// inform our peer
			HIP_IFEL(hip_build_param_esp_prot_anchor(r2, entry->esp_prot_transform,
					NULL, 0), -1,
					"Building of ESP protection anchor failed\n");
		}
	} else
	{
		HIP_DEBUG("esp protection extension NOT in use for this connection\n");

		entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;
	}

  out_err:
	if (anchor)
		free(anchor);

 	return err;
}

int esp_prot_r2_handle_anchor(hip_ha_t *entry, struct hip_context *ctx)
{
	struct hip_param *param = NULL;
	struct esp_prot_anchor *prot_anchor = NULL;
	unsigned char *anchor = NULL;
	int hash_length = 0;
	int err = 0;

	// only process anchor, if we agreed on using it before
	if (entry->esp_prot_transform > ESP_PROT_TFM_UNUSED)
	{
		if (param = hip_get_param(ctx->input, HIP_PARAM_ESP_PROT_ANCHOR))
		{
			prot_anchor = (struct esp_prot_anchor *) param;

			// check if the anchor has got the negotiated transform
			if (prot_anchor->transform == entry->esp_prot_transform)
			{
				hash_length = anchor_db_get_anchor_length(entry->esp_prot_transform);

				memset(entry->esp_peer_anchor, 0, MAX_HASH_LENGTH);
				memcpy(entry->esp_peer_anchor, prot_anchor->anchor, hash_length);

				HIP_HEXDUMP("received anchor: ", entry->esp_peer_anchor, hash_length);

			} else if (prot_anchor->transform == ESP_PROT_TFM_UNUSED)
			{
				HIP_DEBUG("peer encountered problems and did fallback\n");

				// also fallback
				entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;

			} else
			{
				HIP_ERROR("received anchor does NOT use negotiated transform, falling back\n");

				// fallback
				entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;
			}
		} else
		{
			HIP_DEBUG("agreed on using esp hchain extension, but no anchor sent or error\n");

			// fall back option
			entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;
		}
	} else
	{
		HIP_DEBUG("NOT using esp protection extension\n");

		entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;
	}

  out_err:
 	return err;
}

int esp_prot_update_add_anchor(hip_common_t *update, hip_ha_t *entry, int flags)
{
	int hash_length = 0;
	int err = 0;

	// on-path middleboxes have to learn about the anchors in use
	if ((flags & SEND_UPDATE_LOCATOR) && (flags & SEND_UPDATE_ESP_ANCHOR))
	{
		// we can safely assume that this UPDATE was triggered by the firewall
		hash_length = anchor_db_get_anchor_length(entry->esp_prot_transform);

		HIP_IFEL(hip_build_param_esp_prot_anchor(update, entry->esp_prot_transform,
				entry->esp_local_anchor, hash_length), -1,
				"building of ESP protection ANCHOR failed\n");
	}

	// check if we should send an anchor-type update
	if (flags & SEND_UPDATE_ESP_ANCHOR)
	{
		// we can safely assume that this UPDATE was triggered by the firewall
		hash_length = anchor_db_get_anchor_length(entry->esp_prot_transform);

		HIP_IFEL(hip_build_param_esp_prot_anchor(update, entry->esp_prot_transform,
				entry->esp_update_anchor, hash_length), -1,
				"building of ESP protection ANCHOR failed\n");

		/* add a signed ECHO_REQUEST param containing the currently used anchor
		 * for the outbound direction to ensure freshness of this update
		 *
		 * @note anchor chosen as this should be a value that can be verified/
		 *       know by middleboxes and like this no dependency on ESP transform
		 *       which would have been introduce by using the SPI value
		 * @note SEQ not sufficient to guaranty freshness of the UPDATE, could be
		 *       an UPDATE from a previous connection of these hosts with same
		 *       SEQ number. However SEQ allows to distinguish a resent UPDATE
		 *       from a new anchor-update occuring for some reason at the peer. */
		HIP_IFEL(hip_build_param_echo(update, entry->esp_local_anchor, hash_length,
				 1, 1),  -1, "building of ESP protection ECHO_REQ failed\n");
	}

  out_err:
	return err;
}

int esp_prot_update_handle_anchor(hip_common_t *update, hip_ha_t *entry,
		in6_addr_t *src_ip, in6_addr_t *dst_ip, int *send_ack)
{
	struct hip_tlv_common *param = NULL;
	struct esp_prot_anchor *esp_anchor = NULL;
	int hash_length = 0;
	uint32_t spi_in = 0;
	int err = 0;

	if (param = hip_get_param(update, HIP_PARAM_ESP_PROT_ANCHOR))
	{
		esp_anchor = (struct esp_prot_anchor *)param;

		// check that we are receiving an anchor matching the negotiated transform
		HIP_IFEL(entry->esp_prot_transform != esp_anchor->transform, -1,
				"esp prot transform changed without new BEX\n");
		HIP_DEBUG("esp prot transforms match\n");

		// we need to know the hash_length for this transform
		hash_length = anchor_db_get_anchor_length(entry->esp_prot_transform);

		// set the update anchor as the new peer anchor
		memset(entry->esp_peer_anchor, 0, MAX_HASH_LENGTH);
		memcpy(entry->esp_peer_anchor, esp_anchor->anchor, hash_length);

		*send_ack = 1;

		/* like this we do NOT support multihoming
		 *
		 * @todo change when merging with UPDATE re-implementation
		 */
		spi_in = hip_hadb_get_latest_inbound_spi(entry);

		// notify sadb about next anchor
		HIP_IFEL(entry->hadb_ipsec_func->hip_add_sa(src_ip, dst_ip,
				&entry->hit_peer, &entry->hit_our, spi_in, entry->esp_transform,
				&entry->esp_in, &entry->auth_in, 0, HIP_SPI_DIRECTION_IN, 1, entry),
				-1, "failed to notify sadb about next anchor\n");
	}

  out_err:
	return err;
}

int esp_prot_update_handle_ack(hip_ha_t *entry, in6_addr_t *src_ip,
		in6_addr_t *dst_ip)
{
	int err = 0;

	HIP_ASSERT(entry != NULL);

	// make sure we only alter the behavior when esp prot is active
	if (*(entry->esp_update_anchor) != 0)
		entry->update_state = 0;

	// notify sadb about next anchor
	HIP_IFEL(entry->hadb_ipsec_func->hip_add_sa(dst_ip, src_ip,
			&entry->hit_our, &entry->hit_peer, entry->default_spi_out,
			entry->esp_transform, &entry->esp_out, &entry->auth_out, 0,
			HIP_SPI_DIRECTION_OUT, 1, entry), -1,
			"failed to notify sadb about next anchor\n");

  out_err:
	return err;
}

/* simple transform selection: find first match in both arrays
 *
 * returns transform, UNUSED transform on error
 */
uint8_t esp_prot_select_transform(int num_transforms, uint8_t *transforms)
{
	extern int esp_prot_num_transforms;
	extern uint8_t esp_prot_transforms[NUM_TRANSFORMS];
	uint8_t transform = ESP_PROT_TFM_UNUSED;
	int err = 0, i, j;

	for (i = 0; i < esp_prot_num_transforms; i++)
	{
		for (j = 0; j < num_transforms; j++)
		{
			if (esp_prot_transforms[i] == transforms[j])
			{
				HIP_DEBUG("found matching transform: %u\n", esp_prot_transforms[i]);

				transform = esp_prot_transforms[i];
				goto out_err;
			}
		}
	}

	HIP_ERROR("NO matching transform found\n");
	transform = ESP_PROT_TFM_UNUSED;

  out_err:
	if (err)
	{
		transform = ESP_PROT_TFM_UNUSED;
	}

	return transform;
}

/* returns index, if contained; else -1 */
int esp_prot_check_transform(uint8_t transform)
{
	extern int esp_prot_num_transforms;
	extern uint8_t esp_prot_transforms[NUM_TRANSFORMS];
	int err = -1, i;

	// check if local preferred transforms contain passed transform
	for (i = 0; i < esp_prot_num_transforms; i++)
	{
		if (esp_prot_transforms[i] == transform)
		{
			HIP_DEBUG("transform found in local preferred transforms\n");

			err = i;
			goto out_err;
		}
	}

	HIP_DEBUG("transform NOT found in local preferred transforms\n");

  out_err:
	return err;
}
