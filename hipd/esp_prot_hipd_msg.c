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

int esp_prot_sa_add(hip_ha_t *entry, struct hip_common *msg, int direction)
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

		// choose the anchor depending on the direction
		if (direction == HIP_SPI_DIRECTION_IN)
		{
			HIP_IFEL(!(hchain_anchor = entry->esp_peer_anchor), -1,
					"hchain anchor expected, but not present\n");
		} else
		{
			HIP_IFEL(!(hchain_anchor = entry->esp_local_anchor), -1,
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
 	} else
 	{
 		HIP_DEBUG("userspace IPsec hint: esp protection extension UNUSED, skip\n");
 	}

 	_HIP_DUMP_MSG(msg);

  out_err:
 	return err;
}

// TODO check
int esp_prot_r1_handle_transforms(hip_common_t *i2, hip_ha_t *entry,
		struct hip_context *ctx)
{
	struct hip_param *param = NULL;
	int esp_prot_num_transforms;
	uint8_t esp_prot_transforms[NUM_TRANSFORMS];
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
			prot_transform = (struct esp_prot_transform *) param;

			// TODO parse the transform parameter

			// select transform and store it for this connection
			entry->esp_prot_transform = esp_prot_select_transform(esp_prot_num_transforms,
					esp_prot_transforms);

			// transform >= 0 due to data-type
			HIP_ASSERT(entry->esp_prot_transform <= NUM_TRANSFORMS);

		} else
		{
			HIP_DEBUG("R1 does not contain ESP protection transform, setting UNUSED\n");

			// if the other end-host does not want to use the extension, we don't either
			entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;
		}
	} else
	{
		HIP_DEBUG("no userspace IPsec hint for ESP extension, setting UNUSED\n");

		// make sure we don't add the anchor now and don't add any transform or anchor
		entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;
	}
}

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

// TODO check
int esp_prot_i2_add_anchor(hip_common_t *i2, hip_ha_t *entry)
{
	unsigned char *anchor = NULL;
	int hash_length = 0;
	int err = 0;

	// only add, if extension in use and we agreed on a transform
	if (entry->esp_prot_transform > ESP_PROT_TFM_UNUSED)
	{
		if (anchor_db_has_more_anchors(entry->esp_prot_transform))
		{
			hash_length = anchor_db_get_anchor_length(entry->esp_prot_transform);

			HIP_IFEL(!(anchor = anchor_db_get_anchor(entry->esp_prot_transform)), -1,
					"no anchor elements available, threading?\n");
			HIP_IFEL(hip_build_param_esp_prot_anchor(i2, anchor, hash_length), -1,
					"Building of ESP protection anchor failed\n");

			// store local_anchor
			memset(entry->esp_local_anchor, 0, MAX_HASH_LENGTH);
			memcpy(entry->esp_local_anchor, anchor, hash_length);

			HIP_HEXDUMP("stored local anchor: ", entry->esp_local_anchor, hash_length);

		} else
		{
			// fall back
			HIP_ERROR("we agreed on using esp hchain protection, but no elements");
			entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;
		}
	}

  out_err:
	if (anchor)
		free(anchor);

 	return err;
}

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

int esp_prot_i2_handle_anchor(hip_ha_t *entry, struct hip_context *ctx)
{
	struct hip_param *param = NULL;
	struct esp_prot_anchor *prot_anchor = NULL;
	int hash_length = 0;
	int err = 0;

	/* only process the anchor parameter, if we are going to use it */
	if (entry->esp_prot_transform > ESP_PROT_TFM_UNUSED)
	{
		if (param = hip_get_param(ctx->input, HIP_PARAM_ESP_PROT_ANCHOR))
		{
			prot_anchor = (struct esp_prot_anchor *) param;

			// distinguish different hash lengths/transforms
			if (entry->esp_prot_transform > ESP_PROT_TFM_UNUSED)
			{
				hash_length = anchor_db_get_anchor_length(entry->esp_prot_transform);

				// store peer_anchor
				memset(entry->esp_peer_anchor, 0, MAX_HASH_LENGTH);
				memcpy(entry->esp_peer_anchor, prot_anchor->anchor, hash_length);

				HIP_HEXDUMP("received anchor: ", entry->esp_peer_anchor, hash_length);

			} else
			{
				HIP_ERROR("received anchor with unknown transform, falling back\n");

				entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;
			}
		} else
		{
			// fall back option
			HIP_DEBUG("agreed on using esp hchain extension, but no anchor sent or error\n");

			entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;
		}
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
			HIP_IFEL(hip_build_param_esp_prot_anchor(r2, anchor, hash_length), -1,
					"Building of ESP protection anchor failed\n");
			HIP_HEXDUMP("added anchor: ", anchor, hash_length);

			// store local_anchor
			memset(entry->esp_local_anchor, 0, MAX_HASH_LENGTH);
			memcpy(entry->esp_local_anchor, anchor, hash_length);

			HIP_HEXDUMP("stored local anchor: ", entry->esp_local_anchor, hash_length);
		} else
		{
			// fall back
			HIP_ERROR("we agreed on using esp hchain protection, but no elements");
			entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;
		}
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

	param = hip_get_param(ctx->input, HIP_PARAM_ESP_PROT_ANCHOR);
	// only process anchor, if we agreed on using it before
	if (entry->esp_prot_transform > ESP_PROT_TFM_UNUSED && param)
	{
		hash_length = anchor_db_get_anchor_length(entry->esp_prot_transform);

		prot_anchor = (struct esp_prot_anchor *) param;

		memset(entry->esp_peer_anchor, 0, MAX_HASH_LENGTH);
		memcpy(entry->esp_peer_anchor, prot_anchor->anchor, hash_length);

		HIP_HEXDUMP("received anchor: ", entry->esp_peer_anchor, hash_length);
	} else
	{
		HIP_DEBUG("agreed on using esp hchain extension, but no anchor sent or error\n");
		// fall back option
		entry->esp_prot_transform = ESP_PROT_TFM_UNUSED;
	}

  out_err:
 	return err;
}

uint8_t esp_prot_select_transform(int num_transforms, uint8_t *transforms)
{
	uint8_t transform = ESP_PROT_TFM_UNUSED;
	int err = 0;

	// TODO implement

  out_err:
	if (err)
	{
		transform = ESP_PROT_TFM_UNUSED;
	}

	return transform;
}
