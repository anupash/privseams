/*
 * esp_prot_fw_msg.c
 *
 *  Created on: Jul 20, 2008
 *      Author: Rene Hummen <rene.hummen@rwth-aachen.de>
 */

#include "esp_prot_fw_msg.h"
#include "esp_prot_common.h"

/* this sends the prefered transform to hipd implicitely turning on
 * the esp protection extension there */
int send_esp_prot_to_hipd(int active)
{
	int err = 0;
	struct hip_common *msg = NULL;
	uint8_t transform = 0;

	HIP_ASSERT(active >= 0);

	// for now this is the only transform we support
	// TODO extend to support more transforms
	if (active > 0)
		transform = ESP_PROT_TFM_SHA1_8;
	else
		transform = ESP_PROT_TFM_UNUSED;

	HIP_IFEL(!(msg = HIP_MALLOC(HIP_MAX_PACKET, 0)), -1,
		 "failed to allocate memory\n");

	hip_msg_init(msg);

	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_ESP_PROT_TFM, 0), -1,
		 "build hdr failed\n");

	HIP_DEBUG("esp_prot_transform: %u\n", transform);
	HIP_IFEL(hip_build_param_contents(msg, (void *)&transform,
			HIP_PARAM_ESP_PROT_TFM, sizeof(uint8_t)), -1,
			"build param contents failed\n");

	HIP_DEBUG("sending esp protection transform to hipd...\n");
	HIP_DUMP_MSG(msg);

	/* send msg to hipd and receive corresponding reply */
	HIP_IFEL(hip_send_recv_daemon_info(msg), -1, "send_recv msg failed\n");

	/* check error value */
	HIP_IFEL(hip_get_msg_err(msg), -1, "hipd returned error message!\n");

	HIP_DEBUG("send_recv msg succeeded\n");

	HIP_DEBUG("esp extension transform successfully set up\n");

 out_err:
	if (msg)
		free(msg);

	return err;
}

/* sends a list of all available anchor elements in the bex store
 * to the hipd, which then draws the element used in the bex from
 * this list */
int send_bex_store_update_to_hipd(hchain_store_t *bex_store)
{
	struct hip_common *msg = NULL;
	int hash_length = 0;
	int err = 0;

	HIP_ASSERT(bex_store != NULL);

	HIP_DEBUG("sending bex-store update to hipd...\n");

	HIP_IFEL(!(msg = (struct hip_common *)create_bexstore_anchors_message(bex_store)),
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
struct hip_common *create_bex_store_update_msg(hchain_store_t *hcstore)
{
	struct hip_common *msg = NULL;
	int hash_length = 0;
	esp_prot_transform_t *transform = NULL;
	unsigned char *anchor = NULL;
	int err = 0, j;
	uint8_t i;

	HIP_ASSERT(hcstore != NULL);

	HIP_IFEL(!(msg = HIP_MALLOC(HIP_MAX_PACKET, 0)), -1,
		 "failed to allocate memory\n");

	hip_msg_init(msg);

	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_BEX_STORE_UPDATE, 0), -1,
		 "build hdr failed\n");

	// now add the hchain anchors
	for (i = 0; i < NUM_TRANSFORMS; i++)
	{
		HIP_DEBUG("transform %i:\n", i + 1);

		transform = esp_prot_resolve_transform(i);

		hash_length = hash_lengths[transform->hash_func_id][transform->hash_length_id];
		num_hchains = hcstore->hchain_shelves[transform->hash_func_id][transform->hash_length_id].hchain_items[DEFAULT_HCHAIN_LENGTH_ID].num_hchains;

		// add num_hchains for this transform, needed on receiver side
		HIP_DEBUG("adding num_hchains: %i\n", num_hchains);
		HIP_IFEL(hip_build_param_contents(msg, (void *)&num_hchains,
				HIP_PARAM_INT, sizeof(int)), -1,
				"build param contents failed\n");

		// add the hash_length for this transform, needed on receiver side
		HIP_DEBUG("adding hash_length: %i\n", hash_length);
		HIP_IFEL(hip_build_param_contents(msg, (void *)&hash_length,
				HIP_PARAM_INT, sizeof(int)), -1,
				"build param contents failed\n");

		// add anchor with this transform
		for (j = 0; j < hcstore->hchain_shelves[transform->hash_func_id][transform->hash_length_id].hchain_items[DEFAULT_HCHAIN_LENGTH_ID].num_hchains;
				j++)
		{
			anchor = hcstore->hchain_shelves[transform->hash_func_id][transform->hash_length_id].hchain_items[DEFAULT_HCHAIN_LENGTH_ID].hchains[j]->anchor_element->hash;

			HIP_HEXDUMP("adding anchor: ", anchor, hash_length);
			HIP_IFEL(hip_build_param_contents(msg, (void *)anchor,
					HIP_PARAM_HCHAIN_ANCHOR, hash_length),
					-1, "build param contents failed\n");
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
int trigger_update(hip_sa_entry_t *entry)
{
	int err = 0;
	struct hip_common *msg = NULL;
	int hash_length = 0;

	HIP_ASSERT(entry != NULL);

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

	HIP_DEBUG("hash-length: %i\n", hash_length);
	HIP_IFEL(hip_build_param_contents(msg, (void *)&hash_length, HIP_PARAM_INT,
				sizeof(int)), -1, "build param contents failed\n");

	HIP_HEXDUMP("anchor: ", entry->next_hchain->anchor_element->hash, hash_length);
	HIP_IFEL(hip_build_param_contents(msg, (void *)anchor, HIP_PARAM_HCHAIN_ANCHOR,
			esp_prot_transforms[transform]), -1, "build param contents failed\n");

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
	unsigned char *esp_prot_anchor = NULL;
	int hash_length = 0, err = 0;
	*esp_prot_transform = 0;

	HIP_ASSERT(msg != NULL);
	HIP_ASSERT(esp_prot_transform != NULL);

	HIP_IFEL(!(param = (struct hip_tlv_common *)hip_get_param(msg, HIP_PARAM_ESP_PROT_TFM)),
			-1, "esp prot transform missing\n");
	*esp_prot_transform = *((uint8_t *) hip_get_param_contents_direct(param));
	HIP_DEBUG("esp protection transform is %u\n", *esp_prot_transform);

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
