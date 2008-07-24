#include "esp_prot_anchordb.h"


anchor_db_t anchor_db;


void anchor_db_init()
{
	HIP_DEBUG("initializing hchain anchorDB...\n");

	// set to 0 / NULL
	memset(anchor_db.num_anchors, 0, NUM_TRANSFORMS);
	memset(anchor_db.anchor_lengths, 0, NUM_TRANSFORMS);
	memset(anchor_db.anchors, 0, NUM_TRANSFORMS * MAX_HCHAINS_PER_ITEM);

	HIP_DEBUG("uninited hchain anchorDB\n");
}

void anchor_db_uninit()
{
	int i, j;

	// free all hashes
	for (i = 0; i < NUM_TRANSFORMS; i++)
	{
		anchor_db.num_anchors[i] = 0;
		anchor_db.anchor_lengths[i] = 0;

		for (j = 0; j < MAX_HCHAINS_PER_ITEM; j++)
		{
			if (anchor_db.anchors[i][j])
				free(anchor_db.anchors[i][j]);

			anchor_db.anchors[i][j] = NULL;
		}
	}
}

/* simply deletes all elements in the list and adds new ones */
int anchor_db_update(struct hip_common *msg)
{
	struct hip_tlv_common *param = NULL;
	int err = 0, i, j;
	extern uint8_t hip_esp_prot_ext_transform;

	// if this function is called, the extension should be active
	HIP_ASSERT(hip_esp_prot_ext_transform > ESP_PROT_TFM_UNUSED);
	HIP_ASSERT(msg != NULL);

	HIP_DEBUG("updating hchain anchorDB...\n");

	/* @todo extend as ineffcient -> only add non-existing elements
	 *       instead of uniniting and adding all elements again */
	anchor_db_uninit();

	/*** set up anchor_db.num_anchors and anchor_db.anchor_lengths ***/
	// get first int value
	HIP_IFEL(!(param = (struct hip_tlv_common *) hip_get_param(msg, HIP_PARAM_INT)),
			-1, "parameter missing in user-message from fw\n");

	for (i = 0; i < NUM_TRANSFORMS; i++)
	{
		HIP_DEBUG("transform %i:\n", i + 1);

		anchor_db.num_anchors[i] = *(int *) hip_get_param_contents_direct(param);
		HIP_DEBUG("num_anchors is %i\n", anchor_db.num_anchors[i]);

		HIP_IFEL(!(param = (struct hip_tlv_common *) hip_get_next_param(msg, param)),
				-1, "parameter missing in user-message from fw\n");
		anchor_db.anchor_lengths[i] = *(int *) hip_get_param_contents_direct(param);
		HIP_DEBUG("anchor_length is %i\n", anchor_db.anchor_lengths[i]);

		HIP_IFEL(!(param = (struct hip_tlv_common *) hip_get_next_param(msg, param)),
				-1, "parameter missing in user-message from fw\n");
	}

	// test for more int params
	HIP_IFEL(param, -1, "too many INT params in user-message from fw\n");

	/*** now we got all information needed to store the anchors ***/
	// get first anchor
	HIP_IFEL(!(param = (struct hip_tlv_common *) hip_get_param(msg, HIP_PARAM_HCHAIN_ANCHOR)),
			-1, "parameter missing in user-message from fw\n");

	for (i = 0; i < NUM_TRANSFORMS; i++)
	{
		HIP_DEBUG("transform %i:\n", i + 1);

		for (j = 0; j < anchor_db.num_anchors[i]; j++)
		{
			HIP_IFEL(!(anchor_db.anchors[i][j] = (unsigned char *)malloc(anchor_db.anchor_lengths[i])),
					-1, "failed to allocate memory\n");

			HIP_IFEL(!(param = (struct hip_tlv_common *) hip_get_next_param(msg, param)),
					-1, "parameter missing in user-message from fw\n");
			anchor_db.anchors[i][j] = (unsigned char *) hip_get_param_contents_direct(param);
			HIP_HEXDUMP("adding anchor: ", anchor_db.anchors[i][j],
					anchor_db.anchor_lengths[i]);

			HIP_IFEL(!(param = (struct hip_tlv_common *) hip_get_next_param(msg, param)),
					-1, "parameter missing in user-message from fw\n");
		}
	}

	// test for more anchors
	HIP_IFEL(param,	-1, "too many ANCHOR params in user-message from fw\n");

	HIP_DEBUG("anchor_db successfully updated\n");

  out_err:
	return err;
}

int anchor_db_has_more_anchors(uint8_t transform)
{
	HIP_ASSERT(transform > 0 && transform <= NUM_TRANSFORMS);

	if (anchor_db.num_anchors[transform - 1] > 0)
		return 1;
	else
		return 0;
}

/* returns an unused anchor element or NULL if empty */
unsigned char * anchor_db_get_anchor(uint8_t transform)
{
	unsigned char *stored_anchor = NULL;
	int transform_id = 0;
	int anchor_offset = 0;
	int err = 0;

	// ensure correct boundaries
	HIP_ASSERT(transform > 0 && transform <= NUM_TRANSFORMS);

	// calculate the transform index from the transform value
	transform_id = transform - 1;
	// get index of last unused anchor for this transform
	HIP_IFEL((anchor_offset = anchor_db.num_anchors[transform_id] - 1) <= 0, -1,
			"anchor_db is empty for this transform\n");

	// ensure correct boundaries
	HIP_ASSERT(anchor_offset >= 0 && anchor_offset < MAX_HCHAINS_PER_ITEM);
	HIP_IFEL(!(stored_anchor = anchor_db.anchors[transform_id][anchor_offset]), -1,
			"anchor_offset points to empty slot\n");

	// remove anchor from db
	anchor_db.anchors[transform_id][anchor_offset] = NULL;
	anchor_offset = anchor_db.num_anchors[transform_id]--;

  out_err:
  	if (err)
  	{
  		if (stored_anchor)
  			free(stored_anchor);

  		stored_anchor = NULL;
  	}

  	return stored_anchor;
}

int anchor_db_get_anchor_length(uint8_t transform)
{
	HIP_ASSERT(transform > 0 && transform <= NUM_TRANSFORMS);

	return anchor_db.anchor_lengths[transform - 1];
}
