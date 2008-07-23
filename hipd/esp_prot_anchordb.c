#include "esp_prot_anchordb.h"

// set to support max amount of anchors possible

anchor_db_t anchor_db;

void anchor_db_init()
{
	HIP_DEBUG("initializing hchain anchorDB...\n");

	// set to 0 / NULL
	memset(anchor_db.num_anchors, 0, NUM_TRANSFORMS);
	memset(anchor_db.anchors, 0, NUM_TRANSFORMS * MAX_HCHAINS_PER_ITEM);
}

void anchor_db_uninit()
{
	int i, j;

	// free all hashes
	for (i = 0; i < NUM_TRANSFORMS; i++)
	{
		anchor_db.num_anchors[i] = 0;

		for (j = 0; j < MAX_HCHAINS_PER_ITEM; j++)
		{
			if (anchor_db.anchors[i][j])
				free(anchor_db.anchors[i][j]);

			anchor_db.anchors[i][j] = NULL;
		}
	}
}

// TODO modify
/* simply deletes all elements in the list and adds new ones */
// TODO reimplement as ineffcient -> only add non-existing elements
int anchor_db_update(struct hip_common *msg)
{
	struct hip_tlv_common *param = NULL;
	unsigned char *anchor = NULL, *tmp_anchor = NULL;
	int err = 0, hash_length = 0;
	extern uint8_t hip_esp_prot_ext_transform;

	HIP_DEBUG("updating hchain anchorDB...\n");

	hip_ll_uninit(&anchor_list, free);
	HIP_DEBUG("uninited hchain anchorDB\n");

	if (hip_esp_prot_ext_transform > ESP_PROT_TFM_UNUSED)
	{
		hash_length = esp_prot_transforms[hip_esp_prot_ext_transform];
		HIP_DEBUG("hash length is %i \n", hash_length);
	} else
	{
		HIP_ERROR("anchor db update issued, but unexpected transform\n");

		err = 1;
		goto out_err;
	}

	// process message and store anchor elements in the db
	param = (struct hip_tlv_common *)hip_get_param(msg, HIP_PARAM_HCHAIN_ANCHOR);
	do
	{
		HIP_IFEL(!(anchor = (unsigned char *)malloc(hash_length)), -1,
						"failed to allocate memory\n");

		tmp_anchor = (unsigned char *)hip_get_param_contents_direct(param);
		HIP_HEXDUMP("adding anchor: ", tmp_anchor, hash_length);

		memcpy(anchor, tmp_anchor, hash_length);

		hip_ll_add_first(&anchor_list, anchor);
	} while(param = hip_get_next_param(msg, param));

  out_err:
	return err;
}

int has_more_anchors(uint8_t transform)
{
	HIP_ASSERT(transform >= 0 && transform < NUM_TRANSFORMS);

	if (anchor_db.num_anchors[transform] > 0)
		return 1;
	else
		return 0;
}

// TODO modify
/* gets the first element of the list into the supplied buffer */
unsigned char * get_next_anchor(uint8_t transform)
{
	unsigned char *return_anchor = NULL;
	int err = 0;

	HIP_IFEL(!(return_anchor = (unsigned char *)hip_ll_del_first(&anchor_list, NULL)), -1,
			"failed to retrieve anchor\n");

  out_err:
  	if (err)
  	{
  		if (return_anchor)
  			free(return_anchor);
  		return_anchor = NULL;
  	}

  	return return_anchor;
}
