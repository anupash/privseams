#include "hchain_anchordb.h"
#include "linkedlist.h"

hip_ll_t anchor_list;

void init_anchor_db()
{
	HIP_DEBUG("initializing the anchorDB...\n");
	hip_ll_init(&anchor_list);
}

/* simply deletes all elements in the list and adds new ones */
// TODO reimplement as ineffcient -> only add non-existing elements
int update_anchor_db(struct hip_common *msg)
{
	struct hip_tlv_common *param = NULL;
	unsigned char *anchor = NULL;
	int err = 0, hash_length = 0, salt_length = 0, item_length = 0;
	extern uint8_t hip_esp_prot_ext_transform;
	
	hip_ll_uninit(&anchor_list, free);
	
	if (hip_esp_prot_ext_transform > ESP_PROT_TRANSFORM_UNUSED)
	{
		hash_length = esp_prot_transforms[hip_esp_prot_ext_transform];
		HIP_DEBUG("hash length: %i \n", hash_length);
	} else
	{
		HIP_ERROR("anchor db update issued, but wrong transform\n");
		
		err = 1;
		goto out_err;
	}
		
	// process message and store anchor elements in the db
	param = (struct hip_tlv_common *)hip_get_param(msg, HIP_PARAM_HCHAIN_ANCHOR);
	do
	{
		HIP_IFEL(!(anchor = (unsigned char *)malloc(hash_length)), -1,
						"failed to allocate memory\n");
		
		anchor = (unsigned char *)hip_get_param_contents_direct(param);
		HIP_HEXDUMP("anchor: ", anchor, hash_length);
		
		hip_ll_add_first(&anchor_list, anchor);
	} while(param = hip_get_next_param(msg, param));
	
  out_err:
	return err;
}

int has_more_anchors()
{
	if (hip_ll_get_size(&anchor_list))
		return 1;
	else
		return 0;
}

/* gets the first element of the list into the supplied buffer */
int get_next_anchor(unsigned char *anchor)
{
	int err = 0;
	anchor = NULL;
	
	HIP_IFEL(!(anchor = (unsigned char *)hip_ll_del_first(&anchor_list, NULL)), -1,
			"failed to retrieve anchor\n");
	
  out_err:
  	return err;
}
