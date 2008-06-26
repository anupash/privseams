#include "anchordb.h"
#include "linkedlist.h"

void free_anchor_item(void * anchor_item);

hip_ll_t anchor_list;

void init_anchor_db()
{
	HIP_DEBUG("initializing the anchorDB...\n");
	hip_ll_init(&anchor_list);
}

/* simply deletes all elements in the list and adds new ones */
// TODO reimplement as ineffcient
int update_anchor_db(struct hip_common *msg)
{
	struct hip_tlv_common *param = NULL;
	hash_item_t *anchor_item = NULL;
	int err = 0, hash_length = 0, salt_length = 0, item_length = 0;
	
	hip_ll_uninit(&anchor_list, &free_anchor_item);
	
	HIP_IFE(!(anchor_item = (hash_item_t *)malloc(sizeof(hash_item_t))), -1);
	
	// process message and store anchor elements in the db
	param = (struct hip_tlv_common *)hip_get_param(msg, HIP_PARAM_UINT);
	hash_length = *((uint8_t *)hip_get_param_contents_direct(param));
	HIP_DEBUG("hash_length: %u \n", hash_length);
	
	param = (struct hip_tlv_common *)hip_get_next_param(msg, param);
	hash_length = *((uint8_t *)hip_get_param_contents_direct(param));
	HIP_DEBUG("salt_length: %u \n", salt_length);
	
	item_length = hash_length + hash_length;
	
	param = (struct hip_tlv_common *)hip_get_param(msg, HIP_PARAM_HCHAIN_ANCHOR);
	do
	{
		HIP_IFE(!(anchor_item = (hash_item_t *)malloc(sizeof(hash_item_t))), -1);
		
		anchor_item->hash_length = hash_length;
		anchor_item->salt_length = salt_length;
		anchor_item->hash = (unsigned char *)hip_get_param_contents_direct(param);
		HIP_HEXDUMP("anchor: ", anchor_item->hash, item_length);
		
		hip_ll_add_first(&anchor_list, anchor_item);
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
int get_next_anchor(hash_item_t *anchor_item)
{
	int err = 0;
	anchor_item = (hash_item_t *)hip_ll_del_first(&anchor_list, NULL);
	
  out_err:
  	return err;
}

void free_anchor_item(void * anchor_item)
{
	hash_item_t *anchor = NULL;
	
	HIP_ASSERT(anchor_item != NULL);
	
	anchor = (hash_item_t *)anchor_item;
	
	free(anchor->hash);
	free(anchor);
}
