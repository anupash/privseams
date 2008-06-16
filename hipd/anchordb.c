#include "anchordb.h"

SList *anchor_list = NULL;

/* simply deletes all elements in the list and adds new ones */
// TODO reimplement as ineffcient
int update_anchor_db(struct hip_common *msg)
{
	struct hip_tlv_common *param = NULL;
	unsigned char *anchor = NULL;
	int err = 0, i = 1;
	
	free_slist(anchor_list);
	
	// process message and store anchor elements in the db
	param = (struct hip_tlv_common *) hip_get_param(msg, HIP_PARAM_UINT);
	anchor = (unsigned char *) hip_get_param_contents_direct(param);
	HIP_DEBUG("adding anchor %i to anchordb: %x \n", i, *anchor);
	append_to_slist(anchor_element, anchor);
	
	while(param = hip_get_next_param(msg, param))
	{
		i++;
		anchor = (unsigned char *) hip_get_param_contents_direct(param));
		HIP_DEBUG("adding anchor %i to anchordb: %x \n", i, *anchor);
		append_to_slist(anchor_element, anchor);
	}
	
  out_err:
	return err;
}

int has_more_anchors()
{
	if (anchor_list)
		return 1;
	else
		return 0;
}

/* puts the head of the list into the supplied buffer */
int get_next_anchor(unsigned char *anchor_element);
{
	int err = 0;
	anchor_element = (unsigned char *)anchor_list->data;
	remove_from_slist(anchor_list, anchor_element);
	
  out_err:
  	return err;
}