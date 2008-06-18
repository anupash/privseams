#include "anchordb.h"
#include "linkedlist.h"

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
	unsigned char *anchor = NULL;
	int err = 0, i = 1;
	
	hip_ll_uninit(&anchor_list, free);
	
	// process message and store anchor elements in the db
	param = (struct hip_tlv_common *) hip_get_param(msg, HIP_PARAM_UINT);
	anchor = (unsigned char *) hip_get_param_contents_direct(param);
	HIP_DEBUG("adding anchor %i to anchordb: %x \n", i, *anchor);
	hip_ll_add_first(&anchor_list, anchor);
	
	while(param = hip_get_next_param(msg, param))
	{
		i++;
		anchor = (unsigned char *) hip_get_param_contents_direct(param);
		HIP_DEBUG("adding anchor %i to anchordb: %x \n", i, *anchor);
		hip_ll_add_first(&anchor_list, anchor);
	}
	
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
int get_next_anchor(unsigned char *anchor_element)
{
	int err = 0;
	anchor_element = (unsigned char *)hip_ll_del_first(&anchor_list, NULL);
	
  out_err:
  	return err;
}
