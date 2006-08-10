/*
    HIP Agent

    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

/******************************************************************************/
/* INCLUDES */
#include "nh.h"


/******************************************************************************/
/* FUNCTIONS */


/******************************************************************************/
/**
	Set remote HIT group info to new hit -dialog from given group.

	@param g Pointer to remote HIT.
 */
void nh_set_remote_rgroup_info(HIT_Group *g)
{
	/* Variables. */
	char *ps;
	int i;

	i = find_from_cb(g->l->name, widget(ID_NH_LOCAL));
	gtk_combo_box_set_active(widget(ID_NH_LOCAL), i);

	if (g->type == HIT_DB_TYPE_ACCEPT) ps = "accept";
	else ps = "deny";
	i = find_from_cb(ps, widget(ID_NH_TYPE1));
	gtk_combo_box_set_active(widget(ID_NH_TYPE1), i);
	if (g->lightweight == 1) ps = "lightweight";
	else ps = "normal";
	i = find_from_cb(ps, widget(ID_NH_TYPE2));
	gtk_combo_box_set_active(widget(ID_NH_TYPE2), i);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/

