/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

/******************************************************************************/
/* INCLUDES */
#include "tw.h"


/******************************************************************************/
/* VARIABLES */

/** Current mode for toolwindow. */
int tw_current_mode = -1;
/** Pointer to currently set item in toolwindow. */
void *tw_current_item = NULL;


/******************************************************************************/
/* FUNCTIONS */

/******************************************************************************/
/**
	Set tool window mode to no given.
	
	@param mode New mode for toolwindow.
*/
void tw_set_mode(int mode)
{
	/* Variables. */
	GtkWidget *container = widget(ID_TW_CONTAINER);
	
	gtk_widget_set_sensitive(widget(ID_TW_APPLY), FALSE);
	gtk_widget_set_sensitive(widget(ID_TW_CANCEL), FALSE);
	gtk_widget_set_sensitive(widget(ID_TW_DELETE), FALSE);
	
	/* First hide current. */
	switch (tw_current_mode)
	{
	case TWMODE_NONE:
		break;

	case TWMODE_LOCAL:
		gtk_container_remove(container, widget(ID_TWLOCAL));
		break;
	
	case TWMODE_REMOTE:
		gtk_container_remove(container, widget(ID_TWREMOTE));
		break;

	case TWMODE_RGROUP:
		gtk_container_remove(container, widget(ID_TWRGROUP));
		break;
	}
	
	/* Then show selected mode. */
	switch (mode)
	{
	case TWMODE_NONE:
		break;
	
	case TWMODE_LOCAL:
		gtk_widget_set_sensitive(widget(ID_TW_APPLY), TRUE);
		gtk_widget_set_sensitive(widget(ID_TW_CANCEL), TRUE);
		gtk_container_add(container, widget(ID_TWLOCAL));
		gtk_widget_show(widget(ID_TWLOCAL));
		break;
		
	case TWMODE_REMOTE:
		gtk_widget_set_sensitive(widget(ID_TW_APPLY), TRUE);
		gtk_widget_set_sensitive(widget(ID_TW_CANCEL), TRUE);
		gtk_widget_set_sensitive(widget(ID_TW_DELETE), TRUE);
		gtk_container_add(container, widget(ID_TWREMOTE));
		gtk_widget_show(widget(ID_TWREMOTE));
		break;
	
	case TWMODE_RGROUP:
		gtk_widget_set_sensitive(widget(ID_TW_APPLY), TRUE);
		gtk_widget_set_sensitive(widget(ID_TW_CANCEL), TRUE);
		gtk_container_add(container, widget(ID_TWRGROUP));
		gtk_widget_show(widget(ID_TWRGROUP));
		break;
	}
	
	tw_current_mode = mode;
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Set remote HIT info to toolwindow from HIT with given name.
	
	@param hit_name Name of remote HIT.
 */
void tw_set_remote_info(char *hit_name)
{
	/* Variables. */
	GtkWidget *w;
	HIT_Remote *hit;
	char str[320], *ps;
	int i;
	
	hit = hit_db_find(hit_name, NULL);
	
	if (hit)
	{
		gtk_entry_set_text(widget(ID_TWR_NAME), hit->name);
		gtk_entry_set_text(widget(ID_TWR_URL), hit->url);
		sprintf(str, "%d", hit->port);
		gtk_entry_set_text(widget(ID_TWR_PORT), str);
		
		print_hit_to_buffer(str, &hit->hit);
		gtk_entry_set_text(widget(ID_TWR_REMOTE), str);
		
		i = find_from_cb(hit->g->name, widget(ID_TWR_RGROUP));
		gtk_combo_box_set_active(widget(ID_TWR_RGROUP), i);

		tw_set_remote_rgroup_info(hit->g);

		tw_current_item = (void *)hit;
	}
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Set remote HIT group info to toolwindow from given group.
	
	@param hit_name Name of remote HIT.
 */
void tw_set_remote_rgroup_info(HIT_Group *g)
{
	/* Variables. */
	char *ps;
	int i;

	i = find_from_cb(g->l->name, widget(ID_TWR_LOCAL));
	gtk_combo_box_set_active(widget(ID_TWR_LOCAL), i);

	if (g->type == HIT_DB_TYPE_ACCEPT) ps = "accept";
	else ps = "deny";
	i = find_from_cb(ps, widget(ID_TWR_TYPE1));
	gtk_combo_box_set_active(widget(ID_TWR_TYPE1), i);
	if (g->lightweight == 1) ps = "lightweight";
	else ps = "normal";
	i = find_from_cb(ps, widget(ID_TWR_TYPE2));
	gtk_combo_box_set_active(widget(ID_TWR_TYPE2), i);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Set remote HIT info to toolwindow from HIT with given name.
	
	@param hit_name Name of remote HIT.
 */
void tw_set_local_info(char *hit_name)
{
	/* Variables. */
	GtkWidget *w;
	HIT_Local *hit;
	char str[320];
	int i;
	
	hit = hit_db_find_local(hit_name, NULL);
	
	if (hit)
	{
		gtk_entry_set_text(widget(ID_TWL_NAME), hit->name);
		print_hit_to_buffer(str, &hit->lhit);
		gtk_entry_set_text(widget(ID_TWL_LOCAL), str);
		tw_current_item = (void *)hit;
	}
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Set remote HIT info to toolwindow from HIT with given name.
	
	@param hit_name Name of remote HIT.
 */
void tw_set_rgroup_info(char *group_name)
{
	/* Variables. */
	GtkWidget *w;
	HIT_Group *group;
	char str[320], *ps;
	int i;
	
	group = hit_db_find_rgroup(group_name);
	
	if (group)
	{
		i = find_from_cb(group->l->name, widget(ID_TWG_LOCAL));
		
		if (i >= 0)
		{
			gtk_entry_set_text(widget(ID_TWG_NAME), group->name);
			gtk_combo_box_set_active(widget(ID_TWG_LOCAL), i);
			if (group->type == HIT_DB_TYPE_ACCEPT) ps = "accept";
			else ps = "deny";
			i = find_from_cb(ps, widget(ID_TWG_TYPE1));
			gtk_combo_box_set_active(widget(ID_TWG_TYPE1), i);
			if (group->lightweight == 1) ps = "lightweight";
			else ps = "normal";
			i = find_from_cb(ps, widget(ID_TWG_TYPE2));
			gtk_combo_box_set_active(widget(ID_TWG_TYPE2), i);
	
			tw_current_item = (void *)group;
		}
	}
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Add remote group to combo box.
	This is mostly used as enumeration callback function.
	
	@param group Pointer to HIT_Group struct.
	@param p Pointer to combo box widget.
*/
int tw_add_rgroup(HIT_Group *group, void *p)
{
	/* Variables. */
	GtkWidget *w = (GtkWidget *)p;
	
	gtk_combo_box_insert_text(w, 0, group->name);
	
	return (0);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	When apply is pressed in toolwindow.
*/
void tw_apply(void)
{
	/* Variables. */
	HIT_Local *l = (HIT_Local *)tw_current_item;
	HIT_Remote *r = (HIT_Remote *)tw_current_item;
	HIT_Group *g = (HIT_Group *)tw_current_item;
	Update_data ud;
	char *ps;
	
	switch (tw_current_mode)
	{
	case TWMODE_LOCAL:
		ps = gtk_entry_get_text(widget(ID_TWL_NAME));
		if (strlen(ps) > 0)
		{
			NAMECPY(ud.old_name, l->name);
			NAMECPY(ud.new_name, ps);
			NAMECPY(l->name, ps);
			ud.depth = 2;
			ud.indices_first = 0;
			HIP_DEBUG("Updating local HIT %s -> %s.\n", ud.old_name, ud.new_name);
			gtk_tree_model_foreach(widget(ID_RLISTMODEL), gui_update_tree_value, &ud);
			all_update_local(ud.old_name, ud.new_name);
		}
		break;
	
	case TWMODE_REMOTE:
		ps = gtk_entry_get_text(widget(ID_TWR_NAME));
		if (strlen(ps) > 0)
		{
			NAMECPY(ud.old_name, r->name);
			NAMECPY(ud.new_name, ps);
			NAMECPY(r->name, ps);
			ps = gtk_entry_get_text(widget(ID_TWR_URL));
			URLCPY(r->url, ps);
			ps = gtk_entry_get_text(widget(ID_TWR_PORT));
			r->port = atoi(ps);
			
			ud.depth = 3;
			ud.indices_first = 1;
			HIP_DEBUG("Updating remote HIT %s -> %s.\n", ud.old_name, ud.new_name);
			gtk_tree_model_foreach(widget(ID_RLISTMODEL), gui_update_tree_value, &ud);

			/* Change group, if wanted. */
			ps = gtk_combo_box_get_active_text(widget(ID_TWR_RGROUP));
			g = hit_db_find_rgroup(ps);
			if (g && g != r->g)
			{
				r->g = g;
				/* Delete old remote HIT from list. */
				NAMECPY(ud.old_name, r->name);
				ud.new_name[0] = '\0';
				gtk_tree_model_foreach(widget(ID_RLISTMODEL), gui_update_tree_value, &ud);
				/* Add it to new group in list. */
				gui_add_remote_hit(r->name, g->name);
			}
		}
		break;

	case TWMODE_RGROUP:
		ps = gtk_entry_get_text(widget(ID_TWG_NAME));
		if (strlen(ps) > 0)
		{
			NAMECPY(ud.old_name, g->name);
			NAMECPY(ud.new_name, ps);
			NAMECPY(g->name, ps);
			ps = gtk_combo_box_get_active_text(widget(ID_TWG_TYPE1));
			if (strcmp("accept", ps) == 0) g->type = HIT_DB_TYPE_ACCEPT;
			else g->type = HIT_DB_TYPE_DENY;
			ud.depth = 2;
			ud.indices_first = 1;
			HIP_DEBUG("Updating remote group %s -> %s.\n", ud.old_name, ud.new_name);
			gtk_tree_model_foreach(widget(ID_RLISTMODEL), gui_update_tree_value, &ud);
			all_update_rgroups(ud.old_name, ud.new_name);
		}
		break;
	}
	
	return (0);
}
/* END OF FUNCTION */


/******************************************************************************/
/** When cancel is pressed in toolwindow. */
void tw_cancel(void)
{
	/* Variables. */
	HIT_Local *l = (HIT_Local *)tw_current_item;
	HIT_Remote *r = (HIT_Remote *)tw_current_item;
	HIT_Group *g = (HIT_Group *)tw_current_item;
	
	switch (tw_current_mode)
	{
	case TWMODE_LOCAL:
		tw_set_local_info(l->name);
		break;
	
	case TWMODE_REMOTE:
		tw_set_remote_info(r->name);
		break;

	case TWMODE_RGROUP:
		tw_set_rgroup_info(g->name);
		break;
	}
	
	return (0);
}
/* END OF FUNCTION */


/******************************************************************************/
/** When delete is pressed in toolwindow. */
void tw_delete(void)
{
	/* Variables. */
	HIT_Local *l = (HIT_Local *)tw_current_item;
	HIT_Remote *r = (HIT_Remote *)tw_current_item;
	HIT_Group *g = (HIT_Group *)tw_current_item;
	
	switch (tw_current_mode)
	{
	case TWMODE_LOCAL:
		break;
	
	case TWMODE_REMOTE:
		if (hit_db_del(r->name) == 0) tw_set_mode(TWMODE_NONE);
		break;

	case TWMODE_RGROUP:
		break;
	}
	
	return (0);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/

