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
/** Pointer to currently set item in locals toolwindow. */
void *twl_current_item = NULL;


/******************************************************************************/
/* FUNCTIONS */

/******************************************************************************/
/** Just clear both toolwindows as empty ones. */
void tw_clear(void)
{
	gtk_widget_set_sensitive(widget(ID_TW_APPLY), FALSE);
	gtk_widget_set_sensitive(widget(ID_TW_CANCEL), FALSE);
	gtk_widget_set_sensitive(widget(ID_TW_DELETE), FALSE);
	gtk_widget_set_sensitive(widget(ID_TWL_APPLY), FALSE);
	gtk_widget_set_sensitive(widget(ID_TWL_CANCEL), FALSE);
	gtk_widget_set_sensitive(widget(ID_TWL_DELETE), FALSE);
	gtk_entry_set_text(widget(ID_TWR_NAME), "");
	gtk_entry_set_text(widget(ID_TWL_NAME), "");
	gtk_entry_set_text(widget(ID_TWG_NAME), "");
	
	tw_current_item = NULL;
	twl_current_item = NULL;
}
/* END OF FUNCTION */


/******************************************************************************/
/** Just clear remote toolwindow as empty ones. */
void tw_clear_remote(void)
{
	gtk_widget_set_sensitive(widget(ID_TW_APPLY), FALSE);
	gtk_widget_set_sensitive(widget(ID_TW_CANCEL), FALSE);
	gtk_widget_set_sensitive(widget(ID_TW_DELETE), FALSE);
	gtk_entry_set_text(widget(ID_TWR_NAME), "");
	gtk_entry_set_text(widget(ID_TWG_NAME), "");
	
	tw_current_item = NULL;
}
/* END OF FUNCTION */


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
	gtk_widget_show(widget(ID_TW_APPLY));
	gtk_widget_show(widget(ID_TW_CANCEL));
	gtk_widget_show(widget(ID_TW_DELETE));

	/* First hide current. */
	switch (tw_current_mode)
	{
	case TWMODE_NONE:
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
		gtk_widget_hide(widget(ID_TW_APPLY));
		gtk_widget_hide(widget(ID_TW_CANCEL));
		gtk_widget_hide(widget(ID_TW_DELETE));
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
		//sprintf(str, "%d", hit->port);
		gtk_entry_set_text(widget(ID_TWR_PORT), hit->port);

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

	@param g Pointer to remote HIT.
 */
void tw_set_remote_rgroup_info(HIT_Group *g)
{
	/* Variables. */
	char *ps;
	int i;

	i = find_from_cb(g->l->name, widget(ID_TWR_LOCAL));
	gtk_combo_box_set_active(widget(ID_TWR_LOCAL), i);

	if (g->type == HIT_DB_TYPE_ACCEPT) ps = lang_get("group-type-accept");
	else ps = lang_get("group-type-deny");
	i = find_from_cb(ps, widget(ID_TWR_TYPE1));
	gtk_combo_box_set_active(widget(ID_TWR_TYPE1), i);
	if (g->lightweight == 1) ps = lang_get("group-type2-lightweight");
	else ps = lang_get("group-type2-normal");
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

	gtk_widget_set_sensitive(widget(ID_TWL_APPLY), FALSE);
	gtk_widget_set_sensitive(widget(ID_TWL_CANCEL), FALSE);
	hit = hit_db_find_local(hit_name, NULL);

	if (hit)
	{
		gtk_entry_set_text(widget(ID_TWL_NAME), hit->name);
		print_hit_to_buffer(str, &hit->lhit);
		gtk_entry_set_text(widget(ID_TWL_LOCAL), str);
		twl_current_item = (void *)hit;
		gtk_widget_set_sensitive(widget(ID_TWL_APPLY), TRUE);
		gtk_widget_set_sensitive(widget(ID_TWL_CANCEL), TRUE);
	}
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Set remote group info to toolwindow from group with given name.

	@param group_name Name of group.
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
			if (group->type == HIT_DB_TYPE_ACCEPT) ps = lang_get("group-type-accept");
			else ps = lang_get("group-type-deny");
			i = find_from_cb(ps, widget(ID_TWG_TYPE1));
			gtk_combo_box_set_active(widget(ID_TWG_TYPE1), i);
			if (group->lightweight == 1) ps = lang_get("group-type2-lightweight");
			else ps = lang_get("group-type2-normal");
			i = find_from_cb(ps, widget(ID_TWG_TYPE2));
			gtk_combo_box_set_active(widget(ID_TWG_TYPE2), i);

			tw_current_item = (void *)group;
			
			/* If group is empty and not default, allow deleting of the group. */
			if (strcmp(group->name, lang_get("default-group-name")) == 0);
			else if (group->remotec < 1) gtk_widget_set_sensitive(widget(ID_TW_DELETE), TRUE);
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
	HIT_Remote *r = (HIT_Remote *)tw_current_item;
	HIT_Group *g = (HIT_Group *)tw_current_item;
	HIT_Group *g2;
	Update_data ud;
	char *ps, str[256];

	if (!tw_current_item) return;
	
	switch (tw_current_mode)
	{
	case TWMODE_REMOTE:
		strcpy(str, gtk_entry_get_text(widget(ID_TWR_NAME)));
		if (check_hit_name(str, r))
		{
			NAMECPY(ud.old_name, r->name);
			NAMECPY(ud.new_name, str);
			NAMECPY(r->name, str);
			ps = gtk_entry_get_text(widget(ID_TWR_URL));
			URLCPY(r->url, ps);
			ps = gtk_entry_get_text(widget(ID_TWR_PORT));
			URLCPY(r->port, ps);

			ud.depth = 2;
			ud.indices_first = -1;
			HIP_DEBUG("Updating remote HIT %s -> %s.\n", ud.old_name, ud.new_name);
			gtk_tree_model_foreach(widget(ID_RLISTMODEL), gui_update_tree_value, &ud);

			/* Change group, if wanted. */
			ps = gtk_combo_box_get_active_text(widget(ID_TWR_RGROUP));
			g = hit_db_find_rgroup(ps);
			if (g && g != r->g)
			{
				r->g->remotec--;
				g2 = r->g;
				r->g = g;
				r->g->remotec++;
				
				/* Delete old remote HIT from list. */
				NAMECPY(ud.old_name, r->name);
				ud.new_name[0] = '\0';
				gtk_tree_model_foreach(widget(ID_RLISTMODEL), gui_update_tree_value, &ud);
				/* Add it to new group in list. */
				gui_add_remote_hit(r->name, g->name);
				if (g2->remotec < 1) gui_add_remote_hit("", g2->name);
			}
		}
		break;

	case TWMODE_RGROUP:
		strcpy(str, gtk_entry_get_text(widget(ID_TWG_NAME)));
		if (check_group_name(str, g))
		{
			NAMECPY(ud.old_name, g->name);
			NAMECPY(ud.new_name, str);
			NAMECPY(g->name, str);
			ps = gtk_combo_box_get_active_text(widget(ID_TWG_TYPE1));
			if (strcmp(lang_get("hit-type-accept"), ps) == 0) g->type = HIT_DB_TYPE_ACCEPT;
			else g->type = HIT_DB_TYPE_DENY;
			ud.depth = 1;
			ud.indices_first = -1;
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

	if (!tw_current_item) return;
	
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
}
/* END OF FUNCTION */


/******************************************************************************/
/** When delete is pressed in toolwindow. */
void tw_delete(void)
{
	/* Variables. */
	GtkWidget *w;
	HIT_Remote *r = (HIT_Remote *)tw_current_item;
	HIT_Group *g = (HIT_Group *)tw_current_item;
	int err;
	
	if (!tw_current_item) return;
	
	switch (tw_current_mode)
	{
	case TWMODE_REMOTE:
		g = r->g;
		w = gtk_message_dialog_new(NULL, GTK_DIALOG_MODAL,
		                           GTK_MESSAGE_QUESTION, GTK_BUTTONS_YES_NO,
		                           lang_get("ask-delete-hit"));
		gtk_widget_show(w);
		gtk_window_set_keep_above(w, TRUE);
		err = gtk_dialog_run(w);
		gtk_widget_destroy(w);
		if (err != GTK_RESPONSE_YES);
		else if (hit_db_del(r->name) == 0)
		{
			tw_clear_remote();
			tw_set_mode(TWMODE_NONE);
			if (g->remotec < 1) gui_add_remote_hit("", g->name);
		}
		break;

	case TWMODE_RGROUP:
		w = gtk_message_dialog_new(NULL, GTK_DIALOG_MODAL,
		                           GTK_MESSAGE_QUESTION, GTK_BUTTONS_YES_NO,
		                           lang_get("ask-delete-group"));
		gtk_widget_show(w);
		gtk_window_set_keep_above(w, TRUE);
		err = gtk_dialog_run(w);
		gtk_widget_destroy(w);
		if (err != GTK_RESPONSE_YES);
		else if (hit_db_del_rgroup(g->name) == 0)
		{
			tw_clear_remote();
			tw_set_mode(TWMODE_NONE);
		}
		break;
	}
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	When apply is pressed in locals toolwindow.
*/
void twl_apply(void)
{
	/* Variables. */
	HIT_Local *l = (HIT_Local *)twl_current_item;
	Update_data ud;
	char str[256];

	if (!twl_current_item) return;

	strcpy(str, gtk_entry_get_text(widget(ID_TWL_NAME)));
	if (1)//check_name_input(str))
	{
		NAMECPY(ud.old_name, l->name);
		NAMECPY(ud.new_name, str);
		NAMECPY(l->name, str);
		ud.depth = 1;
		ud.indices_first = -1;
		HIP_DEBUG("Updating local HIT %s -> %s.\n", ud.old_name, ud.new_name);
		gtk_tree_model_foreach(widget(ID_LLISTMODEL), gui_update_tree_value, &ud);
		all_update_local(ud.old_name, ud.new_name);
	}
}
/* END OF FUNCTION */


/******************************************************************************/
/** When cancel is pressed in locals toolwindow. */
void twl_cancel(void)
{
	/* Variables. */
	HIT_Local *l = (HIT_Local *)twl_current_item;
	
	if (!twl_current_item) return;

	tw_set_local_info(l->name);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/

