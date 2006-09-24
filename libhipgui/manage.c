/*
    HIP Agent

    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

/******************************************************************************/
/* INCLUDES */
#include "manage.h"


/******************************************************************************/
/* EXTERNS */
extern GtkTreeIter local_top, remote_top, process_top;


/******************************************************************************/
/* FUNCTIONS */

/******************************************************************************/
/**
	Tell GUI to add new local HIT into list.

	@param hit New HIT to add.
*/
void gui_add_local_hit(HIT_Local *hit)
{
	/* Variables. */
	GtkWidget *w;
	GtkTreeIter iter;
	gchar *msg = g_strdup_printf(hit->name);

	w = widget(ID_RLISTMODEL);
	gtk_tree_store_append(w, &iter, &local_top);
	gtk_tree_store_set(w, &iter, 0, msg, -1);
	g_free(msg);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Tell GUI to add new remote group into list.

	@param group New group to add.
*/
void gui_add_rgroup(HIT_Group *group)
{
	/* Variables. */
	GtkWidget *w;
	GtkTreeIter iter;
	gchar *msg = g_strdup_printf(group->name);

	gdk_threads_enter();
	w = widget(ID_RLISTMODEL);
	gtk_tree_store_append(GTK_TREE_STORE(w), &iter, &remote_top);
	gtk_tree_store_set(GTK_TREE_STORE(w), &iter, 0, msg, -1);

	gtk_combo_box_insert_text(widget(ID_TWR_RGROUP), 0, group);
	gtk_combo_box_insert_text(widget(ID_NH_RGROUP), 0, group);

	g_free(msg);
	gdk_threads_leave();
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Tell GUI to add new remote HIT into list.

	@param hit New HIT to add.
	@param group Group where to add new HIT.
*/
void gui_add_remote_hit(char *hit, char *group)
{
	/* Variables. */
	GtkWidget *w;
	GtkTreeIter iter, gtop;
	GtkTreeModel *model;
	int err;
	char *str;

	w = widget(ID_RLISTMODEL);
	err = gtk_tree_model_iter_children(GTK_TREE_STORE(w), &gtop, &remote_top);
	HIP_IFEL(err == FALSE, -1, "No remote groups.\n");
	err = -1;

	do
	{
		gtk_tree_model_get(w, &gtop, 0, &str, -1);
		if (strcmp(str, group) == 0)
		{
			HIP_DEBUG("Found remote group \"%s\", adding remote HIT \"%s\".\n", group, hit);
			gtk_tree_store_append(GTK_TREE_STORE(w), &iter, &gtop);
			gtk_tree_store_set(GTK_TREE_STORE(w), &iter, 0, hit, -1);
			err = 0;
			break;
		}
	} while (gtk_tree_model_iter_next(w, &gtop) != FALSE);

out_err:
	if (err)
	{
		HIP_DEBUG("Did not find remote group \"%s\", could not show new HIT!\n", group);
	}
	return;
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Tell GUI to delete remote HIT from list.

	@param name Name of HIT to be removed.
*/
void gui_delete_remote_hit(char *name)
{
	/* Variables. */
	Update_data ud;

	NAMECPY(ud.old_name, name);
	ud.new_name[0] = '\0';
	ud.depth = 3;
	ud.indices_first = 1;
	gtk_tree_model_foreach(widget(ID_RLISTMODEL), gui_update_tree_value, &ud);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Tell GUI to add new process to process list.

	@param pid Process ID.
	@param name Process name.
	@param time Time used.
	@param msgs Number of messages.
*/
void gui_add_process(int pid, char *name, int time, int msgs)
{
	/* Variables. */
	GtkWidget *w;
	GtkTreeIter iter;

	w = widget(ID_PLISTMODEL);
	gtk_tree_store_insert(w, &iter, NULL, MAX_EXEC_PIDS);
	gtk_tree_store_set(w, &iter, 0, pid, 1, name, -1);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Tell GUI to update value from tree store.
*/
gboolean gui_update_tree_value(GtkTreeModel *model, GtkTreePath *path,
                               GtkTreeIter *iter, gpointer data)
{
	/* Variables. */
	Update_data *ud = (Update_data *)data;
	char *str;
	int *indices, depth;

	gtk_tree_model_get(model, iter, 0, &str, -1);
	indices = gtk_tree_path_get_indices(path);
	depth = gtk_tree_path_get_depth(path);

	if ((indices[0] != ud->indices_first || depth != ud->depth)
	    && ud->indices_first >= 0 && ud->depth >= 0);
	else if (strcmp(ud->old_name, str) == 0)
	{
		/* If new name length is less than one, then delete item. */
		if (strlen(ud->new_name) < 1)
		{
			gtk_tree_store_remove(model, iter);
		}
		else
		{
			gtk_tree_store_set(model, iter, 0, ud->new_name, -1);
		}
		return (TRUE);
	}

	return (FALSE);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Tell GUI to update value from list store (eg. combo box).
*/
gboolean gui_update_list_value(GtkTreeModel *model, GtkTreePath *path,
                               GtkTreeIter *iter, gpointer data)
{
	/* Variables. */
	Update_data *ud = (Update_data *)data;
	char *str;
	int *indices, depth;

	gtk_tree_model_get(model, iter, 0, &str, -1);
	indices = gtk_tree_path_get_indices(path);
	depth = gtk_tree_path_get_depth(path);

	if ((indices[0] != ud->indices_first || depth != ud->depth)
	    && ud->indices_first >= 0 && ud->depth >= 0);
	else if (strcmp(ud->old_name, str) == 0)
	{
		gtk_list_store_set(model, iter, 0, ud->new_name, -1);
		return (TRUE);
	}

	return (FALSE);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Ask for new HIT from user.

	@param hit Information of HIT to be accepted.
	@param inout Whether in or outgoing packet.
	@return Returns 0 on add, -1 on drop.
*/
int gui_ask_new_hit(HIT_Remote *hit, int inout)
{
	/* Variables. */
	static int in_use = 0;
	GtkDialog *dialog = (GtkDialog *)widget(ID_NHDLG);
	HIT_Group *group;
	char phit[128], *ps;
	int err = 0, w, h;

	while (in_use != 0) usleep(100 * 1000);
	in_use = 1;

	gdk_threads_enter();
	gtk_window_get_size(dialog, &w, &h);
	gtk_window_move(dialog, (gdk_screen_width() - w) / 2, (gdk_screen_height() - h) / 2);
	gtk_window_set_keep_above(dialog, TRUE);
	gtk_widget_show(dialog);
	print_hit_to_buffer(phit, &hit->hit);
	gtk_label_set_text(widget(ID_NH_HIT), phit);
	gtk_entry_set_text(widget(ID_NH_NAME), hit->name);
//	delete_all_items_from_cb(widget(ID_NH_RGROUP));
	gtk_combo_box_set_active(widget(ID_NH_RGROUP), 0);

	err = gtk_dialog_run(GTK_DIALOG(dialog));
	switch (err)
	{
	case GTK_RESPONSE_YES:
		err = 0;
		break;
	case GTK_RESPONSE_NO:
	default:
		err = -1;
		break;
	}

	ps = gtk_combo_box_get_active_text(widget(ID_NH_RGROUP));
	group = hit_db_find_rgroup(ps);
	hit->g = group;
	ps = gtk_entry_get_text(widget(ID_NH_NAME));
	NAMECPY(hit->name, ps);
	ps = gtk_entry_get_text(widget(ID_NH_URL));
	URLCPY(hit->url, ps);
	ps = gtk_entry_get_text(widget(ID_NH_PORT));
	URLCPY(hit->port, ps);
	HIP_DEBUG("New hit with parameters: %s, %s, %s.\n", hit->name, hit->g->name,
	          hit->g->type == HIT_DB_TYPE_ACCEPT ? "accept" : "deny");

	gtk_widget_hide(dialog);
	gdk_threads_leave();
	in_use = 0;

	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Set number of remote HITs in use.
*/
void gui_set_nof_hiu(int n)
{
	/* Variables. */
	char str[320];
	
	gdk_threads_enter();
	sprintf(str, "Number of remote HITs in use: %d", n);
	gtk_label_set_text(widget(ID_HIUNUM), str);
	gdk_threads_leave();
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Delete all remote HITs in use from list.
*/
void gui_clear_hiu(void)
{
	/* Variables. */
	GtkWidget *w;
	
	gdk_threads_enter();
	w = widget(ID_PHIUMODEL);
	gtk_tree_store_clear(w);
	gdk_threads_leave();
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Add remote HIT in use.
*/
void gui_add_hiu(HIT_Remote *hit)
{
	/* Variables. */
	GtkWidget *w;
	GtkTreeIter iter;

	gdk_threads_enter();
	w = widget(ID_PHIUMODEL);
	gtk_tree_store_insert(w, &iter, NULL, 99);
	gtk_tree_store_set(w, &iter, 0, hit->name, -1);
	gdk_threads_leave();
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Create new remote group.

	@return Name of new remote group.
*/
char *create_remote_group(void)
{
	/* Variables. */
	GtkWidget *dialog = (GtkWidget *)widget(ID_NGDLG);
	HIT_Group *g;
	HIT_Local *l;
	int err = -1, type, lw;
	char *psn, *psl, *ps;
	pthread_t pt;

	gtk_widget_show(dialog);
	gtk_widget_grab_focus(widget(ID_NG_NAME));
	gtk_entry_set_text(widget(ID_NG_NAME), "");

	err = gtk_dialog_run(dialog);
	if (err == GTK_RESPONSE_OK)
	{
		ps = gtk_combo_box_get_active_text(widget(ID_NG_TYPE1));
		if (strcmp("accept", ps) == 0) type = HIT_DB_TYPE_ACCEPT;
		else type = HIT_DB_TYPE_DENY;
		ps = gtk_combo_box_get_active_text(widget(ID_NG_TYPE2));
		if (strcmp("lightweight", ps) == 0) lw = 1;
		else lw = 0;

		psn = gtk_entry_get_text(widget(ID_NG_NAME));
		psl = gtk_combo_box_get_active_text(widget(ID_NG_LOCAL));
		l = NULL;
		if (strlen(psl) > 0)
		{
			l = hit_db_find_local(psl, NULL);
		}
		if (l == NULL)
		{
			HIP_DEBUG("Failed to find local HIT named: %s\n", psl);
			psn = NULL;
		}
		else if (strlen(psn) > 0)
		{
			g = (HIT_Group *)malloc(sizeof(HIT_Group));
			memset(g, 0, sizeof(HIT_Group));
			NAMECPY(g->name, psn);
			g->l = l;
			g->type = type;
			g->lightweight = lw;

			pthread_create(&pt, NULL, create_remote_group_thread, g);
		}
		else psn = NULL;
	}

out_err:
	gtk_widget_hide(dialog);
	return (psn);
}
/* END OF FUNCTION */


/******************************************************************************/
/** Thread function for adding new remote group. */
void *create_remote_group_thread(void *data)
{
	/* Variables. */
	HIT_Group *g = (HIT_Group *)data;

	hit_db_add_rgroup(g->name, g->l, g->type, g->lightweight);

	return (NULL);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Add local HITs to all combo boxes and such.
	This is a enumeration callback function.
*/
int all_add_local(HIT_Remote *hit, void *p)
{
	gtk_combo_box_append_text(widget(ID_TWR_LOCAL), hit->name);
	gtk_combo_box_append_text(widget(ID_TWG_LOCAL), hit->name);
	gtk_combo_box_append_text(widget(ID_NG_LOCAL), hit->name);
	gtk_combo_box_append_text(widget(ID_NH_LOCAL), hit->name);
	return (0);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Update local HITs to all combo boxes and such.
*/
void all_update_local(char *old_name, char *new_name)
{
	/* Variables. */
	GtkTreeModel *model;
	Update_data ud;

	ud.depth = -1;
	ud.indices_first = -1;
	NAMECPY(ud.old_name, old_name);
	NAMECPY(ud.new_name, new_name);

	model = gtk_combo_box_get_model(widget(ID_TWR_LOCAL));
	gtk_tree_model_foreach(model, gui_update_list_value, &ud);

	model = gtk_combo_box_get_model(widget(ID_TWG_LOCAL));
	gtk_tree_model_foreach(model, gui_update_list_value, &ud);

	model = gtk_combo_box_get_model(widget(ID_NG_LOCAL));
	gtk_tree_model_foreach(model, gui_update_list_value, &ud);

	model = gtk_combo_box_get_model(widget(ID_NH_LOCAL));
	gtk_tree_model_foreach(model, gui_update_list_value, &ud);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Update remote groups to all combo boxes and such.
*/
void all_update_rgroups(char *old_name, char *new_name)
{
	/* Variables. */
	GtkTreeModel *model;
	Update_data ud;

	ud.depth = -1;
	ud.indices_first = -1;
	NAMECPY(ud.old_name, old_name);
	NAMECPY(ud.new_name, new_name);

	model = gtk_combo_box_get_model(widget(ID_TWR_RGROUP));
	gtk_tree_model_foreach(model, gui_update_list_value, &ud);

	model = gtk_combo_box_get_model(widget(ID_NH_RGROUP));
	gtk_tree_model_foreach(model, gui_update_list_value, &ud);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/

