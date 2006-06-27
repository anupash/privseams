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

	@param New hit to add.
*/
void gui_add_local_hit(HIT_Local *hit)
{
	/* Variables. */
	GtkWidget *w;
	GtkTreeIter iter;
	gchar *msg = g_strdup_printf(hit->name);

	w = widget(ID_RLISTMODEL);
	gtk_tree_store_append(GTK_TREE_STORE(w), &iter, &local_top);
	gtk_tree_store_set(GTK_TREE_STORE(w), &iter, 0, msg, -1);
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
	Ask for new HIT from user.
	
	@param hit Information of HIT to be accepted.
	@return Returns 1 on accept, 0 on deny.
*/
int gui_ask_new_hit(HIT_Item *hit)
{
	/* Variables. */
	static int in_use = 0;
	GtkDialog *dialog = (GtkDialog *)widget(ID_NHDLG);
	char phit[128], *ps;
	int err = 0;
	
	while (in_use != 0) usleep(100 * 1000);
	in_use = 1;

	gdk_threads_enter();
	gtk_widget_show(dialog);
	print_hit_to_buffer(phit, &hit->hit);
	gtk_label_set_text(widget(ID_NH_NEWHIT), phit);
	gtk_entry_set_text(widget(ID_NH_NAME), hit->name);
	gtk_combo_box_set_active(widget(ID_NH_RGROUP), 0);
	gtk_combo_box_set_active(widget(ID_NH_LOCAL), 0);
	
	err = gtk_dialog_run(GTK_DIALOG(dialog));
	switch (err)
	{
	case GTK_RESPONSE_YES:
		err = 1;
		break;
	case GTK_RESPONSE_NO:
	default:
		err = 0;
		break;
	}

	ps = gtk_combo_box_get_active_text(widget(ID_NH_RGROUP));
	strcpy(hit->group, ps);
	ps = gtk_entry_get_text(widget(ID_NH_NAME));
	strcpy(hit->name, ps);
	HIP_DEBUG("New hit with parameters: %s, %s.\n", hit->name, hit->group);

	gtk_widget_hide(dialog);
	gdk_threads_leave();
	in_use = 0;

	return (err);
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
	int err = -1;
	char *ps = NULL;
	pthread_t pt;

	gtk_widget_show(dialog);
	gtk_widget_grab_focus(widget(ID_CREATE_NAME));
	gtk_entry_set_text(widget(ID_CREATE_NAME), "");

	err = gtk_dialog_run(dialog);
	if (err == GTK_RESPONSE_OK)
	{
		ps = gtk_entry_get_text(widget(ID_CREATE_NAME));
		if (strlen(ps) > 0)
		{
			g = (HIT_Group *)malloc(sizeof(HIT_Group));
			memset(g, 0, sizeof(HIT_Group));
			strncpy(g->name, ps, 64);
			g->type = HIT_DB_TYPE_ACCEPT;
			g->lightweight = 0;

			pthread_create(&pt, NULL, create_remote_group_thread, g);
		}
		else ps = NULL;
	}

out_err:
	gtk_widget_hide(dialog);
	return (ps);
}
/* END OF FUNCTION */


/******************************************************************************/
/** Thread function for adding new remote group. */
void *create_remote_group_thread(void *data)
{
	/* Variables. */
	HIT_Group *g = (HIT_Group *)data;
	
	hit_db_add_rgroup(g->name, &g->lhit, g->type, g->lightweight);

	return (NULL);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/

