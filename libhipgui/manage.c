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
/* VARIABLES */
int tw_cur_mode = -1;


/******************************************************************************/
/* FUNCTIONS */

/******************************************************************************/
/**
	Tell GUI to add new local HIT into list.

	@param New hit to add.
*/
void gui_add_hit(char *hit)
{
	/* Variables. */
	GtkWidget *w;
	GtkTreeIter iter;
	gchar *msg = g_strdup_printf(hit);

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
	
	tooldlg_add_rgroups(group, widget(ID_TOOLRGROUPS));
	askdlg_add_rgroups(group, widget(ID_AD_RGROUPS));
	
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
		//hit_db_add_rgroup(group);
		//gui_add_remote_hit(hit, group);
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
	gtk_tree_store_insert(GTK_TREE_STORE(w), &iter, NULL, MAX_EXEC_PIDS);
	gtk_tree_store_set(GTK_TREE_STORE(w), &iter, 0, pid, 1, name, -1);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Callback to go trough remote HITs.
*/
void gui_remote_hit_callback(GtkWidget *hit, gpointer data)
{
	if (data == NULL) return;
	
/*	if (!strcmp((char *)data, "clear"))
	{
		gtk_container_remove(GTK_CONTAINER(remote_hits), hit);
	}*/
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Tell GUI to clear remote hits list.
*/
void gui_clear_remote_hits(void)
{
//	gtk_container_foreach(GTK_CONTAINER(remote_hits), gui_remote_hit_callback, "clear");
//	remote_hits_n = 0;
}
/* END OF FUNCTION */


/******************************************************************************/
/** Test function. */
void gui_test_func(void)
{
	printf("Test func called.\n");
}
/* END OF FUNCTION */


/******************************************************************************/
/** Terminate GUI. */
void gui_terminate(void)
{
	gtk_main_quit();
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
	GtkDialog *dialog = gui_get_acceptdialog();
	char phit[128], *ps;
	int err = 0;
	
	while (in_use != 0) usleep(100 * 1000);
	in_use = 1;

	gdk_threads_enter();
	gtk_widget_show(dialog);
	print_hit_to_buffer(phit, &hit->rhit);
	gtk_label_set_text(widget(ID_AD_NEWHIT), phit);
	gtk_entry_set_text(widget(ID_AD_NAME), hit->name);
	gtk_combo_box_set_active(widget(ID_AD_RGROUPS), 0);
	gtk_combo_box_set_active(widget(ID_AD_LHITS), 0);
	
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
	
	if (err = 1) hit->type = HIT_DB_TYPE_ACCEPT;
	else hit->type = HIT_DB_TYPE_DENY;

	ps = gtk_combo_box_get_active_text(widget(ID_AD_RGROUPS));
	strcpy(hit->group, ps);
	ps = gtk_entry_get_text(widget(ID_AD_NAME));
	strcpy(hit->name, ps);
	HIP_DEBUG("New hit with parameters: %s, %s.\n", hit->name, hit->group);

	gtk_widget_hide(dialog);
	gdk_threads_leave();
	in_use = 0;

	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/** Set status bar info text. */
void gui_set_info(const char *string, ...)
{
	/* Variables. */
	static int last = -1;
	GtkWidget *w;
	char *str[2048];
	va_list args;
	
	/* Get args. */
	va_start(args, string);

	/* Set to status bar. */
	vsprintf(str, string, args);
	w = widget(ID_STATUSBAR);
	if (last >= 0) gtk_statusbar_pop(w, last);
	last = gtk_statusbar_get_context_id(w, "info");
	gtk_statusbar_push(w, last, str);

	/* End args. */
	va_end(args);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Add remote groups to tool dialog.
	This is a enumeration callback function.
*/
int tooldlg_add_rgroups(HIT_Group *group, void *p)
{
	/* Variables. */
	GtkWidget *w = (GtkWidget *)p;
	
//	HIP_DEBUG("Appending new remote group \"%s\" to tool window list.\n", group->name);
	gtk_combo_box_insert_text(w, 0, group->name);
	
	return (0);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Add local HITs to tool dialog.
	This is a enumeration callback function.
*/
int tooldlg_add_lhits(HIT_Item *hit, void *p)
{
	/* Variables. */
	GtkWidget *w = (GtkWidget *)p;

//	HIP_DEBUG("Appending new local HIT \"%s\" to tool window list.\n", hit->name);
	gtk_combo_box_append_text(w, hit->name);

	return (0);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Add remote groups to ask dialog.
	This is a enumeration callback function.
*/
int askdlg_add_rgroups(HIT_Group *group, void *p)
{
	/* Variables. */
	GtkWidget *w = (GtkWidget *)p;
	
//	HIP_DEBUG("Appending new remote group \"%s\" to ask window list.\n", group->name);
	gtk_combo_box_insert_text(w, 0, group->name);
	
	return (0);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Add local HITs to ask dialog.
	This is a enumeration callback function.
*/
int askdlg_add_lhits(HIT_Item *hit, void *p)
{
	/* Variables. */
	GtkWidget *w = (GtkWidget *)p;

//	HIP_DEBUG("Appending new local HIT \"%s\" to ask window list.\n", hit->name);
	gtk_combo_box_append_text(w, hit->name);

	return (0);
}
/* END OF FUNCTION */


/******************************************************************************/
/** Set tool window mode to no given. */
void tw_set_mode(int mode)
{
	/* Variables. */
	GtkWidget *window = (GtkWidget *)gui_get_toolwindow();
	
	/* First hide current. */
	switch (tw_cur_mode)
	{
		case TWMODE_NONE:
			break;
	
		case TWMODE_LOCAL:
			gtk_container_remove(GTK_CONTAINER(window), widget(ID_TWLOCAL));
			break;
		
		case TWMODE_REMOTE:
			gtk_container_remove(GTK_CONTAINER(window), widget(ID_TWREMOTE));
			break;
	
		case TWMODE_GROUP:
			gtk_container_remove(GTK_CONTAINER(window), widget(ID_TWGROUP));
			break;
	}
	
	/* Then show selected mode. */
	switch (mode)
	{
	case TWMODE_NONE:
		break;
	
	case TWMODE_LOCAL:
		gtk_container_add(GTK_CONTAINER(window), widget(ID_TWLOCAL));
		gtk_widget_show(widget(ID_TWLOCAL));
		break;
		
	case TWMODE_REMOTE:
		gtk_container_add(GTK_CONTAINER(window), widget(ID_TWREMOTE));
		gtk_widget_show(widget(ID_TWREMOTE));
		break;
	
	case TWMODE_GROUP:
		gtk_container_add(GTK_CONTAINER(window), widget(ID_TWGROUP));
		gtk_widget_show(widget(ID_TWGROUP));
		break;
	}
	
	tw_cur_mode = mode;
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Set remote HIT info to toolwindow.
	
	@param hit_name Name of remote HIT.
 */
void tw_set_remote_info(char *hit_name)
{
	/* Variables. */
	GtkWidget *w;
	HIT_Item *hit;
	char str[320];
	
	hit = hit_db_search(NULL, hit_name, NULL, NULL, NULL,
	                    0, HIT_DB_TYPE_ALL, 1, 0);
	
	if (hit)
	{
		gtk_entry_set_text(widget(ID_TWL_NAME), hit->name);
		gtk_entry_set_text(widget(ID_TWL_URL), hit->url);
		sprintf(str, "%d", hit->port);
		gtk_entry_set_text(widget(ID_TWL_PORT), str);
		
		free(hit);
	}
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
	GtkWidget *dialog = (GtkWidget *)widget(ID_CREATEDLG);
	HIT_Group group;
	int err = -1;
	char *ps = NULL;
	pthread_t pt;

	gtk_widget_show(dialog);
	gtk_widget_grab_focus(widget(ID_CREATE_NAME));
	gtk_entry_set_text(widget(ID_CREATE_NAME), "");

	err = gtk_dialog_run(GTK_DIALOG(dialog));
	if (err == GTK_RESPONSE_OK)
	{
		ps = gtk_entry_get_text(widget(ID_CREATE_NAME));
		if (strlen(ps) > 0)
		{
			pthread_create(&pt, NULL, hit_db_add_rgroup, ps);
		}
		else ps = NULL;
	}

out_err:
	gtk_widget_hide(dialog);
	return (ps);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/

