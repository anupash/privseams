/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

/******************************************************************************/
/* INCLUDES */

/* STANDARD */

/* THIS */
#include "gui_manage.h"


/******************************************************************************/
/* VARIABLES */
void **gui_widgets = NULL;

GtkTreeIter local_top, remote_top;
int remote_hits_n = 0;
int gui_entry_fill_flag = GTK_FILL | GTK_EXPAND;


/******************************************************************************/
/* FUNCTIONS */

/******************************************************************************/
/**
	Initialize GUI widgets system.
	
	@return 0 on success, -1 on errors.
*/
int widget_init(void)
{
	/* Variables. */
	int err = 0;

	gui_widgets = (void **)malloc(sizeof(void *) * IDS_N);
	HIP_IFEL(gui_widgets == NULL, -1, "Failed to allocate widgets pointers.\n");
	memset(gui_widgets, sizeof(GtkWidget *) * IDS_N, 0);

out_err:
	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/** Deinitalize GUI widgets system. */
void widget_quit(void)
{
	if (gui_widgets) free(gui_widgets);
	gui_widgets = NULL;
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Set pointer for given widget.
	
	@param n Widget identifier.
	@param p Pointer to widget.
*/
void widget_set(int n, void *p)
{
	if (n >= 0 && n < IDS_N) gui_widgets[n] = p;
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Returns pointer to given widget.
	
	@param n Widget identifier.
	@return Pointer to widget.
*/
void *widget(int n)
{
	if (n < 0 || n >= IDS_N) return (NULL);
	return (gui_widgets[n]);
}
/* END OF FUNCTION */


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

	@param New hit to add.
*/
void gui_add_rgroup(char *hit)
{
	/* Variables. */
	GtkWidget *w;
	GtkTreeIter iter;
	gchar *msg = g_strdup_printf(hit);

	w = widget(ID_RLISTMODEL);
	gtk_tree_store_append(GTK_TREE_STORE(w), &iter, &remote_top);
	gtk_tree_store_set(GTK_TREE_STORE(w), &iter, 0, msg, -1);
	g_free(msg);
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
		HIP_DEBUG("Did not find remote group \"%s\", creating group.\n", group);
		gui_add_rgroup(group);
		gui_add_remote_hit(hit, group);
	}
	return;
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
	int err = 0;
	GtkDialog *dialog = gui_get_acceptdialog();
	char phit[128];
	
	gdk_threads_enter();
	gtk_widget_show(dialog);
	print_hit_to_buffer(phit, &hit->rhit);
	gtk_label_set_text(widget(ID_NEWHIT), phit);

/*	dialog = gtk_message_dialog_new(NULL, GTK_DIALOG_MODAL,
	                                GTK_MESSAGE_QUESTION, GTK_BUTTONS_YES_NO,
	                                "Accept new HIT?");*/
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
//	gtk_widget_destroy(dialog);
	
	gtk_widget_hide(dialog);
	gdk_threads_leave();
	
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
/** Set tool window mode to no info. */
void info_mode_none(void)
{
	gtk_widget_hide(widget(ID_INFOLOCAL));
	gtk_widget_hide(widget(ID_INFOREMOTE));
	gtk_widget_hide(widget(ID_INFOGROUP));
}
/* END OF FUNCTION */


/******************************************************************************/
/** Set tool window mode to local HIT info. */
void info_mode_local(void)
{
	gtk_widget_show(widget(ID_INFOLOCAL));
	gtk_widget_hide(widget(ID_INFOREMOTE));
	gtk_widget_hide(widget(ID_INFOGROUP));
}
/* END OF FUNCTION */


/******************************************************************************/
/** Set tool window mode to remote HIT info. */
void info_mode_remote(void)
{
	gtk_widget_hide(widget(ID_INFOLOCAL));
	gtk_widget_show(widget(ID_INFOREMOTE));
	gtk_widget_hide(widget(ID_INFOGROUP));
}
/* END OF FUNCTION */


/******************************************************************************/
/** Set tool window mode to group info. */
void info_mode_rgroup(void)
{
	gtk_widget_hide(widget(ID_INFOLOCAL));
	gtk_widget_hide(widget(ID_INFOREMOTE));
	gtk_widget_show(widget(ID_INFOGROUP));
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/

