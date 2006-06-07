/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

/******************************************************************************/
/* INCLUDES */

/* STANDARD */

/* THIS */
#include "event.h"


/******************************************************************************/
/* FUNCTIONS */

/******************************************************************************/
/**
	What to do when user example tries to close the application?
	
	@return TRUE if don't close or FALSE if close.
*/
gboolean delete_event(GtkWidget *widget, GdkEvent *event, gpointer data)
{
	return (FALSE);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	What to do when user example tries to close the tool window?
	
	@return TRUE if don't close or FALSE if close.
*/
gboolean tool_delete_event(GtkWidget *widget, GdkEvent *event, gpointer data)
{
	gtk_widget_hide(widget);
	return (TRUE);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	What to do when user example tries to close the tool window?
	
	@return TRUE if don't close or FALSE if close.
*/
gboolean accept_delete_event(GtkWidget *widget, GdkEvent *event, gpointer data)
{
	gtk_widget_hide(widget);
	return (TRUE);
}
/* END OF FUNCTION */


/******************************************************************************/
/** On window destroy. */
void destroy(GtkWidget *widget, gpointer data)
{
	gtk_main_quit();
}
/* END OF FUNCTION */


/******************************************************************************/
/** On tool window destroy. */
void tool_destroy(GtkWidget *widget, gpointer data)
{
	gtk_widget_hide(widget);
}
/* END OF FUNCTION */


/******************************************************************************/
/** On accept window destroy. */
void accept_destroy(GtkWidget *widget, gpointer data)
{
	gtk_widget_hide(widget);
}
/* END OF FUNCTION */


/******************************************************************************/
/** On list select. */
gboolean select_list(GtkTreeSelection *selection, GtkTreeModel *arg_model,
                     GtkTreePath *path, gboolean pathsel, gpointer data)
{
	/* Variables. */
	GtkTreeIter iter;
	GtkTreeModel *model;
	char *str = NULL, *spath;
	int depth, *indices;
	
	if (pathsel != FALSE &&
	    gtk_tree_selection_path_is_selected(selection, path) != TRUE)
	{
	    return (TRUE);
	}

	depth = gtk_tree_path_get_depth(path);
	indices = gtk_tree_path_get_indices(path);
	spath = gtk_tree_path_to_string(path);
	HIP_DEBUG("Path is: %s\n", spath);
	g_free(spath);

	if (gtk_tree_selection_get_selected(selection, &model, &iter))
	{
		gtk_tree_model_get(model, &iter, 0, &str, -1);
	}
	else str = NULL;

	if (depth == 1)
	{
		if (indices[0] == 0) HIP_DEBUG("You selected local HITs group.\n");
		if (indices[0] == 1) HIP_DEBUG("You selected remote HITs root group.\n");
	}
	else if (depth == 2)
	{
		if (indices[0] == 0) HIP_DEBUG("You selected a local HIT.\n");
		if (indices[0] == 1) HIP_DEBUG("You selected remote HIT(s) group.\n");
	}
	else if (depth == 3 && indices[0] == 1)
	{
		HIP_DEBUG("You selected a remote HIT: %s.\n", str);
	}

	if (str) g_free(str);

/*	str = gtk_tree_path_to_string(path);
	if (HIP_DEBUG("You selected a remote group/HIT %s\n", str);
	g_free(str);
	info_mode_remote();*/

	return (TRUE);
}
/* END OF FUNCTION */


/******************************************************************************/
/** On remote list select. */
gboolean select_rlist(GtkTreeSelection *selection, gpointer data)
{
	GtkTreeIter iter;
	GtkTreeModel *model;
	char *hit;

	if (gtk_tree_selection_get_selected(selection, &model, &iter))
	{
		gtk_tree_model_get(model, &iter, 0, &hit, -1);
		printf("You selected a remote group/HIT %s\n", hit);
		g_free(hit);
		info_mode_remote();
	}
	
	return (TRUE);
}
/* END OF FUNCTION */


/******************************************************************************/
/** When button was pressed. */
void button_event(GtkWidget *warg, gpointer data)
{
	/* Variables. */
	int id = (int)data;
	char *ps, str[1024];
	time_t rawtime;
	struct tm *tinfo;

	switch (id)
	{
	case IDB_SEND:
		ps = gtk_entry_get_text(widget(ID_CHATINPUT));
		if (strlen(ps) < 1) break;
		if (strlen(ps) > (1024 - 128)) ps[1024 - 128] = '\0';
		
		if (ps[0] == '/' && strlen(ps) < 2);
		else if (ps[0] == '/') chat_exec_command(&ps[1]);
		else
		{
			time(&rawtime);
			tinfo = localtime(&rawtime);
			sprintf(str, "%0.2d:%0.2d <%s> %s\n", tinfo->tm_hour,
			        tinfo->tm_min, get_nick(), ps);
			gtk_text_buffer_insert_at_cursor(widget(ID_CHATBUFFER), str, -1);
		}
		gtk_entry_set_text(widget(ID_CHATINPUT), "");
		break;
	}
}
/* END OF FUNCTION */


/******************************************************************************/
/** When toolbar button is pressed. */
void toolbar_event(GtkWidget *warg, gpointer data)
{
	/* Variables. */
	static HIT_Item hit;
	GtkWidget *dialog;
	int id = (int)data;
	pthread_t pt;
	int err;
	char *ps;

	switch (id)
	{
	case ID_TOOLBAR_RUN:
		HIP_DEBUG("Toolbar: Run application.\n");
		exec_application();
		break;

	case ID_TOOLBAR_NEWHIT:
		HIP_DEBUG("Toolbar: Fake popup for new HIT.\n");
		memset(&hit, 0, sizeof(HIT_Item));
		strcpy(hit.name, "Fake hit popup");
		pthread_create(&pt, NULL, gui_ask_new_hit, &hit);
		break;
	
	case ID_TOOLBAR_TOGGLETOOLWINDOW:
		HIP_DEBUG("Toolbar: Toggle toolwindow visibility.\n");
		if (GTK_TOGGLE_BUTTON(warg)->active) gtk_widget_show(gui_get_toolwindow());
		else gtk_widget_hide(gui_get_toolwindow());
		break;
	
	case ID_TOOLBAR_NEWGROUP:
		HIP_DEBUG("Toolbar: Create remote group.\n");
		create_remote_group();
		break;
	}
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/

