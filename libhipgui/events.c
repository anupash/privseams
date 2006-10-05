/*
    HIP Agent

    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

/******************************************************************************/
/* INCLUDES */
#include "events.h"


/******************************************************************************/
/* FUNCTIONS */

/******************************************************************************/
/**
	What to do when user example tries to close the application?

	@return TRUE if don't close or FALSE if close.
*/
gboolean main_delete_event(GtkWidget *w, GdkEvent *event, gpointer data)
{
	return (FALSE);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	What to do when user example tries to close the tool window?

	@return TRUE if don't close or FALSE if close.
*/
gboolean tw_delete_event(GtkWidget *w, GdkEvent *event, gpointer data)
{
	gtk_toggle_button_set_active(widget(ID_TB_TW), FALSE);
	gtk_widget_hide(w);
	return (TRUE);
}
/* END OF FUNCTION */


/******************************************************************************/
/** On window destroy. */
void main_destroy(GtkWidget *w, gpointer data)
{
	connhipd_quit();
	gtk_main_quit();
}
/* END OF FUNCTION */


/******************************************************************************/
/** On tool window destroy. */
void tw_destroy(GtkWidget *widget, gpointer data)
{
	gtk_widget_hide(widget);
}
/* END OF FUNCTION */


/******************************************************************************/
/** On HIT list click. */
gboolean list_click(GtkTreeView *tree, gpointer data)
{
	/* Variables. */
	GtkTreeIter iter;
	GtkTreeModel *model;
	GtkTreePath *path;
	GtkTreeSelection *selection;
	char *str;
	int depth, *indices;

	selection = gtk_tree_view_get_selection(tree);

	if (gtk_tree_selection_get_selected(selection, &model, &iter))
	{
		/* Get values for the path. */
		path = gtk_tree_model_get_path(model, &iter);
		depth = gtk_tree_path_get_depth(path);
		indices = gtk_tree_path_get_indices(path);
		gtk_tree_model_get(model, &iter, 0, &str, -1);

		if (depth == 1)
		{
			if (indices[0] == 0)
			{
				tw_set_mode(TWMODE_NONE);
			}
			if (indices[0] == 1)
			{
				tw_set_mode(TWMODE_NONE);
			}
		}
		else if (depth == 2)
		{
			if (indices[0] == 0)
			{
				tw_set_mode(TWMODE_LOCAL);
				tw_set_local_info(str);
			}
			if (indices[0] == 1)
			{
				tw_set_mode(TWMODE_RGROUP);
				tw_set_rgroup_info(str);
			}
		}
		else if (depth == 3 && indices[0] == 1)
		{
			tw_set_mode(TWMODE_REMOTE);
			tw_set_remote_info(str);
		}

		gtk_tree_path_free(path);
		g_free(str);
	}

	return (TRUE);
}
/* END OF FUNCTION */


/******************************************************************************/
/** On HIT list click. */
gboolean list_press(GtkTreeView *tree, GdkEventButton *button, gpointer data)
{
	/* Variables. */
	GtkTreeIter iter;
	GtkTreeModel *model;
	GtkTreePath *path;
	GtkTreeSelection *selection;
	char *str;
	int depth, *indices;

	if (button->type == GDK_BUTTON_PRESS && button->button == 3)
	{
		selection = gtk_tree_view_get_selection(tree);

		if (gtk_tree_selection_get_selected(selection, &model, &iter))
		{
			/* Get values for the path. */
			path = gtk_tree_model_get_path(model, &iter);
			depth = gtk_tree_path_get_depth(path);
			indices = gtk_tree_path_get_indices(path);
			gtk_tree_model_get(model, &iter, 0, &str, -1);
	
			if (depth == 1)
			{
			}
			else if (depth == 2)
			{
			}
			else if (depth == 3 && indices[0] == 1)
			{
				gtk_menu_popup(widget(ID_RLISTMENU), NULL, NULL, NULL, NULL,
				               button->button, button->time);
				return (TRUE);
			}
	
			gtk_tree_path_free(path);
			g_free(str);
		}
	}
	
	return (FALSE);
}
/* END OF FUNCTION */


/******************************************************************************/
/** On HIT list double click. */
gboolean list_double_click(GtkTreeSelection *selection, GtkTreePath *path,
						   GtkTreeViewColumn *column, gpointer data)
{
	gtk_widget_show(widget(ID_TOOLWND));
	gtk_toggle_button_set_active(widget(ID_TB_TW), TRUE);
}
/* END OF FUNCTION */


/******************************************************************************/
/** When button is pressed. */
void button_event(GtkWidget *warg, gpointer data)
{
	/* Variables. */
	HIT_Group *g;
	int id = (int)data, i;
	char *ps;
	static str[1024];
	time_t rawtime;
	struct tm *tinfo;
	pthread_t pt;
	
	switch (id)
	{
	case IDB_SEND:
		ps = gtk_entry_get_text(widget(ID_TERMINPUT));
		if (strlen(ps) < 1) break;
		if (strlen(ps) > (1024 - 128)) ps[1024 - 128] = '\0';

		if (ps[0] == '/' && strlen(ps) < 2);
		else if (ps[0] == '/') term_exec_command(&ps[1]);
		else
		{
			HIP_DEBUG("nick is: %s\n", get_nick());
			time(&rawtime);
			tinfo = localtime(&rawtime);
			sprintf(str, "%0.2d:%0.2d <%s> %s\n", tinfo->tm_hour,
			        tinfo->tm_min, get_nick(), ps);
			if (term_get_mode() == TERM_MODE_CLIENT)
			{
				pthread_create(&pt, NULL, term_client_send_string, str);
			}
			if (term_get_mode() == TERM_MODE_SERVER)
			{
				pthread_create(&pt, NULL, term_server_send_string, str);
			}
		}
		gtk_entry_set_text(widget(ID_TERMINPUT), "");
		gtk_widget_grab_default(widget(ID_TERMSEND));
		gtk_entry_set_activates_default(widget(ID_TERMINPUT), TRUE);
		gtk_widget_grab_focus(widget(ID_TERMINPUT));
		break;

	case IDB_TW_RGROUPS:
		ps = gtk_combo_box_get_active_text(warg);
		g = hit_db_find_rgroup(ps);
		if (g)
		{
			tw_set_remote_rgroup_info(g);
		}
		else if (strcmp("<create new...>", ps) == 0)
		{
			HIP_DEBUG("Create new group.\n");
			ps = create_remote_group();
			if (ps == NULL) gtk_combo_box_set_active(warg, 0);
			else gtk_combo_box_set_active(warg, 0);
		}
		break;

	case IDB_NH_RGROUPS:
		ps = gtk_combo_box_get_active_text(warg);
		g = hit_db_find_rgroup(ps);
		if (g)
		{
			nh_set_remote_rgroup_info(g);
		}
		else if (strcmp("<create new...>", ps) == 0)
		{
			HIP_DEBUG("Create new group.\n");
			ps = create_remote_group();
			if (ps == NULL) gtk_combo_box_set_active(warg, 0);
			else gtk_combo_box_set_active(warg, 0);
		}
		break;

	case IDB_TW_APPLY:
		tw_apply();
		break;

	case IDB_TW_CANCEL:
		tw_cancel();
		break;

	case IDB_TW_DELETE:
		tw_delete();
		break;
		
	case IDB_SYSTRAY:
		g_object_get(widget(ID_MAINWND), "visible", &i, NULL);
		if (i == TRUE)
		{
			gtk_widget_hide(widget(ID_MAINWND));
		}
		else
		{
			gtk_widget_show(widget(ID_MAINWND));
		}
		break;
		
	case IDM_TRAY_SHOW:
		gtk_widget_show(widget(ID_MAINWND));
		break;
	
	case IDM_TRAY_HIDE:
		gtk_widget_hide(widget(ID_MAINWND));
		break;
	
	case IDM_TRAY_EXIT:
		gui_terminate();
		break;
		
	case IDM_RLIST_DELETE:
		HIP_DEBUG("Delete\n");
		break;
	}
}
/* END OF FUNCTION */


/******************************************************************************/
/** When toolbar button is pressed. */
void toolbar_event(GtkWidget *warg, gpointer data)
{
	/* Variables. */
	static HIT_Remote hit;
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
		memset(&hit, 0, sizeof(HIT_Remote));
		NAMECPY(hit.name, "Fake hit popup");
		pthread_create(&pt, NULL, gui_ask_new_hit, &hit);
		break;

	case ID_TOOLBAR_TOGGLETOOLWINDOW:
		HIP_DEBUG("Toolbar: Toggle toolwindow visibility.\n");
		if (GTK_TOGGLE_BUTTON(warg)->active) gtk_widget_show(widget(ID_TOOLWND));
		else gtk_widget_hide(widget(ID_TOOLWND));
		break;

	case ID_TOOLBAR_NEWGROUP:
		HIP_DEBUG("Toolbar: Create remote group.\n");
		create_remote_group();
		break;
	}
}
/* END OF FUNCTION */


/******************************************************************************/
/** When systray is activated. */
void systray_event(void *warg, guint bid, guint atime, gpointer data)
{
	gtk_menu_popup(widget(ID_SYSTRAYMENU), NULL, NULL, NULL, NULL, 0, atime);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/

