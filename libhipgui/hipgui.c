/*
 * HIPL GTK GUI
 *
 * License: GNU/GPL
 * Authors: Antti Partanen <aehparta@cc.hut.fi>
 */

/******************************************************************************/
/* INCLUDES */
#include "hipgui.h"


/******************************************************************************/
/* FUNCTIONS */

/******************************************************************************/
/**
 * Add new remote HIT.
 * @note This function is for internal use, dont touch!
 */
int _hit_remote_add(const char *group, const char *name)
{
	GtkWidget *w;
	GtkTreeIter iter, gtop;
	GtkTreePath *path;
	GtkTreeModel *model;
	int err = 0;
	char *str;

	w = widget(ID_RLISTMODEL);
	err = gtk_tree_model_iter_children(GTK_TREE_MODEL(w), &gtop, NULL);
	HIP_IFEL(err == FALSE, -1, "No remote groups.\n");
	err = -1;

	do
	{
		gtk_tree_model_get(GTK_TREE_MODEL(w), &gtop, 0, &str, -1);
		if (strcmp(str, group) == 0)
		{
			HIP_DEBUG("Found remote group \"%s\", adding remote HIT \"%s\".\n", group, name);
			/*
				Check that group has some items, if not, then delete "<empty>"
				from the list, before adding new items.
			*/			
			err = gtk_tree_model_iter_children(GTK_TREE_MODEL(w), &iter, &gtop);
			if (err == TRUE)
			{
				gtk_tree_model_get(GTK_TREE_MODEL(w), &iter, 0, &str, -1);
				if (str[0] == ' ') gtk_tree_store_remove(GTK_TREE_STORE(w), &iter);
			}
			else if (err == FALSE && strlen(name) < 1) name = lang_get("hits-group-emptyitem");
			else HIP_IFE(strlen(name) < 1, 1);
			
			gtk_tree_store_append(GTK_TREE_STORE(w), &iter, &gtop);
			gtk_tree_store_set(GTK_TREE_STORE(w), &iter, 0, name, -1);
			path = gtk_tree_model_get_path(widget(ID_RLISTMODEL), &iter);
			gtk_tree_view_expand_to_path(GTK_TREE_VIEW(widget(ID_RLISTVIEW)), path);
			err = 0;
			break;
		}
	} while (gtk_tree_model_iter_next(GTK_TREE_MODEL(w), &gtop) != FALSE);

out_err:
	return err;
}


/******************************************************************************/
/**
 * Initialize GUI for usage.
 *
 * @return 0 if success, -1 on errors.
 */
int gui_init(void)
{
	GtkWidget *w;
	int err = 0;
	char str[320];

#if (GTK_MAJOR_VERSION >= 2) && (GTK_MINOR_VERSION >= 10)
	HIP_DEBUG("GTK version is greater or equal to 2.10, status icon should be shown.\n");
#else
	HIP_DEBUG("GTK version is less than 2.10, status icon not shown.\n");
#endif

	/* Initialize libraries. */
	g_thread_init(NULL);
	gdk_threads_init();
	gtk_init(NULL, NULL);
	widget_init();

	/* Set default icon. */
	gtk_window_set_default_icon_from_file(HIP_DEBIAN_DIR_PIXMAPS "/hipmanager.png", NULL);
//	gtk_window_set_default_icon_name("hipmanager.png");
	
	/* Initialize tooltips. */
	widget_set(ID_TOOLTIPS, gtk_tooltips_new());

	/* Create main GUI window. */
	w = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	widget_set(ID_MAINWND, w);
	gtk_window_set_title(GTK_WINDOW(w), lang_get("title-main"));

	g_signal_connect(w, "delete_event", G_CALLBACK(e_delete_main), NULL);
	g_signal_connect(w, "destroy", G_CALLBACK(e_destroy_main), NULL);
	
	/* Create toolwindow for local HITs. */
	w = gtk_dialog_new_with_buttons(lang_get("title-locals"), NULL, GTK_DIALOG_MODAL,
	                                lang_get("lhdlg-button-apply"), GTK_RESPONSE_YES,
	                                lang_get("lhdlg-button-cancel"), GTK_RESPONSE_NO, NULL);
	gtk_widget_hide(GTK_WIDGET(w));
	g_signal_connect(w, "delete_event", G_CALLBACK(e_delete), NULL);
	widget_set(ID_LOCALDLG, w);

	/* Create new hit -dialog. */
	w = gtk_dialog_new_with_buttons(lang_get("title-newhit"), NULL, GTK_DIALOG_MODAL,
	                                lang_get("nhdlg-button-accept"), GTK_RESPONSE_YES,
	                                lang_get("nhdlg-button-drop"), GTK_RESPONSE_NO, NULL);
	widget_set(ID_NHDLG, w);
	g_signal_connect(w, "delete_event", G_CALLBACK(e_delete), NULL);
	gtk_widget_hide(GTK_WIDGET(w));

	/* Create execute-dialog. */
	w = gtk_dialog_new_with_buttons(lang_get("title-runapp"), NULL, GTK_DIALOG_MODAL, NULL);
	widget_set(ID_EXECDLG, w);
	g_signal_connect(w, "delete_event", G_CALLBACK(e_delete), NULL);
	gtk_widget_hide(GTK_WIDGET(w));

	/* Create create-dialog. */
	w = gtk_dialog_new_with_buttons(lang_get("title-newgroup"), NULL, GTK_DIALOG_MODAL, NULL);
	widget_set(ID_NGDLG, w);
	g_signal_connect(w, "delete_event", G_CALLBACK(e_delete), NULL);
	gtk_widget_hide(GTK_WIDGET(w));

	/* Create own custom message-dialog. */
	w = gtk_dialog_new_with_buttons(lang_get("title-msgdlg"), NULL, GTK_DIALOG_MODAL, NULL);
	widget_set(ID_MSGDLG, w);
	g_signal_connect(w, "delete_event", G_CALLBACK(e_delete), NULL);
	gtk_widget_hide(GTK_WIDGET(w));

	/* Create window content for all windows. */
	HIP_IFEL(create_content_msgdlg(), -1, "Failed to create message-dialog contents.\n");
// 	HIP_IFEL(create_content_nhdlg(), -1, "Failed to create accept-dialog contents.\n");
// 	HIP_IFEL(create_content_execdlg(), -1, "Failed to create run-dialog contents.\n");
// 	HIP_IFEL(create_content_ngdlg(), -1, "Failed to create create-dialog contents.\n");
 	HIP_IFEL(create_content_local_edit(), -1, "Failed to create local HITs edit -dialog contents.\n");
	HIP_IFEL(create_content_main(), -1, "Failed to create main-window contents.\n");

	info_set("HIP manager started.");

out_err:
	return err;
}


/******************************************************************************/
/**
 * Run the GUI. This function is assumed to block the calling thread here
 * as long as GUI is running.
 */
void gui_main(void)
{
	gtk_combo_box_append_text(GTK_COMBO_BOX(widget(ID_TWR_RGROUP)), lang_get("combo-newgroup"));
	gtk_combo_box_append_text(GTK_COMBO_BOX(widget(ID_NH_RGROUP)), lang_get("combo-newgroup"));

	hit_db_enum_locals(local_add, NULL);
	gtk_combo_box_set_active(GTK_COMBO_BOX(widget(ID_TWR_LOCAL)), 0);
	gtk_combo_box_set_active(GTK_COMBO_BOX(widget(ID_TWG_LOCAL)), 0);
	gtk_combo_box_set_active(GTK_COMBO_BOX(widget(ID_NG_LOCAL)), 0);
	
	/* Clear HIT/group edit. */
	edit_group_remote(lang_get("default-group-name"));
//	edit_reset();

	/* Close all groups as default. */
	gtk_tree_view_collapse_all(GTK_TREE_VIEW(widget(ID_RLISTVIEW)));

#if (GTK_MAJOR_VERSION >= 2) && (GTK_MINOR_VERSION >= 10)
	gtk_widget_hide(GTK_WIDGET(widget(ID_MAINWND)));
#else
	gtk_widget_show(GTK_WIDGET(widget(ID_MAINWND)));
#endif
	
	gtk_main();
}


/******************************************************************************/
/**
 * De-initialize GUI stuff.
 */
void gui_quit(void)
{
	widget_quit();
}


/******************************************************************************/
/**
 * 
 * @note Dont call this function inside gtk main loop!
 *
 */
int gui_hit_remote_ask(HIT_Remote *r, int inout)
{
	int err = 0;
	
out_err:
	return err;
}


/******************************************************************************/
/**
 * Tell GUI to add new remote HIT into list.
 * @note Dont call this function inside gtk main loop!
 *
 * @param group Group name where to add new HIT.
 * @param name Name of new HIT to add.
 */
void gui_hit_remote_add(const char *group, const char *name)
{
	int err = 0;

	gdk_threads_enter();
	err = _hit_remote_add(group, name);
	
out_err:
	gdk_threads_leave();
	return;
}


/******************************************************************************/
/**
 * 
 * @note Dont call this function inside gtk main loop!
 *
 */
void gui_hit_remote_del(const char *name)
{
}


/******************************************************************************/
/**
 * 
 * @note Dont call this function inside gtk main loop!
 *
 */
void gui_group_remote_add(const char *name)
{
	GtkWidget *w;
	GtkTreeIter iter;
	GtkTreePath *path;

	gdk_threads_enter();
	
	w = widget(ID_RLISTMODEL);
	gtk_tree_store_append(GTK_TREE_STORE(w), &iter, NULL);
	gtk_tree_store_set(GTK_TREE_STORE(w), &iter, 0, name, -1);
	path = gtk_tree_model_get_path(GTK_TREE_MODEL(w), &iter);
	
	gtk_combo_box_insert_text(GTK_COMBO_BOX(widget(ID_TWR_RGROUP)), 0, (gpointer)name);
	gtk_combo_box_insert_text(GTK_COMBO_BOX(widget(ID_NH_RGROUP)), 0, (gpointer)name);
	gtk_combo_box_set_active(GTK_COMBO_BOX(widget(ID_TWR_RGROUP)), 0);
	gtk_combo_box_set_active(GTK_COMBO_BOX(widget(ID_NH_RGROUP)), 0);
	
	_hit_remote_add(name, lang_get("hits-group-emptyitem"));
	w = widget(ID_RLISTVIEW);
	gtk_tree_view_expand_to_path(GTK_TREE_VIEW(w), path);
	
	gdk_threads_leave();
}


/******************************************************************************/
/**
 * 
 * @note Dont call this function inside gtk main loop!
 *
 */
void gui_group_remote_del(const char *name)
{
}


/******************************************************************************/
/**
 * 
 * @note Dont call this function inside gtk main loop!
 *
 */
void gui_hit_local_add(HIT_Local *l)
{
}


/******************************************************************************/
/**
 * Set GUI statusbar info text.
 * @note Dont call this function inside gtk main loop!
 *
 * @param string printf(3) formatted string presentation.
 */
void gui_set_info(const char *string, ...)
{
	char *str = NULL;
	va_list args;
	
	/* Construct string from given arguments. */
	va_start(args, string);
	vasprintf(&str, string, args);
	va_end(args);
	
	/* Set info to statusbar in safe mode. */
	_info_set(str, 1);
	
	/* Free allocated string pointer. */
	if (str) free(str);
}


/******************************************************************************/
/**
 * Update GUI NAT status in options tab.
 * @note Dont call this function inside gtk main loop!
 *
 * @param status 1 if nat extension on, 0 if not.
 */
void gui_update_nat(int status)
{
	GtkWidget *w = widget(ID_OPT_NAT);
	if (status) status = TRUE;
	else status = FALSE;
	gdk_threads_enter();
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w), status);
	gdk_threads_leave();
}


/******************************************************************************/
/**
 * 
 * @note Dont call this function inside gtk main loop!
 *
 */
void gui_hiu_clear(void)
{
}


/******************************************************************************/
/**
 * 
 * @note Dont call this function inside gtk main loop!
 *
 */
void gui_hiu_add(HIT_Remote *r)
{
}


/******************************************************************************/
/**
 * 
 * @note Dont call this function inside gtk main loop!
 *
 */
void gui_hiu_count(int c)
{
}


