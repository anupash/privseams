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
GtkListStore *rlist_model = NULL, *llist_model = NULL;
GtkTreeView *rlist_view = NULL, *llist_view = NULL;
GtkWidget *statusbar, *info_local, *info_remote, *info_rgroup;
GtkTreeIter local_top, remote_top;
int remote_hits_n = 0;
int gui_entry_fill_flag = GTK_FILL | GTK_EXPAND;
//GUIGroup *rgroups;
GtkWidget *new_hit = NULL;


/******************************************************************************/
/* FUNCTIONS */

/******************************************************************************/
/**
	Create contents of the gui in here.
	
	@return 0 if success, -1 on errors.
*/
int gui_create_content(void)
{
	/* Variables. */
	GtkWidget *window = (GtkWidget *)gui_get_window();
	GtkWidget *pane = NULL;
	GtkWidget *notebook = NULL;
	GtkWidget *button = NULL;
	GtkWidget *scroll = NULL;
	GtkWidget *label, *label2;
	GtkListStore *model;
	GtkWidget *list;

    GtkCellRenderer *cell;
    GtkTreeViewColumn *column;
	GtkTreeSelection *select;
	GtkTreeIter top, child;

	char str[320];
	int i;


	gtk_container_set_border_width(GTK_CONTAINER(window), 1);

	/* Create main pain. */
	pane = gtk_vbox_new(FALSE, 1);
	gtk_container_add(GTK_CONTAINER(window), pane);
	gtk_widget_show(pane);

	/* Create tabbed notebook. */
	notebook = gtk_notebook_new();
	gtk_notebook_set_tab_pos(GTK_NOTEBOOK(notebook), GTK_POS_TOP);
	gtk_box_pack_start(GTK_BOX(pane), notebook, TRUE, TRUE, 0);
	gtk_widget_show(notebook);

	/* Create status bar. */
	statusbar = gtk_statusbar_new();
	gtk_box_pack_start(GTK_BOX(pane), statusbar, FALSE, FALSE, 0);
	gtk_widget_show(statusbar);

	/* Create tabs. */
	pane = gtk_hpaned_new();
	label = gtk_label_new("Treeview");
	gtk_notebook_append_page(GTK_NOTEBOOK(notebook), pane, label);
	gtk_widget_show(pane);
 
	label = gtk_label_new("Net");
	label2 = gtk_label_new("Net");
	gtk_notebook_append_page(GTK_NOTEBOOK(notebook), label, label2);
	gtk_widget_show(label);

	label = gtk_label_new("Privacy");
	label2 = gtk_label_new("Privacy");
	gtk_notebook_append_page(GTK_NOTEBOOK(notebook), label, label2);
	gtk_widget_show(label);

	label = gtk_label_new("Lightweight");
	label2 = gtk_label_new("Lightweight");
	gtk_notebook_append_page(GTK_NOTEBOOK(notebook), label, label2);
	gtk_widget_show(label);

	/* Local HITs. */
/*	scroll = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
	                               GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
	model = gtk_list_store_new(1, G_TYPE_STRING);
	list = gtk_tree_view_new();
	llist_view = GTK_TREE_VIEW(list);
	gtk_tree_view_set_model(GTK_TREE_VIEW(list), GTK_TREE_MODEL(model));
	cell = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes("Local HITs", cell, "text", 0, NULL);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list), GTK_TREE_VIEW_COLUMN(column));
	gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(scroll), list);
	gtk_widget_set_size_request(scroll, 200, 0);
	gtk_paned_add1(GTK_PANED(pane), scroll);
	select = gtk_tree_view_get_selection(GTK_TREE_VIEW(list));
	gtk_tree_selection_set_mode(select, GTK_SELECTION_SINGLE);
	g_signal_connect(G_OBJECT(select), "changed", G_CALLBACK(select_list), (gpointer)"hit list");
	gtk_widget_show(list);
	gtk_widget_show(scroll);
	llist_model = model;*/

	/* Remote HITs. */
	scroll = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
	                               GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
	model = gtk_tree_store_new(1, G_TYPE_STRING);
	gtk_tree_store_append(model, &local_top, NULL);
	gtk_tree_store_set(model, &local_top, 0, "Local HITs", -1);
	gtk_tree_store_append(model, &remote_top, NULL);
	gtk_tree_store_set(model, &remote_top, 0, "Remote HITs", -1);

	list = gtk_tree_view_new();
	rlist_view = GTK_TREE_VIEW(list);
	gtk_tree_view_set_model(GTK_TREE_VIEW(list), GTK_TREE_MODEL(model));
	cell = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes("HITs", cell, "text", 0, NULL);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list), GTK_TREE_VIEW_COLUMN(column));

	gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(scroll), list);
	gtk_widget_set_size_request(scroll, 200, 0);
	gtk_paned_add2(GTK_PANED(pane), scroll);
	select = gtk_tree_view_get_selection(GTK_TREE_VIEW(list));
	gtk_tree_selection_set_mode(select, GTK_SELECTION_SINGLE);
	g_signal_connect(G_OBJECT(select), "changed", G_CALLBACK(select_rlist), (gpointer)"hit list");
	gtk_widget_show(list);
	gtk_widget_show(scroll);
	rlist_model = model;

	/* Add some fake HITs to the window */
//	gui_add_remote_hit("Nordea", "Services");
//	gui_add_remote_hit("Sonera", "Services");
	gui_add_remote_hit("Starcraft", "Games");
	gui_add_remote_hit("Total Annihilation", "Games");
	gui_add_remote_hit("Action Quake", "Games");
	gui_add_remote_hit("Miika", "Friends");
	gui_add_remote_hit("Tobias", "Friends");
	gui_add_remote_hit("Matti", "Friends");
	gui_add_remote_hit("Seppo", "Friends");
	gui_add_remote_hit("something", "Misc");
	gui_add_remote_hit("else", "Misc");
	
	button = gtk_button_new_with_label("testi2");
	gtk_paned_add2(GTK_PANED(pane), button);
	gtk_widget_show(button);

	gtk_widget_show(notebook);
	gtk_widget_show(window);
 
	return (0);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Create contents of the tool window in here.
	
	@return 0 if success, -1 on errors.
*/
int gui_create_toolwindow_content(void)
{
	/* Variables. */
	GtkWidget *window = (GtkWidget *)gui_get_toolwindow();
	GtkWidget *fixed = NULL;
	GtkWidget *label = NULL;
	GtkWidget *w = NULL;
	GList *glist = NULL;
	int y;

	gtk_container_set_border_width(GTK_CONTAINER(window), 1);

	/* Create main widget for adding subwidgets to tool window. */
	fixed = gtk_fixed_new();
	gtk_container_add(GTK_CONTAINER(window), fixed);
	gtk_widget_show(fixed);

	/* Create local HIT info. */
	info_local = gtk_label_new("Local HIT:");
	gtk_fixed_put(GTK_FIXED(fixed), info_local, 0, 0);
	gtk_widget_show(info_local);

	/* Create remote HIT info. */
	y = 0;
	info_remote = gtk_label_new("Remote HIT information:");
	gtk_fixed_put(GTK_FIXED(fixed), info_remote, 0, y);
	gtk_widget_show(info_remote);

	w = gtk_entry_new();
	gtk_entry_set_text(w, "NewHIT");
	y += 23; gtk_fixed_put(GTK_FIXED(fixed), w, 80, y);
	gtk_widget_show(w);
	w = gtk_label_new("Name:");
	y += 4; gtk_fixed_put(GTK_FIXED(fixed), w, 0, y);
	gtk_widget_show(w);

	w = gtk_entry_new();
	gtk_entry_set_text(w, "https://www.nordea.fi <not implemented>");
	y += 23; gtk_fixed_put(GTK_FIXED(fixed), w, 80, y);
	gtk_widget_show(w);
	w = gtk_label_new("URL:");
	y += 4; gtk_fixed_put(GTK_FIXED(fixed), w, 0, y);
	gtk_widget_show(w);

	w = gtk_entry_new();
	gtk_entry_set_text(w, "80 <not implemented>");
	y += 23; gtk_fixed_put(GTK_FIXED(fixed), w, 80, y);
	gtk_widget_show(w);
	w = gtk_label_new("Port:");
	y += 4; gtk_fixed_put(GTK_FIXED(fixed), w, 0, y);
	gtk_widget_show(w);

	w = gtk_combo_new();
	glist = g_list_append(glist, "Accept");
	glist = g_list_append(glist, "Deny");
	gtk_combo_set_popdown_strings(GTK_COMBO(w), glist);
	g_list_free(glist); glist = NULL;
	gtk_entry_set_text(w, "Accept");
	y += 23; gtk_fixed_put(GTK_FIXED(fixed), w, 80, y);
	gtk_widget_show(w);
	w = gtk_label_new("Type:");
	y += 4; gtk_fixed_put(GTK_FIXED(fixed), w, 0, y);
	gtk_widget_show(w);

	w = gtk_combo_new();
	glist = g_list_append(glist, "Primary");
	gtk_combo_set_popdown_strings(GTK_COMBO(w), glist);
	g_list_free(glist); glist = NULL;
	gtk_entry_set_text(w, "Primary");
	y += 23; gtk_fixed_put(GTK_FIXED(fixed), w, 80, y);
	gtk_widget_show(w);
	w = gtk_label_new("Local HIT:");
	y += 4; gtk_fixed_put(GTK_FIXED(fixed), w, 0, y);
	gtk_widget_show(w);

	w = gtk_combo_new();
//	glist = g_list_append(glist, "Services");
	glist = g_list_append(glist, "Games");
	glist = g_list_append(glist, "Friends");
	glist = g_list_append(glist, "Misc");
	gtk_combo_set_popdown_strings(GTK_COMBO(w), glist);
	g_list_free(glist); glist = NULL;
	gtk_entry_set_text(w, "Services");
	y += 23; gtk_fixed_put(GTK_FIXED(fixed), w, 80, y);
	gtk_widget_show(w);
	w = gtk_label_new("Group:");
	y += 4; gtk_fixed_put(GTK_FIXED(fixed), w, 0, y);
	gtk_widget_show(w);

	w = gtk_button_new_with_label("Apply");
	y += 23; gtk_fixed_put(GTK_FIXED(fixed), w, 10, y);
	gtk_widget_show(w);
	w = gtk_button_new_with_label("Cancel");
	gtk_fixed_put(GTK_FIXED(fixed), w, 70, y);
	gtk_widget_show(w);

	/* Create remote group info. */
	info_rgroup = gtk_label_new("Remote group:");
	gtk_fixed_put(GTK_FIXED(fixed), info_rgroup, 0, 0);
	gtk_widget_show(info_rgroup);

	gtk_widget_show(window);
 
 	info_mode_none();
 
	return (0);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Create contents of the accept dialog in here.
	
	@return 0 if success, -1 on errors.
*/
int gui_create_acceptdialog_content(void)
{
	/* Variables. */
	GtkWidget *window = (GtkWidget *)gui_get_acceptdialog();
	GtkWidget *fixed = NULL;
	GtkWidget *label = NULL;
	GtkWidget *w = NULL;
	GList *glist = NULL;
	int y;

	gtk_container_set_border_width(GTK_CONTAINER(window), 1);

	/* Create main widget for adding subwidgets to tool window. */
	fixed = gtk_fixed_new();
	gtk_box_pack_start(GTK_BOX(GTK_DIALOG(window)->vbox), fixed, TRUE, TRUE, 0);
	gtk_widget_show(fixed);

	/* Create local HIT info. */
	y = 0;

	new_hit = gtk_label_new("<empty>");
	y += 23; gtk_fixed_put(GTK_FIXED(fixed), new_hit, 80, y);
	gtk_widget_show(new_hit);
	w = gtk_label_new("New HIT:");
	y += 0; gtk_fixed_put(GTK_FIXED(fixed), w, 0, y);
	gtk_widget_show(w);

	w = gtk_combo_new();
//	glist = g_list_append(glist, "Services");
	glist = g_list_append(glist, "Games");
	glist = g_list_append(glist, "Friends");
	glist = g_list_append(glist, "Misc");
	gtk_combo_set_popdown_strings(GTK_COMBO(w), glist);
	g_list_free(glist); glist = NULL;
	gtk_entry_set_text(w, "Services");
	y += 23; gtk_fixed_put(GTK_FIXED(fixed), w, 80, y);
	gtk_widget_show(w);
	w = gtk_label_new("Group:");
	y += 4; gtk_fixed_put(GTK_FIXED(fixed), w, 0, y);
	gtk_widget_show(w);

	w = gtk_combo_new();
	glist = g_list_append(glist, "Primary");
	gtk_combo_set_popdown_strings(GTK_COMBO(w), glist);
	g_list_free(glist); glist = NULL;
	gtk_entry_set_text(w, "Primary");
	y += 23; gtk_fixed_put(GTK_FIXED(fixed), w, 80, y);
	gtk_widget_show(w);
	w = gtk_label_new("Local HIT:");
	y += 4; gtk_fixed_put(GTK_FIXED(fixed), w, 0, y);
	gtk_widget_show(w);

	return (0);
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
	static int once = 0;
	GtkTreeIter iter;
	gchar *msg = g_strdup_printf(hit);

	gtk_tree_store_append(GTK_TREE_STORE(rlist_model), &iter, &local_top);
	gtk_tree_store_set(GTK_TREE_STORE(rlist_model), &iter, 0, msg, -1);
//	gtk_list_store_append(GTK_LIST_STORE(rlist_model), &iter);
//	gtk_list_store_set(GTK_LIST_STORE(rlist_model), &iter, 0, msg, -1);
	g_free(msg);
	
	if (!once)
	{
		GtkTreeSelection *selection = gtk_tree_view_get_selection(rlist_view);
		gtk_tree_selection_select_iter(selection, &iter);
		once = 1;
	}
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
	static int once = 0;
	GtkTreeIter iter;
	gchar *msg = g_strdup_printf(hit);

	gtk_tree_store_append(GTK_TREE_STORE(rlist_model), &iter, &remote_top);
	gtk_tree_store_set(GTK_TREE_STORE(rlist_model), &iter, 0, msg, -1);
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
	GtkTreeIter iter, gtop;
	GtkTreeModel *model;
	int err;
	char *str;

	err = gtk_tree_model_iter_children(GTK_TREE_STORE(rlist_model), &gtop, &remote_top);
	HIP_IFEL(err == FALSE, -1, "No remote groups.\n");
	err = -1;

	do
	{
		gtk_tree_model_get(rlist_model, &gtop, 0, &str, -1);
		if (strcmp(str, group) == 0)
		{
			HIP_DEBUG("Found remote group \"%s\", adding remote HIT \"%s\".\n", group, hit);
			gtk_tree_store_append(GTK_TREE_STORE(rlist_model), &iter, &gtop);
			gtk_tree_store_set(GTK_TREE_STORE(rlist_model), &iter, 0, hit, -1);
			err = 0;
			break;
		}
	} while (gtk_tree_model_iter_next(rlist_model, &gtop) != FALSE);
	
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
	gtk_label_set_text(new_hit, phit);

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
	char *str[2048];
	va_list args;
	
	/* Get args. */
	va_start(args, string);

	/* Set to status bar. */
	vsprintf(str, string, args);
	if (last >= 0) gtk_statusbar_pop(GTK_STATUSBAR(statusbar), last);
	last = gtk_statusbar_get_context_id(GTK_STATUSBAR(statusbar), "info");
	gtk_statusbar_push(GTK_STATUSBAR(statusbar), last, str);

	/* End args. */
	va_end(args);
}
/* END OF FUNCTION */


/******************************************************************************/
/** Set tool window mode to no info. */
void info_mode_none(void)
{
	gtk_widget_hide(info_local);
	gtk_widget_hide(info_remote);
	gtk_widget_hide(info_rgroup);
}
/* END OF FUNCTION */


/******************************************************************************/
/** Set tool window mode to local HIT info. */
void info_mode_local(void)
{
	gtk_widget_show(info_local);
	gtk_widget_hide(info_remote);
	gtk_widget_hide(info_rgroup);
}
/* END OF FUNCTION */


/******************************************************************************/
/** Set tool window mode to remote HIT info. */
void info_mode_remote(void)
{
	gtk_widget_hide(info_local);
	gtk_widget_show(info_remote);
	gtk_widget_hide(info_rgroup);
}
/* END OF FUNCTION */


/******************************************************************************/
/** Set tool window mode to group info. */
void info_mode_rgroup(void)
{
	gtk_widget_hide(info_local);
	gtk_widget_hide(info_remote);
	gtk_widget_show(info_rgroup);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/

