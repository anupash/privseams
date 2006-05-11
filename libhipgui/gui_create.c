/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

/******************************************************************************/
/* INCLUDES */

/* STANDARD */

/* THIS */
#include "gui_create.h"


/******************************************************************************/
/* EXTERNS */
extern GtkTreeIter local_top, remote_top;


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
	GtkWidget *w = NULL;
	GtkWidget *button = NULL;
	GtkWidget *scroll = NULL;
	GtkWidget *label, *label2;
	GtkTreeStore *model;
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
	w = gtk_statusbar_new();
	gtk_box_pack_start(GTK_BOX(pane), w, FALSE, FALSE, 0);
	gtk_widget_show(w);
	widget_set(ID_STATUSBAR, w);

	/* Create tabs. */
	pane = gtk_hpaned_new();
	label = gtk_label_new("Treeview");
	gtk_notebook_append_page(GTK_NOTEBOOK(notebook), pane, label);
	gtk_widget_show(pane);
 
	label = gtk_label_new("HITs in use");
	label2 = gtk_label_new("HITs in use");
	gtk_notebook_append_page(GTK_NOTEBOOK(notebook), label, label2);
	gtk_widget_show(label);

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
	widget_set(ID_RLISTVIEW, list);
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
	widget_set(ID_RLISTMODEL, model);

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
	w = gtk_label_new("Local HIT:");
	gtk_fixed_put(GTK_FIXED(fixed), w, 0, 0);
	gtk_widget_show(w);
	widget_set(ID_INFOLOCAL, w);

	/* Create remote HIT info. */
	y = 0;
	w = gtk_label_new("Remote HIT information:");
	gtk_fixed_put(GTK_FIXED(fixed), w, 0, y);
	gtk_widget_show(w);
	widget_set(ID_INFOREMOTE, w);

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
	glist = g_list_append(glist, "Normal");
	glist = g_list_append(glist, "Lightweight");
	gtk_combo_set_popdown_strings(GTK_COMBO(w), glist);
	g_list_free(glist); glist = NULL;
	gtk_entry_set_text(w, "Normal");
	y += 23; gtk_fixed_put(GTK_FIXED(fixed), w, 80, y);
	gtk_widget_show(w);
	w = gtk_label_new("Lightweight:");
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
	w = gtk_label_new("Remote group:");
	gtk_fixed_put(GTK_FIXED(fixed), w, 0, 0);
	gtk_widget_show(w);
	widget_set(ID_INFOGROUP, w);

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

	w = gtk_label_new("<empty>");
	y += 23; gtk_fixed_put(GTK_FIXED(fixed), w, 80, y);
	gtk_widget_show(w);
	widget_set(ID_AD_NEWHIT, w);
	w = gtk_label_new("New HIT:");
	y += 0; gtk_fixed_put(GTK_FIXED(fixed), w, 0, y);
	gtk_widget_show(w);

	w = gtk_combo_new();
	widget_set(ID_AD_GROUP, w);
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
	widget_set(ID_AD_LHIT, w);
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
	glist = g_list_append(glist, "Normal");
	glist = g_list_append(glist, "Lightweight");
	gtk_combo_set_popdown_strings(GTK_COMBO(w), glist);
	g_list_free(glist); glist = NULL;
	gtk_entry_set_text(w, "Normal");
	y += 23; gtk_fixed_put(GTK_FIXED(fixed), w, 80, y);
	gtk_widget_show(w);
	w = gtk_label_new("Lightweight:");
	y += 4; gtk_fixed_put(GTK_FIXED(fixed), w, 0, y);
	gtk_widget_show(w);

	return (0);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/

