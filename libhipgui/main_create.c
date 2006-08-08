/*
    HIP Agent

    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

/******************************************************************************/
/* INCLUDES */
#include "main.h"


/******************************************************************************/
/* VARIABLES */
GtkTreeIter local_top, remote_top, process_top;


/******************************************************************************/
/* FUNCTIONS */

/******************************************************************************/
/**
	Create contents of the gui in here.

	@return 0 if success, -1 on errors.
*/
int main_create_content(void)
{
	/* Variables. */
	GtkWidget *window = (GtkWidget *)widget(ID_MAINWND);
	GtkWidget *pane, *pbox, *notebook, *w, *w2;
	GtkWidget *button, *scroll, *chat, *div;
	GtkWidget *label, *label2;
	GtkTreeStore *model;
	GtkWidget *list;
	GtkWidget *toolbar;
	GtkWidget *iconw;
	PangoFontDescription *font_desc;
	GdkColor color;
	GtkCellRenderer *cell;
	GtkTreeViewColumn *column;
	GtkTreeSelection *select;
	GtkTreeIter top, child;
	char str[320];
	int i, err;
	
#if (GTK_MAJOR_VERSION >= 2) && (GTK_MINOR_VERSION >= 10)
	{
		GtkStatusIcon *status_icon;
			
		sprintf(str, "%s/%s", HIP_GUI_DATADIR, "infrahip.png");
//		status_icon = gtk_status_icon_new_from_stock(GTK_STOCK_OPEN);
		status_icon = gtk_status_icon_new_from_file(str);
		gtk_status_icon_set_visible(status_icon, TRUE);
		err = gtk_status_icon_is_embedded(status_icon);
		HIP_DEBUG("Status icon %s.\n", (err ? "is visible" : "could not be shown"));
		
		g_signal_connect(status_icon, "popup-menu", G_CALLBACK(systray_event), (gpointer)"popup-menu");
		g_signal_connect(status_icon, "activate", G_CALLBACK(button_event), (gpointer)IDB_SYSTRAY);
	}
#endif

	gtk_container_set_border_width(window, 3);

	/* Create main pain. */
	pane = gtk_vbox_new(FALSE, 1);
	gtk_container_add(GTK_CONTAINER(window), pane);
	gtk_widget_show(pane);

	/* Create toolbar. */
	toolbar = gtk_toolbar_new();
	gtk_box_pack_start(pane, toolbar, FALSE, FALSE, 0);
	gtk_widget_show(toolbar);
	widget_set(ID_TOOLBAR, toolbar);
	gtk_toolbar_set_style(toolbar, GTK_TOOLBAR_TEXT);

	/* Create toolbar contents. */
	iconw = gtk_image_new_from_file("run.xpm");
	w = gtk_toolbar_append_element(toolbar, GTK_TOOLBAR_CHILD_TOGGLEBUTTON,
	                               NULL, "Toolwindow", "Show/hide toolwindow",
	                               "Private", iconw,
	                               GTK_SIGNAL_FUNC(toolbar_event),
	                               ID_TOOLBAR_TOGGLETOOLWINDOW);
	widget_set(ID_TB_TW, w);

	gtk_toolbar_append_space(toolbar);
	iconw = gtk_image_new_from_file("run.xpm");
	w = gtk_toolbar_append_item(toolbar, "New group",
	                            "Create new remote group",
	                            "Private", iconw,
	                            GTK_SIGNAL_FUNC(toolbar_event), ID_TOOLBAR_NEWGROUP);
	gtk_toolbar_append_space(toolbar);
	iconw = gtk_image_new_from_file("run.xpm");
	w = gtk_toolbar_append_item(toolbar, "Run", "Run new process",
	                            "Private", iconw,
	                            GTK_SIGNAL_FUNC(toolbar_event), ID_TOOLBAR_RUN);
	iconw = gtk_image_new_from_file("run.xpm");
/*	w = gtk_toolbar_append_item(toolbar, "New HIT",
	                            "Popup new HIT dialog for debugging",
	                            "Private", iconw,
	                            GTK_SIGNAL_FUNC(toolbar_event), ID_TOOLBAR_NEWHIT);*/

	/* Create tabbed notebook. */
	notebook = gtk_notebook_new();
	gtk_notebook_set_tab_pos(GTK_NOTEBOOK(notebook), GTK_POS_TOP);
	gtk_box_pack_start(GTK_BOX(pane), notebook, TRUE, TRUE, 0);
	gtk_widget_show(notebook);

	/* Create status bar. */
	w = gtk_statusbar_new();
	gtk_box_pack_end(GTK_BOX(pane), w, FALSE, FALSE, 0);
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

	pbox = gtk_hbox_new(TRUE, 1);
	label2 = gtk_label_new("Processes");
	gtk_notebook_append_page(GTK_NOTEBOOK(notebook), pbox, label2);
	gtk_widget_show(pbox);

	chat = gtk_vbox_new(FALSE, 1);
	label2 = gtk_label_new("Terminal");
	gtk_notebook_append_page(GTK_NOTEBOOK(notebook), chat, label2);
	gtk_widget_show(chat);

	/***************************************
	/* HITs. */
	scroll = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
	                               GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
	model = gtk_tree_store_new(1, G_TYPE_STRING);
	gtk_tree_store_append(model, &local_top, NULL);
	gtk_tree_store_set(model, &local_top, 0, "Local HITs", -1);
	gtk_tree_store_append(model, &remote_top, NULL);
	gtk_tree_store_set(model, &remote_top, 0, "Remote HIT groups", -1);

	list = gtk_tree_view_new();
	g_signal_connect(list, "row-activated", G_CALLBACK(list_double_click), (gpointer)"double_clicked");
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
	g_signal_connect(select, "changed", G_CALLBACK(list_click), (gpointer)"clicked");
	gtk_widget_show(list);
	gtk_widget_show(scroll);
	widget_set(ID_RLISTMODEL, model);

	/***************************************
	/* Process list. */
	scroll = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
	                               GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
	model = gtk_tree_store_new(4, G_TYPE_INT, G_TYPE_STRING, G_TYPE_INT, G_TYPE_INT);
//	gtk_tree_store_append(model, &process_top, NULL);

	list = gtk_tree_view_new();
	widget_set(ID_PLISTVIEW, list);
	gtk_tree_view_set_model(GTK_TREE_VIEW(list), GTK_TREE_MODEL(model));
	cell = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes("PID", cell, "text", 0, NULL);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list), GTK_TREE_VIEW_COLUMN(column));
	cell = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes("process", cell, "text", 1, NULL);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list), GTK_TREE_VIEW_COLUMN(column));

	gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(scroll), list);
	gtk_widget_set_size_request(scroll, 200, 0);
	gtk_box_pack_start(GTK_BOX(pbox), scroll, TRUE, TRUE, 1);
	select = gtk_tree_view_get_selection(GTK_TREE_VIEW(list));
	gtk_tree_selection_set_mode(select, GTK_SELECTION_SINGLE);
	gtk_widget_show(list);
	gtk_widget_show(scroll);
	widget_set(ID_PLISTMODEL, model);

	/***************************************
	/* Terminal. */
	div = gtk_hpaned_new();
	gtk_box_pack_start(chat, div, TRUE, TRUE, 1);
	gtk_widget_show(div);

	scroll = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
	                               GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
	gtk_paned_add1(div, scroll);
	gtk_widget_show(scroll);
	w = gtk_text_view_new();
	widget_set(ID_TERMSCREEN, w);
	w2 = gtk_text_view_get_buffer(w);
	widget_set(ID_TERMBUFFER, w2);
	gtk_text_view_set_editable(w, FALSE);
	gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(scroll), w);
	gtk_widget_show(w);
	/* Change default font throughout the widget */
	font_desc = pango_font_description_from_string("Monospace 12");
	gtk_widget_modify_font(w, font_desc);
	pango_font_description_free(font_desc);
	/* Change default color throughout the widget */
	gdk_color_parse("green", &color);
	gtk_widget_modify_text(w, GTK_STATE_NORMAL, &color);
	gdk_color_parse("black", &color);
	gtk_widget_modify_base(w, GTK_STATE_NORMAL, &color);

/*	scroll = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
	                               GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
	model = gtk_tree_store_new(1, G_TYPE_STRING);

	list = gtk_tree_view_new();
	widget_set(ID_USERVIEW, list);
	gtk_tree_view_set_model(list, model);
	cell = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes("Users", cell, "text", 0, NULL);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list), GTK_TREE_VIEW_COLUMN(column));

	gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(scroll), list);
	gtk_paned_add2(div, scroll);
	w = gtk_tree_view_get_selection(list);
	gtk_tree_selection_set_mode(w, GTK_SELECTION_SINGLE);
	gtk_widget_show(list);
	gtk_widget_show(scroll);
	widget_set(ID_USERMODEL, model);
	gtk_paned_set_position(div, 400);*/

	w2 = gtk_hbox_new(FALSE, 1);
	gtk_box_pack_start(chat, w2, FALSE, FALSE, 1);
	gtk_widget_show(w2);

	w = gtk_entry_new();
	gtk_entry_set_text(w, "");
	widget_set(ID_TERMINPUT, w);
	gtk_box_pack_start(w2, w, TRUE, TRUE, 1);
	gtk_entry_set_activates_default(w, TRUE);
	gtk_widget_grab_focus(w);
	gtk_widget_show(w);

	w = gtk_button_new_with_label("Send");
	GTK_WIDGET_SET_FLAGS(w, GTK_CAN_DEFAULT);
	gtk_box_pack_end(w2, w, FALSE, FALSE, 1);
	gtk_widget_grab_default(w);
	g_signal_connect(w, "clicked", G_CALLBACK(button_event), IDB_SEND);
	gtk_widget_show(w);
	widget_set(ID_TERMSEND, w);

	/* done with notebook tabs. */
	/***************************************/

	gtk_notebook_set_current_page(notebook, 0);
	gtk_widget_show(notebook);
	gtk_widget_show(window);

	return (0);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/

