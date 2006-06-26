/*
    HIP Agent

    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

/******************************************************************************/
/* INCLUDES */
#include "create.h"


/******************************************************************************/
/* EXTERNS */
extern GtkTreeIter local_top, remote_top, process_top;


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
	GtkWidget *window = (GtkWidget *)gui_get_window();
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
	/* XX TODO:
		When GTK-2.10+ version is released,
		add support for "system tray" status icon.

		GtkStatusIcon *status_icon;
		status_icon = gtk_status_icon_new_from_stock(GTK_STOCK_OPEN);
		gtk_status_icon_set_visible(status_icon, TRUE);
		err = gtk_status_icon_is_embedded(status_icon);
		HIP_DEBUG("Status icon %s.\n", (err ? "is visible", "could not be shown"));
	*/
	char str[320];
	int i, err;


	gtk_container_set_border_width(GTK_CONTAINER(window), 1);

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
	w = gtk_toolbar_append_item(toolbar, "New HIT",
	                            "Popup new HIT dialog for debugging",
	                            "Private", iconw,
	                            GTK_SIGNAL_FUNC(toolbar_event), ID_TOOLBAR_NEWHIT);

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
	g_signal_connect(G_OBJECT(select), "changed", G_CALLBACK(select_list), (gpointer)"hit list");
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
	cell = gtk_cell_renderer_text_new();

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

	/* done with notebook tabs. */
	/***************************************/

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
int tooldlg_create_content(void)
{
	/* Variables. */
	GtkWidget *window = (GtkWidget *)gui_get_toolwindow();
	GtkWidget *fixed = NULL, *frame = NULL, *table = NULL;
	GtkWidget *label = NULL, *vb1 = NULL, *vb2 = NULL, *sw = NULL;
	GtkWidget *w = NULL, *hp = NULL, *vb = NULL, *hb = NULL;
	GList *glist = NULL;
	int y;

	gtk_container_set_border_width(GTK_CONTAINER(window), 1);

	/* Create remote HIT info. */
	frame = gtk_frame_new(NULL);
	gtk_frame_set_label(GTK_FRAME(frame), "Remote HIT information:");
	gtk_frame_set_label_align(GTK_FRAME(frame), 0.0, 0.0);
	gtk_frame_set_shadow_type(GTK_FRAME(frame), GTK_SHADOW_ETCHED_OUT);
	gtk_widget_show(frame);
	widget_set(ID_TWREMOTE, frame);
	g_object_ref(frame);

	vb = gtk_vbox_new(FALSE, 1);
	gtk_container_add(GTK_CONTAINER(frame), vb);
	gtk_widget_show(vb);

	sw = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(sw, GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
	gtk_box_pack_start(vb, sw, TRUE, TRUE, 1);
	gtk_widget_show(sw);

	hp = gtk_hpaned_new();
	gtk_scrolled_window_add_with_viewport(sw, hp);
	gtk_widget_show(hp);

	vb1 = gtk_vbox_new(FALSE, 2);
	gtk_paned_add1(hp, vb1);
	gtk_widget_show(vb1);
	vb2 = gtk_vbox_new(FALSE, 1);
	gtk_paned_add2(hp, vb2);
	gtk_widget_show(vb2);

	w = gtk_label_new("Name:");
	gtk_label_set_justify(GTK_LABEL(w), GTK_JUSTIFY_LEFT);
	gtk_box_pack_start(vb1, w, FALSE, FALSE, 5);
	gtk_widget_show(w);
	w = gtk_entry_new();
	gtk_entry_set_text(w, "NewHIT");
	gtk_box_pack_start(vb2, w, FALSE, FALSE, 1);
	gtk_widget_show(w);
	widget_set(ID_TWL_NAME, w);

	w = gtk_label_new("URL:");
	gtk_label_set_justify(GTK_LABEL(w), GTK_JUSTIFY_LEFT);
	gtk_box_pack_start(vb1, w, FALSE, FALSE, 5);
	gtk_widget_show(w);
	w = gtk_entry_new();
	gtk_entry_set_text(w, "https://www.nordea.fi <not implemented>");
	gtk_box_pack_start(vb2, w, FALSE, FALSE, 1);
	gtk_widget_show(w);
	widget_set(ID_TWL_URL, w);

	w = gtk_entry_new();
	gtk_entry_set_text(w, "80 <not implemented>");
	gtk_box_pack_start(vb2, w, FALSE, FALSE, 1);
	gtk_widget_show(w);
	w = gtk_label_new("Port:");
	gtk_box_pack_start(vb1, w, FALSE, FALSE, 5);
	gtk_widget_show(w);
	widget_set(ID_TWL_PORT, w);

	w = gtk_combo_box_new_text();
	gtk_combo_box_append_text(w, "Accept");
	gtk_combo_box_append_text(w, "Deny");
	gtk_combo_box_set_active(w, 0);
	gtk_box_pack_start(vb2, w, FALSE, FALSE, 1);
	gtk_widget_show(w);
	widget_set(ID_TWL_TYPE1, w);
	w = gtk_label_new("Type:");
	gtk_box_pack_start(vb1, w, FALSE, FALSE, 5);
	gtk_widget_show(w);

	w = gtk_combo_box_new_text();
	gtk_combo_box_append_text(w, "Normal");
	gtk_combo_box_append_text(w, "Lightweight");
	gtk_combo_box_set_active(w, 0);
	gtk_box_pack_start(vb2, w, FALSE, FALSE, 1);
	gtk_widget_show(w);
	widget_set(ID_TWL_TYPE2, w);
	w = gtk_label_new("Lightweight:");
	gtk_box_pack_start(vb1, w, FALSE, FALSE, 5);
	gtk_widget_show(w);

	w = gtk_combo_box_new_text();
	widget_set(ID_TOOLLHITS, w);
	gtk_box_pack_start(vb2, w, FALSE, FALSE, 1);
	gtk_widget_show(w);
	widget_set(ID_TWL_LOCAL, w);
	w = gtk_label_new("Local HIT:");
	gtk_box_pack_start(vb1, w, FALSE, FALSE, 5);
	gtk_widget_show(w);

	w = gtk_combo_box_new_text();
	widget_set(ID_TOOLRGROUPS, w);
	g_signal_connect(w, "changed", G_CALLBACK(button_event), IDB_CB_RGROUPS);
	gtk_box_pack_start(vb2, w, FALSE, FALSE, 1);
	gtk_widget_show(w);
	widget_set(ID_TWL_GROUP, w);
	w = gtk_label_new("Group:");
	gtk_box_pack_start(vb1, w, FALSE, FALSE, 5);
	gtk_widget_show(w);

	hb = gtk_hbox_new(FALSE, 1);
	gtk_box_pack_end(vb, hb, FALSE, FALSE, 1);
	gtk_widget_show(hb);

	w = gtk_button_new_with_label("Apply");
	gtk_box_pack_start(hb, w, FALSE, FALSE, 1);
	g_signal_connect(w, "clicked", G_CALLBACK(button_event), IDB_TWAPPLY);
	gtk_widget_show(w);
	w = gtk_button_new_with_label("Cancel");
	gtk_box_pack_start(hb, w, FALSE, FALSE, 1);
	g_signal_connect(w, "clicked", G_CALLBACK(button_event), IDB_TWCANCEL);
	gtk_widget_set_sensitive(w, FALSE);
	gtk_widget_show(w);

	/* Create local HIT info. */
	frame = gtk_frame_new(NULL);
	gtk_frame_set_label(GTK_FRAME(frame), "Local HIT information:");
	gtk_frame_set_label_align(GTK_FRAME(frame), 0.0, 0.0);
	gtk_frame_set_shadow_type(GTK_FRAME(frame), GTK_SHADOW_ETCHED_OUT);
	gtk_widget_show(frame);
	widget_set(ID_TWLOCAL, frame);
	g_object_ref(frame);

	/* Create remote group HIT info. */
	frame = gtk_frame_new(NULL);
	gtk_frame_set_label(GTK_FRAME(frame), "Remote group information:");
	gtk_frame_set_label_align(GTK_FRAME(frame), 0.0, 0.0);
	gtk_frame_set_shadow_type(GTK_FRAME(frame), GTK_SHADOW_ETCHED_OUT);
	gtk_widget_show(frame);
	widget_set(ID_TWGROUP, frame);
	g_object_ref(frame);

	/* Set default mode and hide the toolwindow. */
 	tw_set_mode(TWMODE_NONE);
	gtk_widget_hide(window);

	return (0);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Create contents of the accept dialog in here.

	@return 0 if success, -1 on errors.
*/
int acceptdlg_create_content(void)
{
	/* Variables. */
	GtkWidget *window = (GtkWidget *)gui_get_acceptdialog();
	GtkWidget *fixed = NULL;
	GtkWidget *label = NULL;
	GtkWidget *w = NULL;
	int y;

	gtk_container_set_border_width(GTK_CONTAINER(window), 1);

	/* Create main widget for adding subwidgets to tool window. */
	fixed = gtk_fixed_new();
	gtk_box_pack_start(GTK_BOX(GTK_DIALOG(window)->vbox), fixed, TRUE, TRUE, 3);
	gtk_widget_show(fixed);

	/* Create local HIT info. */
	y = 0;

	w = gtk_label_new("<empty>");
	gtk_widget_set_size_request(w, 200, -1);
	y += 23; gtk_fixed_put(GTK_FIXED(fixed), w, 80, y);
	gtk_widget_show(w);
	widget_set(ID_AD_NEWHIT, w);
	w = gtk_label_new("New HIT:");
	y += 0; gtk_fixed_put(GTK_FIXED(fixed), w, 0, y);
	gtk_widget_show(w);

	w = gtk_entry_new();
	gtk_entry_set_text(w, "<New HIT name>");
	gtk_widget_set_size_request(w, 200, -1);
	y += 26; gtk_fixed_put(GTK_FIXED(fixed), w, 80, y);
	gtk_widget_show(w);
	widget_set(ID_AD_NAME, w);
	w = gtk_label_new("HIT name:");
	y += 0; gtk_fixed_put(GTK_FIXED(fixed), w, 0, y);
	gtk_widget_show(w);

	w = gtk_combo_box_new_text();
	g_signal_connect(w, "changed", G_CALLBACK(button_event), IDB_CB_RGROUPS);
	widget_set(ID_AD_RGROUPS, w);
	gtk_widget_set_size_request(w, 200, -1);
	y += 26; gtk_fixed_put(GTK_FIXED(fixed), w, 80, y);
	gtk_widget_show(w);
	w = gtk_label_new("Group:");
	y += 4; gtk_fixed_put(GTK_FIXED(fixed), w, 0, y);
	gtk_widget_show(w);

	w = gtk_combo_box_new_text();
	widget_set(ID_AD_LHITS, w);
	gtk_widget_set_size_request(w, 200, -1);
	y += 26; gtk_fixed_put(GTK_FIXED(fixed), w, 80, y);
	gtk_widget_show(w);
	w = gtk_label_new("Local HIT:");
	y += 4; gtk_fixed_put(GTK_FIXED(fixed), w, 0, y);
	gtk_widget_show(w);

	w = gtk_combo_box_new_text();
	gtk_combo_box_append_text(w, "Normal");
	gtk_combo_box_append_text(w, "Lightweight");
	gtk_combo_box_set_active(w, 0);
	gtk_widget_set_size_request(w, 200, -1);
	y += 26; gtk_fixed_put(GTK_FIXED(fixed), w, 80, y);
	gtk_widget_show(w);
	w = gtk_label_new("Lightweight:");
	y += 4; gtk_fixed_put(GTK_FIXED(fixed), w, 0, y);
	gtk_widget_show(w);

	return (0);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Create run dialog contents.

	@return 0 if success, -1 on errors.
*/
int rundlg_create_content(void)
{
	/* Variables. */
	GtkWidget *window = (GtkWidget *)widget(ID_RUNDLG);
	GtkWidget *box = NULL;
	GtkWidget *w = NULL;

	gtk_container_set_border_width(GTK_CONTAINER(window), 3);

	/* Create main widget for adding subwidgets to window. */
	box = gtk_vbox_new(FALSE, 3);
	gtk_box_pack_start(GTK_BOX(GTK_DIALOG(window)->vbox), box, TRUE, TRUE, 3);
	gtk_widget_show(box);

	/* Create command-input widget. */
	w = gtk_label_new("Command to execute:");
	gtk_widget_show(w);
	gtk_box_pack_start(GTK_BOX(box), w, FALSE, TRUE, 1);
	w = gtk_entry_new();
	widget_set(ID_RUN_COMMAND, w);
	gtk_entry_set_text(w, "xterm");
	gtk_box_pack_start(GTK_BOX(box), w, FALSE, TRUE, 1);
	gtk_widget_show(w);
	gtk_entry_set_activates_default(GTK_ENTRY(w), TRUE);

	/* Create LD_PRELOAD-input widget. */
	w = gtk_label_new("LD_PRELOAD:");
	gtk_widget_show(w);
	gtk_box_pack_start(GTK_BOX(box), w, FALSE, TRUE, 1);
	w = gtk_entry_new();
	widget_set(ID_RUN_LDPRELOAD, w);
	gtk_entry_set_text(w, "");
	gtk_box_pack_start(GTK_BOX(box), w, FALSE, TRUE, 1);
	gtk_widget_show(w);
	gtk_entry_set_activates_default(GTK_ENTRY(w), TRUE);

	/* Create LD_LIBRARY_PATH-input widget. */
	w = gtk_label_new("LD_LIBRARY_PATH:");
	gtk_widget_show(w);
	gtk_box_pack_start(GTK_BOX(box), w, FALSE, TRUE, 1);
	w = gtk_entry_new();
	widget_set(ID_RUN_LDLIBRARYPATH, w);
	gtk_entry_set_text(w, "");
	gtk_box_pack_start(GTK_BOX(box), w, FALSE, TRUE, 1);
	gtk_widget_show(w);
	gtk_entry_set_activates_default(GTK_ENTRY(w), TRUE);

	/* Add buttons to dialog. */
	w = gtk_dialog_add_button(window, "Run", GTK_RESPONSE_OK);
	gtk_widget_grab_default(w);
	gtk_dialog_add_button(window, "Cancel", GTK_RESPONSE_CANCEL);

	return (0);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Create run dialog contents.

	@return 0 if success, -1 on errors.
*/
int createdlg_create_content(void)
{
	/* Variables. */
	GtkWidget *window = (GtkWidget *)widget(ID_CREATEDLG);
	GtkWidget *hb = NULL;
	GtkWidget *w = NULL;

	gtk_container_set_border_width(GTK_CONTAINER(window), 3);

	/* Create main widget for adding subwidgets to window. */
	hb = gtk_hbox_new(TRUE, 5);
	gtk_box_pack_start(GTK_BOX(GTK_DIALOG(window)->vbox), hb, TRUE, TRUE, 3);
	gtk_widget_show(hb);

	/* Create group name input widget. */
	w = gtk_entry_new();
	widget_set(ID_CREATE_NAME, w);
	gtk_entry_set_text(w, "");
	gtk_box_pack_start(GTK_BOX(hb), w, TRUE, TRUE, 3);
	gtk_widget_show(w);
	gtk_entry_set_activates_default(GTK_ENTRY(w), TRUE);

	/* Add buttons to dialog. */
	w = gtk_dialog_add_button(window, "Create", GTK_RESPONSE_OK);
	gtk_widget_grab_default(w);
	gtk_dialog_add_button(window, "Cancel", GTK_RESPONSE_CANCEL);

	return (0);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/

