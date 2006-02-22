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
GtkListStore *gtk_list_model = NULL;
GtkTreeView *hit_list = NULL;
GtkWidget *remote_hits = NULL;
int remote_hits_n = 0;
int gui_entry_fill_flag = GTK_FILL | GTK_EXPAND;


/******************************************************************************/
/* FUNCTIONS */

/******************************************************************************/
/**
	Create contents for the gui in here.
	
	@return 0 if success, -1 on errors.
*/
int gui_create_content(void)
{
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

	char str[320];
	int i;


	gtk_container_set_border_width(GTK_CONTAINER(window), 1);

	/* Create tabbed notebook. */
	notebook = gtk_notebook_new();
	gtk_notebook_set_tab_pos(GTK_NOTEBOOK(notebook), GTK_POS_TOP);
	gtk_container_add(GTK_CONTAINER(window), notebook);
	gtk_widget_show(notebook);

	/* Create tabs for identities (only default for now). */
	pane = gtk_hpaned_new();
	label = gtk_label_new("Default Identity");
	gtk_notebook_append_page(GTK_NOTEBOOK(notebook), pane, label);
	gtk_widget_show(pane);
 
	label = gtk_label_new("Fake Identity 1");
	label2 = gtk_label_new("Fake Identity 1");
	gtk_notebook_append_page(GTK_NOTEBOOK(notebook), label, label2);
	gtk_widget_show(label);
	label = gtk_label_new("Fake Identity 2");
	label2 = gtk_label_new("Fake Identity 2");
	gtk_notebook_append_page(GTK_NOTEBOOK(notebook), label, label2);
	gtk_widget_show(label);

	scroll = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
	                               GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
	model = gtk_list_store_new(1, G_TYPE_STRING);
	list = gtk_tree_view_new();
	hit_list = GTK_TREE_VIEW(list);
	gtk_tree_view_set_model(GTK_TREE_VIEW(list), GTK_TREE_MODEL(model));
	cell = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes("HITs", cell, "text", 0, NULL);
	gtk_tree_view_append_column(GTK_TREE_VIEW(list), GTK_TREE_VIEW_COLUMN(column));
	gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(scroll), list);
	gtk_widget_set_size_request(scroll, 200, 0);
	gtk_paned_add1(GTK_PANED(pane), scroll);
	select = gtk_tree_view_get_selection(GTK_TREE_VIEW(list));
	gtk_tree_selection_set_mode(select, GTK_SELECTION_SINGLE);
	g_signal_connect(G_OBJECT(select), "changed", G_CALLBACK(select_list), (gpointer)"hit list");
	gtk_widget_show(list);
	gtk_widget_show(scroll);
	gtk_list_model = model;

	scroll = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
	                               GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
	gtk_paned_add2(GTK_PANED(pane), scroll);
	remote_hits = gtk_vbox_new(FALSE, 2);
	gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(scroll), remote_hits);
	gtk_widget_show(remote_hits);
	gtk_widget_show(scroll);

	/* Add some fake HITs to the window */
	gui_add_hit("fake:00...00:0001");
	gui_add_hit("fake:00...00:0002");
	

	button = gtk_button_new_with_label("testi2");
	gtk_paned_add2(GTK_PANED(pane), button);
	gtk_widget_show(button);

	gtk_widget_show(notebook);
	gtk_widget_show(window);
 
	/* Return. */
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
	static int once = 0;
	GtkTreeIter iter;
	gchar *msg = g_strdup_printf(hit);
	gtk_list_store_append(GTK_LIST_STORE(gtk_list_model), &iter);
	gtk_list_store_set(GTK_LIST_STORE(gtk_list_model), &iter, 0, msg, -1);
	g_free(msg);
	
	if (!once)
	{
		GtkTreeSelection *selection = gtk_tree_view_get_selection(hit_list);
		gtk_tree_selection_select_iter(selection, &iter);
		once = 1;
	}
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Tell GUI to add new remote HIT into list.

	@param New hit to add.
	@param url URL of new HIT.
	@param port Port of new HIT.
*/
void gui_add_remote_hit(char *hit, char *url, int port)
{
	GtkWidget *frame;
	GtkWidget *table;
	GtkWidget *entry;
	char str[320];

	/* New remote HIT frame. */
	frame = gtk_frame_new(hit);
	gtk_widget_set_size_request(GTK_WIDGET(frame), 0, 120);
	gtk_box_pack_start(GTK_BOX(remote_hits), frame, FALSE, TRUE, 2);
	gtk_container_set_border_width(GTK_CONTAINER(frame), 2);
	gtk_widget_show(frame);

	/* Remote HIT frame content. */
	table = gtk_table_new(8, 8, FALSE);
	gtk_table_set_homogeneous(GTK_TABLE(table), FALSE);
	gtk_container_set_border_width(GTK_CONTAINER(table), 4);

	gui_new_text_entry(hit, "HIT:", table, 0, 7, 0, 1, 1);
	gui_new_text_entry(url, "URL:", table, 0, 7, 1, 2, 1);
	sprintf(str, "%d", port);
	gui_new_text_entry(str, "Port:", table, 0, 3, 2, 3, 1);
	gui_new_button("remove", NULL, table, 3, 7, 2, 3, 1, button_event, remote_hits_n);

	gtk_container_add(GTK_CONTAINER(frame), table);
	gtk_widget_show(table);

	remote_hits_n++;
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Callback to go trough remote HITs.
*/
void gui_remote_hit_callback(GtkWidget *hit, gpointer data)
{
	if (data == NULL) return;
	
	if (!strcmp((char *)data, "clear"))
	{
		gtk_container_remove(GTK_CONTAINER(remote_hits), hit);
	}
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Tell GUI to clear remote hits list.
*/
void gui_clear_remote_hits(void)
{
	gtk_container_foreach(GTK_CONTAINER(remote_hits), gui_remote_hit_callback, "clear");
	remote_hits_n = 0;
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
/** New text entry. */
void gui_new_text_entry(char *text, char *description, GtkWidget *table,
                        int l, int r, int t, int b, int dw)
{
	GtkWidget *entry;
	
	if (description)
	{
		entry = gtk_label_new(description);
		gtk_table_attach(GTK_TABLE(table), entry, l, l + dw, t, b,
		                 GTK_SHRINK, GTK_SHRINK, 5, 0);
		gtk_widget_show(entry);
	}
	else
	{
		dw = 0;
	}
	
	entry = gtk_entry_new();
	gtk_entry_set_text(GTK_ENTRY(entry), text);
	gtk_widget_set_size_request(GTK_WIDGET(entry), 1, -1);
	gtk_table_attach(GTK_TABLE(table), entry, l + dw, r, t, b,
	                 gui_entry_fill_flag, GTK_EXPAND | GTK_FILL, 0, 0);
	gtk_widget_show(entry);
}
/* END OF FUNCTION */


/******************************************************************************/
/** New text entry. */
void gui_new_button(char *text, char *description, GtkWidget *table,
                    int l, int r, int t, int b, int dw,
                    void (*callback)(GtkWidget *, gpointer), int value)
{
	GtkWidget *entry, *button;
	
	if (description)
	{
		entry = gtk_label_new(description);
		gtk_table_attach(GTK_TABLE(table), entry, l, l + dw, t, b,
		                 GTK_SHRINK, GTK_SHRINK, 5, 0);
		gtk_widget_show(entry);
	}
	else
	{
		dw = 0;
	}
	
	button = gtk_button_new_with_label(text);
	gtk_widget_set_size_request(GTK_WIDGET(button), 1, -1);
	gtk_table_attach(GTK_TABLE(table), button, l + dw, r, t, b,
	                 gui_entry_fill_flag, GTK_EXPAND | GTK_FILL, 8, 8);
    g_signal_connect(G_OBJECT(button), "clicked", G_CALLBACK(callback), (gpointer)value);
	gtk_widget_show(button);
}
/* END OF FUNCTION */


/******************************************************************************/
/** Set entry fill flag. */
void gui_set_entry_fill_flag(int fill)
{
	gui_entry_fill_flag = fill;
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/

