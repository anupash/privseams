/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

/******************************************************************************/
/* INCLUDES */

/* STANDARD */

/* THIS */
#include "main.h"


/******************************************************************************/
/* VARIABLES */
GtkWidget *gtk_window = NULL;
GtkWidget *gtk_toolwindow = NULL;
GtkWidget *gtk_acceptdialog = NULL;
GtkWidget *gtk_rundialog = NULL;


/******************************************************************************/
/* FUNCTIONS */

/******************************************************************************/
/**
	Initialize GUI for usage.
	
	@return 0 if success, -1 on errors.
*/
int gui_init(void)
{
	/* Variables. */
	GtkWidget *w;
	int err = 0;
	char str[320];

	/* Initialize libraries. */
	g_thread_init(NULL);
	gdk_threads_init();
	gtk_init(NULL, NULL);
	widget_init();

	/* Create main GUI window. */
	gtk_window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	widget_set(ID_MAINWND, gtk_window);
	gtk_widget_show(gtk_window);
	gtk_window_set_title(GTK_WINDOW(gtk_window), "HIP Config");
	gtk_widget_set_size_request(gtk_window, 400, 300);

	g_signal_connect(G_OBJECT(gtk_window), "delete_event",
	                 G_CALLBACK(delete_event), NULL);
	g_signal_connect(G_OBJECT(gtk_window), "destroy",
	                 G_CALLBACK(destroy), NULL);

	/* Create tool-dialog. */
	gtk_toolwindow = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	widget_set(ID_TOOLDLG, gtk_toolwindow);
	gtk_widget_show(gtk_toolwindow);
	gtk_window_set_title(GTK_WINDOW(gtk_toolwindow), "HIP tool window");
	gtk_widget_set_size_request(gtk_toolwindow, 450, 300);

	g_signal_connect(G_OBJECT(gtk_toolwindow), "delete_event",
	                 G_CALLBACK(tool_delete_event), NULL);
	g_signal_connect(G_OBJECT(gtk_toolwindow), "destroy",
	                 G_CALLBACK(tool_destroy), NULL);

	/* Create accept-dialog. */
	gtk_acceptdialog = gtk_dialog_new_with_buttons("New HIT received, accept?", NULL, GTK_DIALOG_MODAL,
	                                               "Accept", GTK_RESPONSE_YES,
	                                               "Deny", GTK_RESPONSE_NO, NULL);
	widget_set(ID_ACCEPTDLG, gtk_acceptdialog);
	gtk_widget_hide(gtk_acceptdialog);

	/* Create run-dialog. */
	gtk_rundialog = gtk_dialog_new_with_buttons("Run application", NULL,
	                                            GTK_DIALOG_MODAL, NULL);
	widget_set(ID_RUNDLG, gtk_rundialog);
	gtk_widget_hide(gtk_rundialog);

	/* Create create-dialog. */
	w = gtk_dialog_new_with_buttons("Create new remote group", NULL,
	                                GTK_DIALOG_MODAL, NULL);
	widget_set(ID_CREATEDLG, w);
	gtk_widget_hide(w);
	
	/* Create window content for all windows. */
	HIP_IFEL(tooldlg_create_content(), -1, "Failed to create tool-dialog contents.\n");
	HIP_IFEL(acceptdlg_create_content(), -1, "Failed to create accept-dialog contents.\n");
	HIP_IFEL(rundlg_create_content(), -1, "Failed to create run-dialog contents.\n");
	HIP_IFEL(createdlg_create_content(), -1, "Failed to create create-dialog contents.\n");
	HIP_IFEL(main_create_content(), -1, "Failed to create main-window contents.\n");

	HIP_IFEL(exec_init(), -1, "Execute \"environment\" initialization failed.\n");

	gui_set_info("HIP GUI started.");

	/* Create some random nickname. */
	sprintf(str, "user%0.3d", rand() % 1000);
	set_nick(str);

out_err:
	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Run the GUI. This function is assumed to block the calling thread here
	as long as GUI is running.
*/
int gui_main(void)
{
	/* Variables. */
	GtkWidget *w;
	
	HIP_DEBUG("Appending remote groups to tool window...\n");
	w = widget(ID_TOOLRGROUPS);
	hit_db_enum_rgroups(tooldlg_add_rgroups, w);
	gtk_combo_box_set_active(w, 0);

	HIP_DEBUG("Appending local HITs to tool window...\n");
	w = widget(ID_TOOLLHITS);
	hit_db_enum_locals(tooldlg_add_lhits, w);
	gtk_combo_box_set_active(w, 0);

	HIP_DEBUG("Appending remote groups to ask window...\n");
	w = widget(ID_AD_RGROUPS);
	hit_db_enum_rgroups(askdlg_add_rgroups, w);
	gtk_combo_box_set_active(w, 0);
	
	HIP_DEBUG("Appending local HITs to ask window...\n");
	w = widget(ID_AD_LHITS);
	hit_db_enum_locals(askdlg_add_lhits, w);
	gtk_combo_box_set_active(w, 0);
	
	gtk_main();
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Quit the GUI.
*/
void gui_quit(void)
{
	exec_quit();
	widget_quit();
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Get pointer to window.
	
	@return Pointer to window.
*/
void *gui_get_window(void)
{
	return ((void *)gtk_window);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Get pointer to tool window.
	
	@return Pointer to tool window.
*/
void *gui_get_toolwindow(void)
{
	return ((void *)gtk_toolwindow);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Get pointer to accept window.
	
	@return Pointer to accept window.
*/
void *gui_get_acceptdialog(void)
{
	return ((void *)gtk_acceptdialog);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Get pointer to run window.
	
	@return Pointer to run window.
*/
void *gui_get_rundialog(void)
{
	return ((void *)gtk_rundialog);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/

