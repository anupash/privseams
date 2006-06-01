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
	int err = 0;

	/* Initialize libraries. */
	g_thread_init(NULL);
	gdk_threads_init();
	gtk_init(NULL, NULL);
	widget_init();

	/* Create main GUI window. */
	gtk_window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_widget_show(gtk_window);
	gtk_window_set_title(GTK_WINDOW(gtk_window), "HIP Config");
	gtk_widget_set_size_request(gtk_window, 350, 450);

	g_signal_connect(G_OBJECT(gtk_window), "delete_event",
	                 G_CALLBACK(delete_event), NULL);
	g_signal_connect(G_OBJECT(gtk_window), "destroy",
	                 G_CALLBACK(destroy), NULL);

	/* Create tool window. */
	gtk_toolwindow = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_widget_show(gtk_toolwindow);
	gtk_window_set_title(GTK_WINDOW(gtk_toolwindow), "HIP tool window");
	gtk_widget_set_size_request(gtk_toolwindow, 450, 300);

	g_signal_connect(G_OBJECT(gtk_toolwindow), "delete_event",
	                 G_CALLBACK(tool_delete_event), NULL);
	g_signal_connect(G_OBJECT(gtk_toolwindow), "destroy",
	                 G_CALLBACK(tool_destroy), NULL);

	/* Create accept window. */
	gtk_acceptdialog = gtk_dialog_new_with_buttons("New HIT received, accept?", NULL, GTK_DIALOG_MODAL,
	                                               "Accept", GTK_RESPONSE_YES,
	                                               "Deny", GTK_RESPONSE_NO, NULL);
	gtk_widget_hide(gtk_acceptdialog);

	/* Create accept window. */
	gtk_rundialog = gtk_dialog_new_with_buttons("Run application", NULL,
	                                            GTK_DIALOG_MODAL, NULL);
	gtk_widget_hide(gtk_rundialog);
	
	/* Create window content for all windows. */
	tooldlg_create_content();
	acceptdlg_create_content();
	rundlg_create_content();
	main_create_content();
	
	gui_set_info("HIP GUI started.");
 
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

