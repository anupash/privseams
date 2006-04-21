/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

/******************************************************************************/
/* INCLUDES */

/* STANDARD */

/* THIS */
#include "gui_main.h"


/******************************************************************************/
/* VARIABLES */
GtkWidget *gtk_window = NULL;
GtkWidget *gtk_toolwindow = NULL;


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

	/* Create main GUI window. */
	gtk_window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_widget_show(gtk_window);
	gtk_window_set_title(GTK_WINDOW(gtk_window), "HIP Config");
	gtk_widget_set_size_request(gtk_window, 400, 300);

	g_signal_connect(G_OBJECT(gtk_window), "delete_event",
	                 G_CALLBACK(delete_event), NULL);
	g_signal_connect(G_OBJECT(gtk_window), "destroy",
	                 G_CALLBACK(destroy), NULL);

	/* Create tool window. */
	gtk_toolwindow = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_widget_show(gtk_toolwindow);
	gtk_window_set_title(GTK_WINDOW(gtk_toolwindow), "HIP tool window");
	gtk_widget_set_size_request(gtk_toolwindow, 200, 180);

	g_signal_connect(G_OBJECT(gtk_toolwindow), "delete_event",
	                 G_CALLBACK(tool_delete_event), NULL);
	g_signal_connect(G_OBJECT(gtk_toolwindow), "destroy",
	                 G_CALLBACK(destroy), NULL);
	
	/* Create window content for all windows. */
	gui_create_toolwindow_content();
	gui_create_content();
	
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
	gtk_main();
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Quit the GUI.
*/
void gui_quit(void)
{
	
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


/* END OF SOURCE FILE */
/******************************************************************************/

