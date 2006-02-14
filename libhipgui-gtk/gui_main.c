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


/******************************************************************************/
/* FUNCTIONS */

/******************************************************************************/
/**
	Initialize GUI for usage.
	
	@return 0 if success, -1 on errors.
*/
int gui_init(void)
{
	gtk_init(NULL, NULL);
    
	gtk_window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_widget_show(gtk_window);
	gtk_window_set_title(GTK_WINDOW(gtk_window), "HIP Config");
	gtk_widget_set_size_request(gtk_window, 500, 400);

	g_signal_connect(G_OBJECT(gtk_window), "delete_event",
	                 G_CALLBACK(delete_event), NULL);
	g_signal_connect(G_OBJECT(gtk_window), "destroy",
	                 G_CALLBACK(destroy), NULL);
	
	gui_create_content();

	/* Return. */
	return (0);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Run the GUI.
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


/* END OF SOURCE FILE */
/******************************************************************************/

