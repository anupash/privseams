/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

#ifndef GUI_EVENT_H
#define GUI_EVENT_H

/******************************************************************************/
/* INCLUDES */
#include <string.h>
#include <gtk/gtk.h>


/******************************************************************************/
/* FUNCTION DEFINITIONS */
gboolean delete_event(GtkWidget *, GdkEvent *, gpointer);
gboolean tool_delete_event(GtkWidget *, GdkEvent *, gpointer);
void destroy(GtkWidget *, gpointer);
void select_list(GtkTreeSelection *, gpointer);
void select_rlist(GtkTreeSelection *, gpointer);
void button_event(GtkWidget *, gpointer);


#endif /* END OF HEADER FILE */
/******************************************************************************/

