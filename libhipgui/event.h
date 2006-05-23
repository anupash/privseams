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
#include "debug.h"


/******************************************************************************/
/* FUNCTION DEFINITIONS */
gboolean delete_event(GtkWidget *, GdkEvent *, gpointer);
gboolean tool_delete_event(GtkWidget *, GdkEvent *, gpointer);
gboolean accept_delete_event(GtkWidget *, GdkEvent *, gpointer);
void destroy(GtkWidget *, gpointer);
void tool_destroy(GtkWidget *, gpointer);
void accept_destroy(GtkWidget *, gpointer);
gboolean select_list(GtkTreeSelection *, GtkTreeModel *, GtkTreePath *,
                     gboolean, gpointer);
gboolean select_rlist(GtkTreeSelection *, gpointer);
void button_event(GtkWidget *, gpointer);


#endif /* END OF HEADER FILE */
/******************************************************************************/

