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
#include <pthread.h>
#include <unistd.h>
#include <gtk/gtk.h>
#include "debug.h"
#include "hit_db.h"
#include "manage.h"


/******************************************************************************/
/* DEFINES */
enum TOOLBAR_IDS
{
	ID_TOOLBAR_RUN = 0,
	ID_TOOLBAR_NEWHIT,

	TOOLBAR_IDS_N
};

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
void toolbar_event(GtkWidget *, gpointer);


#endif /* END OF HEADER FILE */
/******************************************************************************/

