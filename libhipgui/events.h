/*
    HIP Agent

    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

#ifndef GUI_EVENTS_H
#define GUI_EVENTS_H

/******************************************************************************/
/* INCLUDES */
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <gtk/gtk.h>
#include "debug.h"
#include "hit_db.h"
#include "manage.h"
#include "exec.h"
#include "tools.h"
#include "terminal.h"
#include "widgets.h"


/******************************************************************************/
/* DEFINES */
enum TOOLBAR_IDS
{
	ID_TOOLBAR_RUN = 0,
	ID_TOOLBAR_NEWHIT,
	ID_TOOLBAR_TOGGLETOOLWINDOW,
	ID_TOOLBAR_NEWGROUP,

	TOOLBAR_IDS_N
};

enum BUTTON_IDS
{
	IDB_SEND,
	IDB_TW_RGROUPS,
	IDB_NH_RGROUPS,

	IDB_TW_APPLY,
	IDB_TW_CANCEL,
	IDB_TW_DELETE,
	
	IDB_SYSTRAY,

	BUTTON_IDS_N
};


/******************************************************************************/
/* FUNCTION DEFINITIONS */
gboolean main_delete_event(GtkWidget *, GdkEvent *, gpointer);
gboolean tw_delete_event(GtkWidget *, GdkEvent *, gpointer);
void main_destroy(GtkWidget *, gpointer);
void tw_destroy(GtkWidget *, gpointer);

gboolean list_click(GtkTreeSelection *, gpointer);
gboolean list_double_click(GtkTreeSelection *, GtkTreePath *,
						   GtkTreeViewColumn *, gpointer);

void button_event(GtkWidget *, gpointer);
void toolbar_event(GtkWidget *, gpointer);
void systray_event(void *, guint, guint, gpointer);


#endif /* END OF HEADER FILE */
/******************************************************************************/

