/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

/******************************************************************************/
/* INCLUDES */

/* STANDARD */

/* THIS */
#include "event.h"


/******************************************************************************/
/* FUNCTIONS */

/******************************************************************************/
/**
	What to do when user example tries to close the application?
	
	@return TRUE if don't close or FALSE if close.
*/
gboolean delete_event(GtkWidget *widget, GdkEvent *event, gpointer data)
{
	return (FALSE);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	What to do when user example tries to close the tool window?
	
	@return TRUE if don't close or FALSE if close.
*/
gboolean tool_delete_event(GtkWidget *widget, GdkEvent *event, gpointer data)
{
	return (FALSE);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	What to do when user example tries to close the tool window?
	
	@return TRUE if don't close or FALSE if close.
*/
gboolean accept_delete_event(GtkWidget *widget, GdkEvent *event, gpointer data)
{
	gtk_widget_hide(widget);
	return (TRUE);
}
/* END OF FUNCTION */


/******************************************************************************/
/** On window destroy. */
void destroy(GtkWidget *widget, gpointer data)
{
	gtk_main_quit();
}
/* END OF FUNCTION */


/******************************************************************************/
/** On tool window destroy. */
void tool_destroy(GtkWidget *widget, gpointer data)
{
	gtk_widget_hide(widget);
}
/* END OF FUNCTION */


/******************************************************************************/
/** On accept window destroy. */
void accept_destroy(GtkWidget *widget, gpointer data)
{
	gtk_widget_hide(widget);
}
/* END OF FUNCTION */


/******************************************************************************/
/** On list select. */
void select_list(GtkTreeSelection *selection, gpointer data)
{
	GtkTreeIter iter;
	GtkTreeModel *model;
	char *hit;

	if (gtk_tree_selection_get_selected(selection, &model, &iter))
	{
		gtk_tree_model_get(model, &iter, 0, &hit, -1);
		printf("You selected a HIT %s\n", hit);
		g_free(hit);
		info_mode_local();
	}
}
/* END OF FUNCTION */


/******************************************************************************/
/** On remote list select. */
void select_rlist(GtkTreeSelection *selection, gpointer data)
{
	GtkTreeIter iter;
	GtkTreeModel *model;
	char *hit;

	if (gtk_tree_selection_get_selected(selection, &model, &iter))
	{
		gtk_tree_model_get(model, &iter, 0, &hit, -1);
		printf("You selected a remote group/HIT %s\n", hit);
		g_free(hit);
		info_mode_remote();
	}
}
/* END OF FUNCTION */


/******************************************************************************/
/** On button event (clicked). */
void button_event(GtkWidget *widget, gpointer value)
{
	printf("Received button event (value: %d).\n", (int)value);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/

