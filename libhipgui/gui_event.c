/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

/******************************************************************************/
/* INCLUDES */

/* STANDARD */

/* THIS */
#include "gui_event.h"


/******************************************************************************/
/* FUNCTIONS */

/******************************************************************************/
/**
	What to do when user example tries to close the application?
	
	@return TRUE if don't close or FALSE if close.
*/
gboolean delete_event(GtkWidget *widget,
                      GdkEvent *event,
                      gpointer data)
{
	return (FALSE);
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

		gui_clear_remote_hits();

		if (strstr(hit, "fake") != NULL)
		{
			/* Add fake items for HIT. */
			if (hit[strlen(hit) - 1] == '1')
			{
				gui_add_remote_hit("fake:remote...xxx1", "none", 80);
				gui_add_remote_hit("fake:remote...xxx2", "none", 80);
				gui_add_remote_hit("fake:remote...xxx3", "none", 80);
				gui_add_remote_hit("fake:remote...xxx4", "none", 80);
				gui_add_remote_hit("fake:remote...xxx5", "none", 80);
				gui_add_remote_hit("fake:remote...xxx6", "none", 80);
			}
			else if (hit[strlen(hit) - 1] == '2')
			{
				gui_add_remote_hit("fake:remote...yyy1", "none", 80);
				gui_add_remote_hit("fake:remote...yyy2", "none", 80);
			}
		}
		
		g_free(hit);
	}
}
/* END OF FUNCTION */


/******************************************************************************/
/** On button event (clicked). */
void button_event(GtkWidget *widget, gpointer value)
{
	printf("Received button event (value: %d).\n", (int)value);
	gui_ask_new_hit(NULL);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/

