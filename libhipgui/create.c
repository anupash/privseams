/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

/******************************************************************************/
/* INCLUDES */
#include "create.h"


/******************************************************************************/
/* FUNCTIONS */

/******************************************************************************/
/**
	Create "new remote group"-dialog contents.

	@return 0 if success, -1 on errors.
*/
int ngdlg_create_content(void)
{
	/* Variables. */
	GtkWidget *window = (GtkWidget *)widget(ID_NGDLG);
	GtkWidget *hb = NULL;
	GtkWidget *w = NULL;

	gtk_container_set_border_width(GTK_CONTAINER(window), 3);

	/* Create main widget for adding subwidgets to window. */
	hb = gtk_hbox_new(TRUE, 5);
	gtk_box_pack_start(GTK_BOX(GTK_DIALOG(window)->vbox), hb, TRUE, TRUE, 3);
	gtk_widget_show(hb);

	/* Create group name input widget. */
	w = gtk_entry_new();
	widget_set(ID_CREATE_NAME, w);
	gtk_entry_set_text(w, "");
	gtk_box_pack_start(GTK_BOX(hb), w, TRUE, TRUE, 3);
	gtk_widget_show(w);
	gtk_entry_set_activates_default(GTK_ENTRY(w), TRUE);

	/* Add buttons to dialog. */
	w = gtk_dialog_add_button(window, "Create", GTK_RESPONSE_OK);
	gtk_widget_grab_default(w);
	gtk_dialog_add_button(window, "Cancel", GTK_RESPONSE_CANCEL);

	return (0);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/

