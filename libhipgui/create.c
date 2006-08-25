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
	GtkWidget *hb, *w, *vb;

	gtk_container_set_border_width(GTK_CONTAINER(window), 3);

	/* This box is for adding everything inside previous frame. */
	vb = gtk_vbox_new(FALSE, 1);
	gtk_box_pack_start(GTK_BOX(GTK_DIALOG(window)->vbox), vb, TRUE, TRUE, 3);
	gtk_widget_show(vb);
	
	hb = gtk_hbox_new(FALSE, 5);
	gtk_box_pack_start(vb, hb, FALSE, FALSE, 5);
	gtk_widget_show(hb);

	w = gtk_label_new("Name:");
	gtk_box_pack_start(hb, w, FALSE, FALSE, 5);
	gtk_widget_show(w);
	w = gtk_entry_new();
	gtk_entry_set_text(w, "");
	gtk_box_pack_start(hb, w, TRUE, TRUE, 5);
	gtk_entry_set_max_length(w, 64);
	gtk_widget_show(w);
	gtk_entry_set_activates_default(w, TRUE);
	widget_set(ID_NG_NAME, w);

	hb = gtk_hbox_new(FALSE, 1);
	gtk_box_pack_start(vb, hb, FALSE, FALSE, 1);
	gtk_widget_show(hb);
	
	w = gtk_label_new("Local HIT:");
	gtk_box_pack_start(hb, w, FALSE, FALSE, 5);
	gtk_widget_show(w);
	w = gtk_combo_box_new_text();
	gtk_box_pack_start(hb, w, TRUE, TRUE, 5);
	gtk_widget_show(w);
	widget_set(ID_NG_LOCAL, w);

	hb = gtk_hbox_new(FALSE, 1);
	gtk_box_pack_start(vb, hb, FALSE, FALSE, 1);
	gtk_widget_show(hb);
	
	w = gtk_label_new("Type:");
	gtk_box_pack_start(hb, w, FALSE, FALSE, 5);
	gtk_widget_show(w);
	w = gtk_combo_box_new_text();
	gtk_combo_box_append_text(w, "accept");
	gtk_combo_box_append_text(w, "deny");
	gtk_combo_box_set_active(w, 0);
	gtk_box_pack_start(hb, w, TRUE, TRUE, 1);
	gtk_widget_show(w);
	widget_set(ID_NG_TYPE1, w);

	w = gtk_label_new("Lightweight:");
	gtk_box_pack_start(hb, w, FALSE, FALSE, 5);
	gtk_widget_show(w);
	w = gtk_combo_box_new_text();
	gtk_combo_box_append_text(w, "normal");
	gtk_combo_box_append_text(w, "lightweight");
	gtk_combo_box_set_active(w, 0);
	gtk_box_pack_start(hb, w, TRUE, TRUE, 1);
	gtk_widget_set_sensitive(w, FALSE);
	gtk_widget_show(w);
	widget_set(ID_NG_TYPE2, w);

	/* Add buttons to dialog. */
	w = gtk_dialog_add_button(window, "Create", GTK_RESPONSE_OK);
	gtk_widget_grab_default(w);
	gtk_dialog_add_button(window, "Cancel", GTK_RESPONSE_CANCEL);

	return (0);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/

