/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

/******************************************************************************/
/* INCLUDES */
#include "nh.h"


/******************************************************************************/
/* FUNCTIONS */

/******************************************************************************/
/**
	Create contents of the accept dialog in here.

	@return 0 if success, -1 on errors.
*/
int nhdlg_create_content(void)
{
	/* Variables. */
	GtkWidget *window = (GtkWidget *)widget(ID_NHDLG);
	GtkWidget *fixed = NULL;
	GtkWidget *label = NULL;
	GtkWidget *w = NULL;
	int y;

	gtk_container_set_border_width(GTK_CONTAINER(window), 1);

	/* Create main widget for adding subwidgets to tool window. */
	fixed = gtk_fixed_new();
	gtk_box_pack_start(GTK_BOX(GTK_DIALOG(window)->vbox), fixed, TRUE, TRUE, 3);
	gtk_widget_show(fixed);

	/* Create local HIT info. */
	y = 0;

	w = gtk_label_new("<empty>");
	gtk_widget_set_size_request(w, 200, -1);
	y += 23; gtk_fixed_put(GTK_FIXED(fixed), w, 80, y);
	gtk_widget_show(w);
	widget_set(ID_NH_NEWHIT, w);
	w = gtk_label_new("New HIT:");
	y += 0; gtk_fixed_put(GTK_FIXED(fixed), w, 0, y);
	gtk_widget_show(w);

	w = gtk_entry_new();
	gtk_entry_set_text(w, "<New HIT name>");
	gtk_widget_set_size_request(w, 200, -1);
	y += 26; gtk_fixed_put(GTK_FIXED(fixed), w, 80, y);
	gtk_widget_show(w);
	widget_set(ID_NH_NAME, w);
	w = gtk_label_new("HIT name:");
	y += 0; gtk_fixed_put(GTK_FIXED(fixed), w, 0, y);
	gtk_widget_show(w);

	w = gtk_combo_box_new_text();
	g_signal_connect(w, "changed", G_CALLBACK(button_event), IDB_CB_RGROUPS);
	widget_set(ID_NH_RGROUP, w);
	gtk_widget_set_size_request(w, 200, -1);
	y += 26; gtk_fixed_put(GTK_FIXED(fixed), w, 80, y);
	gtk_widget_show(w);
	w = gtk_label_new("Group:");
	y += 4; gtk_fixed_put(GTK_FIXED(fixed), w, 0, y);
	gtk_widget_show(w);

	w = gtk_combo_box_new_text();
	widget_set(ID_NH_LOCAL, w);
	gtk_widget_set_size_request(w, 200, -1);
	y += 26; gtk_fixed_put(GTK_FIXED(fixed), w, 80, y);
	gtk_widget_show(w);
	w = gtk_label_new("Local HIT:");
	y += 4; gtk_fixed_put(GTK_FIXED(fixed), w, 0, y);
	gtk_widget_show(w);

	w = gtk_combo_box_new_text();
	gtk_combo_box_append_text(w, "Normal");
	gtk_combo_box_append_text(w, "Lightweight");
	gtk_combo_box_set_active(w, 0);
	gtk_widget_set_size_request(w, 200, -1);
	y += 26; gtk_fixed_put(GTK_FIXED(fixed), w, 80, y);
	gtk_widget_show(w);
	w = gtk_label_new("Lightweight:");
	y += 4; gtk_fixed_put(GTK_FIXED(fixed), w, 0, y);
	gtk_widget_show(w);

	return (0);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/

