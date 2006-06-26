/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

/******************************************************************************/
/* INCLUDES */
#include "tw.h"


/******************************************************************************/
/* FUNCTIONS */

/******************************************************************************/
/**
	Create contents of the tool window in here.

	@return 0 if success, -1 on errors.
*/
int tw_create_content(void)
{
	/* Variables. */
	GtkWidget *window = (GtkWidget *)widget(ID_TOOLWND);
	GtkWidget *fixed = NULL, *frame = NULL, *table = NULL;
	GtkWidget *label = NULL, *vb1 = NULL, *vb2 = NULL, *sw = NULL;
	GtkWidget *w = NULL, *hp = NULL, *vb = NULL, *hb = NULL;
	GList *glist = NULL;
	int y;

	gtk_container_set_border_width(GTK_CONTAINER(window), 1);

	/* Create remote HIT info. */
	frame = gtk_frame_new(NULL);
	gtk_frame_set_label(GTK_FRAME(frame), "Remote HIT information:");
	gtk_frame_set_label_align(GTK_FRAME(frame), 0.0, 0.0);
	gtk_frame_set_shadow_type(GTK_FRAME(frame), GTK_SHADOW_ETCHED_OUT);
	gtk_widget_show(frame);
	widget_set(ID_TWREMOTE, frame);
	g_object_ref(frame);

	vb = gtk_vbox_new(FALSE, 1);
	gtk_container_add(GTK_CONTAINER(frame), vb);
	gtk_widget_show(vb);

	sw = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(sw, GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
	gtk_box_pack_start(vb, sw, TRUE, TRUE, 1);
	gtk_widget_show(sw);

	hp = gtk_hpaned_new();
	gtk_scrolled_window_add_with_viewport(sw, hp);
	gtk_widget_show(hp);

	vb1 = gtk_vbox_new(FALSE, 2);
	gtk_paned_add1(hp, vb1);
	gtk_widget_show(vb1);
	vb2 = gtk_vbox_new(FALSE, 1);
	gtk_paned_add2(hp, vb2);
	gtk_widget_show(vb2);

	w = gtk_label_new("Name:");
	gtk_label_set_justify(GTK_LABEL(w), GTK_JUSTIFY_LEFT);
	gtk_box_pack_start(vb1, w, FALSE, FALSE, 5);
	gtk_widget_show(w);
	w = gtk_entry_new();
	gtk_entry_set_text(w, "NewHIT");
	gtk_box_pack_start(vb2, w, FALSE, FALSE, 1);
	gtk_widget_show(w);
	widget_set(ID_TWR_NAME, w);

	w = gtk_label_new("URL:");
	gtk_label_set_justify(GTK_LABEL(w), GTK_JUSTIFY_LEFT);
	gtk_box_pack_start(vb1, w, FALSE, FALSE, 5);
	gtk_widget_show(w);
	w = gtk_entry_new();
	gtk_entry_set_text(w, "https://www.nordea.fi <not implemented>");
	gtk_box_pack_start(vb2, w, FALSE, FALSE, 1);
	gtk_widget_show(w);
	widget_set(ID_TWR_URL, w);

	w = gtk_entry_new();
	gtk_entry_set_text(w, "80 <not implemented>");
	gtk_box_pack_start(vb2, w, FALSE, FALSE, 1);
	gtk_widget_show(w);
	w = gtk_label_new("Port:");
	gtk_box_pack_start(vb1, w, FALSE, FALSE, 5);
	gtk_widget_show(w);
	widget_set(ID_TWR_PORT, w);

	w = gtk_combo_box_new_text();
	gtk_combo_box_append_text(w, "Accept");
	gtk_combo_box_append_text(w, "Deny");
	gtk_combo_box_set_active(w, 0);
	gtk_box_pack_start(vb2, w, FALSE, FALSE, 1);
	gtk_widget_show(w);
	widget_set(ID_TWR_TYPE1, w);
	w = gtk_label_new("Type:");
	gtk_box_pack_start(vb1, w, FALSE, FALSE, 5);
	gtk_widget_show(w);

	w = gtk_combo_box_new_text();
	gtk_combo_box_append_text(w, "Normal");
	gtk_combo_box_append_text(w, "Lightweight");
	gtk_combo_box_set_active(w, 0);
	gtk_box_pack_start(vb2, w, FALSE, FALSE, 1);
	gtk_widget_show(w);
	widget_set(ID_TWR_TYPE2, w);
	w = gtk_label_new("Lightweight:");
	gtk_box_pack_start(vb1, w, FALSE, FALSE, 5);
	gtk_widget_show(w);

	w = gtk_combo_box_new_text();
	widget_set(ID_TWLOCAL, w);
	gtk_box_pack_start(vb2, w, FALSE, FALSE, 1);
	gtk_widget_show(w);
	widget_set(ID_TWR_LOCAL, w);
	w = gtk_label_new("Local HIT:");
	gtk_box_pack_start(vb1, w, FALSE, FALSE, 5);
	gtk_widget_show(w);

	w = gtk_combo_box_new_text();
	widget_set(ID_TWRGROUP, w);
	g_signal_connect(w, "changed", G_CALLBACK(button_event), IDB_CB_RGROUPS);
	gtk_box_pack_start(vb2, w, FALSE, FALSE, 1);
	gtk_widget_show(w);
	widget_set(ID_TWR_RGROUP, w);
	w = gtk_label_new("Group:");
	gtk_box_pack_start(vb1, w, FALSE, FALSE, 5);
	gtk_widget_show(w);

	hb = gtk_hbox_new(FALSE, 1);
	gtk_box_pack_end(vb, hb, FALSE, FALSE, 1);
	gtk_widget_show(hb);

	w = gtk_button_new_with_label("Apply");
	gtk_box_pack_start(hb, w, FALSE, FALSE, 1);
	g_signal_connect(w, "clicked", G_CALLBACK(button_event), IDB_TWAPPLY);
	gtk_widget_show(w);
	w = gtk_button_new_with_label("Cancel");
	gtk_box_pack_start(hb, w, FALSE, FALSE, 1);
	g_signal_connect(w, "clicked", G_CALLBACK(button_event), IDB_TWCANCEL);
	gtk_widget_set_sensitive(w, FALSE);
	gtk_widget_show(w);

	/* Create local HIT info. */
	frame = gtk_frame_new(NULL);
	gtk_frame_set_label(GTK_FRAME(frame), "Local HIT information:");
	gtk_frame_set_label_align(GTK_FRAME(frame), 0.0, 0.0);
	gtk_frame_set_shadow_type(GTK_FRAME(frame), GTK_SHADOW_ETCHED_OUT);
	gtk_widget_show(frame);
	widget_set(ID_TWLOCAL, frame);
	g_object_ref(frame);

	/* Create remote group HIT info. */
	frame = gtk_frame_new(NULL);
	gtk_frame_set_label(GTK_FRAME(frame), "Remote group information:");
	gtk_frame_set_label_align(GTK_FRAME(frame), 0.0, 0.0);
	gtk_frame_set_shadow_type(GTK_FRAME(frame), GTK_SHADOW_ETCHED_OUT);
	gtk_widget_show(frame);
	widget_set(ID_TWRGROUP, frame);
	g_object_ref(frame);

	/* Set default mode and hide the toolwindow. */
 	tw_set_mode(TWMODE_NONE);
	gtk_widget_hide(window);

	return (0);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/

