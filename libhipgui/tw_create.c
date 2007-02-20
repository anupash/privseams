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
	GtkWidget *w, *hb, *vb;
	int err = 0;

	gtk_container_set_border_width(widget(ID_TOOLWND), 1);
	gtk_container_set_border_width(widget(ID_LTOOLWND), 1);

	/* Create remote -tab content. */
	vb = gtk_vbox_new(FALSE, 5);
	gtk_box_pack_start(widget(ID_TOOLWND), vb, FALSE, FALSE, 1);
	gtk_widget_show(vb);
	widget_set(ID_TW_CONTAINER, vb);

	HIP_IFEL(tw_create_remote(), -1, "Failed to create remote info toolwindow.\n");
	HIP_IFEL(tw_create_rgroup(), -1, "Failed to create remote group info toolwindow.\n");

	hb = gtk_hbox_new(FALSE, 5);
	gtk_box_pack_start(widget(ID_TOOLWND), hb, FALSE, FALSE, 1);
	gtk_widget_show(hb);
	
	w = gtk_button_new_with_label(lang_get("tw-button-delete"));
	gtk_box_pack_end(hb, w, FALSE, FALSE, 1);
	g_signal_connect(w, "clicked", G_CALLBACK(button_event), IDB_TW_DELETE);
	gtk_widget_set_sensitive(w, FALSE);
	gtk_widget_show(w);
	widget_set(ID_TW_DELETE, w);
	
	w = gtk_button_new_with_label(lang_get("tw-button-cancel"));
	gtk_box_pack_end(hb, w, FALSE, FALSE, 1);
	g_signal_connect(w, "clicked", G_CALLBACK(button_event), IDB_TW_CANCEL);
	gtk_widget_set_sensitive(w, FALSE);
	gtk_widget_show(w);
	widget_set(ID_TW_CANCEL, w);

	w = gtk_button_new_with_label(lang_get("tw-button-apply"));
	gtk_box_pack_end(hb, w, FALSE, FALSE, 1);
	g_signal_connect(w, "clicked", G_CALLBACK(button_event), IDB_TW_APPLY);
	GTK_WIDGET_SET_FLAGS(w, GTK_CAN_DEFAULT);
	gtk_widget_set_sensitive(w, FALSE);
	gtk_widget_show(w);
	widget_set(ID_TW_APPLY, w);
	
	/* Create local -tab content. */
	vb = gtk_vbox_new(FALSE, 5);
	gtk_box_pack_start(GTK_BOX(GTK_DIALOG(widget(ID_LTOOLWND))->vbox), vb, TRUE, TRUE, 3);
	gtk_widget_show(vb);
	widget_set(ID_TWL_CONTAINER, vb);
	
	HIP_IFEL(tw_create_local(), -1, "Failed to create local info toolwindow.\n");

	gtk_widget_show(widget(ID_TOOLWND));
//	gtk_widget_grab_default(widget(ID_TW_APPLY));

out_err:
	return (err);
}
/* END OF FUNCTION */

/******************************************************************************/
/**
	Create contents for remote HIT information.
	
	@return 0 on success, -1 on errors.
*/
int tw_create_remote(void)
{
	/* Variables. */
	GtkWidget *frame, *w, *vb, *vb1, *vb2, *sw, *hb, *hp, *exp, *label;
	
	/* Create menu for right click popup. */
	w = gtk_menu_new();
	
	label = gtk_menu_item_new_with_label(lang_get("tw-button-delete"));
	gtk_menu_shell_append(w, label);
	g_signal_connect(label, "activate", G_CALLBACK(button_event), (gpointer)IDM_RLIST_DELETE);
	gtk_widget_show(label);
	
	widget_set(ID_RLISTMENU, w);

	/* Create remote HIT info. */
	frame = gtk_frame_new(NULL);
	gtk_frame_set_label(frame, lang_get("tw-hit-info"));
	gtk_frame_set_label_align(frame, 0.0, 0.0);
	gtk_frame_set_shadow_type(frame, GTK_SHADOW_ETCHED_OUT);
	gtk_container_set_border_width(frame, 5);
	gtk_widget_show(frame);
	widget_set(ID_TWREMOTE, frame);
	g_object_ref(frame);

	/* This box is for adding everything inside previous frame. */
	vb = gtk_vbox_new(FALSE, 1);
	gtk_container_add(frame, vb);
	gtk_widget_show(vb);

	/* Now create basic information. */
	hb = gtk_hbox_new(FALSE, 1);
	gtk_box_pack_start(vb, hb, FALSE, FALSE, 1);
	gtk_widget_show(hb);

	w = gtk_label_new(lang_get("tw-hit-name"));
	gtk_box_pack_start(hb, w, FALSE, FALSE, 5);
	gtk_widget_show(w);
	w = gtk_entry_new();
	gtk_entry_set_text(w, "NewHIT");
	gtk_box_pack_start(hb, w, TRUE, TRUE, 5);
	gtk_entry_set_max_length(w, MAX_NAME_LEN);
	gtk_entry_set_activates_default(w, TRUE);
	gtk_widget_show(w);
	widget_set(ID_TWR_NAME, w);

	w = gtk_label_new(lang_get("tw-hit-group"));
	gtk_box_pack_start(hb, w, FALSE, FALSE, 5);
	gtk_widget_show(w);
	w = gtk_combo_box_new_text();
	widget_set(ID_TWRGROUP, w);
	g_signal_connect(w, "changed", G_CALLBACK(button_event), IDB_TW_RGROUPS);
	gtk_box_pack_start(hb, w, FALSE, FALSE, 5);
	gtk_widget_show(w);
	widget_set(ID_TWR_RGROUP, w);

	/* Separator between basic and advanced. */
	w = gtk_hseparator_new();
	gtk_box_pack_start(vb, w, FALSE, FALSE, 2);
	gtk_widget_show(w);

	/* Advanced information. */
	exp = gtk_expander_new(lang_get("tw-hit-advanced"));
	gtk_box_pack_start(vb, exp, FALSE, TRUE, 2);
	gtk_widget_show(exp);
	
	vb2 = gtk_vbox_new(FALSE, 2);
	gtk_container_add(exp, vb2);
	gtk_widget_show(vb2);

	hb = gtk_hbox_new(FALSE, 1);
	gtk_box_pack_start(vb2, hb, FALSE, FALSE, 1);
	gtk_widget_show(hb);
	
	w = gtk_label_new(lang_get("tw-hit-hit"));
	gtk_box_pack_start(hb, w, FALSE, FALSE, 5);
	gtk_widget_show(w);
	w = gtk_entry_new();
	gtk_entry_set_text(w, "0");
	gtk_box_pack_start(hb, w, TRUE, TRUE, 5);
	gtk_widget_set_sensitive(w, FALSE);
	gtk_widget_show(w);
	widget_set(ID_TWR_REMOTE, w);

	w = gtk_label_new(lang_get("tw-hit-port"));
	gtk_box_pack_start(hb, w, FALSE, FALSE, 5);
	gtk_widget_show(w);
	w = gtk_entry_new();
	gtk_entry_set_text(w, "0");
	gtk_box_pack_start(hb, w, FALSE, TRUE, 5);
	gtk_widget_set_size_request(w, 90, -1);
	gtk_entry_set_activates_default(w, TRUE);
	gtk_entry_set_max_length(w, MAX_URL_LEN);
	gtk_widget_show(w);
	widget_set(ID_TWR_PORT, w);

	hb = gtk_hbox_new(FALSE, 1);
	gtk_box_pack_start(vb2, hb, FALSE, FALSE, 1);
	gtk_widget_show(hb);
	
	w = gtk_label_new(lang_get("tw-hit-url"));
	gtk_box_pack_start(hb, w, FALSE, FALSE, 5);
//	gtk_widget_show(w);
	w = gtk_entry_new();
	gtk_entry_set_text(w, "<notset>");
	gtk_box_pack_start(hb, w, TRUE, TRUE, 5);
	gtk_entry_set_max_length(w, MAX_URL_LEN);
	gtk_entry_set_activates_default(w, TRUE);
//	gtk_widget_show(w);
	widget_set(ID_TWR_URL, w);

	frame = gtk_frame_new(NULL);
	gtk_frame_set_label(frame, lang_get("tw-hit-groupinfo"));
	gtk_frame_set_label_align(frame, 0.0, 0.0);
	gtk_frame_set_shadow_type(frame, GTK_SHADOW_ETCHED_OUT);
	gtk_container_set_border_width(frame, 5);
	gtk_box_pack_start(vb2, frame, FALSE, FALSE, 1);
	gtk_widget_show(frame);

	vb2 = gtk_vbox_new(FALSE, 2);
	gtk_container_add(frame, vb2);
	gtk_widget_show(vb2);

	hb = gtk_hbox_new(FALSE, 1);
	gtk_box_pack_start(vb2, hb, FALSE, FALSE, 1);
	gtk_widget_show(hb);
	
	w = gtk_label_new(lang_get("tw-hit-local"));
	gtk_box_pack_start(hb, w, FALSE, FALSE, 5);
	gtk_widget_show(w);
	w = gtk_combo_box_new_text();
	widget_set(ID_TWLOCAL, w);
	gtk_box_pack_start(hb, w, TRUE, TRUE, 1);
	gtk_widget_set_sensitive(w, FALSE);
	gtk_widget_show(w);
	widget_set(ID_TWR_LOCAL, w);

	hb = gtk_hbox_new(FALSE, 1);
	gtk_box_pack_start(vb2, hb, FALSE, FALSE, 1);
	gtk_widget_show(hb);

	w = gtk_label_new(lang_get("tw-hitgroup-type"));
	gtk_box_pack_start(hb, w, FALSE, FALSE, 5);
	gtk_widget_show(w);
	w = gtk_combo_box_new_text();
	gtk_combo_box_append_text(w, lang_get("group-type-accept"));
	gtk_combo_box_append_text(w, lang_get("group-type-deny"));
	gtk_combo_box_set_active(w, 0);
	gtk_box_pack_start(hb, w, TRUE, TRUE, 1);
	gtk_widget_set_sensitive(w, FALSE);
	gtk_widget_show(w);
	widget_set(ID_TWR_TYPE1, w);

	w = gtk_label_new(lang_get("tw-hitgroup-lightweight"));
	gtk_box_pack_start(hb, w, FALSE, FALSE, 5);
	gtk_widget_show(w);
	w = gtk_combo_box_new_text();
	gtk_combo_box_append_text(w, lang_get("group-type2-normal"));
	gtk_combo_box_append_text(w, lang_get("group-type2-lightweight"));
	gtk_combo_box_set_active(w, 0);
	gtk_box_pack_start(hb, w, TRUE, TRUE, 1);
	gtk_widget_set_sensitive(w, FALSE);
	gtk_widget_show(w);
	widget_set(ID_TWR_TYPE2, w);

	return (0);
}
/* END OF FUNCTION */
	

/******************************************************************************/
/**
	Create contents for local HIT information.
	
	@return 0 on success, -1 on errors.
*/
int tw_create_local(void)
{
	/* Variables. */
	GtkWidget *frame, *w, *vb, *hb;
	
	/* Create local HIT info. */
	frame = gtk_frame_new(NULL);
	gtk_frame_set_label(GTK_FRAME(frame), lang_get("lh-info"));
	gtk_frame_set_label_align(GTK_FRAME(frame), 0.0, 0.0);
	gtk_frame_set_shadow_type(GTK_FRAME(frame), GTK_SHADOW_ETCHED_OUT);
	gtk_container_set_border_width(frame, 5);
	gtk_widget_show(frame);
	widget_set(ID_TWLOCAL, frame);
	gtk_box_pack_start(widget(ID_TWL_CONTAINER), widget(ID_TWLOCAL), FALSE, FALSE, 1);
	g_object_ref(frame);

	/* This box is for adding everything inside previous frame. */
	vb = gtk_vbox_new(FALSE, 1);
	gtk_container_add(frame, vb);
	gtk_widget_show(vb);

	/* Now create basic information. */
	hb = gtk_hbox_new(FALSE, 1);
	gtk_box_pack_start(vb, hb, FALSE, FALSE, 1);
	gtk_widget_show(hb);

	w = gtk_label_new(lang_get("lh-name"));
	gtk_box_pack_start(hb, w, FALSE, FALSE, 5);
	gtk_widget_show(w);
	w = gtk_entry_new();
	gtk_entry_set_text(w, "");
	gtk_box_pack_start(hb, w, TRUE, TRUE, 5);
	gtk_entry_set_max_length(w, MAX_NAME_LEN);
	gtk_entry_set_activates_default(w, TRUE);
	gtk_widget_show(w);
	widget_set(ID_TWL_NAME, w);

	hb = gtk_hbox_new(FALSE, 1);
	gtk_box_pack_start(vb, hb, FALSE, FALSE, 1);
	gtk_widget_show(hb);

	w = gtk_label_new(lang_get("lh-hit"));
	gtk_box_pack_start(hb, w, FALSE, FALSE, 5);
	gtk_widget_show(w);
	w = gtk_entry_new();
	gtk_entry_set_text(w, "0");
	gtk_box_pack_start(hb, w, TRUE, TRUE, 5);
	gtk_widget_set_sensitive(w, FALSE);
	gtk_widget_show(w);
	widget_set(ID_TWL_LOCAL, w);

	return (0);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Create contents for remote group information.
	
	@return 0 on success, -1 on errors.
*/
int tw_create_rgroup(void)
{
	/* Variables. */
	GtkWidget *frame, *w, *vb, *vb2, *hb, *exp;
	
	/* Create remote group HIT info. */
	frame = gtk_frame_new(NULL);
	gtk_frame_set_label(GTK_FRAME(frame), lang_get("tw-group-info"));
	gtk_frame_set_label_align(GTK_FRAME(frame), 0.0, 0.0);
	gtk_frame_set_shadow_type(GTK_FRAME(frame), GTK_SHADOW_ETCHED_OUT);
	gtk_container_set_border_width(frame, 5);
	gtk_widget_show(frame);
	widget_set(ID_TWRGROUP, frame);
	g_object_ref(frame);

	/* This box is for adding everything inside previous frame. */
	vb = gtk_vbox_new(FALSE, 1);
	gtk_container_add(frame, vb);
	gtk_widget_show(vb);

	/* Now create basic information. */
	hb = gtk_hbox_new(FALSE, 1);
	gtk_box_pack_start(vb, hb, FALSE, FALSE, 1);
	gtk_widget_show(hb);

	w = gtk_label_new(lang_get("tw-group-name"));
	gtk_box_pack_start(hb, w, FALSE, FALSE, 5);
	gtk_widget_show(w);
	w = gtk_entry_new();
	gtk_entry_set_text(w, "");
	gtk_box_pack_start(hb, w, TRUE, TRUE, 5);
	gtk_entry_set_max_length(w, MAX_NAME_LEN);
	gtk_entry_set_activates_default(w, TRUE);
	gtk_widget_show(w);
	widget_set(ID_TWG_NAME, w);

	/* Separator between basic and advanced. */
	w = gtk_hseparator_new();
	gtk_box_pack_start(vb, w, FALSE, FALSE, 2);
	gtk_widget_show(w);

	/* Advanced information. */
	exp = gtk_expander_new(lang_get("tw-group-advanced"));
	gtk_box_pack_start(vb, exp, FALSE, TRUE, 2);
	gtk_widget_show(exp);
	
	vb2 = gtk_vbox_new(FALSE, 2);
	gtk_container_add(exp, vb2);
	gtk_widget_show(vb2);

	hb = gtk_hbox_new(FALSE, 1);
	gtk_box_pack_start(vb2, hb, FALSE, FALSE, 1);
	gtk_widget_show(hb);

	w = gtk_label_new(lang_get("tw-group-local"));
	gtk_box_pack_start(hb, w, FALSE, FALSE, 5);
	gtk_widget_show(w);
	w = gtk_combo_box_new_text();
	gtk_box_pack_start(hb, w, TRUE, TRUE, 1);
	gtk_widget_set_sensitive(w, FALSE);
	gtk_widget_show(w);
	widget_set(ID_TWG_LOCAL, w);

	hb = gtk_hbox_new(FALSE, 1);
	gtk_box_pack_start(vb2, hb, FALSE, FALSE, 1);
	gtk_widget_show(hb);
	
	w = gtk_label_new(lang_get("tw-hitgroup-type"));
	gtk_box_pack_start(hb, w, FALSE, FALSE, 5);
	gtk_widget_show(w);
	w = gtk_combo_box_new_text();
	gtk_combo_box_append_text(w, lang_get("group-type-accept"));
	gtk_combo_box_append_text(w, lang_get("group-type-deny"));
	gtk_combo_box_set_active(w, 0);
	gtk_box_pack_start(hb, w, TRUE, TRUE, 1);
	gtk_widget_show(w);
	widget_set(ID_TWG_TYPE1, w);

	w = gtk_label_new(lang_get("tw-hitgroup-lightweight"));
	gtk_box_pack_start(hb, w, FALSE, FALSE, 5);
	gtk_widget_show(w);
	w = gtk_combo_box_new_text();
	gtk_combo_box_append_text(w, lang_get("group-type2-normal"));
	gtk_combo_box_append_text(w, lang_get("group-type2-lightweight"));
	gtk_combo_box_set_active(w, 0);
	gtk_box_pack_start(hb, w, TRUE, TRUE, 1);
	gtk_widget_set_sensitive(w, FALSE);
	gtk_widget_show(w);
	widget_set(ID_TWG_TYPE2, w);

	return (0);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/

