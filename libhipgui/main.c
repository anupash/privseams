/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

/******************************************************************************/
/* INCLUDES */
#include "main.h"


/******************************************************************************/
/* FUNCTIONS */

/******************************************************************************/
/**
	Initialize GUI for usage.
	
	@return 0 if success, -1 on errors.
*/
int gui_init(void)
{
	/* Variables. */
	GtkWidget *w;
	int err = 0;
	char str[320];

	/* Initialize libraries. */
	g_thread_init(NULL);
	gdk_threads_init();
	gtk_init(NULL, NULL);
	widget_init();

	/* Create main GUI window. */
	w = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	widget_set(ID_MAINWND, w);
	gtk_widget_show(w);
	gtk_window_set_title(w, "HIP Config");
	gtk_widget_set_size_request(w, 400, 300);

	g_signal_connect(w, "delete_event", G_CALLBACK(main_delete), NULL);
	g_signal_connect(w, "destroy", G_CALLBACK(main_destroy), NULL);

	/* Create tool-dialog. */
	w = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	widget_set(ID_TOOLWND, w);
	gtk_widget_show(w);
	gtk_window_set_title(w, "HIP tool window");
	gtk_widget_set_size_request(w, 450, 300);

	g_signal_connect(w, "delete_event", G_CALLBACK(tw_delete), NULL);
	g_signal_connect(w, "destroy", G_CALLBACK(tw_destroy), NULL);

	/* Create accept-dialog. */
	w = gtk_dialog_new_with_buttons("New HIT received, accept?", NULL, GTK_DIALOG_MODAL,
	                                "Accept", GTK_RESPONSE_YES,
	                                "Deny", GTK_RESPONSE_NO, NULL);
	widget_set(ID_ACCEPTDLG, w);
	gtk_widget_hide(w);

	/* Create execute-dialog. */
	w = gtk_dialog_new_with_buttons("Run application", NULL, GTK_DIALOG_MODAL, NULL);
	widget_set(ID_EXECDLG, w);
	gtk_widget_hide(w);

	/* Create create-dialog. */
	w = gtk_dialog_new_with_buttons("Create new remote group", NULL, GTK_DIALOG_MODAL, NULL);
	widget_set(ID_CREATEDLG, w);
	gtk_widget_hide(w);
	
	/* Create window content for all windows. */
	HIP_IFEL(tw_create_content(), -1, "Failed to create tool-dialog contents.\n");
	HIP_IFEL(acceptdlg_create_content(), -1, "Failed to create accept-dialog contents.\n");
	HIP_IFEL(rundlg_create_content(), -1, "Failed to create run-dialog contents.\n");
	HIP_IFEL(createdlg_create_content(), -1, "Failed to create create-dialog contents.\n");
	HIP_IFEL(main_create_content(), -1, "Failed to create main-window contents.\n");

	HIP_IFEL(exec_init(), -1, "Execute \"environment\" initialization failed.\n");

	gui_set_info("HIP GUI started.");
	term_print("* HIP GUI started.\n");

	/* Create some random nickname. */
	sprintf(str, "user%0.3d", rand() % 1000);
	set_nick(str);

out_err:
	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Run the GUI. This function is assumed to block the calling thread here
	as long as GUI is running.
*/
int gui_main(void)
{
	/* Variables. */
	GtkWidget *w;
	
/*	HIP_DEBUG("Appending remote groups to tool window...\n");
	w = widget(ID_TWRGROUPS);
//	hit_db_enum_rgroups(tooldlg_add_rgroups, w);
	gtk_combo_box_append_text(w, "<create new...>");
	gtk_combo_box_set_active(w, 0);

	HIP_DEBUG("Appending local HITs to tool window...\n");
	w = widget(ID_TWLHITS);
	hit_db_enum_locals(tooldlg_add_lhits, w);
	gtk_combo_box_set_active(w, 0);

	HIP_DEBUG("Appending remote groups to ask window...\n");
	w = widget(ID_AD_RGROUPS);
//	hit_db_enum_rgroups(askdlg_add_rgroups, w);
	gtk_combo_box_append_text(w, "<create new...>");
	gtk_combo_box_set_active(w, 0);
	
	HIP_DEBUG("Appending local HITs to ask window...\n");
	w = widget(ID_AD_LHITS);
	hit_db_enum_locals(askdlg_add_lhits, w);
	gtk_combo_box_set_active(w, 0);*/
	
	gtk_main();
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Quit the GUI.
*/
void gui_quit(void)
{
	exec_quit();
	widget_quit();
}
/* END OF FUNCTION */


/******************************************************************************/
/** Set status bar info text. */
void gui_set_info(const char *string, ...)
{
	/* Variables. */
	static int last = -1;
	GtkWidget *w;
	char *str[2048];
	va_list args;
	
	/* Get args. */
	va_start(args, string);

	/* Set to status bar. */
	vsprintf(str, string, args);
	w = widget(ID_STATUSBAR);
	if (last >= 0) gtk_statusbar_pop(w, last);
	last = gtk_statusbar_get_context_id(w, "info");
	gtk_statusbar_push(w, last, str);

	/* End args. */
	va_end(args);
}
/* END OF FUNCTION */


/******************************************************************************/
/** Terminate GUI. */
void gui_terminate(void)
{
	gtk_main_quit();
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/

