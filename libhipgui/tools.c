/*
    DNET - Duge's Networking Library

    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

/******************************************************************************/
/* INCLUDES */
#include "tools.h"


/******************************************************************************/
/* VARIABLES */
char nickname[MAX_NAME_LEN + 1];


/******************************************************************************/
/* FUNCTIONS */

/******************************************************************************/
/** Get current nickname. */
char *get_nick(void)
{
	return (nickname);
}
/* END OF FUNCTION */


/******************************************************************************/
/** Set current nickname. */
void set_nick(char *newnick)
{
	NAMECPY(nickname, newnick);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Find index of given named item from combo box.

	@param name Name of item to search.
	@param warg Pointer to GtkWidget type combo box.
	@return Index of item, or -1 if not found.
*/
int find_from_cb(char *name, GtkWidget *warg)
{
	/* Variables. */
	GtkTreeModel *model;
	GtkTreeIter iter;
	char *str = NULL;
	int err = -1, i = 0;

	model = gtk_combo_box_get_model(warg);
	HIP_IFE(gtk_tree_model_get_iter_first(model, &iter) == FALSE, -1);

	do
	{
		gtk_tree_model_get(model, &iter, 0, &str, -1);
		if (strcmp(name, str) == 0)
		{
			err = i;
			break;
		}
		g_free(str);
		str = NULL;
		i++;
	} while (gtk_tree_model_iter_next(model, &iter) == TRUE);

out_err:
	if (str) g_free(str);
	if (err < 0) HIP_DEBUG("Didn't find item from combo box: %s\n", name);
	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Delete all items from combo box.

	@param warg Pointer to GtkWidget type combo box.
 */
void delete_all_items_from_cb(GtkWidget *warg)
{
	/* Variables. */
	GtkTreeModel *model;
	GtkTreeIter iter;

	model = gtk_combo_box_get_model(warg);
	if (gtk_tree_model_get_iter_first(model, &iter) == TRUE)
	{
		while (gtk_list_store_remove(model, &iter) != NULL);
	}
}
/* END OF FUNCTION */


/******************************************************************************/
/** Check group name. */
int check_group_name(char *name, HIT_Group *ge)
{
	/* Variables. */
	HIT_Group *g;
	int i, err = 1;
	char *msg = lang_get("ngdlg-err-invalid");
	
	HIP_IFE(name == NULL, 0);
	
	/* Remove whitespaces from start and end. */
	for (i = 0; isspace(name[i]) && i < strlen(name); i++);
	strcpy(name, &name[i]);
	HIP_IFE(strlen(name) < 1, 0);
	for (i = (strlen(name) - 1); isspace(name[i]) && i > 0; i--);
	name[i + 1] = '\0';
	HIP_IFE(strlen(name) < 1, 0);
	
	g = hit_db_find_rgroup(name);
	msg = lang_get("ngdlg-err-exists");
	if (g != ge) HIP_IFE(g, 0);

out_err:
	if (!err)
	{
		GtkDialog *dialog;
		dialog = gtk_message_dialog_new(NULL, GTK_DIALOG_MODAL, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK, msg);
		gtk_window_set_keep_above(dialog, TRUE);
		gtk_widget_show(dialog);
		gtk_dialog_run(dialog);
		gtk_widget_destroy(dialog);
	}
	
	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/** Check hit name. */
int check_hit_name(char *name, HIT_Remote *re)
{
	/* Variables. */
	HIT_Remote *r;
	int i, err = 1;
	char *msg = lang_get("nhdlg-err-invalid");
	
	HIP_IFE(name == NULL, 0);
	
	/* Remove whitespaces from start and end. */
	for (i = 0; isspace(name[i]) && i < strlen(name); i++);
	strcpy(name, &name[i]);
	HIP_IFE(strlen(name) < 1, 0);
	for (i = (strlen(name) - 1); isspace(name[i]) && i > 0; i--);
	name[i + 1] = '\0';
	HIP_IFE(strlen(name) < 1, 0);
	
	r = hit_db_find(name, NULL);
	msg = lang_get("nhdlg-err-exists");
	if (r != re) HIP_IFE(r, 0);

out_err:
	if (!err)
	{
		GtkDialog *dialog;
		dialog = gtk_message_dialog_new(NULL, GTK_DIALOG_MODAL, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK, msg);
		gtk_window_set_keep_above(dialog, TRUE);
		gtk_widget_show(dialog);
		gtk_dialog_run(dialog);
		gtk_widget_destroy(dialog);
	}
	
	return (err);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/

