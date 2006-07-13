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


/* END OF SOURCE FILE */
/******************************************************************************/

