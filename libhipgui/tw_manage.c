/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

/******************************************************************************/
/* INCLUDES */
#include "tw.h"


/******************************************************************************/
/* VARIABLES */
/** Current mode for toolwindow. */
int tw_current_mode = -1;


/******************************************************************************/
/* FUNCTIONS */

/******************************************************************************/
/**
	Set tool window mode to no given.
	
	@param mode New mode for toolwindow.
*/
void tw_set_mode(int mode)
{
	/* Variables. */
	GtkWidget *window = widget(ID_TOOLWND);
	
	/* First hide current. */
	switch (tw_current_mode)
	{
		case TWMODE_NONE:
			break;
	
		case TWMODE_LOCAL:
			gtk_container_remove(GTK_CONTAINER(window), widget(ID_TWLOCAL));
			break;
		
		case TWMODE_REMOTE:
			gtk_container_remove(GTK_CONTAINER(window), widget(ID_TWREMOTE));
			break;
	
		case TWMODE_GROUP:
			gtk_container_remove(GTK_CONTAINER(window), widget(ID_TWRGROUP));
			break;
	}
	
	/* Then show selected mode. */
	switch (mode)
	{
	case TWMODE_NONE:
		break;
	
	case TWMODE_LOCAL:
		gtk_container_add(GTK_CONTAINER(window), widget(ID_TWLOCAL));
		gtk_widget_show(widget(ID_TWLOCAL));
		break;
		
	case TWMODE_REMOTE:
		gtk_container_add(GTK_CONTAINER(window), widget(ID_TWREMOTE));
		gtk_widget_show(widget(ID_TWREMOTE));
		break;
	
	case TWMODE_GROUP:
		gtk_container_add(GTK_CONTAINER(window), widget(ID_TWRGROUP));
		gtk_widget_show(widget(ID_TWRGROUP));
		break;
	}
	
	tw_current_mode = mode;
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Set remote HIT info to toolwindow from HIT with given name.
	
	@param hit_name Name of remote HIT.
 */
void tw_set_remote_info(char *hit_name)
{
	/* Variables. */
	GtkWidget *w;
	HIT_Item *hit;
	char str[320];
	
	hit = hit_db_search(NULL, hit_name, NULL, NULL, NULL,
	                    0, HIT_DB_TYPE_ALL, 1, 0);
	
	if (hit)
	{
		gtk_entry_set_text(widget(ID_TWR_NAME), hit->name);
		gtk_entry_set_text(widget(ID_TWR_URL), hit->url);
		sprintf(str, "%d", hit->port);
		gtk_entry_set_text(widget(ID_TWR_PORT), str);
		
		free(hit);
	}
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Add remote group to combo box.
	This is mostly used as enumeration callback function.
	
	@param group Pointer to HIT_Group struct.
	@param p Pointer to combo box widget.
*/
int tw_add_rgroup(HIT_Group *group, void *p)
{
	/* Variables. */
	GtkWidget *w = (GtkWidget *)p;
	
//	HIP_DEBUG("Appending new remote group \"%s\" to tool window list.\n", group->name);
	gtk_combo_box_insert_text(w, 0, group->name);
	
	return (0);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Add local HITs to tool dialog.
	This is a enumeration callback function.
*/
int tooldlg_add_lhits(HIT_Item *hit, void *p)
{
	/* Variables. */
	GtkWidget *w = (GtkWidget *)p;

//	HIP_DEBUG("Appending new local HIT \"%s\" to tool window list.\n", hit->name);
	gtk_combo_box_append_text(w, hit->name);

	return (0);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/

