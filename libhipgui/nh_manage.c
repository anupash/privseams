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
	Add local HIT to "new hit"-dialog.
	This is a enumeration callback function.
*/
int nh_add_local(HIT_Item *hit, void *p)
{
	gtk_combo_box_append_text(widget(ID_NH_LOCAL), hit->name);
	return (0);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/

