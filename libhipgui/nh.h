/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

#ifndef GUI_NH_H
#define GUI_NH_H

/******************************************************************************/
/* INCLUDES */
#include <gtk/gtk.h>

#include "events.h"
#include "widgets.h"


/******************************************************************************/
/* FUNCTION DEFINITIONS */

/* file: nh_create.c */
int nhdlg_create_content(void);

/* file: nh_manage.c */
int nh_add_local(HIT_Item *, void *);


#endif /* END OF HEADER FILE */
/******************************************************************************/

