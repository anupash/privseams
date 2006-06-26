/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

#ifndef GUI_TW_H
#define GUI_TW_H

/******************************************************************************/
/* INCLUDES */
#include <gtk/gtk.h>

#include "events.h"
#include "widgets.h"


/******************************************************************************/
/* DEFINES */
enum TOOLWINDOW_MODES
{
	TWMODE_NONE = 0,
	TWMODE_LOCAL,
	TWMODE_REMOTE,
	TWMODE_GROUP
};


/******************************************************************************/
/* FUNCTION DEFINITIONS */

/* file: tw_create.c */
int tw_create_content(void);

/* file: tw_manage.c */
void tw_set_mode(int);
void tw_set_remote_info(char *);


#endif /* END OF HEADER FILE */
/******************************************************************************/

