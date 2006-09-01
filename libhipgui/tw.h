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

/*!
	\addtogroup libhipgui
	@{
*/

/******************************************************************************/
/* DEFINES */
enum TOOLWINDOW_MODES
{
	TWMODE_NONE = 0,
	TWMODE_LOCAL,
	TWMODE_REMOTE,
	TWMODE_RGROUP
};


/******************************************************************************/
/* FUNCTION DEFINITIONS */

/* file: tw_create.c */
int tw_create_content(void);
int tw_create_remote(void);
int tw_create_local(void);
int tw_create_rgroup(void);

/* file: tw_manage.c */
void tw_set_mode(int);
void tw_set_remote_info(char *);
void tw_set_remote_rgroup_info(HIT_Group *);
void tw_set_local_info(char *);
void tw_set_rgroup_info(char *);
void tw_apply(void);
void tw_cancel(void);
void tw_delete(void);


/*! @} addtogroup libhipgui */

#endif /* END OF HEADER FILE */
/******************************************************************************/

