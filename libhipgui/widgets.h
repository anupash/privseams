/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

#ifndef GUI_WIDGETS_H
#define GUI_WIDGETS_H


/******************************************************************************/
/* DEFINES */
enum WIDGET_IDS
{
	ID_RLISTMODEL = 0,
	ID_LLISTMODEL,
	ID_RLISTVIEW,
	ID_LLISTVIEW,
	ID_STATUSBAR,

	/* Tool dialog IDs. */
	ID_INFOLOCAL,
	ID_INFOREMOTE,
	ID_INFOGROUP,
	ID_TOOLRGROUPS,
	ID_TOOLLHITS,
	
	/* Accept dialog IDs. */
	ID_AD_NEWHIT,
	ID_AD_GROUP,
	ID_AD_LHIT,

	IDS_N,
};


/******************************************************************************/
/* INCLUDES */
#include <stdlib.h>
#include <string.h>
#include <gtk/gtk.h>
#include "debug.h"


/******************************************************************************/
/* FUNCTION DEFINITIONS */
int widget_init(void);
void widget_quit(void);
void widget_set(int, void *);
void *widget(int);


#endif /* END OF HEADER FILE */
/******************************************************************************/

