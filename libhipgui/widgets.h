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
	/* Windows. */
	ID_MAINWND = 0,
	ID_TOOLDLG,
	ID_ACCEPTDLG,
	ID_RUNDLG,
	ID_CREATEDLG,

	/* Main window IDs. */
	ID_RLISTMODEL,
	ID_LLISTMODEL,
	ID_RLISTVIEW,
	ID_LLISTVIEW,
	ID_STATUSBAR,
	ID_TOOLBAR,
	ID_PLISTMODEL,
	ID_PLISTVIEW,
	ID_TERMSCREEN,
	ID_TERMINPUT,
	ID_TERMBUFFER,
	ID_USERVIEW,
	ID_USERMODEL,

	/* Tool dialog IDs. */
	ID_INFOLOCAL,
	ID_INFOREMOTE,
	ID_INFOGROUP,
	ID_TOOLRGROUPS,
	ID_TOOLLHITS,
	
	/* Accept dialog IDs. */
	ID_AD_NEWHIT,
	ID_AD_RGROUPS,
	ID_AD_LHITS,
	ID_AD_NAME,

	/* Run dialog IDs. */
	ID_RUN_COMMAND,
	ID_RUN_LDPRELOAD,
	ID_RUN_LDLIBRARYPATH,

	/* Create dialog IDs. */
	ID_CREATE_NAME,

	WIDGET_IDS_N
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

