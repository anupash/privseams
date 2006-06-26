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
	ID_TOOLWND,
	ID_ACCEPTDLG,
	ID_EXECDLG,
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
	ID_TB_TW,

	/* Tool dialog IDs. */
	ID_TWLOCAL,
	ID_TWREMOTE,
	ID_TWRGROUP,
	ID_TWR_NAME,
	ID_TWR_URL,
	ID_TWR_PORT,
	ID_TWR_TYPE1,
	ID_TWR_TYPE2,
	ID_TWR_LOCAL,
	ID_TWR_RGROUP,
	
	/* New hit dialog IDs. */
	ID_NH_NEWHIT,
	ID_NH_RGROUP,
	ID_NH_LOCAL,
	ID_NH_NAME,

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

