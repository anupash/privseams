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
	ID_NHDLG,
	ID_EXECDLG,
	ID_NGDLG,

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
	ID_TW_CONTAINER,
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
	ID_TWR_REMOTE,
	ID_TWG_NAME,
	ID_TWG_LOCAL,
	ID_TWG_TYPE1,
	ID_TWG_TYPE2,
	ID_TWG_LW,
	ID_TWL_NAME,
	ID_TWL_LOCAL,
	ID_TW_APPLY,
	ID_TW_CANCEL,
	ID_TW_DELETE,

	/* New hit dialog IDs. */
	ID_NH_HIT,
	ID_NH_RGROUP,
	ID_NH_NAME,
	ID_NH_URL,
	ID_NH_PORT,

	/* Run dialog IDs. */
	ID_RUN_COMMAND,
	ID_RUN_LDPRELOAD,
	ID_RUN_LDLIBRARYPATH,

	/* New group dialog IDs. */
	ID_NG_NAME,
	ID_NG_LOCAL,
	ID_NG_TYPE1,
	ID_NG_TYPE2,

	/* IDs for hipstart. */
	ID_HS_MAIN,
	ID_HS_MODEL,
	ID_HS_VIEW,
	ID_HS_EXECAGENT,
	ID_HS_CLEARDB,

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

