/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

#ifndef GUI_MANAGE_H
#define GUI_MANAGE_H


/******************************************************************************/
/* DEFINES */
enum
{
	ID_RLISTMODEL = 0,
	ID_LLISTMODEL,
	ID_RLISTVIEW,
	ID_LLISTVIEW,
	ID_STATUSBAR,
	ID_INFOLOCAL,
	ID_INFOREMOTE,
	ID_INFOGROUP,
	ID_NEWHIT,

	IDS_N,
};


/******************************************************************************/
/* INCLUDES */
#include "gui_main.h"
#include "hit_db.h"


/******************************************************************************/
/* FUNCTION DEFINITIONS */
int widget_init(void);
void widget_quit(void);
void widget_set(int, void *);
void *widget(int);

void gui_add_hit(char *);
void gui_add_rgroup(char *);
void gui_add_remote_hit(char *, char *);
void gui_remote_hit_callback(GtkWidget *, gpointer);
void gui_clear_remote_hits(void);

void gui_test_func(void);

void gui_terminate(void);

int gui_ask_new_hit(HIT_Item *);

void gui_set_info(const char *, ...);

void info_mode_none(void);
void info_mode_local(void);
void info_mode_remote(void);
void info_mode_rgroup(void);


#endif /* END OF HEADER FILE */
/******************************************************************************/

