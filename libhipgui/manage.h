/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

#ifndef GUI_MANAGE_H
#define GUI_MANAGE_H


/******************************************************************************/
/* INCLUDES */
#include "main.h"
#include "hit_db.h"
#include "widgets.h"


/******************************************************************************/
/* FUNCTION DEFINITIONS */
void gui_add_hit(char *);
void gui_add_rgroup(HIT_Group *);
void gui_add_remote_hit(char *, char *);
void gui_add_process(int, char *, int, int);
void gui_remote_hit_callback(GtkWidget *, gpointer);
void gui_clear_remote_hits(void);

void gui_test_func(void);

void gui_terminate(void);

int gui_ask_new_hit(HIT_Item *);

void gui_set_info(const char *, ...);

int tooldlg_add_rgroups(HIT_Group *, void *);
int tooldlg_add_lhits(HIT_Item *, void *);
int askdlg_add_rgroups(HIT_Group *, void *);
int askdlg_add_lhits(HIT_Item *, void *);

void info_mode_none(void);
void info_mode_local(void);
void info_mode_remote(void);
void info_mode_rgroup(void);

char *create_remote_group(void);


#endif /* END OF HEADER FILE */
/******************************************************************************/

