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

int gui_ask_new_hit(HIT_Item *);

int tooldlg_add_rgroups(HIT_Group *, void *);
int tooldlg_add_lhits(HIT_Item *, void *);
int askdlg_add_rgroups(HIT_Group *, void *);
int askdlg_add_lhits(HIT_Item *, void *);

char *create_remote_group(void);


#endif /* END OF HEADER FILE */
/******************************************************************************/

