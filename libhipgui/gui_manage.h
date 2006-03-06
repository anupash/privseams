/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

#ifndef GUI_MANAGE_H
#define GUI_MANAGE_H

/******************************************************************************/
/* INCLUDES */
#include "gui_main.h"


/******************************************************************************/
/* FUNCTION DEFINITIONS */
int gui_create_content(void);
void gui_add_hit(char *);
void gui_add_remote_hit(char *, char *, int);
void gui_remote_hit_callback(GtkWidget *, gpointer);
void gui_clear_remote_hits(void);

void gui_test_func(void);

void gui_new_text_entry(char *, char *, GtkWidget *, int, int, int, int, int);
void gui_new_button(char *, char *, GtkWidget *, int, int, int, int, int,
                    void (*)(GtkWidget *, gpointer), int);
void gui_set_entry_fill_flag(int fill);

void gui_terminate(void);


#endif /* END OF HEADER FILE */
/******************************************************************************/

