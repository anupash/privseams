/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

#ifndef GUI_MAIN_H
#define GUI_MAIN_H

/******************************************************************************/
/* INCLUDES */
#include <gtk/gtk.h>

#include "gui_event.h"


/******************************************************************************/
/* FUNCTION DEFINITIONS */
int gui_init(void);
int gui_main(void);
void gui_quit(void);
void *gui_get_window(void);
void *gui_get_toolwindow(void);
void *gui_get_acceptdialog(void);


#endif /* END OF HEADER FILE */
/******************************************************************************/

