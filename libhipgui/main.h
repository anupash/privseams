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

#include "events.h"
#include "nh.h"
#include "tw.h"
#include "widgets.h"
#include "str_var.h"
#include "language.h"
#include "rhit_dnd.h"


/*!
	\addtogroup libhipgui
	@{
*/

/******************************************************************************/
/* FUNCTION DEFINITIONS */

/* file: main.c */
int gui_init(void);
int gui_main(void);
void gui_quit(void);
void gui_set_info(const char *, ...);
void gui_terminate(void);

/* file: main_create.c */
int main_create_content(void);


/*! @} addtogroup libhipgui */

#endif /* END OF HEADER FILE */
/******************************************************************************/

