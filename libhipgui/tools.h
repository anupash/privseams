/*
    DNET - Duge's Networking Library

    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

#ifndef TOOLS_H
#define TOOLS_H

/******************************************************************************/
/* INCLUDES */
#include <stdlib.h>
#include <gtk/gtk.h>

#include "debug.h"
#include "hit_db.h"

/*!
	\addtogroup libhipgui
	@{
*/

/******************************************************************************/
/* FUNCTION DEFINITIONS */
char *get_nick(void);
void set_nick(char *);
int find_from_cb(char *, GtkWidget *);
void delete_all_items_from_cb(GtkWidget *);
int check_name_input(char *);


/*! @} addtogroup libhipgui */

#endif /* END OF HEADER FILE */
/******************************************************************************/

