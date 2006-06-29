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


/******************************************************************************/
/* FUNCTION DEFINITIONS */
char *get_nick(void);
void set_nick(char *);
int find_from_cb(char *, GtkWidget *);


#endif /* END OF HEADER FILE */
/******************************************************************************/

