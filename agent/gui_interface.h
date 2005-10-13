/*
    HIP Agent
*/

#ifndef GUI_INTERFACE_H
#define GUI_INTERFACE_H

/******************************************************************************/
/* INCLUDES */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hit_db.h"
#include "./gui/interface.h"


/******************************************************************************/
/* FUNCTION DEFINITIONS */
int gui_init(void);
int gui_check_hit(HIT_Item *);


#endif /* END OF HEADER FILE */
/******************************************************************************/

