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
#include "./gui/agent_interface.h"


/******************************************************************************/
/* Set up for C function definitions, even when using C++ */
#ifdef __cplusplus
extern "C" {
#endif
/******************************************************************************/


/******************************************************************************/
/* FUNCTION DEFINITIONS */
int gui_init(void);
int gui_check_hit(HIT_Item *);


/******************************************************************************/
/* Ends C function definitions when using C++ */
#ifdef __cplusplus
}
#endif
/******************************************************************************/


#endif /* END OF HEADER FILE */
/******************************************************************************/

