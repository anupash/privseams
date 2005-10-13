/*
    HIP Agent
*/

#ifndef INTERFACE_H
#define INTERFACE_H

/******************************************************************************/
/* INCLUDES */
#ifdef __cplusplus
#include "hipgui.h"
#endif


/******************************************************************************/
/* Set up for C function definitions, even when using C++ */
#ifdef __cplusplus
extern "C" {
#endif
/******************************************************************************/


/******************************************************************************/
/* FUNCTION DEFINITIONS */
int gui_init_interface(void);
int gui_ask_hit_accept(char *);


/******************************************************************************/
/* Ends C function definitions when using C++ */
#ifdef __cplusplus
}
#endif
/******************************************************************************/


#endif /* END OF HEADER FILE */
/******************************************************************************/

