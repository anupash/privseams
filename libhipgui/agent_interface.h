/*
    HIP GUI
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
             Matti Saarinen
*/

#ifndef AGENT_INTERFACE_H
#define AGENT_INTERFACE_H

/******************************************************************************/
/* INCLUDES */
#include "hit_db.h"

//#include <socket.h>
#include <sys/types.h>

#ifdef __cplusplus
#include "hipagent.h"
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
void gui_quit_interface(void);

int gui_ask_hit_accept(char *, char *);
void gui_add_new_hit(HIT_Item *);
void gui_ask_new_hit_timer(void *);


/* "Extern" function from agent code, file: agent_tools.c. */
void print_hit_to_buffer(char *, struct in6_addr *);
void read_hit_from_buffer(struct in6_addr *, char *);


/******************************************************************************/
/* Ends C function definitions when using C++ */
#ifdef __cplusplus
}
#endif
/******************************************************************************/


#endif /* END OF HEADER FILE */
/******************************************************************************/

