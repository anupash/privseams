/*
    HIP Agent
*/

#ifndef AGENT_TOOLS_H
#define AGENT_TOOLS_H

/******************************************************************************/
/* INCLUDES */
#include <socket.h>
#include <sys/types.h>

#include "hip.h"


/******************************************************************************/
/* Set up for C function definitions, even when using C++ */
#ifdef __cplusplus
extern "C" {
#endif
/******************************************************************************/


/******************************************************************************/
/* FUNCTION DEFINITIONS */
int agent_exec(void);
void agent_exit(void);

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

