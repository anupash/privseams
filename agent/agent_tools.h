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
/* FUNCTION DEFINITIONS */
int agent_exec(void);
void agent_exit(void);

void print_hit_to_buffer(char *, struct in6_addr *);


#endif /* END OF HEADER FILE */
/******************************************************************************/

