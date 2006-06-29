/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

#ifndef GUI_TERMINAL_H
#define GUI_TERMINAL_H

/******************************************************************************/
/* INCLUDES */
#include "exec.h"
#include "tools.h"

/******************************************************************************/
/* STRUCTS */
/** Command struct. */
typedef struct
{
	char *cmd;
	void (*func)(char *);
} TERMINAL_COMMAND;


/******************************************************************************/
/* FUNCTION DEFINITIONS */
void cmd_help(char *);
void cmd_exec(char *);

void term_exec_command(char *);
void term_print(const char *, ...);


#endif /* END OF HEADER FILE */
/******************************************************************************/

