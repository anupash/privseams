/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

#ifndef GUI_CHAT_H
#define GUI_CHAT_H

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
} GUI_CHAT_COMMAND;


/******************************************************************************/
/* FUNCTION DEFINITIONS */
void cmd_help(char *);
void cmd_exec(char *);

void chat_exec_command(char *);
void chat_print(const char *, ...);


#endif /* END OF HEADER FILE */
/******************************************************************************/

