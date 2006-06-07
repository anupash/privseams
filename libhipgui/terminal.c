/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

/******************************************************************************/
/* INCLUDES */
#include "terminal.h"


/******************************************************************************/
/* GLOBALS */
/* Command list. */
TERMINAL_COMMAND cmds[] =
{
	{ "help", cmd_help },
	{ "exec", cmd_exec },
	{ 0, 0 }
};


/******************************************************************************/
/* FUNCTIONS */

/******************************************************************************/
/** Help-command. */
void cmd_help(char *x)
{
	term_print("\n"
	           "* HIP GUI chat help:\n"
	           "*  help         - Prints this help.\n"
	           "*  exec         - Show application execute dialog.\n"
	           "\n");
}
/* END OF FUNCTION */


/******************************************************************************/
/** Exec-command. */
void cmd_exec(char *x)
{
	exec_application();
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Execute command.
*/
void term_exec_command(char *cmd)
{
	/* Variables. */
	int i;
	int k;
	char b = 0;
	
	/* Check empty command. */
	if (strlen(cmd) < 1)
	{
		return;
	}
	
	/* Find space. */
	for (k = 0;
	     cmd[k] != '\0' && cmd[k] != ' ';
	     k++);

	cmd[k] = '\0';
	k++;
			
	/* Compare commands. */
	for (i = 0; cmds[i].func != 0; i++)
	{
		if (strcmp(cmd, cmds[i].cmd) == 0)
		{
			cmds[i].func(&cmd[k]);
			b = 1;
			break;
		}
	}
	
	/* If command not found. */
	if (!b)
	{
		term_print("* Invalid command.\n");
	}
	
	/* Return. */
	return;
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Print string to terminal. Use like printf().
*/
void term_print(const char *string, ...)
{
	/* Variables. */
	va_list args;
	char str[1024];

	/* Get args. */
	va_start(args, string);

	/* Print to terminal. */
	vsprintf(str, string, args);
	gtk_text_buffer_insert_at_cursor(widget(ID_TERMBUFFER), str, -1);
	
	/* End args. */
	va_end(args);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/

