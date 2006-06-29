/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

#ifndef GUI_EXEC_H
#define GUI_EXEC_H

/******************************************************************************/
/* INCLUDES */
#include <sys/wait.h>
#include <unistd.h>
#include <gtk/gtk.h>
#include "main.h"


/******************************************************************************/
/* DEFINE */
/**
	This determines how many process IDs can be stored for executed
	applications. This execute-feature is mostly used for debug purposes,
	so it is best to make the maximum process count to be static becose
	of memory handling.
*/
#define MAX_EXEC_PIDS	32


/******************************************************************************/
/* FUNCTION DEFINITIONS */
int exec_init(void);
void exec_quit(void);
void exec_application(void);
int exec_empty_pid(void);
void *exec_timer_thread(void *);


#endif /* END OF HEADER FILE */
/******************************************************************************/

