/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

/******************************************************************************/
/* INCLUDES */
#include "agent.h"


/******************************************************************************/
/** Catch SIGINT. */
void sig_catch_int(int signum)
{
	static int force_exit = 0;
	
	signal(SIGINT, sig_catch_int);
	agent_exit();
	if (force_exit < 1) HIP_DEBUG("SIGINT (CTRL-C) caught, exiting agent...\n");
	else if (force_exit < 2) HIP_DEBUG("SIGINT (CTRL-C) caught, still once to terminate brutally.\n");
	else
	{
		HIP_DEBUG("SIGINT (CTRL-C) caught, terminating!\n");
		exit(1);
	}

	force_exit++;
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	main().
*/
int main(int argn, char *argv[])
{
	/* Variables. */
	int err = 0;
	char db_path[1024];

	/* Create database path. */
	sprintf(db_path, "%s/%s", getenv("HOME"), ".hipagentdb");

	/* Check command line options. */
	term_set_mode(TERM_MODE_NONE);
	err = -1;
	if (argn == 2)
	{
		if (argv[1][0] == '-')
		{
			if (argv[1][1] == 's')
			{
				term_set_mode(TERM_MODE_SERVER);
				err = 0;
			}
		}
	}
	if (argn == 3)
	{
		if (argv[1][0] == '-')
		{
			if (argv[1][1] == 'c')
			{
				term_set_mode(TERM_MODE_CLIENT);
				term_set_server_addr(argv[2]);
				err = 0;
			}
		}
	}
	if (argn == 1) err = 0;

	HIP_IFEL(err, -1, "Invalid command line parameters.\n");

	/* Set some random seed. */
	srand(time(NULL));

	/* Set signalling. */
	signal(SIGINT, sig_catch_int);

	/* Initialize GUI. */
	HIP_DEBUG("##### 1. Initializing GUI...\n");
	HIP_IFEL(gui_init(), -1, "Failed to initialize GUI!\n");

	/* Initialize database. */
	HIP_DEBUG("##### 2. Initializing database...\n");
	HIP_IFEL(hit_db_init(db_path), -1, "Failed to load agent database!\n");

	/* Initialize connection to HIP daemon. */
	HIP_DEBUG("##### 3. Initializing connection to HIP daemon...\n");
#ifndef CONFIG_HIP_DEBUG
	HIP_IFEL(connhipd_init(), -1, "Failed to open connection to HIP daemon!\n");
#else
	/*
		If in debug mode, try to execute daemon from GUI,
		if connection to daemon fails.
	*/
	err = connhipd_init();
	
	/*
		If connection to daemon failed, assume that daemon
		is not running and try to fork it.
	*/
	if (err != 0 && 0)
	{
		err = fork();
		
		if (err < 0) HIP_DEBUG("fork() failed!\n");
		else if (err > 0)
		{
			/* Wait for daemon to start. */
			sleep(2);
			/* Initialize connection to HIP daemon. */
			err = connhipd_init();
		}
		else if(err == 0)
		{
			err = execlp("./hipd/hipd", "", (char *)0);
			if (err != 0)
			{
				HIP_DEBUG("Executing HIP daemon failed!\n");
				exit(1);
			}
		}
	}

#endif

	HIP_DEBUG("##### 4. Executing GUI main.\n");
	gui_main();

	agent_exit();

out_err:
	gui_terminate();
	connhipd_quit();
	hit_db_quit(db_path);

	HIP_DEBUG("##### X. Exiting application...\n");
	return (err);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/

