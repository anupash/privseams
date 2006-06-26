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

	/* Set some random seed. */
	srand(time(NULL));

	/* Set signalling. */
	signal(SIGINT, sig_catch_int);

	/* Initialize GUI. */
	HIP_IFEL(gui_init(), -1, "Failed to initialize GUI!\n");

	/* Initialize database. */
	HIP_IFEL(hit_db_init("/etc/hip/agentdb"), -1, "Failed to load agent database!\n");

	/* Initialize connection to HIP daemon. */
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

	gui_main();
	agent_exit();

out_err:
	gui_terminate();
	connhipd_quit();
	hit_db_quit("/etc/hip/agentdb");
	
	return (err);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/

