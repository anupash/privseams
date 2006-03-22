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
	signal(SIGINT, sig_catch_int);
	HIP_DEBUG("SIGINT (CTRL-C) caught, exiting agent...\n");
	agent_exit();
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	main().
*/
int main(int argc, char *argv[])
{
	/* Variables. */
	int err = 0;

	/* Set signalling. */
	signal(SIGINT, sig_catch_int);

	/* Initialize GUI. */
	HIP_IFE(gui_init(), -1);

	/* Initialize database. */
	HIP_IFE(hit_db_init("/etc/hip/agentdb"), -1);

	/* Initialize connection to HIP daemon. */
#ifndef CONFIG_HIP_DEBUG
	HIP_IFE(connhipd_init(), -1);
#else
	/* If in debug mode, don't care about failed connection to HIP daemon. */
	connhipd_init();
#endif

	gui_main();
	agent_exit();

out_err:
	gui_terminate();
	connhipd_quit();
	hit_db_quit("/etc/hip/agentdb");
	
	return err;
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/

