/*
    HIP Agent
*/

/******************************************************************************/
/* INCLUDES */
#include "agent.h"


/******************************************************************************/
/**
	main().
*/
#ifdef CONFIG_HIPGUI_COMMANDLINE
int main(int argc, char *argv[])
{
#else
int agent_main(void)
{
#endif
	/* Variables. */
	int err = 0;

	/* Initialize database. */
	HIP_IFE(hit_db_init(), -1);

	/* Initialize connection to HIP daemon. */
	HIP_IFE(connhipd_init(), -1);

#ifdef CONFIG_HIPGUI_COMMANDLINE
	/* Initialize GUI. */
//	HIP_IFE(gui_init(), -1);

	/* Wait for agent quit message. */
	while (agent_exec())
	{
		/* Maybe do something... */
		
		/* Wait a little, dont waste all cpu here. */
		sleep(100);
	}
#endif

	return (0);

out_err:
//	connhipd_quit();
//	hit_db_quit();
//	gui_quit();
	
	return err;
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/

