/*
    HIP Agent
*/

/******************************************************************************/
/* INCLUDES */
#include "agent_tools.h"


/******************************************************************************/
/* VARIABLES */
/** This determines whether agent is executing or not. */
int agent_exec_state = 1;


/******************************************************************************/
/* FUNCTIONS */

/******************************************************************************/
/**
	Check whether agent should be executing or not.

	@return 1 if executing, 0 if not.
*/
int agent_exec(void)
{
	/* Return. */
	return (agent_exec_state);
}
/* END OF FUNCTION */

/******************************************************************************/
/**
	Stop and exit agent.
*/
void agent_exit(void)
{
	agent_exec_state = 0;
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Prints given hit to buffer as text.
*/
void print_hit_to_buffer(char *buffer, struct in6_addr *hit)
{
	int n, b;
	
	buffer[0] ='\0';
	b = 0;
	
	for (n = 0; n < 16; n++)
	{
		sprintf(&buffer[b], "%02x", (int)hit->s6_addr[n]);
		b += 2;

		if ((n % 2) == 1 && n > 0 && n < 15)
		{
			strcat(buffer, ":");
			b++;
		}
	}
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/

