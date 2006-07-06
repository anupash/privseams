/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
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


/******************************************************************************/
/**
	Read hit from text buffer as hit.
*/
void read_hit_from_buffer(struct in6_addr *hit, char *buffer)
{
	int n, i;
	int v[8];
	
	memset(v, 0, sizeof(int) * 8);

	sscanf(buffer, "%x:%x:%x:%x:%x:%x:%x:%x",
	       &v[7], &v[6], &v[5], &v[4],
	       &v[3], &v[2], &v[1], &v[0]);
	
	n = 0;
	for (i = 7; i >= 0; i--)
	{
		hit->s6_addr[n + 1] = v[i] & 0xff;
		hit->s6_addr[n] = (v[i] >> 8) & 0xff;
		n += 2;
	}
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/

