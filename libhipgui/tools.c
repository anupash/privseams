/*
    DNET - Duge's Networking Library

    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

/******************************************************************************/
/* INCLUDES */
#include "tools.h"


/******************************************************************************/
/* VARIABLES */
char nickname[32 + 1];


/******************************************************************************/
/* FUNCTIONS */

/******************************************************************************/
/** Get current nickname. */
char *get_nick(void)
{
	return (nickname);
}
/* END OF FUNCTION */


/******************************************************************************/
/** Set current nickname. */
void set_nick(char *newnick)
{
	strncpy(nickname, newnick, 32);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/

