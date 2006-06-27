/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

/******************************************************************************/
/* INCLUDES */
#include "gui_interface.h"


/******************************************************************************/
/* FUNCTIONS */

/******************************************************************************/
/**
	Ask GUI, if new hit should be accepted and added.

	@param hit Pointer to hit that should be accepted.
	@return 0 if accept, -1 on other cases.
*/
int check_hit(HIT_Item *hit)
{
	/* Variables. */
	HIT_Item *fhit = NULL;
	struct in6_addr temp_hit;
	int err = 0, ndx;
	char hits[128], hitr[128], msg[1024];
	
	fhit = hit_db_search(&ndx, NULL, &hit->hit, hit->url, hit->port, NULL, 1, 1);

	if (fhit)
	{
		HIP_DEBUG("Found HIT from database.\n");

		err = 0;
		
		free(fhit);

		goto out_err;
	}
	else
	{
		HIP_DEBUG("Did not find HIT from database.\n");
	}
	
	fprintf(stdout, "New HIT received, accept or not (y or n)?\n");
	
	HIP_DEBUG("Calling GUI for accepting new HIT.\n");
	err = gui_ask_new_hit(hit);

	/* Add hit info to database, if answer was yes. */
	if (err == 1)
	{
		HIP_DEBUG("Adding new remote HIT to database with type accept.\n");
	}
	if (err == 0)
	{
		HIP_DEBUG("Adding new remote HIT to database with type deny.\n");
	}

	hit_db_add(hit->name, &hit->hit, hit->url, hit->port, hit->group, 0);

out_err:
	/* Return. */
	return (err);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/

