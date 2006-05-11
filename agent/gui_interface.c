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
	
	/*
	  First search database. Do search twice,
	  if first find did not find match. On second search swap
	  hits, because we can not know whether this packet is outgoing
	  or incoming.
	*/
	fhit = hit_db_search(&ndx, NULL, &hit->lhit, &hit->rhit,
	                     hit->url, hit->port, 1, 1);
	if (!fhit)
	{
		memcpy(&temp_hit, &hit->lhit, sizeof(struct in6_addr));
		memcpy(&hit->lhit, &hit->rhit, sizeof(struct in6_addr));
		memcpy(&hit->rhit, &temp_hit, sizeof(struct in6_addr));
		fhit = hit_db_search(&ndx, NULL, &hit->lhit, &hit->rhit,
		                     hit->url, hit->port, 1, 1);
	}

	if (fhit)
	{
		HIP_DEBUG("Found HIT from database with type \"%s\".\n",
		          ((fhit->type == HIT_DB_TYPE_ACCEPT) ? "accept" : "deny"));

		if (fhit->type == HIT_DB_TYPE_ACCEPT)
		{
			err = 0;
		}
		else
		{
			err = -1;
		}
		
		free(fhit);

		goto out_err;
	}
	else
	{
		HIP_DEBUG("Did not find HIT from database.\n");
	}

	/* If not found, ask user. */
	print_hit_to_buffer(hits, &hit->lhit);
	print_hit_to_buffer(hitr, &hit->rhit);
	
	fprintf(stdout, "New HIT received, accept or not (y or n)?\n"
	        " sender hit: %s\n receiver hit: %s\n", hits, hitr);

#ifdef CONFIG_HIPGUI_COMMANDLINE

	while (1)
	{
		char input[32];
	
		fgets(input, 32, stdin);

		if (input[0] == 'y')
		{
			err = 0;
			break;
		}
		else if (input[0] == 'n')
		{
			err = -1;
			break;
		}
		
		fprintf(stdout, "Please, answer y or n...\n");
	}
#else
	HIP_DEBUG("Calling GUI for accepting new HIT.\n");
/*	sprintf(msg, "New HIT received, accept?\n"
	        " sender hit: %s\n receiver hit: %s", hits, hitr);*/
	err = gui_ask_new_hit(hit);
	//err = 0;
#endif

	/* Add hit info to database, if answer was yes. */
	if (err == 1)
	{
		HIP_DEBUG("Adding new remote HIT to database with type accept.\n");
	}
	if (err == 0)
	{
		HIP_DEBUG("Adding new remote HIT to database with type deny.\n");
	}

	hit_db_add(hit->name, &hit->lhit, &hit->rhit, hit->url, hit->port,
	           hit->type, hit->group, hit->lightweight, 0);


out_err:
	/* Return. */
	return (err);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/

