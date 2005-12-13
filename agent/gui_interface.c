/*
    HIP Agent
*/

/******************************************************************************/
/* INCLUDES */
#include "gui_interface.h"


/******************************************************************************/
/* FUNCTIONS */

/******************************************************************************/
/**
	Initialize HIP GUI.
	
	@return 0 on success, -1 on errors.
*/
int gui_init(void)
{
	int err = 0;
	
#ifndef CONFIG_HIPGUI_COMMANDLINE
	HIP_DEBUG("Initializing GUI...\n");
	if (gui_init_interface()) goto out_err;
	HIP_DEBUG("GUI inialized succesfully...\n");
#endif
		
	return (0);
	
out_err:
	
	return (-1);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Ask GUI, if new hit should be accepted and added.

	@param hit Pointer to hit that should be accepted.
	@return 0 if accept, -1 on other cases.
*/
int gui_check_hit(HIT_Item *hit)
{
	/* Variables. */
	HIT_Item *fhit = NULL;
	int err = 0, ndx;
	char hits[128], hitr[128], msg[1024];
	
	/*
	  First search database. Do search twice,
	  if first find did not find match. On second search swap
	  hits, because we can not know whether this packet is outgoing
	  or incoming.
	*/
	fhit = hit_db_search(&ndx, NULL, &hit->lhit, &hit->rhit,
	                   hit->url, hit->port, 1);
	if (!fhit) fhit= hit_db_search(&ndx, NULL, &hit->rhit, &hit->lhit,
				     hit->url, hit->port, 1);
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
		
		goto out;
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
/* XX TODO: Call the real GUI here. */
	HIP_DEBUG("Calling GUI for accepting new HIT.\n");
	sprintf(msg, "New HIT received, accept?\n"
	        " sender hit: %s\n receiver hit: %s", hits, hitr);
	err = gui_ask_hit_accept("Accept new HIT?", msg);
#endif

	/* Add hit info to database, if answer was yes. */
	if (err == 0)
	{
		HIP_DEBUG("Adding new HIT to database with type accept.\n");
		hit_db_add(hit->name, &hit->lhit, &hit->rhit, hit->url, hit->port,
		           HIT_DB_TYPE_ACCEPT);
	}
	if (err == -1)
	{
		HIP_DEBUG("Adding new HIT to database with type deny.\n");
		hit_db_add(hit->name, &hit->lhit, &hit->rhit, hit->url, hit->port,
		           HIT_DB_TYPE_DENY);
	}


out:
	/* Return. */
	return (err);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/

