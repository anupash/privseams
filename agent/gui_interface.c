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
	Ask GUI, if new hit should be accepted and added.

	@param hit Pointer to hit that should be accepted.
	@return 0 if accept, -1 on other cases.
*/
int gui_new_hit(HIT_Item *hit)
{
	/* Variables. */
	HIT_Item *fhit = NULL;
	int err = 0, ndx;
	char hits[128], hitr[128];
	
	/* First check for database and this hit. */
	fhit = hit_db_find(&ndx, NULL, NULL, &hit->rhit, NULL, 0);
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
#ifdef CONFIG_HIPGUI_COMMANDLINE
	print_hit_to_buffer(hits, &hit->lhit);
	print_hit_to_buffer(hitr, &hit->rhit);
	
	fprintf(stdout, "New HIT received, accept or not (y or n)?\n"
	        " sender hit: %s\n receiver hit: %s\n", hits, hitr);

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
#endif

	/* Add hit info to database, if answer was yes. */
	if (err == 0)
	{
		HIP_DEBUG("Adding new HIT to database with type accept.\n");
		hit_db_add("test", &hit->lhit, &hit->rhit, "yes", 0,
		           HIT_DB_TYPE_ACCEPT);
	}
	if (err == -1)
	{
		HIP_DEBUG("Adding new HIT to database with type deny.\n");
		hit_db_add("test", &hit->lhit, &hit->rhit, "no", 0,
		           HIT_DB_TYPE_DENY);
	}


out:
	/* Return. */
	return (err);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/

