/*
    HIP Agent
*/

/******************************************************************************/
/* INCLUDES */

/* STANDARD */
#include <stdlib.h>

/* THIS */
#include "hit_db.h"


/******************************************************************************/
/* DEFINES */
/**
	Define minimum amount of allocated space for database items and amount
	of memory allocated more, when not enough space for new items.
*/
#define HIT_DB_ITEMS_REALLOC			8

#define HIT_DB_LOCK() { while (hit_db_lock); hit_db_lock = 1; }
#define HIT_DB_UNLOCK() { hit_db_lock = 0; }


/******************************************************************************/
/* VARIABLES */
/** All HIT-data in the database is stored in here. */
HIT_Item *hit_db = NULL;
/** Counts items in database. */
int hit_db_n = 0;
/** Counts amount of allocated items. */
int hit_db_ni = 0;

/** Almost atomic lock. */
int hit_db_lock = 1;


/******************************************************************************/
/* FUNCTIONS */

/******************************************************************************/
/**
	Initialize HIP agent HIT database. This function must be called before
	using database at all.
	
	@return 0 on success, -1 on errors.
*/
int hit_db_init(void)
{
	/* Variables. */
	int err = 0;
	
	/* Lock just for sure. */
	hit_db_lock = 1;
	
	/* Allocate minimum space for HI's and reset all data. */
	hit_db = (HIT_Item *)malloc(sizeof(HIT_Item) * HIT_DB_ITEMS_REALLOC);
	if (!hit_db) goto out_err;

	memset(hit_db, 0, sizeof(HIT_Item) * HIT_DB_ITEMS_REALLOC);
	hit_db_ni = HIT_DB_ITEMS_REALLOC;
	hit_db_n = 0;

	hit_db_lock = 0;
	goto out;

	/* Return failure. */
out_err:
	if (hit_db)
	{
		free(hit_db);
		hit_db = NULL;
		hit_db_ni = 0;
		hit_db_n = 0;
	}
	err = -1;
out:
	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Deinitialize HIP agent HIT database. This function must be called when
	closing application and stopping using database.
*/
void hit_db_quit(void)
{
	/* Lock just for sure. */
	hit_db_lock = 1;
	
	if (hit_db)
	{
		free(hit_db);
		hit_db = NULL;
		hit_db_ni = 0;
		hit_db_n = 0;
	}
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Adds new HIT to database.
*/
int hit_db_add_hit(HIT_Item *hit)
{
	return (hit_db_add(hit->name, &hit->lhit, &hit->rhit,
	                   hit->url, hit->port, hit->type));
}
/* END OF FUNCTION */

	
/******************************************************************************/
/**
	Adds new HIT to database.
	
	@param name 'Human' identifier for this item: it's name.
	@param hit HIT of this item.
	@param url URL, which is connected to this item, can be NULL.
	@param port Port, which is connected to this item, can be 0 if not needed.
	@param type HIT type, accept or deny.

	@return 0 on success, -1 on errors.
*/
int hit_db_add(char *name,
               struct in6_addr *lhit,
               struct in6_addr *rhit,
               char *url,
               int port,
               int type)
{
	/* Variables. */
	int n, err = 0;

	HIT_DB_LOCK();

	/* If there is no space for new item, allocate more space. */
	if (hit_db_n >= hit_db_ni)
	{
		n = HIT_DB_ITEMS_REALLOC + hit_db_ni;
		hit_db = (HIT_Item *)realloc(hit_db, sizeof(HIT_Item) * n);
		if (!hit_db) goto out_err;
	}

	hit_db_ni = n;

	/* Copy info. */
	n = hit_db_n;
	strncpy(hit_db[n].name, name, 48);
	hit_db[n].name[48] = '\0';
	memcpy(&hit_db[n].lhit, lhit, sizeof(struct in6_addr));
	memcpy(&hit_db[n].rhit, rhit, sizeof(struct in6_addr));
	hit_db[n].port = port;
	hit_db[n].type = type;
	hit_db[n].index = n;
	strcpy(hit_db[n].url, url);

/* XX TODO: Copy url too someday: hi_db[n].url */
	HIP_DEBUG("Calling GUI to show new HIT...");
	gui_add_new_hit(&hit_db[n]);
	HIP_DEBUG(" Add succesfull.\n");

	hit_db_n++; /* Count to next free item. */
	
	goto out;

	/* Return failure. */
out_err:
	if (!hit_db)
	{
		hit_db = NULL;
		hit_db_ni = 0;
		hit_db_n = 0;
	}
	err = -1;
out:
	HIT_DB_UNLOCK();
	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Delete hit with given index.
	
	@param ndx Index of hit in db list.
	@return 0 if hit removed, -1 on errors.
*/
int hit_db_del(int ndx)
{
	/* Variables. */
	int i, err = 0;
	
	HIT_DB_LOCK();

	/* Check that index is valid. */
	if (ndx >= hit_db_n || ndx < 0) goto out_err;
	if (strlen(hit_db[ndx].name) < 1) goto out_err;
	
	/* Remove from list. */
	if ((ndx + 1) >= hit_db_n);
	else if (hit_db_n > 1)
	{
		memmove(&hit_db[ndx], &hit_db[ndx + 1], sizeof(HIT_Item));
	}
	hit_db_n--;

	/* If there is too much empty space in list, shrink it. */
	if ((hit_db_ni - hit_db_n) > HIT_DB_ITEMS_REALLOC)
	{
		hit_db_ni -= HIT_DB_ITEMS_REALLOC;
		hit_db = (HIT_Item *)realloc(hit_db, sizeof(HIT_Item) * hit_db_ni);
	}
	
	/* Go trough the list and reset indexes. */
	for (i = 0; i < hit_db_n; i++)
	{
		hit_db[i].index = i;
	}
	
	goto out;

	/* Return failure. */
out_err:
out:
	HIT_DB_UNLOCK();
	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	This function finds the first hit matching the given description.
	If all parameters are invalid (pointer to number of results is not included
	and number of maximum results is omitted),
	then whole database is returned as result.

	@param number Pointer where to store number of HITs found. (Can be NULL)
	@param name Name of hit.
	@param hit Pointer to hip_lhi-struct.
	@param url Pointer to url.
	@param port Port number.
	@param max_find Atmost return this many hits found.
	@return Pointer to array of HITs if found, NULL if not.
	        Pointer must be freed after usage.
*/
HIT_Item *hit_db_find(int *number,
                      char *name,
                      struct in6_addr *lhit,
                      struct in6_addr *rhit,
                      char *url,
                      int port,
                      int max_find)
{
	/* Variables. */
	HIT_Item *fh1 = NULL, *fh2 = NULL, *hits = NULL;
	int n, hits_found = 0, err = 0;
	char buffer1[128], buffer2[128];

	HIT_DB_LOCK();

	hits = malloc(sizeof(HIT_Item) * hit_db_n);
	if (!hits) goto out_err;
		
	if (number)
	{
		*number = 0;
	}

	/* If whole database should be returned? */
	if (!name && !lhit && !rhit && !url && port == 0)
	{
		memcpy(hits, hit_db, sizeof(HIT_Item) * hit_db_n);
		if (number) *number = hit_db_n;
		goto out;
	}

	/* Loop trough all hits. */
	HIP_DEBUG("Finding HIT from database.\n");
	for (n = 0; n < hit_db_n; n++)
	{
		fh1 = NULL;
		fh2 = NULL;

		/* If name is not NULL, compare name. */
		if (name != NULL)
		{
			/* Compare name. */
			if (strcmp(hit_db[n].name, name) == 0)
			{
				fh2 = &hit_db[n];
			}
		}
		
		if (fh1 == NULL)
		{
			fh1 = fh2;
			fh2 = NULL;
		}

		/* If hit is not NULL... */
		if (lhit != NULL)
		{
			if (memcmp(&hit_db[n].lhit, lhit, sizeof(struct in6_addr)) == 0)
			{
				HIP_DEBUG("Found match for local hit...\n");
				fh2 = &hit_db[n];
			}
		}

		if (fh1 != NULL && fh2 != NULL && fh1 != fh2)
		{
			/* This hit didn't match exactly to given description. */
			fh1 = NULL;
			continue;
		}

		if (fh1 == NULL)
		{
			fh1 = fh2;
			fh2 = NULL;
		}

		if (rhit != NULL)
		{
			if (memcmp(&hit_db[n].rhit, rhit, sizeof(struct in6_addr)) == 0)
			{
				print_hit_to_buffer(buffer1, rhit);
				print_hit_to_buffer(buffer2, &hit_db[n].rhit);
				HIP_DEBUG("Found match for remote hit:\n %s==%s\n", buffer1, buffer2);
				fh2 = &hit_db[n];
			}
		}

		if ((fh1 != NULL && fh2 != NULL && fh1 != fh2) ||
			(rhit != NULL && fh1 != NULL && fh1 != fh2))
		{
			/* This hit didn't match exactly to given description. */
			fh1 = NULL;
			continue;
		}
		
		if (fh1 == NULL)
		{
			fh1 = fh2;
			fh2 = NULL;
		}
		
/* XX TODO: Compare URLs. */


		/* If port is not zero... */
		if (port != 0)
		{
			if (hit_db[n].port == port)
			{
				fh2 = &hit_db[n];
			}
		}

		if (fh1 != NULL && fh2 != NULL && fh1 != fh2)
		{
			/* This hit didn't match exactly to given description. */
			fh1 = NULL;
			continue;
		}

		if (fh1 == NULL)
		{
			fh1 = fh2;
			fh2 = NULL;
		}
		
		/* If reached this point and found hit. */
		if (fh1 != NULL)
		{
			HIP_DEBUG("Remote hit matches with database.\n");
			memcpy(&hits[hits_found], fh1, sizeof(HIT_Item));
			hits_found++;
		}
		
		if (hits_found >= max_find)
		{
			break;
		}
	}
	
	if (number) *number = hits_found;
	hits = realloc(hits, sizeof(HIT_Item) * hits_found);
	goto out;

	/* Return found hit or NULL. */
out_err:
	if (hits)
	{
		free(hits);
		hits = NULL;
	}
	if (number) *number = 0;
out:
	HIT_DB_UNLOCK();
	return (hits);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/

