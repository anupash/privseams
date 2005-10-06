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


/******************************************************************************/
/* VARIABLES */
/** All HIT-data in the database is stored in here. */
HIT_Item *hit_db = NULL;
/** Counts items in database. */
int hit_db_n = 0;
/** Counts amount of allocated items. */
int hit_db_ni = 0;


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
	/* Allocate minimum space for HI's and reset all data. */
	hit_db = (HIT_Item *)malloc(sizeof(HIT_Item) * HIT_DB_ITEMS_REALLOC);
	if (!hit_db) goto out_err;

	memset(hit_db, 0, sizeof(HIT_Item) * HIT_DB_ITEMS_REALLOC);
	hit_db_ni = HIT_DB_ITEMS_REALLOC;
	hit_db_n = 0;

	/* Return OK. */
	return (0);

	/* Return failure. */
out_err:
	if (hit_db)
	{
		free(hit_db);
		hit_db = NULL;
		hit_db_ni = 0;
		hit_db_n = 0;
	}

	return (-1);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Deinitialize HIP agent HIT database. This function must be called when
	closing application and stopping using database.
*/
void hit_db_quit(void)
{
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
	
	@param name 'Human' identifier for this item: it's name.
	@param hit HIT of this item.
	@param url URL, which is connected to this item, can be NULL.
	@param port Port, which is connected to this item, can be 0 if not needed.
	
	@return 0 on success, -1 on errors.
*/
int hit_db_add(char *name, void *hit, char *url, uint16_t port)
{
	/* Variables. */
	int n;

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
	memcpy(&hit_db[n].hit, hit, sizeof(struct hip_lhi));
	hit_db[n].port = port;
/* XX TODO: Copy url too someday: hi_db[n].url */

	hit_db_n++; /* Count to next free item. */
	
	/* Return OK. */
	return (0);

	/* Return failure. */
out_err:
	if (!hit_db)
	{
		hit_db = NULL;
		hit_db_ni = 0;
		hit_db_n = 0;
	}

	return (-1);
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
	
	/* Return OK. */
	return (0);

	/* Return failure. */
out_err:
	return (-1);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	This function finds the first hit matching the given description.
	
	@param ndx Pointer where to store index of found item in hit db list.
	           (Can be NULL. Set to -1, if nothing found)
	@param name Name of hit.
	@param hit Pointer to hip_lhi-struct.
	@param url Pointer to url.
	@param port Port number.
	@return Pointer to hit if found, NULL if not.
*/
HIT_Item *hit_db_find(int *ndx, char *name, void *hit, char *url, uint16_t port)
{
	/* Variables. */
	HIT_Item *fh1 = NULL, *fh2 = NULL;
	int n;
	
	if (ndx)
	{
		*ndx = -1;
	}

	/* Loop trough all hits. */
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
		
		fh1 = fh2;
		fh2 = NULL;

		/* If hit is not NULL... */
/* XX TODO: Compare hits. */
		if (hit != NULL && 0)
		{
			if (0)
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

		fh1 = fh2;
		fh2 = NULL;
		
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

		fh1 = fh2;
		fh2 = NULL;
		
		/* If reached this point and found hit. */
		if (fh1 != NULL)
		{
			if (ndx)
			{
				*ndx = n;
			}
			break;
		}
	}
	
	/* Return found hit or NULL. */
	return (fh1);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/

