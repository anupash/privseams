/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
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
	
	@param file If not NULL, database is initialized from here.
	@return 0 on success, -1 on errors.
*/
int hit_db_init(char *file)
{
	/* Variables. */
	int err = 0;
	
	if (file)
	{
		hit_db_lock = 0;
		if (hit_db_load_from_file(file) == 0) goto out;
	}

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

	@param file If not NULL, database saved to here.
*/
void hit_db_quit(char *file)
{
	if (file) hit_db_save_to_file(file);

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
	Clear HIT database.

	@return 0 on success, -1 on errors.
*/
int hit_db_clear(void)
{
	HIT_DB_LOCK();
	hit_db_quit(NULL);
	return (hit_db_init(NULL));
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Adds new HIT to database.
*/
int hit_db_add_hit(HIT_Item *hit, int nolock)
{
	return (hit_db_add(hit->name, &hit->lhit, &hit->rhit,
	                   hit->url, hit->port, hit->type, nolock));
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
	@param nolock Set to one if no database lock is needed.

	@return 0 on success, -1 on errors.
*/
int hit_db_add(char *name,
               struct in6_addr *lhit,
               struct in6_addr *rhit,
               char *url,
               int port,
               int type,
               int nolock)
{
	/* Variables. */
	int n, err = 0;

	if (!nolock) HIT_DB_LOCK();

	/* If there is no space for new item, allocate more space. */
	if (hit_db_n >= hit_db_ni)
	{
		n = HIT_DB_ITEMS_REALLOC + hit_db_ni;
		hit_db = (HIT_Item *)realloc(hit_db, sizeof(HIT_Item) * n);
		if (!hit_db) goto out_err;
		hit_db_ni = n;
	}

	/* Copy info. */
	n = hit_db_n;
	HIP_DEBUG("New item has index #%d...\n", n);
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
	HIP_DEBUG("%d items in database.\n", hit_db_n);

	err = 0;
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
	if (!nolock) HIT_DB_UNLOCK();
	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Delete hit with given index.
	
	@param lhit Local HIT.
	@param rhit Remote HIT.
	@param nolock If no database locking is needed.
	@return 0 if hit removed, -1 on errors.
*/
int hit_db_del(struct in6_addr *lhit, struct in6_addr *rhit, int nolock)
{
	/* Variables. */
	HIT_Item *fhit, temp_hit;
	int i, err = 0, ndx;
	
	if (!nolock) HIT_DB_LOCK();

	/* Search for given HIT pair. */
	fhit = hit_db_search(&ndx, NULL, lhit, rhit, NULL, 0, 1, 0);
	if (!fhit)
	{
		memcpy(&temp_hit, lhit, sizeof(struct in6_addr));
		memcpy(lhit, rhit, sizeof(struct in6_addr));
		memcpy(rhit, &temp_hit, sizeof(struct in6_addr));
		fhit = hit_db_search(&ndx, NULL, lhit, rhit, NULL, 0, 1, 0);
	}

	if (!fhit)
	{
		err = -1;
		goto out_err;
	}

	ndx = fhit->index;

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
	if (!nolock) HIT_DB_UNLOCK();
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
	@param nolock If no database locking is needed.
	@return Pointer to array of HITs if found, NULL if not.
	        Pointer must be freed after usage.
*/
HIT_Item *hit_db_search(int *number,
			            char *name,
			            struct in6_addr *lhit,
			            struct in6_addr *rhit,
			            char *url,
			            int port,
			            int max_find,
			            int nolock)
{
	/* Variables. */
	HIT_Item *fh1 = NULL, *fh2 = NULL, *hits = NULL;
	int n, hits_found = 0, err = 0;
	char buffer1[128], buffer2[128];

	if (!nolock) HIT_DB_LOCK();

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
	if (!nolock) HIT_DB_UNLOCK();
	return (hits);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Save database to file.
	
	@param file Filename for saving database.
	@return 0 on success, -1 on errors.
*/
int hit_db_save_to_file(char *file)
{
	/* Variables. */
	HIT_Item *items = NULL;
	FILE *f = NULL;
	int err = -1, i;
	char lhit[128], rhit[128];
	
	HIT_DB_LOCK();
	
	HIP_DEBUG("Saving HIT database to %s.\n", file);

	f = fopen(file, "w");
	if (!f) goto out_err;

	/* Write all HITs to file. */
	for (i = 0; i < hit_db_n; i++)
	{
		print_hit_to_buffer(lhit, &hit_db[i].lhit);
		print_hit_to_buffer(rhit, &hit_db[i].rhit);
		fprintf(f, "%s %s %s %s %d %s\n",
		        lhit, rhit, hit_db[i].name, hit_db[i].url, hit_db[i].port,
		        ((hit_db[i].type == HIT_DB_TYPE_ACCEPT) ? "accept" : "deny"));
	}
	
	err = 0;

out_err:
	if (f) fclose(f);
	HIT_DB_UNLOCK();
	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Load database from file.
	
	@param file Filename for saving database.
	@return 0 on success, -1 on errors.
*/
int hit_db_load_from_file(char *file)
{
	/* Variables. */
	HIT_Item item;
	FILE *f = NULL;
	struct in6_addr slhit, srhit;
	char buf[1024], ch, lhit[128], rhit[128];
	char name[128], url[320], type[128];
	int err = 0, i, n, port;

	hit_db_clear();
	HIT_DB_LOCK();

	HIP_DEBUG("Loading HIT database from %s.\n", file);

	f = fopen(file, "r");
	if (!f) goto out_err;

	/* Start parsing. */
	memset(buf, '\0', 1024); i = 0; n = -1;
	for (ch = fgetc(f); ch != EOF; ch = fgetc(f))
	{
		/* Remove whitespaces from line start. */
		if (i == 0 && (ch == ' ' || ch == '\t')) continue;
		
		/* Find end of line. */
		if (ch != '\n')
		{
			buf[i] = ch;
			i++;
			continue;
		}

		/*
			Check whether there is carriage return
			in the stream and remove it.
		*/
		ch = fgetc(f);
		
		if (ch != '\r') ungetc(ch, f);
		
		/* Check for empty lines and for commented lines. */
		if (strlen(buf) < 1) goto loop_end;
		if (buf[0] == '#') goto loop_end;
		
		/* Parse values from current line. */
		n = sscanf(buf, "%s %s %s %s %d %s",
		           lhit, rhit, item.name, item.url, &item.port, type);
		
		if (n != 6)
		{
			HIP_DEBUG("Broken line in database file: %s", buf);
			goto loop_end;
		}
		
		HIP_DEBUG("Scanned line with values: %s %s %s %s %d %s\n",
		          lhit, rhit, item.name, item.url, item.port, type);
		
		if (strstr(type, "accept") != NULL) item.type = HIT_DB_TYPE_ACCEPT;
		else item.type = HIT_DB_TYPE_DENY;

		read_hit_from_buffer(&item.lhit, lhit);
		read_hit_from_buffer(&item.rhit, rhit);
		
		hit_db_add_hit(&item, 1);
	
	loop_end:
		/* Clear buffer. */
		memset(buf, '\0', 1024); i = 0;
	}
	
	goto out;
	
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
	if (f) fclose(f);
	HIT_DB_UNLOCK();
	return (err);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/

