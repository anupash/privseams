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
/** All groups in database are stored in here. */
HIT_Group *group_db = NULL, *group_db_last = NULL;
/** All local HITs in database are stored in here. */
HIT_Local *local_db = NULL, *local_db_last = NULL;
/** Counts items in database. */
int hit_db_n = 0;
/** Counts amount of allocated items. */
int hit_db_ni = 0;
/** Count groups in database. */
int group_db_n = 0;
/** Count local HITs in database. */
int local_db_n = 0;

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
	/* Variables. */
	HIT_Group *g1, *g2;

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
	
	/* Free groups. */
	g1 = group_db;
	group_db = NULL;
	while (g1)
	{
		g2 = g1->next;
		free(g1);
		g1 = g2;
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
	return (hit_db_add(hit->name, &hit->hit, hit->url, hit->port, hit->group, nolock));
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
	@param group HIT group.
	@param nolock Set to one if no database lock is needed.

	@return 0 on success, -1 on errors.
*/
int hit_db_add(char *name,
               struct in6_addr *hit,
               char *url,
               int port,
               char *group,
               int nolock)
{
	/* Variables. */
	int n, err = 0;
	char hitb[128];

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
	strncpy(hit_db[n].name, name, 64);
	hit_db[n].name[64] = '\0';
	memcpy(&hit_db[n].hit, hit, sizeof(struct in6_addr));
	hit_db[n].port = port;
	strcpy(hit_db[n].url, url);
	strcpy(hit_db[n].group, group);
	
	/* Then call GUI to show new HIT. */
	HIP_DEBUG("Calling GUI to show new HIT...\n");
	print_hit_to_buffer(hitb, &hit_db[n].hit);
	gui_add_remote_hit(name, hit_db[n].group);
	HIP_DEBUG("Add succesfull.\n");

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
int hit_db_del(struct in6_addr *hit, int nolock)
{
	/* Variables. */
	HIT_Item *fhit, temp_hit;
	int i, err = 0, ndx;
	
	if (!nolock) HIT_DB_LOCK();

	/* Search for given HIT pair. */
/*	fhit = hit_db_search(NULL, NULL, hit, NULL, 0, NULL, 1, 0);

	if (!fhit)
	{
		err = -1;
		goto out_err;
	}

	/* Remove from list. */
/*	if ((ndx + 1) >= hit_db_n);
	else if (hit_db_n > 1)
	{
		memmove(&hit_db[ndx], &hit_db[ndx + 1], sizeof(HIT_Item));
	}
	hit_db_n--;

	/* If there is too much empty space in list, shrink it. */
/*	if ((hit_db_ni - hit_db_n) > HIT_DB_ITEMS_REALLOC)
	{
		hit_db_ni -= HIT_DB_ITEMS_REALLOC;
		hit_db = (HIT_Item *)realloc(hit_db, sizeof(HIT_Item) * hit_db_ni);
	}
	
	/* Go trough the list and reset indexes. */
/*	for (i = 0; i < hit_db_n; i++)
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
	@param type HIT type, example HIT_DB_TYPE_LOCAL.
	@param max_find Atmost return this many hits found.
	@param nolock If no database locking is needed.
	@return Pointer to array of HITs if found, NULL if not.
	        Pointer must be freed after usage.
*/
HIT_Item *hit_db_search(int *number,
			            char *name,
			            struct in6_addr *hit,
			            char *url,
			            int port,
			            char *group,
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
	if (!name && !hit && !url && port == 0 && !group)
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
		err = 0;
		
		/* If name is not NULL, compare name. */
		if (name != NULL)
		{
			err = 1;
			/* Compare name. */
			if (strcmp(hit_db[n].name, name) == 0)
			{
				fh2 = &hit_db[n];
				err = 0;
			}
		}
		if (err != 0) continue;

		/* If group is not NULL, compare group. */
		if (group != NULL)
		{
			err = 1;
			/* Compare group. */
			if (strcmp(hit_db[n].group, group) == 0)
			{
				fh2 = &hit_db[n];
				err = 0;
			}
		}
		if (err != 0) continue;

		if (hit != NULL)
		{
			err = 1;
			if (memcmp(&hit_db[n].hit, hit, sizeof(struct in6_addr)) == 0)
			{
				print_hit_to_buffer(buffer1, hit);
				print_hit_to_buffer(buffer2, &hit_db[n].hit);
				HIP_DEBUG("Found match for remote hit:\n %s==%s\n", buffer1, buffer2);
				fh2 = &hit_db[n];
				err = 0;
			}
		}
		if (err != 0) continue;

/* XX TODO: Compare URLs. */


		/* If port is not zero... */
		if (port != 0)
		{
			err = 1;
			if (hit_db[n].port == port)
			{
				fh2 = &hit_db[n];
				err = 0;
			}
		}
		if (err != 0) continue;

		/* If reached this point and found hit. */
		HIP_DEBUG("Remote hit matches with database.\n");
		memcpy(&hits[hits_found], fh2, sizeof(HIT_Item));
		hits_found++;
		
		if (hits_found >= max_find && max_find > 0)
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
	char hit[128];
	
	HIT_DB_LOCK();
	
	HIP_DEBUG("Saving HIT database to %s.\n", file);

	f = fopen(file, "w");
	HIP_IFEL(f == NULL, -1, "Failed to save database.\n");

	/* Write all remote groups to file. */
	hit_db_enum_rgroups(hit_db_save_rgroup_to_file, f);
	hit_db_enum_locals(hit_db_save_local_to_file, f);

	/* Write all HITs to file. */
	for (i = 0; i < hit_db_n; i++)
	{
		print_hit_to_buffer(hit, &hit_db[i].hit);
		fprintf(f, "r %s %s %s %d %s\n", hit, hit_db[i].name,
		        hit_db[i].url, hit_db[i].port, hit_db[i].group);
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
	Write remote group to agent database -file.
	This is a enumeration callback function used by hit_db_enum_rgroups().
*/
int hit_db_save_rgroup_to_file(HIT_Group *group, void *p)
{
	/* Variables. */
	FILE *f = (FILE *)p;
	char hit[128];
	
	print_hit_to_buffer(hit, &group->lhit);
	fprintf(f, "g %s %s %d %d\n", group->name, hit, group->type, group->lightweight);
	
	return (0);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Write local HIT to agent database -file.
	This is a enumeration callback function used by hit_db_enum_locals().
*/
int hit_db_save_local_to_file(HIT_Local *local, void *p)
{
	/* Variables. */
	FILE *f = (FILE *)p;
	char hit[128];
	
	print_hit_to_buffer(hit, &local->lhit);
	fprintf(f, "l %s %s\n", local->name, hit);
	
	return (0);
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
	FILE *f = NULL;
	char buf[1024], ch;
	int err = 0, i, n;
	struct in6_addr hit;

	hit_db_clear();
	HIT_DB_LOCK();

	HIP_DEBUG("Loading HIT database from %s.\n", file);

	f = fopen(file, "r");
	if (!f)
	{
		HIP_DEBUG("Failed to open HIT database file \"%s\" for reading!\n", file);
	}
	else
	{
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
			if (strlen(buf) < 3) goto loop_end;
			if (buf[0] == '#') goto loop_end;
		
			if (buf[0] == 'r') hit_db_parse_hit(&buf[2]);
			else if (buf[0] == 'l') hit_db_parse_local(&buf[2]);
			else if (buf[0] == 'g') hit_db_parse_rgroup(&buf[2]);
		
		loop_end:
			/* Clear buffer. */
			memset(buf, '\0', 1024); i = 0;
		}
	}

	if (group_db_n < 1)
	{
		HIP_DEBUG("Group database emty, adding default group.\n");
		memset(&hit, 0, sizeof(struct in6_addr));
		hit_db_add_rgroup("default", &hit, HIT_DB_TYPE_ACCEPT, 0);
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
out:
	if (f) fclose(f);
	HIT_DB_UNLOCK();
	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Load one HIT from given string.
	
	@param buf String containing HIT information.
	@return 0 on success, -1 on errors.
*/
int hit_db_parse_hit(char *buf)
{
	/* Variables. */
	HIT_Item item;
	struct in6_addr slhit, srhit;
	int err = 0, n, port;
	char type[128], lhit[128];

	/* Parse values from current line. */
	n = sscanf(buf, "%s %s %s %d %s",
	           lhit, item.name, item.url, &item.port, item.group);
		
	HIP_IFEL(n != 5, -1, "Broken line in database file: %s\n", buf);
		
	HIP_DEBUG("Scanned HIT line with values: %s %s %s %d %s\n",
	          lhit, item.name, item.url, item.port, item.group);

	read_hit_from_buffer(&item.hit, lhit);
		
	hit_db_add_hit(&item, 1);

out_err:	
	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Load one remote group from given string.
	
	@param buf String containing remote group information.
	@return 0 on success, -1 on errors.
*/
int hit_db_parse_rgroup(char *buf)
{
	/* Variables. */
	int err = 0, n;
	char name[64 + 1], hit[128];
	struct in6_addr lhit;
	int type, lightweight;
	
	/* Parse values from current line. */
	n = sscanf(buf, "%s %s %d %d", name, hit, &type, &lightweight);
	HIP_IFEL(n != 4, -1, "Broken line in database file: %s\n", buf);
	HIP_DEBUG("Scanned remote group line with values: %s\n", name);
	read_hit_from_buffer(&lhit, hit);
	hit_db_add_rgroup(name, &lhit, type, lightweight);

out_err:	
	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Load one local HIT from given string.
	
	@param buf String containing local HIT information.
	@return 0 on success, -1 on errors.
*/
int hit_db_parse_local(char *buf)
{
	/* Variables. */
	int err = 0, n;
	char name[64 + 1], hit[128];
	struct in6_addr lhit;
	
	/* Parse values from current line. */
	n = sscanf(buf, "%s %s", name, hit);
	HIP_IFEL(n != 2, -1, "Broken line in database file: %s\n", buf);
	HIP_DEBUG("Scanned remote group line with values: %s %s\n", name, hit);
	read_hit_from_buffer(&lhit, hit);
	hit_db_add_local(name, &lhit);

out_err:	
	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Add new remote group to HIT group database. Notice that this function don't
	lock the database!
	
	@return Returns pointer to new group or if group already existed, pointer
	        to old one. Returns NULL on errors.
*/
HIT_Group *hit_db_add_rgroup(char *name, struct in6_addr *lhit,
                             int type, int lightweight)
{
	/* Variables. */
	HIT_Group *g, *err = NULL;

	/* Check group name length. */
	HIP_IFEL(strlen(name) < 1, NULL, "Remote group name too short.\n");
 
	/* Check database for group already with same name. */
	g = hit_db_find_rgroup(name);
	HIP_IFEL(g != NULL, g, "Group already found from database, returning it."
	                       " (This is not an actual error)\n");

	/* Allocate new remote group item. */
	g = (HIT_Group *)malloc(sizeof(HIT_Group));
	HIP_IFEL(g == NULL, NULL, "Failed to allocate new remote group item.\n");
	
	/* Setup remote group item. */
	memset(g, 0, sizeof(HIT_Group));
	strncpy(g->name, name, 64);
	memcpy(&g->lhit, lhit, sizeof(struct in6_addr));
	g->type = type;
	g->lightweight = lightweight;

	/* Add remote group item to database. */
	if (group_db == NULL) group_db = g;
	else group_db_last->next = (void *)g;

	group_db_last = g;
	group_db_n++;

	HIP_DEBUG("New group added with name \"%s\", calling GUI to show it.\n", name);

	/* Tell GUI to show new group item. */
	gui_add_rgroup(g);
	err = g;

out_err:
	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Delete remote group from HIT group database.

	@return 0 on success, -1 on errors.
*/
int hit_db_del_rgroup(char *name)
{
	/* Variables. */
	int err = -1;

	/* XX TODO: Implement! */
	HIP_DEBUG("Group delete not implemented yet!!!\n");
	
out_err:
	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Find a group from remote group database.
	
	@param group Name of remote group to be searched.
	@return Pointer to group found, or NULL if none found.
*/
HIT_Group *hit_db_find_rgroup(char *name)
{
	/* Variables. */
	HIT_Group *g;
	
	g = group_db;
	while (g != NULL)
	{
		if (strncmp(g->name, name, 64) == 0) break;
		g = (HIT_Group *)g->next;
	}
	
	return (g);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Enumerate all remote groups in database. This function does not lock the
	database!

	@param f Function to call for every group in database. This function should
	         return 0 if continue enumeration and something else, if enumeration
	         should be stopped.
	@param p Pointer to user data.
	@return Number of groups enumerated.
*/
int hit_db_enum_rgroups(int (*f)(HIT_Group *, void *), void *p)
{
	/* Variables. */
	HIT_Group *g;
	int err = 0, n = 0;
	
	g = group_db;
	while (g != NULL && err == 0)
	{
		err = f(g, p);
		n++;
		g = (HIT_Group *)g->next;
	}

	HIP_DEBUG("Enumerated %d groups.\n", n);
	
	return (n);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Add new local HIT database. Notice that this function don't
	lock the database!
	
	@return Returns pointer to new HIT or if HIT already existed, pointer
	        to old one. Returns NULL on errors.
*/
HIT_Local *hit_db_add_local(char *name, struct in6_addr *hit)
{
	/* Variables. */
	HIT_Local *h, *err = NULL;

	/* Check HIT name length. */
	HIP_IFEL(strlen(name) < 1, NULL, "Local HIT name too short.\n");
 
	/* Check database for HIT already with same name. */
	h = hit_db_find_local(name);
	HIP_IFEL(h != NULL, h, "Local HIT already found from database, returning it."
	                       " (This is not an actual error)\n");

	/* Allocate new remote group item. */
	h = (HIT_Local *)malloc(sizeof(HIT_Local));
	HIP_IFEL(h == NULL, NULL, "Failed to allocate new local HIT.\n");
	
	/* Setup local HIT. */
	memset(h, 0, sizeof(HIT_Local));
	strncpy(h->name, name, 64);
	memcpy(&h->lhit, hit, sizeof(struct in6_addr));

	/* Add local HIT to database. */
	if (local_db == NULL) local_db = h;
	else local_db_last->next = (void *)h;

	local_db_last = h;
	local_db_n++;

	HIP_DEBUG("New local HIT added with name \"%s\", calling GUI to show it.\n", name);

	/* Tell GUI to show local HIT. */
	gui_add_local_hit(h);
	err = h;

out_err:
	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Delete local HIT from database.

	@return 0 on success, -1 on errors.
*/
int hit_db_del_local(char *name)
{
	/* Variables. */
	int err = -1;

	/* XX TODO: Implement! */
	HIP_DEBUG("Local HIT delete not implemented yet!!!\n");
	
out_err:
	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Find a local HIT from database.
	
	@param hit Name of HIT to be searched.
	@return Pointer to HIT found, or NULL if none found.
*/
HIT_Local *hit_db_find_local(char *name)
{
	/* Variables. */
	HIT_Local *h;
	
	h = local_db;
	while (h != NULL)
	{
		if (strncmp(h->name, name, 64) == 0) break;
		h = (HIT_Local *)h->next;
	}
	
	return (h);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Enumerate all local HITs in database. This function locks the database.
	
	@param f Function to call for every local HIT in database. This function
	         should return 0 if continue enumeration and something else, if
	         enumeration should be stopped.
	@param p Pointer to user data.
	@return Number of HITs enumerated.
*/
int hit_db_enum_locals(int (*f)(HIT_Local *, void *), void *p)
{
	/* Variables. */
	HIT_Local *h;
	int err = 0, n = 0;
	
	h = local_db;
	while (h != NULL && err == 0)
	{
		err = f(h, p);
		n++;
		h = (HIT_Local *)h->next;
	}

	HIP_DEBUG("Enumerated %d local HITs.\n", n);
	
	return (n);
}
/* END OF FUNCTION */


/* END OF SOURCE FILE */
/******************************************************************************/

