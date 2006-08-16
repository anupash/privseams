/*
    HIP Agent
    
    License: GNU/GPL
    Authors: Antti Partanen <aehparta@cc.hut.fi>
*/

/******************************************************************************/
/* INCLUDES */

/* STANDARD */
#include <stdlib.h>
#include <errno.h>
#include <string.h>

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
HIT_Remote *remote_db = NULL, *remote_db_last = NULL;
/** All groups in database are stored in here. */
HIT_Group *group_db = NULL, *group_db_last = NULL;
/** All local HITs in database are stored in here. */
HIT_Local *local_db = NULL, *local_db_last = NULL;
/** Counts items in database. */
int remote_db_n = 0;
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
	
	hit_db_lock = 0;
	hit_db_clear();

	if (file) HIP_IFE(hit_db_load_from_file(file), -1);

out_err:
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
	hit_db_clear();
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Clear HIT database.

	@return 0 on success, -1 on errors.
*/
void hit_db_clear(void)
{
	/* Variables. */
	HIT_Remote *r1, *r2;
	HIT_Group *g1, *g2;
	HIT_Local *l1, *l2;
	
	HIT_DB_LOCK();

	/* Free remote. */
	r1 = remote_db;
	remote_db = NULL;
	remote_db_n = 0;
	while (r1)
	{
		r2 = r1->next;
		free(r1);
		r1 = r2;
	}
	
	/* Free groups. */
	g1 = group_db;
	group_db = NULL;
	group_db_n = 0;
	while (g1)
	{
		g2 = g1->next;
		free(g1);
		g1 = g2;
	}

	/* Free locals. */
	l1 = local_db;
	local_db = NULL;
	local_db_n = 0;
	while (l1)
	{
		l2 = l1->next;
		free(l1);
		l1 = l2;
	}
	
	HIT_DB_UNLOCK();
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Adds new HIT to database.
*/
HIT_Remote *hit_db_add_hit(HIT_Remote *hit, int nolock)
{
	return (hit_db_add(hit->name, &hit->hit, hit->url, hit->port, hit->g, nolock));
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

	@return Pointer to new remote HIT on success, NULL on errors.
*/
HIT_Remote *hit_db_add(char *name, struct in6_addr *hit, char *url,
                       char *port, HIT_Group *group, int nolock)
{
	/* Variables. */
	HIT_Remote *r, *err = NULL;
	char hitb[128];
	struct in6_addr lhit;

	if (!nolock) HIT_DB_LOCK();

	/* Check group name length. */
	HIP_IFEL(strlen(name) < 1, NULL, "Remote HIT name too short.\n");
 
	/* Check database for group already with same name. */
	r = hit_db_find(name, NULL);
	HIP_IFEL(r != NULL, r, "Remote HIT already found from database with same"
	                       " name, returning it, could not add new.\n");
	r = hit_db_find(NULL, hit);
	HIP_IFEL(r != NULL, r, "Remote HIT already found from database, returning it.\n");

	/* Allocate new remote HIT. */
	r = (HIT_Remote *)malloc(sizeof(HIT_Remote));
	HIP_IFEL(r == NULL, NULL, "Failed to allocate new remote HIT.\n");

	/* Copy info. */
	memset(r, 0, sizeof(HIT_Remote));
	NAMECPY(r->name, name);
	memcpy(&r->hit, hit, sizeof(struct in6_addr));
	URLCPY(r->port, port);
	URLCPY(r->url, url);
	
	/* Check that group is not NULL and set group. */
	if (group == NULL)
	{
		if (group_db_n < 1)
		{
			HIP_DEBUG("Group database emty, adding default group.\n");
			hit_db_add_rgroup("default", local_db, HIT_DB_TYPE_ACCEPT, 0);
		}
		group = group_db;
	}
	r->g = group;

	/* Add remote group item to database. */
	if (remote_db == NULL) remote_db = r;
	else remote_db_last->next = (void *)r;

	remote_db_last = r;
	remote_db_n++;

	/* Then call GUI to show new HIT. */
	HIP_DEBUG("Calling GUI to show new HIT...\n");
	gui_add_remote_hit(name, group->name);

	HIP_DEBUG("%d items in database.\n", remote_db_n);

	err = r;

out_err:
	if (!nolock) HIT_DB_UNLOCK();
	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Delete hit with given index.
	
	@param name Name of remote HIT to be removed.
	@return 0 if hit removed, -1 on errors.
*/
int hit_db_del(char *n)
{
	/* Variables. */
	HIT_Remote *r1, *r2;
	char name[MAX_NAME_LEN + 1];
	int err = 0;
	
	/* Check that database is not empty. */
	HIP_IFEL(remote_db_n < 1, -1, "Remote database is empty, should not happen!\n");
	
	NAMECPY(name, n);
	HIP_DEBUG("Deleting remote HIT: %s\n", name);

	/* Check whether this HIT is the first. */
	if (strncmp(remote_db->name, name, MAX_NAME_LEN) == 0)
	{
		r1 = remote_db;
		remote_db = (HIT_Remote *)remote_db->next;
		free(r1);
		remote_db_n--;
		if (remote_db_n < 1)
		{
			remote_db = NULL;
			remote_db_last = NULL;
		}
	}
	else
	{
		/* Find previous HIT first. */
		r1 = remote_db;
		while (r1 != NULL)
		{
			r2 = (HIT_Remote *)r1->next;
			if (r2 == NULL) break;
		
			if (strncmp(r2->name, name, MAX_NAME_LEN) == 0) break;
			
			r1 = r2;
		}
	
		/* Then delete, if found. */
		if (r2 != NULL)
		{
			r1->next = r2->next;
			if (remote_db_last == r2) remote_db_last = r1;
			free(r2);
		}
		else err = -1;
	}

out_err:
	if (err) HIP_DEBUG("Deleting remote HIT failed: %s\n", name);
	else gui_delete_remote_hit(name);

	return (err);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Find a remote HIT from database.
	
	@param name Name of HIT to be searched.
	@param hit HIT to be searched.
	@return Pointer to HIT found, or NULL if none found.
*/
HIT_Remote *hit_db_find(char *name, struct in6_addr *hit)
{
	/* Variables. */
	HIT_Remote *r;
	int err;
	
	r = remote_db;
	while (r != NULL)
	{
		err = 0;
		if (name == NULL) err++;
		else if (strncmp(r->name, name, MAX_NAME_LEN) == 0) err++;
		if (hit == NULL) err++;
		else if (memcmp(&r->hit, hit, sizeof(struct in6_addr)) == 0) err++;
		
		if (err == 2) break;
		r = (HIT_Remote *)r->next;
	}
	
	return (r);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Enumerate all remote HITs in database. This function locks the database.
	
	@param f Function to call for every remote HIT in database. This function
	         should return 0 if continue enumeration and something else, if
	         enumeration should be stopped.
	@param p Pointer to user data.
	@return Number of HITs enumerated.
*/
int hit_db_enum(int (*f)(HIT_Remote *, void *), void *p)
{
	/* Variables. */
	HIT_Remote *r;
	int err = 0, n = 0;
	
	r = remote_db;
	while (r != NULL && err == 0)
	{
		err = f(r, p);
		n++;
		r = (HIT_Remote *)r->next;
	}

	HIP_DEBUG("Enumerated %d remote HITs.\n", n);
	
	return (n);
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
	HIT_Remote *items = NULL;
	FILE *f = NULL;
	int err = 0, i;
	char hit[128];
	
	HIT_DB_LOCK();
	
	HIP_DEBUG("Saving HIT database to %s.\n", file);

	f = fopen(file, "w");
	HIP_IFEL(f == NULL, -1, "Failed to save database.\n");

	/* Write all local HITs to file. */
	hit_db_enum_locals(hit_db_save_local_to_file, f);
	/* Write all remote groups to file. */
	hit_db_enum_rgroups(hit_db_save_rgroup_to_file, f);
	/* Write all remote HITs to file. */
	hit_db_enum(hit_db_save_remote_to_file, f);

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
int hit_db_save_rgroup_to_file(HIT_Group *g, void *p)
{
	/* Variables. */
	FILE *f = (FILE *)p;
	char hit[128];
	
	fprintf(f, "g \"%s\" \"%s\" %d %d\n", g->name, g->l->name, g->type, g->lightweight);
	
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
	fprintf(f, "l \"%s\" %s\n", local->name, hit);
	
	return (0);
}
/* END OF FUNCTION */


/******************************************************************************/
/**
	Write remote HIT to agent database -file.
	This is a enumeration callback function used by hit_db_enum_locals().
*/
int hit_db_save_remote_to_file(HIT_Remote *r, void *p)
{
	/* Variables. */
	FILE *f = (FILE *)p;
	char hit[128];
	
	print_hit_to_buffer(hit, &r->hit);
	fprintf(f, "r %s \"%s\" \"%s\" \"%s\" \"%s\"\n", hit, r->name,
	        r->url, r->port, r->g->name);

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
	char buf[2048], ch;
	int err = 0, i, n;
	struct in6_addr hit;

	hit_db_clear();
	HIT_DB_LOCK();

	HIP_DEBUG("Loading HIT database from %s.\n", file);

	f = fopen(file, "r");
	HIP_IFEL(!f, 0, "Failed to open HIT database file \"%s\" for reading.\n", file);

	/* Start parsing. */
	memset(buf, '\0', sizeof(buf)); i = 0; n = -1;
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
		memset(buf, '\0', sizeof(buf)); i = 0;
	}
	
out_err:
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
	HIT_Remote item;
	struct in6_addr slhit, srhit;
	int err = 0, n;
	char type[128], lhit[128], group[320];

	/* Parse values from current line. */
	n = sscanf(buf, "%s \"%64[^\"]\" \"%1024[^\"]\" \"%1024[^\"]\" \"%64[^\"]\"",
	           lhit, item.name, item.url, item.port, group);

	HIP_IFEL(n != 5, -1, "Broken line in database file: %s\n", buf);
		
	HIP_DEBUG("Scanned HIT line with values: %s %s %s %s %s\n",
	          lhit, item.name, item.url, item.port, group);

	read_hit_from_buffer(&item.hit, lhit);
	item.g = hit_db_find_rgroup(group);
	HIP_IFEL(item.g == NULL, -1, "Invalid group for HIT in database file!\n");

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
	HIT_Local *l;
	HIT_Group *g;
	int err = 0, n;
	char name[MAX_NAME_LEN + 1], hit[128];
	int type, lightweight;
	
	/* Parse values from current line. */
	n = sscanf(buf, "\"%64[^\"]\" \"%64[^\"]\" %d %d",
	           name, hit, &type, &lightweight);
	HIP_IFEL(n != 4, -1, "Broken line in database file: %s\n", buf);
	HIP_DEBUG("Scanned remote group line with values: %s %s %d %d\n",
	          name, hit, type, lightweight);
	l = hit_db_find_local(hit, NULL);
	HIP_IFEL(!l, -1, "Failed to find local HIT for remote group!\n");
	g = hit_db_add_rgroup(name, l, type, lightweight);
	if (g && strncmp("default", name, MAX_NAME_LEN) == 0)
	{
		g->l = l;
		g->type = type;
		g->lightweight = lightweight;
	}


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
	char name[MAX_NAME_LEN + 1], hit[128];
	struct in6_addr lhit;
	
	/* Parse values from current line. */
	n = sscanf(buf, "\"%64[^\"]\" %s", name, hit);
	HIP_IFEL(n != 2, -1, "Broken line in database file: %s\n", buf);
	HIP_DEBUG("Scanned local HIT line with values: %s %s\n", name, hit);
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
HIT_Group *hit_db_add_rgroup(char *name, HIT_Local *lhit,
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
	NAMECPY(g->name, name);
	g->l = lhit;
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
		if (strncmp(g->name, name, MAX_NAME_LEN) == 0) break;
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
	h = hit_db_find_local(name, NULL);
	HIP_IFEL(h != NULL, h, "Local HIT already found from database, returning it."
	                       " (This is not an actual error)\n");
	h = hit_db_find_local(NULL, hit);
	HIP_IFEL(h != NULL, h, "Local HIT already found from database, returning it."
	                       " (This is not an actual error)\n");

	/* Allocate new remote group item. */
	h = (HIT_Local *)malloc(sizeof(HIT_Local));
	HIP_IFEL(h == NULL, NULL, "Failed to allocate new local HIT.\n");
	
	/* Setup local HIT. */
	memset(h, 0, sizeof(HIT_Local));
	NAMECPY(h->name, name);
	memcpy(&h->lhit, hit, sizeof(struct in6_addr));

	/* Add local HIT to database. */
	if (local_db == NULL) local_db = h;
	else local_db_last->next = (void *)h;

	local_db_last = h;
	local_db_n++;

	if (group_db_n < 1)
	{
		HIP_DEBUG("Group database emty, adding default group.\n");
		hit_db_add_rgroup("default", h, HIT_DB_TYPE_ACCEPT, 0);
	}

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
	
	@param name Name of HIT to be searched.
	@param hit HIT to be searched.
	@return Pointer to HIT found, or NULL if none found.
*/
HIT_Local *hit_db_find_local(char *name, struct in6_addr *hit)
{
	/* Variables. */
	HIT_Local *h;
	int err;
	
	h = local_db;
	while (h != NULL)
	{
		err = 0;
		if (name == NULL) err++;
		else if (strncmp(h->name, name, MAX_NAME_LEN) == 0) err++;
		if (hit == NULL) err++;
		else if (memcmp(&h->lhit, hit, sizeof(struct in6_addr)) == 0) err++;
		
		if (err == 2) break;
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

