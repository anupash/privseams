/**
 * @file agent/hitdb.c
 *
 * <LICENSE TEMLPATE LINE - LEAVE THIS LINE INTACT>
 *
 * Functions to manipulate the HIT database and do searcher from it.
 * Also contains the functionality that inserts the records from memory to
 * sqlite3 database.
 *
 * @brief Functions to manipulate the HIT database, insert, remove, search.
 *
 * @author Antti Partanen <aehparta@cc.hut.fi>
 * @author Samu Varjonen <samu.varjonen@hiit.fi>
 **/
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/un.h>
#include <sys/types.h>

#include "hitdb.h"
#include "language.h"
#include "tools.h"
#include "lib/gui/hipgui.h"
#include "lib/core/debug.h"
#include "lib/core/ife.h"
#include "lib/core/sqlitedbapi.h"

#define HIT_DB_LOCK() { while (hit_db_lock) {; } hit_db_lock = 1; }
#define HIT_DB_UNLOCK() { hit_db_lock = 0; }

/** All HIT-data in the database is stored in here. */
HIT_Remote *remote_db = NULL, *remote_db_last = NULL;
/** All groups in database are stored in here. */
HIT_Group *group_db   = NULL, *group_db_last = NULL;
/** All local HITs in database are stored in here. */
HIT_Local *local_db   = NULL, *local_db_last = NULL;
/** Counts items in database. */
int remote_db_n       = 0;
/** Count groups in database. */
int group_db_n        = 0;
/** Count local HITs in database. */
int local_db_n        = 0;

/** Almost atomic lock. */
int hit_db_lock       = 1;

/** Forwards, prototypes */
static void hit_db_clear(void);
static int hit_db_load_from_file(char *);
static int hit_db_parse_hit(char *);
static int hit_db_parse_rgroup(char *);
static int hit_db_parse_local(char *);

/* Callback functions for the database functions to use to handle all the data
 * from queries */

/**
 * hip_agent_db_local_callback - Callback function to get the data from the
 *                               db table local
 *
 * @param NotUsed Not used
 * @param argc How many arguments
 * @param argv Arguments
 * @param azColName Column name
 *
 * @return 0 if created and/or opened OK otherwise negative
 *
 * @note Notice that the parameters are allways the same
 */
static int hip_agent_db_local_callback(void *NotUsed, int argc,
                                       char **argv, char **azColName)
{
    int i;
    char buf[118];     // sum of the ones below and some more
    char lname[66];
    char lhit[42];

    for (i = 0; i < argc; i++) {
        _HIP_DEBUG("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
        if (!strcmp(azColName[i], "lname")) {
            sprintf(lname, "%s", argv[i] ? argv[i] : "NULL");
        }
        if (!strcmp(azColName[i], "lhit")) {
            sprintf(lhit, "%s", argv[i] ? argv[i] : "NULL");
        }
    }
    if ((i % 2) == 0 && (i > 0)) {
        sprintf(buf, "\"%s\" %s",
                lname, lhit);
        _HIP_DEBUG("HIT BUF %s\n", buf);
        hit_db_parse_local(buf);
        memset(lname, '\0', sizeof(lname));
        memset(lhit, '\0', sizeof(lhit));
    }
    return 0;
}

/**
 * hip_agent_db_remote_callback - Callback function to get the data from the db
 *                                table remote
 *
 * @param NotUsed Not used
 * @param argc How many arguments
 * @param argv Arguments
 * @param azColName Column name
 *
 * @return 0 if created and/or opened OK otherwise negative
 *
 * @note Notice that the parameters are allways the same
 */
static int hip_agent_db_remote_callback(void *NotUsed, int argc,
                                        char **argv, char **azColName)
{
    int i, err = 0;
    char buf[2236];     // should be the sum of the below + 10 or more :)
    char rname[66];
    char rhit[42];
    char url[1026];
    char port[1026];
    char gname[66];

    for (i = 0; i < argc; i++) {
        _HIP_DEBUG("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
        if (!strcmp(azColName[i], "rname")) {
            err = sprintf(rname, "%s", argv[i] ? argv[i] : "NULL");
        }
        if (!strcmp(azColName[i], "rhit")) {
            err = sprintf(rhit, "%s", argv[i] ? argv[i] : "NULL");
        }
        if (!strcmp(azColName[i], "url")) {
            err = sprintf(url, "%s", argv[i] ? argv[i] : "NULL");
        }
        if (!strcmp(azColName[i], "port")) {
            err = sprintf(port, "%s", argv[i] ? argv[i] : "NULL");
        }
        if (!strcmp(azColName[i], "gname")) {
            err = sprintf(gname, "%s", argv[i] ? argv[i] : "NULL");
        }
    }
    if ((i % 5) == 0 && (i > 0)) {
        sprintf(buf, "\"%s\" \"%s\" \"%s\" \"%s\" \"%s\"",
                rname, rhit, url, port, gname);
        hit_db_parse_hit(buf);
        memset(rname, '\0', sizeof(rname));
        memset(rhit, '\0', sizeof(rhit));
        memset(port, '\0', sizeof(port));
        memset(url, '\0', sizeof(url));
        memset(gname, '\0', sizeof(gname));
    }
    return 0;
}

/**
 * hip_agent_db_groupts_callback - Callback function to get the data from
 *                                 the db table groups
 *
 * @param NotUsed Not used
 * @param argc How many arguments
 * @param argv Arguments
 * @param azColName Column name
 *
 * @return 0 if created and/or opened OK otherwise negative
 *
 * @note Notice that the parameters are allways the same
 */
static int hip_agent_db_groups_callback(void *NotUsed, int argc,
                                        char **argv, char **azColName)
{
    int i;
    char buf[118];     // sum of the ones below + some more
    char name[66];
    char lhit[42];
    char *accept = NULL, *lw = NULL;

    memset(name, '\0', sizeof(name));
    memset(lhit, '\0', sizeof(lhit));
    accept = lw = 0;

    for (i = 0; i < argc; i++) {
        _HIP_DEBUG("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
        if (!strcmp(azColName[i], "gname")) {
            sprintf(name, "%s", argv[i] ? argv[i] : "NULL");
        }
        if (!strcmp(azColName[i], "lhitname")) {
            sprintf(lhit, "%s", argv[i] ? argv[i] : "NULL");
        }
        if (!strcmp(azColName[i], "accept")) {
            accept = argv[i] ? argv[i] : "NULL";
        }
        if (!strcmp(azColName[i], "lightweight")) {
            lw = argv[i] ? argv[i] : "NULL";
        }
    }
    if ((i % 4) == 0 && (i > 0)) {
        sprintf(buf, "\"%s\" \"%s\" %d %d",
                name,
                lhit,
                (accept ? 1 : 0),
                (lw ? 1 : 0));
        hit_db_parse_rgroup(buf);
        memset(name, '\0', sizeof(name));
        memset(lhit, '\0', sizeof(lhit));
        accept = lw = 0;
    }
    return 0;
}

/**
 * hit_db_init - Initialize HIP agent HIT database.
 *
 * @param file path tho the file that is the sqlite3 database to be opened
 *
 * @return 0 on success, -1 on errors
 *
 * @note This function must be called before using database at all.
 **/
int hit_db_init(char *file)
{
    int err = 0;
    extern int init_in_progress;

    hit_db_lock      = 0;
    hit_db_clear();
    init_in_progress = 0;

    if (file) {
        HIP_IFE(hit_db_load_from_file(file), -1);
    }
    init_in_progress = 1;
out_err:
    return err;
}

/**
 * hit_db_quit - Deinitialize HIP agent HIT database and calls cleanup for db in memory.
 *
 * @return void
 *
 * @note This function must be called when closing application and stopping using database.
 **/
void hit_db_quit(void)
{
    int err = 0;
    extern sqlite3 *agent_db;

    HIP_IFEL(hip_sqlite_close_db(agent_db), -1, "Failed to close the db\n");
    hit_db_clear();
out_err:
    return;
}

/**
 * hit_db_clear - Frees memory used by the agents db in memory
 *
 * @return void
 **/
static void hit_db_clear(void)
{
    HIT_Remote *r1, *r2;
    HIT_Group *g1, *g2;
    HIT_Local *l1, *l2;

    HIT_DB_LOCK();

    /* Free remote. */
    r1          = remote_db;
    remote_db   = NULL;
    remote_db_n = 0;
    while (r1) {
        r2 = r1->next;
        free(r1);
        r1 = r2;
    }

    /* Free groups. */
    g1         = group_db;
    group_db   = NULL;
    group_db_n = 0;
    while (g1) {
        g2 = g1->next;
        free(g1);
        g1 = g2;
    }

    /* Free locals. */
    l1         = local_db;
    local_db   = NULL;
    local_db_n = 0;
    while (l1) {
        l2 = l1->next;
        free(l1);
        l1 = l2;
    }

    HIT_DB_UNLOCK();
}

/**
 * hit_db_add_hit - Adds new HIT to database.
 *
 * @param hit to be added
 * @param nolock should we lock the db or not
 *
 * @return pointer to HIT_Remote
 *
 * @note This is a wrapper for hit_db_add for using HIT_Remote struct @see hit_db_add
 **/
HIT_Remote *hit_db_add_hit(HIT_Remote *hit, int nolock)
{
    return hit_db_add(hit->name, &hit->hit, hit->url, hit->port, hit->g, nolock);
}

/**
 *	hit_db_add - Adds new HIT to database.
 *
 *	@param name 'Human' identifier for this item: it's name.
 *      @param hit HIT of this item.
 *	@param url URL, which is connected to this item, can be NULL.
 *	@param port Port, which is connected to this item, can be 0 if not needed.
 *	@param group To which group the HIT is added.
 *	@param nolock Set to one if no database lock is needed.
 *
 *	@return Pointer to new remote HIT on success, NULL on errors.
 */
HIT_Remote *hit_db_add(char *name, struct in6_addr *hit, char *url,
                       char *port, HIT_Group *group, int nolock)
{
    HIT_Remote *r, *err = NULL;
    char insert_into[256];
    int ret = 0;
    extern sqlite3 *agent_db;
    extern int init_in_progress;

    if (!nolock) {
        HIT_DB_LOCK();
    }

    HIP_IFEL(strlen(name) < 1, NULL, "Remote HIT name too short.\n");

    /* Check database for group already with same name. */
    r = hit_db_find(name, NULL);
    HIP_IFEL(r != NULL, r, "Remote HIT already found from database with same"
                           " name, returning it, could not add new.\n");
    r = hit_db_find(NULL, hit);
    HIP_IFEL(r != NULL, r, "Remote HIT already found from database, returning it.\n");

    /* Allocate new remote HIT. */
    r = (HIT_Remote *) malloc(sizeof(HIT_Remote));
    HIP_IFEL(r == NULL, NULL, "Failed to allocate new remote HIT.\n");

    /* Copy info. */
    memset(r, 0, sizeof(HIT_Remote));
    NAMECPY(r->name, name);
    memcpy(&r->hit, hit, sizeof(struct in6_addr));
    URLCPY(r->port, port);
    URLCPY(r->url, url);

    /* Check that group is not NULL and set group. */
    if (group == NULL) {
        group = group_db;
    }
    r->g = group;
    r->g->remotec++;

    /* Add remote group item to database. */
    if (remote_db == NULL) {
        remote_db = r;
    } else {      remote_db_last->next = (void *) r;
    }

    remote_db_last = r;
    remote_db_n++;

    /* Add it to the db on disk too */
    if (init_in_progress == 1) {
        print_hit_to_buffer((char *) hit, &r->hit);
        sprintf(insert_into, "INSERT INTO remote VALUES("
                             "'%s', '%s', '%s', '%s', '%s');",
                r->name, (char *) hit, "x", r->port, r->g->name);
        ret = hip_sqlite_insert_into_table(agent_db, insert_into);
    }
    /* Then call GUI to show new HIT. */
    if (group->name[0] != ' ') {
        _HIP_DEBUG("Calling GUI to show new HIT %s...\n", r->name);
        gui_hit_remote_add(group->name, r->name);
    }

    _HIP_DEBUG("%d items in database.\n", remote_db_n);

    err = r;

out_err:
    if (!nolock) {
        HIT_DB_UNLOCK();
    }
    return err;
}

/**
 * hit_db_del - Delete HIT with given name.
 *
 * @param n Name of remote HIT to be removed.
 *
 * @return 0 if HIT removed, -1 on errors.
 **/
int hit_db_del(char *n)
{
    HIT_Remote *r1 = NULL, *r2 = NULL;
    char name[MAX_NAME_LEN + 1], group_name[MAX_NAME_LEN + 1];
    int err        = 0;
    char delete_from[256];
    extern sqlite3 *agent_db;

    /* Check that database is not empty. */
    HIP_IFEL(remote_db_n < 1, -1, "Remote database is empty, should not happen!\n");

    NAMECPY(name, n);
    _HIP_DEBUG("Deleting remote HIT: %s\n", name);

    /* Check whether this HIT is the first. */
    if (strncmp(remote_db->name, name, MAX_NAME_LEN) == 0) {
        r1        = remote_db;
        r1->g->remotec--;
        NAMECPY(group_name, r1->g->name);
        remote_db = (HIT_Remote *) remote_db->next;
        free(r1);
        remote_db_n--;
        if (remote_db_n < 1) {
            remote_db      = NULL;
            remote_db_last = NULL;
        }
    } else {
        /* Find previous HIT first. */
        r1 = remote_db;
        while (r1 != NULL) {
            r2 = (HIT_Remote *) r1->next;
            if (r2 == NULL) {
                break;
            }

            if (strncmp(r2->name, name, MAX_NAME_LEN) == 0) {
                break;
            }

            r1 = r2;
        }

        /* Then delete, if found. */
        if (r2 != NULL) {
            r1->next = r2->next;
            r2->g->remotec--;
            NAMECPY(group_name, r2->g->name);
            if (remote_db_last == r2) {
                remote_db_last = r1;
            }
            free(r2);
        } else {err = -1;
        }
    }
    /* Mirror the delete to the db on disk */
    sprintf(delete_from, "DELETE FROM remote WHERE rname = %s;", name);
    _HIP_DEBUG("DEL :: %s\n", delete_from);
    HIP_IFEL(hip_sqlite_delete_from_table(agent_db, delete_from),
             -1, "Failed to execute delete query on remote table\n");

out_err:
    if (err) {
        _HIP_DEBUG("Deleting remote HIT failed: %s\n", name);
    } else {      gui_hit_remote_del(name, group_name);
    }

    return err;
}

/**
 * hit_db_find - Find a remote HIT from database.
 *
 * @param name Name of HIT to be searched.
 * @param hit HIT to be searched.
 *
 * @return Pointer to HIT found, or NULL if none found.
 **/
HIT_Remote *hit_db_find(char *name, struct in6_addr *hit)
{
    HIT_Remote *r;
    int err;

    r = remote_db;
    while (r != NULL) {
        err = 0;
        if (name == NULL) {
            err++;
        } else if (strncmp(r->name, name, MAX_NAME_LEN) == 0) {
            err++;
        }
        if (hit == NULL) {
            err++;
        } else if (memcmp(&r->hit, hit, sizeof(struct in6_addr)) == 0) {
            err++;
        }

        if (err == 2) {
            break;
        }
        r = (HIT_Remote *) r->next;
    }

    return r;
}

/**
 * hit_db_load_from_file - Load database from file.
 *
 * @param file Filename for saving database.
 *
 * @return 0 on success, -1 on errors.
 **/
static int hit_db_load_from_file(char *file)
{
    FILE *db_file = NULL;
    int err       = 0;
    extern sqlite3 *agent_db;
    extern int init_in_progress;

    hit_db_clear();
    HIT_DB_LOCK();

    _HIP_DEBUG("Loading HIT database from %s.\n", file);

    db_file = fopen(file, "r");
    if (!db_file) {
        /* first time creation has to add local info */
        HIP_DEBUG("Adding local info on this run\n");
        init_in_progress = 1;
    }
    agent_db = hip_sqlite_open_db(file, HIP_AGENT_DB_CREATE_TBLS);
    HIP_IFE(!agent_db, -1);

    HIP_IFEL(hip_sqlite_select(agent_db, HIP_AGENT_DB_SELECT_LOCAL,
                               hip_agent_db_local_callback), -1,
             "Failed to execute select query (local) on the db\n");
    HIP_IFEL(hip_sqlite_select(agent_db, HIP_AGENT_DB_SELECT_GROUPS,
                               hip_agent_db_groups_callback), -1,
             "Failed to execute select query (groups) on the db\n");
    HIP_IFEL(hip_sqlite_select(agent_db, HIP_AGENT_DB_SELECT_REMOTE,
                               hip_agent_db_remote_callback), -1,
             "Failed to execute select query (remote) on the db\n");

out_err:
    if (db_file) {
        fclose(db_file);
    }
    HIT_DB_UNLOCK();
    return err;
}

/**
 * hit_db_parse_hit - Parse a HIT from given string and add it to the database.
 *
 * @param buf String containing HIT information.
 *
 * @return 0 on success, -1 on errors.
 **/
static int hit_db_parse_hit(char *buf)
{
    HIT_Remote item;
    int err = 0, n;
    char lhit[128], group[320];

    /* Parse values from current line. */
    n = sscanf(buf, "%s \"%1024[^\"]\" \"%64[^\"]\"  \"%1024[^\"]\" \"%64[^\"]\"",
               item.name, lhit,  item.url, item.port, group);

    HIP_IFEL(n != 5, -1, "Broken line in database file: %s\n", buf);
    read_hit_from_buffer(&item.hit, lhit);
    item.g = hit_db_find_rgroup(group);
    HIP_IFEL(item.g == NULL, -1, "Invalid group for HIT in database file!\n");

    hit_db_add_hit(&item, 1);

out_err:
    return err;
}

/**
 * hit_db_parse_rgroup - Parse a remote group information from given string
 *                       and add it to the database.
 *
 * @param buf String containing remote group information.
 * @return  0 on success, -1 on errors.
 **/
static int hit_db_parse_rgroup(char *buf)
{
    HIT_Local *l;
    HIT_Group *g;
    int err = 0, n;
    char name[MAX_NAME_LEN + 1], hit[128];
    int accept, lightweight;

    /* Parse values from current line. */
    n = sscanf(buf, "\"%64[^\"]\" \"%64[^\"]\" %d %d",
               name, hit, &accept, &lightweight);
    HIP_IFEL(n != 4, -1, "Broken line in database file: %s\n", buf);
    l = hit_db_find_local(hit, NULL);
    HIP_IFEL(!l, -1, "Failed to find local HIT for remote group!\n");
    g = hit_db_add_rgroup(name, l, accept, lightweight);
    if (g && strncmp(lang_get("default-group-name"), name, MAX_NAME_LEN) == 0) {
        g->l           = l;
        g->accept      = accept;
        g->lightweight = lightweight;
    }

out_err:
    return err;
}

/**
 * hit_db_parse_local - Parse a local HIT from given string and add it to the database.
 *
 * @param buf String containing local HIT information.
 *
 * @return 0 on success, -1 on errors.
 **/
static int hit_db_parse_local(char *buf)
{
    int err = 0, n;
    char name[MAX_NAME_LEN + 1], hit[128];
    struct in6_addr lhit;

    /* Parse values from current line. */
    n = sscanf(buf, "\"%64[^\"]\" %s", name, hit);
    HIP_IFEL(n != 2, -1, "Broken line in database file: %s\n", buf);
    read_hit_from_buffer(&lhit, hit);
    hit_db_add_local(name, &lhit);

out_err:
    return err;
}

/**
 * hit_db_add_rgroup - Adds a remote group to the database
 *
 * @param name Name of the group
 * @param lhit Local HIT to associate the group with
 * @param accept Do we accept HITs belonging to this group or not
 * @param lightweight 1 if lightweight group
 *
 * @return Returns pointer to new group or if group already existed, pointer
 *	   to old one. Returns NULL on errors.
 * @note The lightweight parameter is a place marker for Lightweight HIP not
 *       used at the moment, for now use zero.
 **/
HIT_Group *hit_db_add_rgroup(char *name, HIT_Local *lhit,
                             int accept, int lightweight)
{
    HIT_Group *g, *err = NULL;
    char insert_into[256];
    int ret = 0;
    extern sqlite3 *agent_db;
    extern int init_in_progress;

    /* Check group name length. */
    HIP_IFEL(strlen(name) < 1, NULL, "Remote group name too short.\n");

    /* Check database for group already with same name. */
    g = hit_db_find_rgroup(name);
    HIP_IFE(g != NULL, g);

    /* Allocate new remote group item. */
    g = (HIT_Group *) malloc(sizeof(HIT_Group));
    HIP_IFEL(g == NULL, NULL, "Failed to allocate new remote group item.\n");

    /* Setup remote group item. */
    memset(g, 0, sizeof(HIT_Group));
    NAMECPY(g->name, name);
    g->l           = lhit;
    g->accept      = accept;
    g->lightweight = lightweight;
    g->remotec     = 0;

    /* Add remote group item to database. */
    if (group_db == NULL) {
        group_db = g;
    } else {      group_db_last->next = (void *) g;
    }

    group_db_last = g;
    group_db_n++;

    /* add the group also to the db on disk
     * " deny" group is not necessary on disk?*/
    if (init_in_progress == 1 && strcmp(" deny", g->name)) {
        sprintf(insert_into, "INSERT INTO groups VALUES("
                             "'%s', '%s', %d, %d);",
                g->name, g->l->name, g->accept, g->lightweight);
        ret = hip_sqlite_insert_into_table(agent_db, insert_into);
    }
    /* Tell GUI to show new group item. */
    if (g->name[0] != ' ') {
        _HIP_DEBUG("New group added with name \"%s\", calling GUI to show it.\n", name);
        gui_group_remote_add(g->name);
    }
    err = g;

out_err:
    return err;
}

/**
 * hit_db_del_rgroup - Delete remote group from HIT remote group table in the database.
 *
 * @param name of the group to be removed
 *
 * @return @return 0 on success, -1 on errors.
 **/
int hit_db_del_rgroup(char *name)
{
    HIT_Group *g, *g2;
    int err = 0;
    char delete_from[256];
    extern sqlite3 *agent_db;

    /* Find group from database first. */
    g = hit_db_find_rgroup(name);
    HIP_IFEL(!g, -1, "Tried to delete unexisting group \"%s\" from database", name);

    /* If group is first group.. */
    if (g == group_db) {
        group_db = (HIT_Group *) g->next;
        if (g == group_db_last) {
            group_db_last = NULL;
        }
    } else {
        /* Find previous group from database. */
        g2       = group_db;
        while (g2->next != (void *) g && g2) {
            g2 = (HIT_Group *) g2->next;
        }
        HIP_IFEL(!g2, -1, "Could not find previous group for group \"%s\"!\n",
                 name);
        g2->next = g->next;
        if (g == group_db_last) {
            group_db_last = g2;
        }
    }
    /* Mirror the delete to the db on disk */
    sprintf(delete_from, "DELETE FROM groups WHERE gname = '%s';", name);
    _HIP_DEBUG("DEL :: %s\n", delete_from);
    HIP_IFEL(hip_sqlite_delete_from_table(agent_db, delete_from),
             -1, "Failed to execute delete query group table\n");

    gui_group_remote_del(name);
    free(g);
    group_db_n--;

    /* If this was last group, (re-)create default group. */
    if (group_db_n < 1) {
        hit_db_add_rgroup(lang_get("default-group-name"), local_db, HIT_ACCEPT, 0);
    }

out_err:
    return err;
}

/**
 * hit_db_find_rgroup - Find a group from remote group database.
 *
 * @param name Name of remote group to be searched.
 *
 * @return Pointer to group found, or NULL if none found.
 **/
HIT_Group *hit_db_find_rgroup(const char *name)
{
    HIT_Group *g;

    g = group_db;
    while (g != NULL) {
        if (strncmp(g->name, name, MAX_NAME_LEN) == 0) {
            break;
        }
        g = (HIT_Group *) g->next;
    }

    return g;
}

/**
 * hit_db_add_local - Add new local HIT database.
 *
 * @param name Name of the HIT to be added
 * @param hit HIT to be added
 *
 * @return Returns pointer to new HIT or if HIT already existed, pointer
 *         to old one. Returns NULL on errors.
 *
 * @note Notice that this function doesn't lock the database!
 **/
HIT_Local *hit_db_add_local(char *name, struct in6_addr *hit)
{
    HIT_Local *h, *err = NULL;
    char lhit[128];
    char insert_into[256];
    int ret = 0;
    extern sqlite3 *agent_db;
    extern int init_in_progress;

    /* Check HIT name length. */
    HIP_IFEL(strlen(name) < 1, NULL, "Local HIT name too short.\n");

    /* Check database for HIT already with same name. */
    h = hit_db_find_local(name, NULL);
    HIP_IFE(h != NULL, h);
    h = hit_db_find_local(NULL, hit);
    HIP_IFE(h != NULL, h);

    /* Allocate new remote group item. */
    h = (HIT_Local *) malloc(sizeof(HIT_Local));
    HIP_IFEL(h == NULL, NULL, "Failed to allocate new local HIT.\n");

    /* Setup local HIT. */
    memset(h, 0, sizeof(HIT_Local));
    NAMECPY(h->name, name);
    memcpy(&h->lhit, hit, sizeof(struct in6_addr));

    /* Add local HIT to database. */
    if (local_db == NULL) {
        local_db = h;
    } else {      local_db_last->next = (void *) h;
    }

    local_db_last = h;
    local_db_n++;

    /* Add it also to the db on disk */
    if (init_in_progress == 1) {
        HIP_DEBUG("Saving local value to disk\n");
        print_hit_to_buffer(lhit, hit);
        sprintf(insert_into, "INSERT INTO local VALUES("
                             "'%s', '%s');", name, lhit);
        ret = hip_sqlite_insert_into_table(agent_db, insert_into);
    }

    _HIP_DEBUG("Group database empty, adding default group.\n");
    hit_db_add_rgroup(lang_get("default-group-name"), h, HIT_ACCEPT, 0);

    _HIP_DEBUG("New local HIT added with name \"%s\", calling GUI to show it.\n", name);
    err = h;

out_err:
    return err;
}

/**
 * hit_db_find_local - Find a local HIT from database.
 *
 * @param name Name of HIT to be searched.
 * @param hit HIT to be searched.
 *
 * @return Pointer to HIT found, or NULL if none found.
 **/
HIT_Local *hit_db_find_local(char *name, struct in6_addr *hit)
{
    HIT_Local *h;
    int err;

    h = local_db;
    while (h != NULL) {
        err = 0;
        if (name == NULL) {
            err++;
        } else if (strncmp(h->name, name, MAX_NAME_LEN) == 0) {
            err++;
        }
        if (hit == NULL) {
            err++;
        } else if (memcmp(&h->lhit, hit, sizeof(struct in6_addr)) == 0) {
            err++;
        }

        if (err == 2) {
            break;
        }
        h = (HIT_Local *) h->next;
    }

    return h;
}

/**
 * hit_db_enum_locals - Enumerate all local HITs in database. This function locks the database.
 *
 * @param f Function to call for every local HIT in database. This function
 *          should return 0 if continue enumeration and something else, if
 *          enumeration should be stopped.
 *
 * @return Number of HITs enumerated.
 **/
int hit_db_enum_locals(int (*f)(HIT_Local *))
{
    /* Variables. */
    HIT_Local *h;
    int err = 0, n = 0;

    h = local_db;
    while (h != NULL && err == 0) {
        err = f(h);
        n++;
        h   = (HIT_Local *) h->next;
    }

    _HIP_DEBUG("Enumerated %d local HITs.\n", n);

    return n;
}

/**
 * hit_db_count_locals - Return number of local HITs in database.
 *
 * @return Number of local HITs.
 */
int hit_db_count_locals(void)
{
    return local_db_n;
}
