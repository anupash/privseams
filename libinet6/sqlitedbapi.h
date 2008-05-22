#ifndef HIP_SQLITEDBAPI_H
#define HIP_SQLITEDBAPI_H

/** @file
 * A header file for sqlitedbapi.c
 *
 * All functions needed for the sqlite usage in HIPL
 *
 * @author Samu Varjonen
 * @version 0.1
 * @date 31.3.2008
 *
 */

#include <stdio.h>
#include <sqlite3.h>
#include "debug.h"
#include "ife.h"

#define HIP_CERT_DB_PATH_AND_NAME "/etc/hip/certdb.db"

sqlite3 * hip_sqlite_open_db(const char *, const char *);
int hip_sqlite_close_db(sqlite3 *);
int hip_sqlite_select(sqlite3 *, const char *, 
                             int (*callback)(void*,int,char**,char**));
int hip_sqlite_execute_into_db(sqlite3 *, const char *);
/* These three functions are just wrappers for the one in above */
int hip_sqlite_delete_from_table(sqlite3 *, const char *);
int hip_sqlite_insert_into_table(sqlite3 *, const char *);
int hip_sqlite_create_table(sqlite3 *, const char *);
#endif /* HIP_SQLITEDBAPI_H */
