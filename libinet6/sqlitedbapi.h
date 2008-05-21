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

#define HIP_CERT_DB_PATH_AND_NAME "/etc/hip/certdb"

int hip_sqlite_open_db(sqlite3 *, char *, int);
int hip_sqlite_close_db(sqlite3 *);

#endif /* HIP_SQLITEDBAPI_H */
