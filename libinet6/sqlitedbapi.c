/** @file
 * This file defines the api for sqlite to use with HIPL
 *
 * @author Samu Varjonen
 * @version 0.1
 * @date 21.5.2008
 *
 */

#include "sqlitedbapi.h"

/**
 * Function that opens the database, can also create the database 
 *
 * @param db is where a pointer to the database is to be stored
 * @param db_path is a char pointer pointing telling where the db is
 * @param create is used to tell if the db is to be created 
 * (0 is to create otherwise not)
 *
 * @return 0 if created and/or opened OK otherwise negative
 */
int hip_sqlite_open_db(sqlite3 *db, char * db_path, int create) {
        int err = 0;

        if (create) {
                HIP_DEBUG("Using open rw and create flags\n");
        } else {
                HIP_DEBUG("Using open rw flags\n");

        }
        HIP_DEBUG("Opening the db\n");
        HIP_IFEL(!sqlite3_open(db_path, db), -1,
                 "Failed to open db\n"); 
 out_err:
        return(err);
}

/**
 * Function that closes the database 
 *
 * @param db a pointer to the database
 *
 * @return 0 if closed ok
 *
 * @note may be useless function
 */
int hip_sqlite_close_db(sqlite3 * db) {
        int err = 0;
        HIP_IFEL(sqlite3_close(db), -1, "Failed to close that db\n");
 out_err:
        return(err);
}
