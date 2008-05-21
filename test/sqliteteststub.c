/** @file
 * A teststub for certtools.c/h
 *
 * File for testing the main operations of certtools.
 * First this test takes the default HIT and the corresponding key.
 * Secondly it creates a certificate where itself is the issuer and the subject.
 * Then it tries to verify it. If it succeeds everything should be OK :)
 *
 * @author Samu Varjonen
 * @version 0.1
 * @date 31.3.2008
 *
 */

#include "utils.h"
#include "sqlitedbapi.h"
 
int main(int argc, char *argv[]) {
        int err = 0;
        sqlite3 * db;
        char dbpath[256];
 
        HIP_IFEL(hip_tmpname(dbpath), -1, 
                 "Failed to make tmp name for the database\n");
        HIP_IFEL(hip_sqlite_open_db(db, dbpath, 0), -1,
                 "Failed to open/create the database\n");

 out_err:
        return(err);
}
