/** @file
 * This file defines the main function of the command line tool 'hipconf'.
 *
 * @author  Miika Komu <miika_iki.fi>
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 * @bug     makefile compiles prefix of debug messages wrong for hipconf in
 *          "make all"
 */

#include "lib/core/conf.h"
#include "lib/core/debug.h"
#include "lib/core/ife.h"

/**
 * Sets system log type and calls hipconf with command line arguments.
 *
 * @param argc   the number of elements in the array @c argv.
 * @param argv   an array of pointers to the command line arguments after
 *               the action and type.
 * @return       zero on success, or negative error value on error.
 */
int main(int argc, char *argv[])
{
    int err = 0;

    /* we don't want log messages via syslog */
    hip_set_logtype(LOGTYPE_STDERR);
    hip_set_logfmt(LOGFMT_SHORT);

    // workaround for bug #604
    hip_set_logdebug(LOGDEBUG_ALL);

    HIP_IFEL(hip_do_hipconf(argc, argv, 0), -2,
             "Error: Cannot configure the HIP daemon.\n");

out_err:
    return err;
}
