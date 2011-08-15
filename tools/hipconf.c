/*
 * Copyright (c) 2010 Aalto University and RWTH Aachen University.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

/**
 * @file
 * This file defines the main function of the command line tool 'hipconf'.
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
int main(int argc, const char *argv[])
{
    int err = 0;

    /* we don't want log messages via syslog */
    hip_set_logtype(LOGTYPE_STDERR);
    hip_set_logfmt(LOGFMT_SHORT);

    /* Reenable logging for hipconf. Since hipconf reads the hipd configuration
     * file, hipconf will be silent if debug level is set to none there. */
    hip_set_logdebug(LOGDEBUG_ALL);

    HIP_IFEL(hip_do_hipconf(argc, argv, 0), -2,
             "Error: Cannot configure the HIP daemon.\n");

out_err:
    return err;
}
