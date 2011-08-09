/*
 * Copyright (c) 2010-2011 Aalto University and RWTH Aachen University.
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
 * The HIPL main file containing the daemon main function.
 */

#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>


#include "hipd/hipd.h"
#include "init.h"
#include "lib/core/debug.h"


/**
 * the main function for hipd
 *
 * @param argc number of command line arguments
 * @param argv the command line arguments
 * @return zero on success or negative on error
 */
int main(int argc, char *argv[])
{
    uint64_t sflags = HIPD_START_FOREGROUND | HIPD_START_LOWCAP;

    /* The flushing is enabled by default. The reason for this is that
     * people are doing some very experimental features on some branches
     * that may crash the daemon and leave the SAs floating around to
     * disturb further base exchanges. Use -N flag to disable this. */
    sflags |= HIPD_START_FLUSH_IPSEC;

    /* The default behaviour is to allow hipd to load the required modules
     * and unload them when exiting.
     */
    sflags |= HIPD_START_LOAD_KMOD;

    /* set the initial verbosity level */
    hip_set_logdebug(LOGDEBUG_MEDIUM);

    /* One should be able to check the hipd version and usage,
     * even without having root privileges.
     */
    if (hipd_parse_cmdline_opts(argc, argv, &sflags)) {
        return EXIT_SUCCESS;
    }

    /* We need to recreate the NAT UDP sockets to bind to the new port. */
    if (getuid()) {
        HIP_ERROR("hipd must be started as root!\n");
        return EXIT_FAILURE;
    }

    if (hipd_main(sflags)) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
