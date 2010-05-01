/** @file
 * utility functions
 * @author Diego Biurrun <diego@biurrun.de>
 */

#include <stdio.h>
#include <stdlib.h>

#include "config.h"
#include "util.h"
#include "version.h"

/**
 * Print version information to stdout.
 */
int hip_print_version(const char *name)
{
    printf("%s %s (Bazaar branch-nick: '%s', revision: %s)\n",
           name, VERSION, BZR_BRANCH, BZR_REVISION);
    printf("build configuration: %s\n", HIPL_CONFIGURATION);
    exit(EXIT_SUCCESS);
}
