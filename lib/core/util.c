/** @file
 * utility functions
 * @author Diego Biurrun <diego@biurrun.de>
 */

#include <stdio.h>
#include <stdlib.h>

#include "config.h"
#include "version.h"

/**
 * Print version information to stdout.
 */
int hip_print_version(const char *name)
{
    printf("%s %s (Bazaar revision %s)\n", name, VERSION, BZR_REVISION);
    printf("build configuration: %s\n", HIPL_CONFIGURATION);
    exit(EXIT_SUCCESS);
}
