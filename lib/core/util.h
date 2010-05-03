/** @file
 * utility functions
 * @author Diego Biurrun <diego@biurrun.de>
 */

#ifndef HIP_LIB_CORE_UTIL_H
#define HIP_LIB_CORE_UTIL_H

#include <stdio.h>

#include "config.h"
#include "util.h"
#include "version.h"

/**
 * Print version information to stdout.
 */
static inline void hip_print_version(const char *name)
{
    printf("%s %s (Bazaar branch-nick: '%s', revision: %s)\n",
           name, VERSION, BZR_BRANCH, BZR_REVISION);
    printf("build configuration: %s\n", HIPL_CONFIGURATION);
}

#endif /* HIP_LIB_CORE_UTIL_H */
