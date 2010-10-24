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
 * utility functions
 * @author Diego Biurrun <diego@biurrun.de>
 */

#ifndef HIP_LIB_CORE_UTIL_H
#define HIP_LIB_CORE_UTIL_H

#include <stdio.h>

#include "config.h"
#include "version.h"

/**
 * Print version information to stdout.
 */
static inline void hip_print_version(const char *name)
{
    printf("%s %s (Bazaar branch-nick: '%s', revision: %s, commit date: '%s')\n",
           name, VERSION, BZR_BRANCH, BZR_REVISION, BZR_DATE);
    printf("build configuration: %s\n", HIPL_CONFIGURATION);
}

#endif /* HIP_LIB_CORE_UTIL_H */
