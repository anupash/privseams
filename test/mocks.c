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
 * @brief Mock functions for unit tests.
 *
 * Because unit tests should be self-contained and predictable, testing
 * functions that rely on external state can be tricky. Sometimes, the easiest
 * solution lies in overloading certain library functions with so-called
 * <i>mock functions</i> that simulate those calls and produce user-supplied
 * fake output.
 *
 * <h2>Short tutorial</h2>
 * - In Makefile.am
 *   - add test/mock.c to your check program's _SOURCE,
 *   - add -ldl to your check program's _LDFLAGS.
 * - Copy & Paste one of the implementations below.
 *
 *
 * <h2>Background</h2>
 *
 * Mock functions in HIPL are implemented using the fact that the linker tries
 * to satisfy declarations by using statically defined symbols first, before
 * resorting to dynamic libraries.
 * In other words: providing an implementation with the exact same prototype as
 * the library function is all you need, first of all.
 *
 * Mocks can be defined in the file they're needed in, but beware:
 * The overriding implementation's definition cannot be static: a compiler error
 * will be emitted. On the other hand, a non-static definition will be picked up
 * by other object files in the same test suite, i.e. they will invariably use
 * your mock function which may not be intended.
 * This also implies that each other suite can not define an own implementation
 * due to "duplicate symbol" errors.
 *
 * For this reason, and to encourage modularity, mock functions should be
 * defined in this file. They should be opt-in by enabling a global boolean
 * flag, in order not to disrupt other unit tests.
 * Remember that each test runs in a process of its own, so the flags must be
 * set at the beginning of each.
 *
 * @note The documentation implies that argments of disabled mock functions are
 *       passed to the original implementation.
 *
 * @author Christof Mroz <christof.mroz@rwth-aachen.de>
 */

//
// RTLD_NEXT is optional in POSIX, and unit tests relying on mock functions will
// be silently ignored on systems that don't support it. See get_original().
//
// Some libc implementations (e.g. uclibc) export RTLD_NEXT by default, if
// supported. glibc considers this a GNU extension, so we pass _GNU_SOURCE
// (which should not affect non-glibc systems).
//
#define _GNU_SOURCE

#include <check.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "test/mocks.h"


// A NULL argument to dlsym() is allowed as per POSIX, and may do the trick,
// even though the chances are slim. We try it anyway.
#ifndef RTLD_NEXT
#define RTLD_NEXT NULL
#endif

/**
 * Retrieve a pointer to the real implementation of the library function
 * name by symbol @a name.
 * Exits with status 0 if it cannot be retrieved.
 *
 * @param mock A pointer to the mock function. This is used to guard against
 *             returning a pointer to the mock rather than the real function
 *             instead, which would in turn be called by the mock itself and so
 *             on, thereby triggering infinite recursion.
 * @param name Symbolic (i.e. exported) name, of the original function. It will
 *             be searched in default shared object load order and the first
 *             occurence retrieved.
 * @return     Function pointer to import symbol @a name.
 *             Does not return on failure.
 */
static void *get_original(const void *const mock, const char *const name)
{
    void *ret = dlsym(RTLD_NEXT, name);

    fail_if(!ret, "dlsym(\"%s\"): %s\n", name, dlerror());
    fail_if(!mock);

    // Avoid infinite recursion. This can happen if RTLD_NEXT was aliased to
    // NULL above.
    if (ret == mock) {
        fprintf(stderr,
                "Skipping check: function chaining not supported by lib\n");
        exit(EXIT_SUCCESS);
    }

    return ret;
}

/*** time(2) ***/

bool   mock_time = false; /**< time(2) mock enabled? */
time_t mock_time_next;    /**< value returned on next invocation of time(2) mock */

/**
 * time(2) mock function. Controlled by the ::mock_time flag.
 * Returns the preset value ::mock_time_next, if enabled.
 *
 * @param t If non-NULL, the return value is also stored in the memory pointed
 *          to by @a t.
 * @return  The current value of ::mock_time_next.
 */
time_t time(time_t *t) {
    if (!mock_time) {
        time_t (*original)(time_t*) = get_original(time, "time");
        return original(t);
    }


    if (t) {
        *t = mock_time_next;
    }

    return mock_time_next;
}

/*** system(3) ***/

bool  mock_system      = false;
char *mock_system_last = NULL;
int   mock_system_exit = EXIT_SUCCESS;

/**
 * system(3) mock function. Controlled by the ::mock_system flag.
 * Stores a copy of @a command in ::mock_system_last, if enabled.
 *
 * @param command A copy of this string will be stored in ::mock_system_last of
 *                non-NULL. Otherwise, ::mock_system_last is set to NULL.
 * @return        The value of ::mock_system_exit if @a command was non-NULL, -1
 *                otherwise.
 */
int system(const char *command) {
    if (!mock_system) {
        int (*original)(const char *) = get_original(system, "system");
        return original(command);
    }

    free(mock_system_last);
    if (command) {
        mock_system_last = strdup(command);
    } else {
        mock_system_last = NULL;
        return -1;
    }

    return mock_system_exit;
}
