/**
 * @file
 *
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
 *
 * @brief Few "utility" functions for the firewall
 *
 * @author Essi Vehmersalo
 *
 * @todo the actual utility of this file seems questionable (should be removed)
 */

#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "lib/core/debug.h"
#include "helpers.h"

/**
 * A wrapper for inet_ntop(). Converts a numeric IPv6 address to a string.
 *
 * @param addrp an IPv6 address to be converted to a string
 *
 * @return A static pointer to a string containing the the IPv6 address.
 *         Caller must not try to deallocate. On error, returns NULL and sets
 *         errno (see man inet_ntop).
 *
 * @note this function is not re-entrant and should not be used with threads
 *
 */
const char *addr_to_numeric(const struct in6_addr *addrp)
{
    static char buf[50 + 1];
    return inet_ntop(AF_INET6, addrp, buf, sizeof(buf));
}

/**
 * A wrapper for inet_pton(). Converts a string to a numeric IPv6 address
 *
 * @param num the string to be converted into an in6_addr structure
 *
 * @return A static pointer to an in6_addr structure corresponding to the
 *         given "num" string. Caller must not try to deallocate.
 *         On error, returns NULL and sets errno (see man inet_ntop).
 *
 * @note this function is not re-entrant and should not be used with threads
 */
struct in6_addr *numeric_to_addr(const char *num)
{
    static struct in6_addr ap;
    int err;
    if ((err = inet_pton(AF_INET6, num, &ap)) == 1) {
        return &ap;
    }
    return (struct in6_addr *) NULL;
}

/**
 * Executes a system command and prints an error if
 * command wasn't successfull.
 *
 * @param command The system command. The caller of
 *                this function must take care that
 *                command does not contain malicious
 *                code.
 */
void system_print(const char *command)
{
    if (system(command) == -1) {
        HIP_ERROR("Could not execute system command %s", command);
    }
}
