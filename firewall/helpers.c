#include "helpers.h"

#include <linux/types.h>
#include <limits.h>
#include <linux/netfilter_ipv6.h>


/**
 * get char* out of in6_addr
 */
char *addr_to_numeric(const struct in6_addr *addrp)
{
    static char buf[50 + 1];
    return (char *) inet_ntop(AF_INET6, addrp, buf, sizeof(buf));
}

/**
 * get in6_addr out of char*
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
 **/
void system_print(char *command)
{
    if (system(command) == -1) {
        HIP_ERROR("Could not execute system command %s", command);
    }
}
