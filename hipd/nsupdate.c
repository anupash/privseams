/**
 * @file
 *
 * Copyright (c) 2010 Aalto University) and RWTH Aachen University.
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
 * @brief Update DNS data for the hit-to-ip domain name.
 * @brief It executes an external perl script for each HIT
 * @brief and passes it a list of the current IP addresses.
 *
 * @brief hip_set_nsupdate_status and hip_get_nsupdate_status are usually invoked by hipconf
 * @brief and nsupdate by hip_send_locators_to_all_peers and hipd_init
 *
 * @author Oleg Ponomarev <oleg.ponomarev@hiit.fi>
 */

#define _BSD_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "lib/core/common.h"
#include "lib/core/debug.h"
#include "lib/core/hit.h"
#include "lib/core/ife.h"
#include "lib/core/list.h"
#include "lib/core/prefix.h"
#include "lib/core/state.h"
#include "lib/tool/nlink.h"
#include "config.h"
#include "hidb.h"
#include "hipd.h"
#include "nsupdate.h"

// parameters for nsupdate.pl
#define VAR_IPS "HIPD_IPS"
#define VAR_HIT "HIPD_HIT"
#define VAR_START "HIPD_START"
#define NSUPDATE_ARG0 "nsupdate.pl"

// path to the perl script
#define NSUPDATE_PL HIPL_DEFAULT_PREFIX "/sbin/" "nsupdate.pl"

//  value to return by the function
#define ERR -1


int hip_nsupdate_status = 0;

/**
 * hip_set_nsupdate_status
 *
 * This function is an interface to turn on/off DNS updates
 *
 * @param status    0 unless DNS updates wanted, 1 otherwise
 */

void hip_set_nsupdate_status(int status)
{
    hip_nsupdate_status = status;
}

/**
 * hip_get_nsupdate_status
 *
 * This function is an interface to check if DNS updates are wanted
 *
 * @return  0 unless DNS updates wanted, 1 otherwise
 */

int hip_get_nsupdate_status(void)
{
    return hip_nsupdate_status;
}

/**
 * make_env
 *
 * returns string "name=value"
 * remember to free() the result afterwards
 *
 * @param name      string to put before '='
 * @param value     string to put after '='
 * @return          newly allocated string with result or NULL in case of error
 */

static char *make_env(const char *name, char *value)
{
    char *result = NULL;
    int err      = 0;

    if ((name == NULL) || (value == NULL)) {
        return NULL;
    }

    HIP_IFEL(!(result = malloc(strlen(name) + 1 + strlen(value) + 1)),
             -1, "malloc");     // name,'=',value,0

    strcpy(result, name);
    strcat(result, "=");
    strcat(result, value);

out_err:

    return result;
}

/**
 * sig_chld
 *
 * Handle child exits to avoid zombies
 *
 * @param signo number of the signal triggered the function
 *        Needed because of the signal-handler signature.
 */
static void sig_chld(UNUSED int signo)
{
    pid_t child_pid;
    int child_status;     // child exit code
    child_pid = waitpid(0, &child_status, WNOHANG);
}

/**
 * netdev_address_to_str
 *
 * This function converts the netdev_address structure src into
 * a character string, which is copied to a character buffer dst,
 * which is cnt bytes long.
 *
 * @param src       address in netdev_address structure
 * @param dst       buffer to store the address as string
 * @param cnt       length of the buffer dst
 * @return          On success, a non-null pointer to dst. NULL is returned
 *                  if there was an error, with errno set to indicate the error
 */

static const char *netdev_address_to_str(struct netdev_address *src, char *dst, socklen_t cnt)
{
    struct sockaddr *tmp_sockaddr_ptr         = (struct sockaddr *) &(src->addr);
    struct sockaddr_in  *tmp_sockaddr_in_ptr  = (struct sockaddr_in *)  tmp_sockaddr_ptr;
    struct sockaddr_in6 *tmp_sockaddr_in6_ptr = (struct sockaddr_in6 *) tmp_sockaddr_ptr;

    struct in_addr tmp_in_addr;
    struct in6_addr *tmp_in6_addr_ptr         = NULL;

    void *inet_ntop_src                       = NULL;
    int af                                    = tmp_sockaddr_ptr->sa_family; // might be changed because of ip4->ip6 mapping

    switch (af) {
    case AF_INET:
        inet_ntop_src    = &(tmp_sockaddr_in_ptr->sin_addr);
        break;

    case AF_INET6:
        tmp_in6_addr_ptr = &(tmp_sockaddr_in6_ptr->sin6_addr);
        if (IN6_IS_ADDR_V4MAPPED(tmp_in6_addr_ptr)) {
            IPV6_TO_IPV4_MAP(tmp_in6_addr_ptr, &tmp_in_addr)
            af            = AF_INET;
            inet_ntop_src = &tmp_in_addr;
        } else {
            inet_ntop_src = tmp_in6_addr_ptr;
        }
        break;
    }

    return inet_ntop(af, inet_ntop_src, dst, cnt);
}

/**
 * run_nsupdate
 *
 * Execute nsupdate.pl with IP addresses and HIT given as environment variables
 *
 * @param ips   comma-separated list of IP addresses as a string
 * @param hit   HIT as a string
 * @param start pass 1 if executed on start, then the update script will check first if update is needed
 * @return  0 on success, -1 otherwise
 */

static int run_nsupdate(char *ips, char *hit, int start)
{
    struct sigaction act;
    pid_t child_pid;

    HIP_DEBUG("Updating dns records...\n");

    act.sa_handler = sig_chld;

    /* We don't want to block any other signals */
    sigemptyset(&act.sa_mask);

    /*
     * We're only interested in children that have terminated, not ones
     * which have been stopped (eg user pressing control-Z at terminal)
     */
    act.sa_flags = SA_NOCLDSTOP | SA_RESTART;

    /* Make the handler effective */
    if (sigaction(SIGCHLD, &act, NULL) < 0) {
        HIP_PERROR("sigaction");
        return ERR;
    }

    /* Let us fork to execute nsupdate as a separate process */
    child_pid = fork();

    if (child_pid < 0) {
        HIP_PERROR("fork");
        return ERR;
    } else if (child_pid == 0)   { // CHILD
        char nsupdate_arg0[] = NSUPDATE_ARG0;
        char start_str[2];

        snprintf(start_str, sizeof(start_str), "%i", start);

        char *env_ips   = make_env(VAR_IPS, ips);
        char *env_hit   = make_env(VAR_HIT, hit);
        char *env_start = make_env(VAR_START, start_str);

        char *cmd[]           = { nsupdate_arg0, NULL };
        char *const env[]     = { env_ips, env_hit, env_start, NULL };

        HIP_DEBUG("Executing %s with %s; %s; %s\n", NSUPDATE_PL, env_hit, env_ips, env_start);
        execve(NSUPDATE_PL, cmd, env);

        if (env_ips) {
            free(env_ips);
        }
        if (env_hit) {
            free(env_hit);
        }
        if (env_start) {
            free(env_start);
        }

        /* Executed only if error */
        HIP_PERROR("execve");
        exit(1);         // just in case
    } else {  // PARENT
        /* We execute waitpid in SIGCHLD handler */
        return 0;
    }
}

/**
 * run_nsupdate_for_hit
 *
 * run nsupdate with the current HIT
 * called from hip_for_each_hi
 *
 * @param entry     iterator from the cycle
 * @param opaq      value of start to pass to run_nsupdate
 * @return          0
 */

static int run_nsupdate_for_hit(struct hip_host_id_entry *entry, void *opaq)
{
    int start          = 0;
    char ip_str[40];     // buffer for one IP address
    char ips_str[1024] = "";     // list of IP addresses
    hip_list_t *item, *tmp_hip_list_t;
    int i;
    char hit[INET6_ADDRSTRLEN + 2];

    if (opaq != NULL) {
        start = *(int *) opaq;
    }

    HIP_DEBUG("run_nsupdate_for_hit (start=%d)\n", start);

    hip_convert_hit_to_str(&entry->lhi.hit, NULL, hit);

    /* make space-separated list of IP addresses in ips_str */
    list_for_each_safe(item, tmp_hip_list_t, addresses, i) {
        struct netdev_address *n = list_entry(item);

        if (netdev_address_to_str(n, ip_str, sizeof(ip_str)) == NULL) {
            HIP_PERROR("netdev_address_to_str");
        } else {
            if (ips_str[0] != 0) {         // not empty
                strncat(ips_str, " ", sizeof(ips_str) - strlen(ips_str));
            }
            strncat(ips_str, ip_str, sizeof(ips_str) - strlen(ips_str));
        }
    }

    run_nsupdate(ips_str, hit, start);

    return 0;
}

/**
 * nsupdate
 *
 * Update records for all hits. The host should be able to send packets
 * to HITs to modify the DNS records
 *
 * @param start     pass 1 if executed on start, then the update script will
 *                  check first if update is needed
 * @return 0
 */
int nsupdate(int start)
{
    HIP_DEBUG("Updating dns records...\n");
    hip_for_each_hi(run_nsupdate_for_hit, &start);
    return 0;
}
