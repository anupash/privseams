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
 * HIP Firewall entry point and command line interface.
 *
 * @note Functionality should be kept at a minimum, because linking this
 *       object causes a "symbol defined already" error if an alternative
 *       entry point is used, e.g. for unit tests. Put more simply:
 *       Anything defined here will be unavailable in these cases.
 */

#define _BSD_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

#include "lib/core/filemanip.h"
#include "lib/core/debug.h"
#include "lib/core/util.h"
#include "firewall.h"
#include "conntrack.h"


/**
 * Print usage of firewall to stdout.
 */
static void hipfw_usage(void)
{
    puts("HIP Firewall");
    puts("Usage: hipfw [-f file_name] [-d|-v] [-A] [-F] [-H] [-b] [-a] [-c] [-k] [-i|-I|-e] [-l] [-o] [-p] [-t <seconds>] [-u] [-h] [-V]");
#ifdef CONFIG_HIP_MIDAUTH
    puts(" [-m]");
#endif
    puts("");
    puts("      -f file_name = is a path to a file containing firewall filtering rules");
    puts("      -V = print version information and exit");
    puts("      -d = debugging output");
    puts("      -v = verbose output");
    puts("      -A = accept all HIP traffic, still do HIP filtering (default: drop all non-authenticated HIP traffic)");
    puts("      -F = accept all HIP traffic, deactivate HIP traffic filtering");
    puts("      -H = drop all non-HIP traffic (default: accept non-HIP traffic)");
    puts("      -b = fork the firewall to background");
    puts("      -k = kill running firewall pid");
    puts("      -i = switch on userspace ipsec");
    puts("      -I = as -i, also allow fallback to kernel ipsec when exiting hipfw");
    puts("      -e = use esp protection extension (also sets -i)");
    puts("      -l = activate lsi support");
    puts("      -p = run with lowered privileges. iptables rules will not be flushed on exit");
    puts("      -t <seconds> = set timeout interval to <seconds>. Disable if <seconds> = 0.\n");
    puts("      -u = prefer userspace processing: don't add iptables rules for speedups\n");
    puts("      -h = print this help");
#ifdef CONFIG_HIP_MIDAUTH
    puts("      -m = middlebox authentication");
    puts("      -w = IP address of web-based authentication server");
#endif
    puts("");
}

/**
 * Entry-point for the HIP Firewall.
 * Parses the given command line options and delegates control to the
 * actual firewall code if successful. May fork into background beforehand,
 * if demanded by the user.
 *
 * @param argc Number of command line arguments.
 * @param argv An array of pointers to the command line arguments.
 *
 * @return Either EXIT_SUCCESS or EXIT_FAILURE.
 *
 * @see hipfw_main()
 */
int main(int argc, char *argv[])
{
    bool        foreground         = true;
    bool        kill_old           = false;
    bool        limit_capabilities = false;
    const char *rule_file          = NULL;

    char *end_of_number;
    int   ch;

    /* Make sure that root path is set up correctly (e.g. on Fedora 9).
     * Otherwise may get warnings from system_print() commands. */
    setenv("PATH", HIP_DEFAULT_EXEC_PATH, 1);

    while ((ch = getopt(argc, argv, "aAbcdef:FhHiIklmpt:uvV")) != -1) {
        switch (ch) {
        case 'A':
            accept_hip_esp_traffic_by_default = 1;
            restore_accept_hip_esp_traffic    = 1;
            break;
        case 'b':
            foreground = 0;
            break;
        case 'd':
            log_level = LOGDEBUG_ALL;
            break;
        case 'e':
            hip_esp_protection = 1;
            break;
        case 'f':
            rule_file = optarg;
            break;
        case 'F':
            filter_traffic         = 0;
            restore_filter_traffic = filter_traffic;
            break;
        case 'h':
            hipfw_usage();
            return EXIT_SUCCESS;
        case 'H':
            accept_normal_traffic_by_default = 0;
            break;
        case 'i':
            hip_userspace_ipsec       = 1;
            hip_kernel_ipsec_fallback = 0;
            break;
        case 'I':
            hip_userspace_ipsec       = 1;
            hip_kernel_ipsec_fallback = 1;
            break;
        case 'k':
            kill_old = 1;
            break;
        case 'l':
            hip_lsi_support = 1;
            break;
        case 'm':
#ifdef CONFIG_HIP_MIDAUTH
            filter_traffic = 1;
            use_midauth    = 1;
            break;
#endif
        case 'p':
            limit_capabilities = 1;
            break;
        case 't':
            connection_timeout = strtoul(optarg, &end_of_number, 10);
            if (end_of_number == optarg) {
                fprintf(stderr, "Error: Invalid timeout given\n");
                hipfw_usage();
                return EXIT_FAILURE;
            }
            if (connection_timeout < cleanup_interval) {
                /* we must poll at least once per timeout interval */
                cleanup_interval = connection_timeout;
            }
            break;
        case 'u':
            prefer_userspace = 1;
            break;
        case 'v':
            log_level = LOGDEBUG_MEDIUM;
            hip_set_logfmt(LOGFMT_SHORT);
            break;
        case 'V':
            hip_print_version("hipfw");
            return EXIT_SUCCESS;
        case ':':         /* option without operand */
            printf("Option -%c requires an operand\n", optopt);
            hipfw_usage();
            return EXIT_FAILURE;
        case '?':
            printf("Unrecognized option: -%c\n", optopt);
            hipfw_usage();
            return EXIT_FAILURE;
        }
    }

    if (geteuid() != 0) {
        HIP_ERROR("Firewall must be run as root\n");
        exit(-1);
    }

    if (!foreground) {
        hip_set_logtype(LOGTYPE_SYSLOG);
        HIP_DEBUG("Forking into background\n");
        if (fork() > 0) {
            return EXIT_SUCCESS;
        }
    }

    return hipfw_main(rule_file, kill_old, limit_capabilities) == 0 ? EXIT_SUCCESS
                                                                    : EXIT_FAILURE;
}
