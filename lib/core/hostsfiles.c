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
 * This file contains iterator functions to access and parse
 * /etc/hosts and HIPL_SYSCONFDIR/hosts files. Also, this file contains
 * a number of predefined functions that support mapping between
 * hostnames, HITs, LSIs and routable IP addresses.
 *
 * @brief parser for /etc/hosts and HIPL_SYSCONFDIR/hosts
 *
 * @author Miika Komu <miika@iki.fi>
 *
 * @todo is there a standard API for accessing hosts files?
 */

#define _BSD_SOURCE

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "config.h"
#include "lib/tool/lutil.h"
#include "ife.h"
#include "prefix.h"
#include "protodefs.h"
#include "hostsfiles.h"

#define HOSTS_FILE "/etc/hosts"

struct hosts_file_line {
    char           *hostname, *alias, *alias2;
    struct in6_addr id;
    int             lineno;
};

/**
 * "For-each" loop to iterate through /etc/hosts or HIPL_SYSCONFDIR/hosts
 * file, line by line.
 *
 * @param hosts_file the path and name to the hosts file
 * @param func the iterator function pointer
 * @param arg an input argument for the function pointer
 * @param result an output argument for the function pointer
 * @return zero on success or non-zero on failure
 */
static int hip_for_each_hosts_file_line(const char *hosts_file,
                                        int(*func)(const struct hosts_file_line *line,
                                                   const void *arg,
                                                   void *result),
                                        const void *arg,
                                        void *result)
{
    FILE                  *hip_hosts = NULL;
    struct list            mylist;
    char                   line[500];
    int                    err = 0, lineno = 0;
    struct in_addr         in_addr;
    struct hosts_file_line entry;
    char                  *hostname = NULL, *alias = NULL, *alias2 = NULL, *addr_ptr = NULL;

    initlist(&mylist);

    /* check whether  given hit_str is actually a HIT */

    hip_hosts = fopen(hosts_file, "r");

    HIP_IFEL(!hip_hosts, -1, "Failed to open hosts file\n");

    /* For each line in the given hosts file, convert the line into binary
     * format and call the given the handler  */

    err = 1;
    while (fgets(line, sizeof(line) - 1, hip_hosts) != NULL) {
        char *eofline, *c, *comment;
        int   len;

        lineno++;
        c = line;

        /* Remove whitespace */
        while (*c == ' ' || *c == '\t') {
            c++;
        }

        /* Line is a comment or empty */
        if (*c == '#' || *c == '\n' || *c == '\0') {
            continue;
        }

        eofline = strchr(c, '\n');
        if (eofline) {
            *eofline = '\0';
        }

        /* Terminate before (the first) trailing comment */
        comment = strchr(c, '#');
        if (comment) {
            *comment = '\0';
        }

        /* shortest hostname: ":: a" = 4 */
        if ((len = strlen(c)) < 4) {
            HIP_DEBUG("skip line\n");
            continue;
        }

        /* Split line into list */
        extractsubstrings(c, &mylist);

        len = length(&mylist);
        if (len < 2 || len > 4) {
            HIP_ERROR("Bad number of items on line %d in %s, skipping\n",
                      lineno, hosts_file);
            continue;
        }

        /* The list contains hosts line in reverse order. Let's sort it. */
        switch (len) {
        case (2):
            alias    = NULL;
            hostname = getitem(&mylist, 0);
            addr_ptr = getitem(&mylist, 1);
            break;
        case (3):
            alias    = getitem(&mylist, 0);
            hostname = getitem(&mylist, 1);
            addr_ptr = getitem(&mylist, 2);
            break;
        case (4):
            alias2   = getitem(&mylist, 0);
            alias    = getitem(&mylist, 1);
            hostname = getitem(&mylist, 2);
            addr_ptr = getitem(&mylist, 3);
            break;
        }

        HIP_ASSERT(addr_ptr);
        err = inet_pton(AF_INET6, addr_ptr, &entry.id);
        if (err <= 0) {
            err = inet_pton(AF_INET, addr_ptr, &in_addr);
            if (err <= 0) {
                HIP_ERROR("Bad address %s on line %d in %s, skipping\n",
                          addr_ptr, lineno, hosts_file);
                continue;
            }
            IPV4_TO_IPV6_MAP(&in_addr, &entry.id);
        }

        entry.hostname = hostname;
        HIP_ASSERT(entry.hostname)

        entry.alias2 = alias2;
        entry.alias  = alias;
        entry.lineno = lineno;

        /* Finally, call the handler function to handle the line */

        if (func(&entry, arg, result) == 0) {
            err = 0;
            break;
        }

        destroy(&mylist);
    }

out_err:

    destroy(&mylist);

    if (hip_hosts) {
        fclose(hip_hosts);
    }

    return err;
}

/**
 * A "for-each" iterator function for hosts files that returns the first
 * hostname that matches the given address
 *
 * @param entry a hosts file line entry
 * @param arg the IPv6 or IPv6-mapped IPv4 address to match
 * @param result An output argument where the matching hostname will be
 *        written. Minimum buffer length is HOST_NAME_MAX chars.
 * @return zero on match or one otherwise
 */
static int hip_map_first_id_to_hostname_from_hosts(const struct hosts_file_line *entry,
                                                   const void *arg,
                                                   void *result)
{
    int err = 1;

    if (!ipv6_addr_cmp(arg, &entry->id)) {
        memcpy(result, entry->hostname, strlen(entry->hostname));
        err = 0; /* Stop at the first match */
    }

    return err;
}

/**
 * A "for-each" iterator function for hosts files that returns the first
 * hostname that matches the given LSI
 *
 * @param entry a hosts file line entry
 * @param arg an IPv6-mapped LSI to match
 * @param result An output argument where the matching hostname will be
 *        written. Minimum buffer length is HOST_NAME_MAX chars.
 * @return zero on match or one otherwise
 */
static int hip_map_first_lsi_to_hostname_from_hosts(const struct hosts_file_line *entry,
                                                    const void *arg,
                                                    void *result)
{
    int err    = 1;
    int is_lsi = hip_id_type_match(&entry->id, 2);

    if (!ipv6_addr_cmp(arg, &entry->id) && is_lsi) {
        memcpy(result, entry->hostname, strlen(entry->hostname));
        err = 0; /* Stop at the first match */
    }

    return err;
}

/**
 * find the hostname matching the given LSI from HIPL_SYSCONFDIR/hosts and
 * /etc/hosts (in this particular order)
 *
 * @param lsi the LSI to match
 * @param hostname An output argument where the matching hostname
 *                 will be written. Minimum buffer length is
 *                 HOST_NAME_MAX chars.
 * @return zero on successful match or non-zero otherwise
 */
int hip_map_lsi_to_hostname_from_hosts(hip_lsi_t *lsi, char *hostname)
{
    return hip_for_each_hosts_file_line(HIPL_HOSTS_FILE,
                                        hip_map_first_lsi_to_hostname_from_hosts,
                                        lsi, hostname) &&
           hip_for_each_hosts_file_line(HOSTS_FILE,
                                        hip_map_first_lsi_to_hostname_from_hosts,
                                        lsi, hostname);
}

/**
 * A "for-each" iterator function for hosts files that returns the first
 * HIT that matches the hostname
 *
 * @param entry a hosts file line entry
 * @param arg a hostname as a string
 * @param result An output argument where the matching matching HIT will be
 *        written. Minimum buffer length is sizeof(struct hip_hit_t)
 * @return zero on match or one otherwise
 */
static int hip_map_first_hostname_to_hit_from_hosts(const struct hosts_file_line *entry,
                                                    const void *arg,
                                                    void *result)
{
    int err = 1;
    int is_hit;

    /* test if hostname/alias matches and the type is hit */
    if (!strncmp(arg, entry->hostname, HOST_NAME_MAX) ||
        (entry->alias && !strncmp(arg, entry->alias, HOST_NAME_MAX)) ||
        (entry->alias2 && !strncmp(arg, entry->alias2, HOST_NAME_MAX))) {
        is_hit = hip_id_type_match(&entry->id, 1);

        HIP_IFE(!is_hit, 1);

        ipv6_addr_copy(result, &entry->id);
        err = 0; /* Stop at the first match */
    }

out_err:

    return err;
}

/**
 * A "for-each" iterator function for hosts files that returns the first
 * LSI that matches the hostname
 *
 * @param entry a hosts file line entry
 * @param arg a hostname as a string
 * @param result An output argument where the matching matching LSI will be
 *        written in IPv6 mapped format. Minimum buffer length is
 *        sizeof(struct in6_addr)
 * @return zero on match or one otherwise
 */
static int hip_map_first_hostname_to_lsi_from_hosts(const struct hosts_file_line *entry,
                                                    const void *arg,
                                                    void *result)
{
    int err = 1;
    int is_lsi;

    /* test if hostname/alias matches and the type is lsi */
    if (!strncmp(arg, entry->hostname, HOST_NAME_MAX) ||
        (entry->alias && !strncmp(arg, entry->alias, HOST_NAME_MAX)) ||
        (entry->alias2 && !strncmp(arg, entry->alias2, HOST_NAME_MAX))) {
        is_lsi = hip_id_type_match(&entry->id, 2);

        HIP_IFE(!is_lsi, 1);

        ipv6_addr_copy(result, &entry->id);
        err = 0; /* Stop at the first match */
    }

out_err:

    return err;
}

/**
 * A "for-each" iterator function for hosts files that returns the first
 * routable IP address that matches the hostname
 *
 * @param entry a hosts file line entry
 * @param arg a hostname as a string
 * @param result An output argument where the matching matching IP address will be
 *        written. IPv4 addresses are written in IPv6 mapped format and
 *        the minimum buffer length is sizeof(struct in6_addr)
 * @return zero on match or one otherwise
 */
static int hip_map_first_hostname_to_ip_from_hosts(const struct hosts_file_line *entry,
                                                   const void *arg,
                                                   void *result)
{
    int err = 1;

    /* test if hostname/alias matches and the type is routable ip */
    if (!strncmp(arg, entry->hostname, HOST_NAME_MAX) ||
        (entry->alias && !strncmp(arg, entry->alias, HOST_NAME_MAX)) ||
        (entry->alias2 && !strncmp(arg, entry->alias2, HOST_NAME_MAX))) {
        /* check that we did not resolve name to a HIT or an LSI */
        HIP_IFEL(hip_id_type_match(&entry->id, 1) ||
                 hip_id_type_match(&entry->id, 2),
                 1, "resolved hostname to non-routable HIT or LSI\n");

        ipv6_addr_copy(result, &entry->id);
        err = 0; /* Stop at the first match */
    }

out_err:

    return err;
}

/**
 * find the HIT matching to the given LSI from HIPL_SYSCONFDIR/hosts and
 * /etc/hosts (in this particular order)
 *
 * @param lsi the LSI to match
 * @param hit An output argument where the matching matching HIT will be
 *            written. Minimum buffer length is sizeof(struct hip_hit_t)
 * @return zero on successful match or non-zero otherwise
 */
int hip_map_lsi_to_hit_from_hosts_files(const hip_lsi_t *lsi, hip_hit_t *hit)
{
    int             err                     = 0;
    uint8_t         hostname[HOST_NAME_MAX] = { 0 };
    struct in6_addr mapped_lsi;

    HIP_ASSERT(lsi && hit);

    IPV4_TO_IPV6_MAP(lsi, &mapped_lsi);

    err = hip_for_each_hosts_file_line(HIPL_HOSTS_FILE,
                                       hip_map_first_id_to_hostname_from_hosts,
                                       &mapped_lsi, hostname);
    if (err) {
        err = hip_for_each_hosts_file_line(HOSTS_FILE,
                                           hip_map_first_id_to_hostname_from_hosts,
                                           &mapped_lsi, hostname);
    }

    HIP_IFEL(err, -1, "Failed to map id to hostname\n");

    err = hip_for_each_hosts_file_line(HIPL_HOSTS_FILE,
                                       hip_map_first_hostname_to_hit_from_hosts,
                                       hostname, hit);
    if (err) {
        err = hip_for_each_hosts_file_line(HOSTS_FILE,
                                           hip_map_first_hostname_to_hit_from_hosts,
                                           hostname, hit);
    }

    HIP_IFEL(err, -1, "Failed to map id to hostname\n");

    HIP_DEBUG_HIT("Found hit: ", hit);

out_err:

    return err;
}

/**
 * find the LSI matching to the given HIT from HIPL_SYSCONFDIR/hosts and
 * /etc/hosts (in this particular order)
 *
 * @param hit the HIT to match
 * @param lsi An output argument where the matching matching LSI will
 *            will be written
 * @return zero on successful match or non-zero otherwise
 */
int hip_map_hit_to_lsi_from_hosts_files(const hip_hit_t *hit, hip_lsi_t *lsi)
{
    int             err                     = 0;
    uint8_t         hostname[HOST_NAME_MAX] = { 0 };
    struct in6_addr mapped_lsi;

    HIP_ASSERT(lsi && hit);

    err = (hip_for_each_hosts_file_line(HIPL_HOSTS_FILE,
                                        hip_map_first_id_to_hostname_from_hosts,
                                        hit, hostname) &&
           hip_for_each_hosts_file_line(HOSTS_FILE,
                                        hip_map_first_id_to_hostname_from_hosts,
                                        hit, hostname));
    HIP_IFEL(err, -1, "Failed to map id to hostname\n");

    err = (hip_for_each_hosts_file_line(HIPL_HOSTS_FILE,
                                        hip_map_first_hostname_to_lsi_from_hosts,
                                        hostname, &mapped_lsi) &&
           hip_for_each_hosts_file_line(HOSTS_FILE,
                                        hip_map_first_hostname_to_lsi_from_hosts,
                                        hostname, &mapped_lsi));
    HIP_IFEL(err, -1, "Failed to map hostname to lsi\n");

    IPV6_TO_IPV4_MAP(&mapped_lsi, lsi);

    HIP_DEBUG_LSI("Found lsi: ", lsi);

out_err:

    return err;
}

/**
 * This function maps a HIT or a LSI (nodename) to an IP address using
 * the two hosts files.
 * The function implements this in two steps. First, it maps the HIT or
 * LSI to an hostname from HIPL_SYSCONFDIR/hosts or /etc/hosts. Second, it
 * maps the hostname to an IP address from /etc/hosts. The IP address
 * is returned in the res argument.
 *
 * @param hit a HIT to be mapped
 * @param lsi an LSI to be mapped
 * @param ip the resulting routable IP address if found
 * @return zero on successful match or non-zero otherwise
 */
int hip_map_id_to_ip_from_hosts_files(const hip_hit_t *hit,
                                      const hip_lsi_t *lsi,
                                      struct in6_addr *ip)
{
    int     err                     = 0;
    uint8_t hostname[HOST_NAME_MAX] = { 0 };

    HIP_ASSERT((hit || lsi) && ip);

    if (hit && !ipv6_addr_any(hit)) {
        err = (hip_for_each_hosts_file_line(HIPL_HOSTS_FILE,
                                            hip_map_first_id_to_hostname_from_hosts,
                                            hit, hostname) &&
               hip_for_each_hosts_file_line(HOSTS_FILE,
                                            hip_map_first_id_to_hostname_from_hosts,
                                            hit, hostname));
    } else {
        struct in6_addr mapped_lsi;
        IPV4_TO_IPV6_MAP(lsi, &mapped_lsi);
        err = (hip_for_each_hosts_file_line(HIPL_HOSTS_FILE,
                                            hip_map_first_id_to_hostname_from_hosts,
                                            &mapped_lsi, hostname) &&
               hip_for_each_hosts_file_line(HOSTS_FILE,
                                            hip_map_first_id_to_hostname_from_hosts,
                                            &mapped_lsi, hostname));
    }

    HIP_IFEL(err, -1, "Failed to map id to hostname\n");

    err = hip_for_each_hosts_file_line(HOSTS_FILE,
                                       hip_map_first_hostname_to_ip_from_hosts,
                                       hostname, ip);
    HIP_IFEL(err, -1, "Failed to map id to ip\n");

out_err:
    return err;
}

/**
 * check if the given LSI is in the hosts files
 *
 * @param lsi the LSI to be searched for
 * @return one if the LSI exists or zero otherwise
 *
 */
int hip_host_file_info_exists_lsi(hip_lsi_t *lsi)
{
    uint8_t         hostname[HOST_NAME_MAX] = { 0 };
    struct in6_addr mapped_lsi;

    IPV4_TO_IPV6_MAP(lsi, &mapped_lsi);

    return !(hip_for_each_hosts_file_line(HIPL_HOSTS_FILE,
                                          hip_map_first_id_to_hostname_from_hosts,
                                          &mapped_lsi, hostname) &&
             hip_for_each_hosts_file_line(HOSTS_FILE,
                                          hip_map_first_id_to_hostname_from_hosts,
                                          &mapped_lsi, hostname));
}
