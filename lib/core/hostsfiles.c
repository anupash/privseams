/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 *
 * This file contains iterator functions to access and parse
 * /etc/hosts and /etc/hip/hosts files. Also, this file contains a
 * number of predefined functions that support mapping between
 * hostnames, HITs, LSIs and routable IP addresses.
 *
 * @brief parser for /etc/hosts and /etc/hip/hosts
 *
 * @author Miika Komu <miika@iki.fi>
 *
 * @todo is there a standard API for accessing hosts files?
 */

/* required for s6_addr32 */
#define _BSD_SOURCE

#include <arpa/inet.h>
#include <time.h>
#include <netinet/in.h>

#include "config.h"
#include "misc.h"
#include "hostsfiles.h"


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
int hip_map_first_id_to_hostname_from_hosts(const struct hosts_file_line *entry,
                                            const void *arg,
                                            void *result)
{
    int err = 1;

    if (!ipv6_addr_cmp((struct in6_addr *) arg, &entry->id)) {
        _HIP_DEBUG("Match on line %d\n", entry->lineno);
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
int hip_map_first_lsi_to_hostname_from_hosts(const struct hosts_file_line *entry,
                                             const void *arg,
                                             void *result)
{
    int err    = 1;
    int is_lsi = hip_id_type_match(&entry->id, 2);

    if (!ipv6_addr_cmp((struct in6_addr *) arg, &entry->id) && is_lsi) {
        _HIP_DEBUG("Match on line %d\n", entry->lineno);
        memcpy(result, entry->hostname, strlen(entry->hostname));
        err = 0; /* Stop at the first match */
    }

    return err;
}

/**
 * find the hostname matching the given LSI from /etc/hip/hosts and
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
int hip_map_first_hostname_to_hit_from_hosts(const struct hosts_file_line *entry,
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

        _HIP_DEBUG("Match on line %d\n", entry->lineno);
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
int hip_map_first_hostname_to_lsi_from_hosts(const struct hosts_file_line *entry,
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

        _HIP_DEBUG("Match on line %d\n", entry->lineno);
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
int hip_map_first_hostname_to_ip_from_hosts(const struct hosts_file_line *entry,
                                            const void *arg,
                                            void *result)
{
    int err = 1;
    int is_lsi, is_hit;

    /* test if hostname/alias matches and the type is routable ip */
    if (!strncmp(arg, entry->hostname, HOST_NAME_MAX) ||
        (entry->alias && !strncmp(arg, entry->alias, HOST_NAME_MAX)) ||
        (entry->alias2 && !strncmp(arg, entry->alias2, HOST_NAME_MAX))) {
        is_hit = hip_id_type_match(&entry->id, 1);
        is_lsi = hip_id_type_match(&entry->id, 2);

        HIP_IFE((is_hit || is_lsi), 1);

        _HIP_DEBUG("Match on line %d\n", entry->lineno);
        ipv6_addr_copy(result, &entry->id);
        err = 0; /* Stop at the first match */
    }

out_err:

    return err;
}

/**
 * A "for-each" iterator function for hosts files to calculate
 * the number of non-commented lines
 *
 * @param entry a hosts file line entry
 * @param arg unused, but required by the API
 * @param result an int pointer where the number of lines
 *               will be calculated
 * @return always one
 */
int hip_calc_lines_in_hosts(const struct hosts_file_line *entry,
                            const void *arg,
                            void *result)
{
    int *res = (int *) result;
    (*res)++;
    return 1;
}

/**
 * A "for-each" iterator function for hosts files that returns the Nth
 * identifier (address, LSI or HIT) from a hosts file
 *
 * @param entry a hosts file line entry
 * @param arg the N as an int pointer
 * @param result An output argument where the matching matching address will be
 *        written. IPv4 addresses are written in IPv6 mapped format and
 *        the minimum buffer length is sizeof(struct in6_addr).
 * @return zero on match or one otherwise
 */
int hip_get_nth_id_from_hosts(const struct hosts_file_line *entry,
                              const void *arg,
                              void *result)
{
    int err         = 1;
    const int *nth  = (const int *) arg;
    int *total_past = (int *) result;

    if (*nth == *total_past) {
        ipv6_addr_copy(result, &entry->id);
        err = 0;
    } else {
        (*total_past)++;
    }
    return err;
}

/**
 * "For-each" loop to iterate through /etc/hosts or /etc/hip/hosts file, line
 * by line.
 *
 * @param hosts_file the path and name to the hosts file
 * @param func the iterator function pointer
 * @param arg an input argument for the function pointer
 * @param an output argument for the function pointer
 * @return zero on success or non-zero on failure
 */
int hip_for_each_hosts_file_line(const char *hosts_file,
                                 int(*func)(const struct hosts_file_line *line,
                                            const void *arg,
                                            void *result),
                                 void *arg,
                                 void *result)
{
    FILE *hip_hosts = NULL;
    List mylist;
    char line[500];
    int err         = 0, lineno = 0;
    struct in_addr in_addr;
    struct hosts_file_line entry;
    char *hostname  = NULL, *alias = NULL, *alias2 = NULL, *addr_ptr = NULL;

    initlist(&mylist);
    memset(line, 0, sizeof(line));

    /* check whether  given hit_str is actually a HIT */

    hip_hosts = fopen(hosts_file, "r");

    HIP_IFEL(!hip_hosts, -1, "Failed to open hosts file\n");

    /* For each line in the given hosts file, convert the line into binary format and
     * call the given the handler  */

    err = 1;
    while (fgets(line, sizeof(line) - 1, hip_hosts) != NULL) {
        char *eofline, *c, *comment;
        int len;

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

        _HIP_DEBUG("lineno=%d, str=%s\n", lineno, c);

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

        /* Initialize entry */

        memset(&entry, 0, sizeof(entry));

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

        entry.alias2   = alias2;
        entry.alias    = alias;
        entry.lineno   = lineno;

        /* Finally, call the handler function to handle the line */

        if (func(&entry, arg, result) == 0) {
            _HIP_DEBUG("Match on line %d in %s\n", lineno, hosts_file);
            err = 0;
            break;
        }

        memset(line, 0, sizeof(line));
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
 * find the HIT matching to the given LSI from /etc/hip/hosts and
 * /etc/hosts (in this particular order)
 *
 * @param lsi the LSI to match
 * @param hit An output argument where the matching matching HIT will be
 *            written. Minimum buffer length is sizeof(struct hip_hit_t)
 * @return zero on successful match or non-zero otherwise
 */
int hip_map_lsi_to_hit_from_hosts_files(hip_lsi_t *lsi, hip_hit_t *hit)
{
    int err = 0;
    uint8_t hostname[HOST_NAME_MAX];
    struct in6_addr mapped_lsi;

    memset(hostname, 0, sizeof(hostname));
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
 * find the LSI matching to the given HIT from /etc/hip/hosts and
 * /etc/hosts (in this particular order)
 *
 * @param hit the HIT to match
 * @param lsi An output argument where the matching matching LSI will
 *            will be written
 * @return zero on successful match or non-zero otherwise
 */
int hip_map_hit_to_lsi_from_hosts_files(const hip_hit_t *hit, hip_lsi_t *lsi)
{
    int err = 0;
    uint8_t hostname[HOST_NAME_MAX];
    struct in6_addr mapped_lsi;

    memset(hostname, 0, sizeof(hostname));
    HIP_ASSERT(lsi && hit);

    err = (hip_for_each_hosts_file_line(HIPL_HOSTS_FILE,
                                        hip_map_first_id_to_hostname_from_hosts,
                                        (hip_hit_t *) hit, hostname) &&
           hip_for_each_hosts_file_line(HOSTS_FILE,
                                        hip_map_first_id_to_hostname_from_hosts,
                                        (hip_hit_t *) hit, hostname));
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
 * Fetch a random host name from a hosts file. Currently this
 * is used for selecting a random DHT node for load balancing.
 *
 * @param filename the hosts file path and file name
 * @param hostname the hostname will be written here
 * @param id_str The address, LSI or HIT corresponding to the
 *               the hostname will be written here as a string.
 * @return zero on successful match or non-zero on failure
 */
int hip_get_random_hostname_id_from_hosts(char *filename,
                                          char *hostname,
                                          char *id_str)
{
    int lines = 0, err = 0, nth;
    struct in6_addr id;

    memset(&id, 0, sizeof(struct in6_addr));

    /* ignore return value, returns always error */
    hip_for_each_hosts_file_line(filename,
                                 hip_calc_lines_in_hosts,
                                 NULL,
                                 &lines);
    HIP_IFEL((lines == 0), -1,
             "No lines in host file %s\n", filename);

    srand(time(NULL));
    nth = rand() % lines;

    err = hip_for_each_hosts_file_line(filename,
                                       hip_get_nth_id_from_hosts,
                                       &nth,
                                       &id);
    HIP_IFEL(err, -1, "Failed to get random id\n");

    err = hip_for_each_hosts_file_line(filename,
                                       hip_map_first_id_to_hostname_from_hosts,
                                       &id,
                                       hostname);
    HIP_IFEL(err, -1, "Failed to map to hostname\n");

    if (IN6_IS_ADDR_V4MAPPED(&id)) {
        struct in_addr id4;
        IPV6_TO_IPV4_MAP(&id, &id4);
        HIP_IFEL(!inet_ntop(AF_INET, &id4, id_str,
                            INET_ADDRSTRLEN), -1,
                 "inet_ntop failed\n");
    } else {
        HIP_IFEL(!inet_ntop(AF_INET6, &id, id_str,
                            INET6_ADDRSTRLEN), -1,
                 "inet_ntop failed\n");
    }

out_err:
    return err;
}

/**
 * This function maps a HIT or a LSI (nodename) to an IP address using the two hosts files.
 * The function implements this in two steps. First, it maps the HIT or LSI to an hostname
 * from /etc/hip/hosts or /etc/hosts. Second, it maps the hostname to a IP address from
 * /etc/hosts. The IP address is returned in the res argument.
 *
 * @param hit a HIT to be mapped
 * @param lsi an LSI to be mapped
 * @param ip the resulting routable IP address if found
 * @return zero on successful match or non-zero otherwise
 */
int hip_map_id_to_ip_from_hosts_files(hip_hit_t *hit, hip_lsi_t *lsi, struct in6_addr *ip)
{
    int err = 0;
    uint8_t hostname[HOST_NAME_MAX];

    HIP_ASSERT((hit || lsi) && ip);

    memset(hostname, 0, sizeof(hostname));

    if (hit && !ipv6_addr_any(hit)) {
        err = hip_for_each_hosts_file_line(HIPL_HOSTS_FILE,
                                           hip_map_first_id_to_hostname_from_hosts,
                                           hit, hostname);
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
