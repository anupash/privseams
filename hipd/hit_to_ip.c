/*
 * Copyright (c) 2010-2011 Aalto University and RWTH Aachen University.
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
 * @brief look for locators in hit-to-ip domain
 * @brief usually invoked by hip_map_id_to_addr
 *
 * @brief i.e. 5.7.d.1.c.c.8.d.0.6.3.b.a.4.6.2.5.0.5.2.e.4.7.5.e.1.0.0.1.0.0.2.hit-to-ip.infrahip.net for 2001:1e:574e:2505:264a:b360:d8cc:1d75
 *
 * @author Oleg Ponomarev <oleg.ponomarev@hiit.fi>
 * @author Stefan Götz <stefan.goetz@web.de>
 */

#define _BSD_SOURCE

#include <netdb.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "hit_to_ip.h"
#include "lib/core/conf.h"
#include "lib/core/debug.h"
#include "lib/core/prefix.h"
#include "maintenance.h"


static int hip_hit_to_ip_status = 0;

/**
 * This function is an interface to turn on/off locators lookup in hit-to-ip domain
 *
 * @param status 0 unless locator lookups in hit-to-ip domain wanted, 1 otherwise
 */
void hip_set_hit_to_ip_status(const int status)
{
    hip_hit_to_ip_status = status;
}

/**
 * This function is an interface to check if locators lookup in hit-to-ip domain if wanted
 *
 * @return 0 unless locator lookups in hit-to-ip domain wanted, 1 otherwise
 */

int hip_get_hit_to_ip_status(void)
{
    return hip_hit_to_ip_status;
}

// append unless set in configuration
#define HIT_TO_IP_ZONE_DEFAULT "hit-to-ip.infrahip.net"

static char *hip_hit_to_ip_zone = NULL;

/**
 * Set the zone for hit-to-ip domain lookups
 *
 * @param zone  domain as a string, e.g. "hit-to-ip.infrahip.net"
 */
void hip_hit_to_ip_set(const char *zone)
{
    char *tmp = hip_hit_to_ip_zone;

    hip_hit_to_ip_zone = strdup(zone);

    free(tmp);
}

static const char hex_digits[] = {
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
};

/**
 * returns "5.7.d.1.c.c.8.d.0.6.3.b.a.4.6.2.5.0.5.2.e.4.7.5.e.1.0.0.1.0.0.2.hit-to-ip.infrahip.net" for 2001:1e:574e:2505:264a:b360:d8cc:1d75
 *
 * @param hit               HIT as a string
 * @param hostname          buffer for the result
 * @param hostname_len      length of the buffer
 * @return                  0
 */
static int hip_get_hit_to_ip_hostname(const hip_hit_t *hit, char *hostname, const int hostname_len)
{
    const uint8_t *bytes = (const uint8_t *) hit->s6_addr;
    char          *cp    = hostname;
    int            i;

    if ((hit == NULL) || (hostname == NULL)) {
        return -1;
    }

    for (i = 15; i >= 0; i--) {
        *cp++ = hex_digits[bytes[i] & 0x0f];
        *cp++ = '.';
        *cp++ = hex_digits[(bytes[i] >> 4) & 0x0f];
        *cp++ = '.';
    }

    if (hip_hit_to_ip_zone == NULL) {
        strncpy(cp, HIT_TO_IP_ZONE_DEFAULT, hostname_len - 64);
    } else {
        strncpy(cp, hip_hit_to_ip_zone, hostname_len - 64);
    }

    return 0;
}

/**
 * checks for ip address for hit preferring IPv4 one
 *
 * @param hit           HIT to look locators for
 * @param retval        buffer for the result
 * @return              0 on success, -1 otherwise
 */

int hip_hit_to_ip(const hip_hit_t *hit, struct in6_addr *retval)
{
    struct addrinfo *rp = NULL;     // no C99 :(
    char             hit_to_ip_hostname[64 + HIT_TO_IP_ZONE_MAX_LEN + 1];
    int              found_addr = 0;
    struct addrinfo  hints      = { 0 };
    struct addrinfo *result     = NULL;
    int              res;

    if ((hit == NULL) || (retval == NULL)) {
        return -1;
    }

    if (hip_get_hit_to_ip_hostname(hit, hit_to_ip_hostname, sizeof(hit_to_ip_hostname)) != 0) {
        return -1;
    }

    hints.ai_family   = AF_UNSPEC;      /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_DGRAM;     /* Datagram socket. Right? */
    hints.ai_flags    = AI_PASSIVE;     /* For wildcard IP address */

    /* getaddrinfo is too complex for DNS lookup, but let us use it now */
    res = getaddrinfo(hit_to_ip_hostname, NULL, &hints, &result);
    HIP_DEBUG("getaddrinfo(%s) returned %d\n", hit_to_ip_hostname, res);

    if (res != 0) {
        HIP_DEBUG("getaddrinfo error %s\n", gai_strerror(res));
        return -1;
    }

    /* Look at the list and return only one address, let us prefer AF_INET */
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        HIP_DEBUG_SOCKADDR("getaddrinfo result", rp->ai_addr);

        if (rp->ai_family == AF_INET) {
            struct sockaddr_in *tmp_sockaddr_in_ptr = (struct sockaddr_in *) (rp->ai_addr);
            IPV4_TO_IPV6_MAP(&(tmp_sockaddr_in_ptr->sin_addr), retval)
            found_addr = 1;
            break;
        } else if (rp->ai_family == AF_INET6) {
            struct sockaddr_in6 *tmp_sockaddr_in6_ptr = (struct sockaddr_in6 *) (rp->ai_addr);
            ipv6_addr_copy(retval, &(tmp_sockaddr_in6_ptr->sin6_addr));
            found_addr = 1;
        }
    }

    if (result) {
        freeaddrinfo(result);
    }

    if (found_addr) {
        return 0;
    } else {
        return -1;
    }
}
