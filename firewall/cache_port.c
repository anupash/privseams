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
 * Cache TCP and UDP port information for incoming HIP-related connections for
 * LSIs. When hipfw sees an incoming HIT-based connection, it needs to figure out if
 * it needs to be translated to LSI or not. LSI translation is done only when there is
 * no IPv6 application bound the corresponding TCP or UDP port. The port information
 * can be read from /proc but consumes time. To avoid this overhead, hipfw caches
 * the port information after the first read. Notice that cache is static and hipfw
 * must be restarted if there are changes in the port numbers. This is described in
 * more detail in <a
 * href="http://hipl.hiit.fi/hipl/thesis_teresa_finez.pdf">T. Finez,
 * Backwards Compatibility Experimentation with Host Identity Protocol
 * and Legacy Software and Networks , final project, December 2008</a>.
 *
 * @brief Cache TCP and UDP port numbers for inbound HIP-related connections to optimize LSI translation
 *
 * @author Miika Komu <miika@iki.fi>, Stefan Goetz <stefan.goetz@cs.rwth-aachen.de>
 */

#include <stdint.h>
#include <string.h>
#include <netinet/in.h>

#include "lib/core/debug.h"
#include "lib/core/list.h"
#include "lib/tool/lutil.h"
#include "lib/core/prefix.h"
#include "cache_port.h"


/**
 * Pointer to the port information cache.
 *
 * The cache is a two-dimensional array.
 * The first dimension is the transport protocol for which a port can be bound
 * (supported are TCP and UDP).
 * The second dimension is the port number itself.
 * The value is a uint8_t representation of an enum hip_firewall_port_info value
 */
static uint8_t *cache = NULL;

static const unsigned long CACHE_SIZE_PROTOS = 2;
static const unsigned long CACHE_SIZE_PORTS = 1 << (sizeof(in_port_t) * 8);
static unsigned long cache_size_entries = 0;
static unsigned long cache_size_bytes = 0;


/**
 * Allocate and initializes the cache resources.
 * If this function has not been called first, the results of calling
 * cache_get() and cache_set() are undefined.
 */
static void
cache_init(void)
{
    HIP_ASSERT(NULL == cache);

    cache_size_entries = CACHE_SIZE_PROTOS * CACHE_SIZE_PORTS;
    cache_size_bytes = cache_size_entries * sizeof(*cache);

    cache = calloc(1, cache_size_bytes);
    /* We zero the cache on allocation assuming that HIP_FIREWALL_PORT_UNKNOWN
    is 0 and thus the whole cache initially has that value. */
    if (NULL == cache) {
        HIP_ERROR("Allocating the port info cache failed\n");
    }
}

/**
 * Release the cache resources.
 * After calling this function, the results of calling cache_get() and
 * cache_set() are undefined.
 */
static void
cache_uninit(void)
{
    if (NULL != cache) {
        free(cache);
        cache = NULL;
    } else {
        HIP_ERROR("Deallocating the port info cache failed because it was not allocated\n");
    }
}

/**
 * Determines the index of a cache entry.
 * The cache array should only be indexed via this function.
 *
 * The flat cache entry index can be used to access the cache as a
 * one-dimensional array.
 * Using it is not strictly necessary because it would be possible and more
 * beautiful to behold to access the cache as a two-dimensional array, but the
 * one-dimensional flat index determined here can also be used for bounds
 * checking.
 *
 * @param protocol the protocol the specified port belongs to.
 *  The value is the same as used in the IPv4 'protocol' and the IPv6 'Next
 *  Header' fields.
 *  The only supported values are 6 for TCP and 17 for UDP.
 * @param port the port in host byte order to set the port information for.
 *  Valid values range from 0 to 2^16-1.
 * @return the index of the cache entry for @a protocol and @a port.
 */
static unsigned long
cache_index(const uint8_t protocol,
            const uint16_t port)
{
    unsigned long index = 0;
    unsigned long protocol_offset = 0;

    // check input paramaters
    HIP_ASSERT(IPPROTO_TCP == protocol || IPPROTO_UDP == protocol);
    
    // determine the offset into the first (protocol) dimension
    if (IPPROTO_TCP == protocol) {
        protocol_offset = 0;
    } else if (IPPROTO_UDP == protocol) {
        protocol_offset = 1;
    }

    // calculate the index
    index = (protocol_offset * CACHE_SIZE_PORTS) + port;

    // check return value
    HIP_ASSERT(index < cache_size_entries);

    return index;
}

/**
 * Cache information on the port of a given protocol.
 *
 * Looking up the port information from the /proc file systems is relatively
 * expensive.
 * Thus, we use this cache to speed up the lookup.
 *
 * This function is called after looking up port information from the /proc
 * file system.
 * After it has been called, a call to hip_firewall_port_cache_set() with the
 * same protocol and prot returns the previously set prot information.
 *
 * @param protocol the protocol the specified port belongs to.
 *  The value is the same as used in the IPv4 'protocol' and the IPv6 'Next
 *  Header' fields.
 *  The only supported values are 6 for TCP and 17 for UDP.
 * @param port the port in host byte order to set the port information for.
 *  Valid values range from 0 to 2^16-1.
 * @param info the information to store in the cache.
 */
static void
cache_set(const uint8_t protocol,
          const uint16_t port,
          const enum hip_firewall_port_info info)
{
    // check input paramaters
    HIP_ASSERT(IPPROTO_TCP == protocol || IPPROTO_UDP == protocol);
    
    // fail gracefully if the cache is not allocated
    if (NULL != cache) {
        // calculate index of cache entry
        const unsigned long index = cache_index(protocol, port);

        // convert the port info to the cache storage type
        const uint8_t value = (uint8_t)info;
        
        // check that the conversion is consistent
        HIP_ASSERT((const enum hip_firewall_port_info)value == info);

        cache[index] = value;
    } else {
        HIP_ERROR("Unable to set cache entry, cache not allocated\n");
    }
}

/**
 * Retrieve port information for a given protocol from the cache.
 *
 * Looking up the port information from the /proc file systems is relatively
 * expensive.
 * Thus, we use this cache to speed up the lookup.
 *
 * This function is called before looking up port information from the /proc
 * file system.
 *
 * @param protocol the protocol the specified port belongs to.
 *  The value is the same as used in the IPv4 'protocol' and the IPv6 'Next
 *  Header' fields.
 *  The only supported values are 6 for TCP and 17 for UDP.
 * @param port the port in host byte order to set the port information for.
 *  Valid values range from 0 to 2^16-1.
 * @return If the port information was previously stored, it is returned.
 *  If the port information was not previously stored or the cache is not
 *  available, HIP_FIREWALL_PORT_UNKNOWN is returned.
 */
static enum hip_firewall_port_info
cache_get(const uint8_t protocol,
          const uint16_t port)
{
    enum hip_firewall_port_info info = HIP_FIREWALL_PORT_UNKNOWN;

    // check input paramaters
    HIP_ASSERT(IPPROTO_TCP == protocol || IPPROTO_UDP == protocol);
    
    // fail gracefully if cache is not available
    if (NULL != cache) {
        const unsigned long index = cache_index(protocol, port);

        info = (enum hip_firewall_port_info)cache[index];
    }

    // check return value
    HIP_ASSERT(HIP_FIREWALL_PORT_UNKNOWN == info ||
               HIP_FIREWALL_PORT_UNBOUND == info ||
               HIP_FIREWALL_PORT_IPV6 == info ||
               HIP_FIREWALL_PORT_IPV4 == info ||
               HIP_FIREWALL_PORT_LSI == info);

    return info;
}

/**
 * Check from the proc file system whether a local port is attached
 * to an IPv4 or IPv6 address. This is required to determine whether
 * incoming packets should be diverted to an LSI.
 *
 * @param port_dest     the port number of the socket
 * @param *protocol     protocol type
 * @return              the traffic type associated with the given port.
 */
static enum hip_firewall_port_info
proc_get(const uint8_t protocol,
         const in_port_t port_dest)
{
    FILE *fd       = NULL;
    char line[500], sub_string_addr_hex[8], path[20];
    char *fqdn_str = NULL, *separator = NULL, *sub_string_port_hex = NULL;
    int lineno     = 0, index_addr_port = 0, result;
    enum hip_firewall_port_info exists = HIP_FIREWALL_PORT_UNBOUND;
    uint32_t result_addr;
    struct in_addr addr;
    List list;
    char protocol_str[10];

    switch (protocol) {
    case IPPROTO_UDP:
        strcpy(protocol_str, "udp6");
        index_addr_port = 10;
        break;
    case IPPROTO_TCP:
        strcpy(protocol_str, "tcp6");
        index_addr_port = 15;
        break;
    case IPPROTO_ICMPV6:
        break;
    default:
        goto out;
        break;
    }

    strcpy(path, "/proc/net/");
    strcat(path, protocol_str);
    fd = fopen(path, "r");

    initlist(&list);
    while (fd && getwithoutnewline(line, 500, fd) != NULL &&
           exists == HIP_FIREWALL_PORT_UNBOUND) {
        lineno++;

        destroy(&list);
        initlist(&list);

        if (lineno == 1 || strlen(line) <= 1) {
            continue;
        }

        extractsubstrings(line, &list);

        fqdn_str = getitem(&list, index_addr_port);
        if (fqdn_str) {
            separator = strrchr(fqdn_str, ':');
        }

        if (!separator) {
            continue;
        }

        sub_string_port_hex = strtok(separator, ":");
        sscanf(sub_string_port_hex, "%X", &result);
        HIP_DEBUG("Result %i\n", result);
        HIP_DEBUG("port dest %i\n", port_dest);
        if (result == port_dest) {
            if (!strcmp(protocol_str, "tcp6") || !strcmp(protocol_str, "udp6")) {
                exists = HIP_FIREWALL_PORT_IPV6;
            } else {
                strncpy(sub_string_addr_hex, fqdn_str, 8);
                sscanf(sub_string_addr_hex, "%X", &result_addr);
                addr.s_addr = result_addr;
                if (IS_LSI32(addr.s_addr)) {
                    exists = HIP_FIREWALL_PORT_LSI;
                } else {
                    exists = HIP_FIREWALL_PORT_IPV4;
                }
            }
            break;
        }
    }     /* end of while */
    if (fd) {
        fclose(fd);
    }
    destroy(&list);

out:
    HIP_ASSERT(HIP_FIREWALL_PORT_UNBOUND == exists ||
               HIP_FIREWALL_PORT_IPV6 == exists ||
               HIP_FIREWALL_PORT_IPV4 == exists ||
               HIP_FIREWALL_PORT_LSI == exists);
    return exists;
}

/**
 * Search in the port cache database. The key composed of port and protocol
 *
 * @param port the TCP or UDP port to search for
 * @param protocol the protocol (IPPROTO_UDP, IPPROTO_TCP or IPPROTO_ICMPV6)
 *
 * @return the cache entry if found or NULL otherwise
 */
enum hip_firewall_port_info
hip_firewall_port_cache_lookup_binding(const uint8_t protocol,
                                       const in_port_t port)
{
    enum hip_firewall_port_info info = HIP_FIREWALL_PORT_UNBOUND;

    // check input paramaters
    if (IPPROTO_TCP == protocol ||
        IPPROTO_UDP == protocol) {
        const uint8_t port_hbo = ntohs(port);

        // check the cache before checking /proc
        info = cache_get(protocol, port_hbo);

        if (HIP_FIREWALL_PORT_UNKNOWN == info) {
            info = proc_get(protocol, port_hbo);
            cache_set(protocol, port_hbo, info);
        }
    } else {
        HIP_ERROR("Protocol %d not supported\n", protocol);
    }

    // check return value
    HIP_ASSERT(HIP_FIREWALL_PORT_UNBOUND == info ||
               HIP_FIREWALL_PORT_IPV6 == info ||
               HIP_FIREWALL_PORT_IPV4 == info ||
               HIP_FIREWALL_PORT_LSI == info);

    return info;
}

void hip_firewall_port_cache_init(void)
{
    cache_init();
}

void hip_firewall_port_cache_uninit(void)
{
    cache_uninit();
}

