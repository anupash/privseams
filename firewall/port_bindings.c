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
 * @brief Look up whether a port corresponds to a local bound socket, which influences LSI handling.
 *
 * @author Miika Komu <miika@iki.fi>, Stefan Goetz <stefan.goetz@cs.rwth-aachen.de>
 */

#include <stdint.h> // uint16_t
#include <stdlib.h> // strtoul()
#include <netinet/in.h> // in_port_t
#include <string.h> // memset()

#include "lib/core/debug.h"
#include "firewall/line_parser.h"
#include "firewall/port_bindings.h"

/**
 * Pointer to the port bindings cache.
 *
 * The cache is a two-dimensional array.
 * The first dimension is the transport protocol for which a port can be bound
 * (supported are TCP and UDP).
 * The second dimension is the port number itself.
 * The value is a uint8_t representation of an enum hip_port_binding value
 */
static uint8_t *cache = NULL;

static const unsigned int CACHE_SIZE_PROTOS = 2;
static const unsigned int CACHE_SIZE_PORTS = 1 << (sizeof(in_port_t) * 8);
static unsigned int cache_size_entries = 0;
static unsigned int cache_size_bytes = 0;

/**
 * Allocate and initializes the cache resources.
 * If this function has not been called first, the results of calling
 * cache_get() and cache_set() are undefined.
 */
static void init_cache(void)
{
    HIP_ASSERT(NULL == cache);

    cache_size_entries = CACHE_SIZE_PROTOS * CACHE_SIZE_PORTS;
    cache_size_bytes = cache_size_entries * sizeof(*cache);

    cache = calloc(1, cache_size_bytes);
    /* We zero the cache on allocation assuming that HIP_PORT_INFO_UNKNOWN
    is 0 and thus the whole cache initially has that value. */
    if (NULL == cache) {
        HIP_ERROR("Allocating the port bindings cache failed\n");
    }
}

/**
 * Release the cache resources.
 * After calling this function, the results of calling cache_get() and
 * cache_set() are undefined.
 */
static void uninit_cache(void)
{
    if (NULL != cache) {
        free(cache);
        cache = NULL;
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
 * @param port the port in host byte order to get the port binding for.
 *  Valid values range from 0 to 2^16-1.
 * @return the index of the cache entry for @a protocol and @a port.
 */
static unsigned int get_cache_index(const uint8_t protocol,
                                    const uint16_t port)
{
    unsigned int index = 0;
    unsigned int protocol_offset = 0;

    // check input parameters
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
 * Cache binding state on the port of a given protocol.
 *
 * This function is called after looking up port binding status from the /proc
 * file system.
 * After it has been called, a call to hip_firewall_port_cache_set() with the
 * same protocol and port returns the previously set port binding.
 *
 * @param protocol the protocol the specified port belongs to.
 *  The value is the same as used in the IPv4 'protocol' and the IPv6 'Next
 *  Header' fields.
 *  The only supported values are 6 for TCP and 17 for UDP.
 * @param port the port in host byte order to set the port binding for.
 *  Valid values range from 0 to 2^16-1.
 * @param binding the binding to store in the cache.
 */
static void set_cache_entry(const uint8_t protocol,
                            const uint16_t port,
                            const enum hip_port_binding binding)
{
    // fail gracefully if the cache is not allocated
    if (NULL != cache) {
        // check input parameters
        HIP_ASSERT(IPPROTO_TCP == protocol || IPPROTO_UDP == protocol);

        // calculate index of cache entry
        const unsigned int index = get_cache_index(protocol, port);

        // convert the port binding to the cache storage type
        const uint8_t value = (uint8_t)binding;

        // check that the conversion is consistent
        HIP_ASSERT((const enum hip_port_binding)value == binding);

        cache[index] = value;
    }
}

/**
 * Retrieve port binding for a given protocol from the cache.
 *
 * Looking up the port binding from the /proc file systems is relatively
 * expensive.
 * Thus, we use this cache to speed up the lookup.
 *
 * This function is called before looking up the port binding from the /proc
 * file system.
 *
 * @param protocol the protocol the specified port belongs to.
 *  The value is the same as used in the IPv4 'protocol' and the IPv6 'Next
 *  Header' fields.
 *  The only supported values are 6 for TCP and 17 for UDP.
 * @param port the port in host byte order to set the port binding for.
 *  Valid values range from 0 to 2^16-1.
 * @return If the port binding was previously stored, it is returned.
 *  If the port binding was not previously stored or the cache is not
 *  available, HIP_PORT_INFO_UNKNOWN is returned.
 */
static enum hip_port_binding get_cache_entry(const uint8_t protocol,
                                             const uint16_t port)
{
    enum hip_port_binding binding = HIP_PORT_INFO_UNKNOWN;

    // fail gracefully if cache is not available
    if (NULL != cache) {
        // check input parameters
        HIP_ASSERT(IPPROTO_TCP == protocol || IPPROTO_UDP == protocol);

        const unsigned int index = get_cache_index(protocol, port);

        binding = (enum hip_port_binding)cache[index];

        // check return value
        HIP_ASSERT(HIP_PORT_INFO_UNKNOWN == binding ||
                   HIP_PORT_INFO_IPV6UNBOUND == binding ||
                   HIP_PORT_INFO_IPV6BOUND == binding);
    }

    return binding;
}

/**
 * Invalidate all cache entries.
 *
 * After calling this function, all valid invocations of get_cache_entry()
 * return HIP_PORT_INFO_UNKNOWN.
 */
//static void invalidate_cache(void)
//{
//    if (cache != NULL) {
//        memset(cache, 0, cache_size_bytes);
//    }
//}






static struct hip_line_parser *tcp6_parser = NULL;
static struct hip_line_parser *udp6_parser = NULL;

/**
 * Look up the port binding from the proc file system.
 *
 * @param protocol protocol type
 * @param port the port number of the socket
 * @return the traffic type associated with the given port.
 */
static enum hip_port_binding get_port_binding_from_proc(const uint8_t protocol,
                                                        const uint16_t port)
{
    enum hip_port_binding result = HIP_PORT_INFO_IPV6UNBOUND;
    // the files /proc/net/{udp,tcp}6 are line-based and the line number of the
    // port to look up is not known in advance
    // -> use a parser that lets us iterate over the lines in the files
    struct hip_line_parser *lp = NULL;

    // the parser can re-read the file contents online, so we re-use the parser
    // objects for all lookups
    HIP_ASSERT(IPPROTO_TCP == protocol ||
               IPPROTO_UDP == protocol);
    switch (protocol) {
    case IPPROTO_TCP:
        lp = tcp6_parser;
        break;
    case IPPROTO_UDP:
        lp = udp6_parser;
        break;
    }

    // The proc files change quickly so we reload their contents before parsing.
    // TODO: This is surprisingly expensive and should be changed and
    // synchronized with cache invalidation
    hip_lp_reload(lp);
    char *line = hip_lp_first(lp);
    while (line != NULL) {
        const unsigned int PORT_OFFSET_IN_LINE = 39;
        const unsigned int PORT_BASE_HEX = 16;
        unsigned long proc_port = 0;
        // note that strtoul() is about 10 times faster than sscanf().
        proc_port = strtoul(line + PORT_OFFSET_IN_LINE, NULL, PORT_BASE_HEX);
        if (proc_port == port) {
            result = HIP_PORT_INFO_IPV6BOUND;
            break;
        }
        line = hip_lp_next(lp);
    }

    HIP_ASSERT(HIP_PORT_INFO_IPV6UNBOUND == result ||
               HIP_PORT_INFO_IPV6BOUND == result);
    return result;
}

/**
 * Initialize the port binding lookup and allocate any necessary resources.
 *
 * @param enable_cache if not 0, use an internal cache that is consulted on
 *  lookups in favor of parsing the proc file.
 */
void hip_port_bindings_init(const bool enable_cache)
{
    // The cache is built such that it can be disabled just by not initializing
    // it here.
    if (enable_cache) {
        init_cache();
    }
    tcp6_parser = hip_lp_create("/proc/net/tcp6");
    udp6_parser = hip_lp_create("/proc/net/udp6");
}

/**
 * Release any resources allocated for port binding lookups.
 */
void hip_port_bindings_uninit(void)
{
    hip_lp_delete(tcp6_parser);
    hip_lp_delete(udp6_parser);
    uninit_cache();
}

/**
 * Determine whether the given port is bound under the given protocol to an
 * IPv6 address on the local host.
 *
 * For example, on a system with a running IPv6-capable web server, this
 * function returns HIP_PORT_INFO_IPV6BOUND.
 * If there is no web server or it only supports (or binds to) IPv4 addresses,
 * this function returns HIP_PORT_INFO_IPV6UNBOUND.
 *
 * @param protocol the protocol to check the port binding for.
 *  The values are equivalent to those found in the 'Protocol' field of the
 *  IPv4 header and the 'Next Header' field of the IPv6 header.
 *  The only supported values are those for TCP (6) and UDP (17).
 * @param port the port to look up.
 *  The value is expected in network byte order, as it is found in protocol
 *  headers.
 * @return HIP_PORT_INFO_IPV6BOUND if the given port is bound under the given
 *  protocol to an IPv6 address.
 *  HIP_PORT_INFO_IPV6UNBOUND if it is not.
 */
enum hip_port_binding hip_port_bindings_get(const uint8_t protocol,
                                            const in_port_t port)
{
    enum hip_port_binding binding = HIP_PORT_INFO_IPV6UNBOUND;

    // check input parameters
    if (IPPROTO_TCP == protocol ||
        IPPROTO_UDP == protocol) {
        const uint8_t port_hbo = ntohs(port);

        // check the cache before checking /proc
        binding = get_cache_entry(protocol, port_hbo);

        if (HIP_PORT_INFO_UNKNOWN == binding) {
            binding = get_port_binding_from_proc(protocol, port_hbo);
            set_cache_entry(protocol, port_hbo, binding);
        }
    } else {
        HIP_ERROR("Protocol %d not supported\n", protocol);
    }

    // check return value
    HIP_ASSERT(HIP_PORT_INFO_IPV6UNBOUND == binding ||
               HIP_PORT_INFO_IPV6BOUND == binding);

    return binding;
}
