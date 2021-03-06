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
 * @brief Look up whether a port corresponds to a local bound socket, which influences LSI handling.
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "lib/core/common.h"
#include "lib/core/debug.h"
#include "lib/core/ife.h"
#include "line_parser.h"
#include "port_bindings.h"
#include "file_buffer.h"

/**
 * The number of seconds after which hip_port_bindings_trigger_reload() is
 * called periodically.
 * The smaller this number, the more up-to-date information is returned by
 * hip_port_bindings_get().
 * At the same time, a small interval also causes the somewhat expensive
 * hip_port_bindings_reload() to be called more frequently.
 */
static const unsigned int INVALIDATION_INTERVAL = 1;

/**
 * Indicates whether the caches should be invalidated.
 * This is periodically set to 1 by a timer and reset the next time a lookup is
 * performed.
 */
static volatile sig_atomic_t cache_invalidation_flag = 1;

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

static const unsigned int CACHE_SIZE_PROTOS  = 2;
static const unsigned int CACHE_SIZE_PORTS   = 1 << (sizeof(in_port_t) * 8);
static unsigned int       cache_size_entries = 0;
static unsigned int       cache_size_bytes   = 0;

/**
 * Allocate and initializes the cache resources.
 * If this function has not been called first, the results of calling
 * cache_get() and cache_set() are undefined.
 *
 * @return 0 if the function completes successfully.
 *  If the memory for the cache could not be allocated, this function returns
 *  -1.
 */
static int init_cache(void)
{
    HIP_ASSERT(!cache);

    cache_size_entries = CACHE_SIZE_PROTOS * CACHE_SIZE_PORTS;
    cache_size_bytes   = cache_size_entries * sizeof(*cache);

    // check that the conversion used in the cache from enum hip_port_binding
    // to uint8_t is consistent
    HIP_ASSERT(HIP_PORT_INFO_IPV6UNBOUND == (enum hip_port_binding) (uint8_t) HIP_PORT_INFO_IPV6UNBOUND);
    HIP_ASSERT(HIP_PORT_INFO_IPV6BOUND == (enum hip_port_binding) (uint8_t) HIP_PORT_INFO_IPV6BOUND);

    /* We zero the cache on allocation assuming that HIP_PORT_INFO_UNKNOWN
     * is 0 and thus the whole cache initially has that value. */
    HIP_ASSERT((uint8_t) HIP_PORT_INFO_UNKNOWN == 0);
    cache = calloc(1, cache_size_bytes);
    if (cache) {
        return 0;
    } else {
        HIP_ERROR("Allocating the port bindings cache failed\n");
        return -1;
    }
}

/**
 * Release the cache resources.
 * After calling this function, the results of calling cache_get() and
 * cache_set() are undefined.
 */
static void uninit_cache(void)
{
    free(cache);
    cache = NULL;
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
static inline unsigned int get_cache_index(const uint8_t protocol,
                                           const uint16_t port)
{
    unsigned int index           = 0;
    unsigned int protocol_offset = 0;

    // determine the offset into the first (protocol) dimension
    if (IPPROTO_TCP == protocol) {
        protocol_offset = 0;
    } else if (IPPROTO_UDP == protocol) {
        protocol_offset = 1;
    } else {
        HIP_DIE("Invalid protocol");
    }

    // calculate the index
    index = (protocol_offset * CACHE_SIZE_PORTS) + port;

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
    if (cache) {
        // calculate index of cache entry
        const unsigned int index = get_cache_index(protocol, port);

        // convert the port binding to the cache storage type
        const uint8_t value = (uint8_t) binding;

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
    if (cache) {
        const unsigned int index = get_cache_index(protocol, port);

        binding = (enum hip_port_binding) cache[index];
    }

    return binding;
}

/**
 * Invalidate all cache entries.
 *
 * After calling this function, all valid invocations of get_cache_entry()
 * return HIP_PORT_INFO_UNKNOWN.
 */
static void invalidate_cache(void)
{
    if (cache) {
        memset(cache, HIP_PORT_INFO_UNKNOWN, cache_size_bytes);
    }
}

static struct hip_file_buffer tcp6_file;
static struct hip_file_buffer udp6_file;

/**
 * Handles ALRM signals and triggers caches to be reloaded.
 * After this function has been called, the next call to
 * hip_port_bindings_get() calls hip_port_bindings_reload() to invalidate the
 * port and the file caches before performing a port lookup.
 * This tries to strike a balance between the cost of
 * hip_port_bindings_reload() and the freshness of the lookup information
 * returned by hip_port_bindings_get().
 * This function is called every INVALIDATION_INTERVAL seconds.
 */
static void hip_port_bindings_trigger_reload(UNUSED const int sig)
{
    cache_invalidation_flag = 1;
}

/**
 * Load the latest information from /proc.
 * This consists of handling two separate caching layers:
 * a) re-reading the file contents in the tcp6/udp6 file buffer objects and
 * b) invalidating the lookup cache.
 * On the one hand, this operation should ideally be called for every call to
 * hip_port_bindings_get() to retrieve up-to-date information from /proc
 * about which ports are bound.
 * On the other hand, this operation is about 300 times more expensive than
 * parsing the /proc file and even more expensive compared to a cache lookup.
 * hip_port_bindings_trigger_reload() tries to balance this conflict.
 * After calling this function, the cache is empty and the file buffers contain
 * the up-to-date file contents from /proc.
 *
 * @todo TODO efficiency could be increased by narrowing this down from
 *  reloading the files and invalidating the caches of all protocols to
 *  individual protocols.
 *
 * @return If this function completes successfully, it returns 0.
 *  If one of the proc files could not be reloaded from the file system, this
 *  function returns -1.
 */
static int hip_port_bindings_reload(void)
{
    int err = 0;

    invalidate_cache();

    err  = hip_fb_reload(&tcp6_file);
    err |= hip_fb_reload(&udp6_file);

    return (err == 0) ? 0 : -1;
}

/**
 * Look up in the proc file system whether a TCP or UDP port is bound under
 * IPv6.
 * It iterates over the lines in /proc/net/{udp,tcp}6 via a line parser object
 * and returns whether a match was found.
 *
 * @param protocol the protocol to check the port binding for.
 *  The values are equivalent to those found in the 'Protocol' field of the
 *  IPv4 header and the 'Next Header' field of the IPv6 header.
 *  The only supported values are those for TCP (6) and UDP (17).
 *  The effect of calling this function with an unsupported value is undefined.
 * @param port the port to look up.
 *  The value is expected in host byte order.
 * @return HIP_PORT_INFO_IPV6BOUND if the given port is bound under the given
 *  protocol to an IPv6 address.
 *  HIP_PORT_INFO_IPV6UNBOUND if it is not.
 */
static enum hip_port_binding hip_port_bindings_get_from_proc(const uint8_t protocol,
                                                             const uint16_t port)
{
    const unsigned int         PORT_STR_OFFSET = 39;
    const unsigned int         PORT_STR_LEN    = 4;
    enum hip_port_binding      result          = HIP_PORT_INFO_IPV6UNBOUND;
    const struct hip_mem_area *ma              = NULL;
    char                      *line;
    // the files /proc/net/{udp,tcp}6 are line-based and the line number of the
    // port to look up is not known in advance
    // -> use a parser that lets us iterate over the lines in the files
    struct hip_line_parser lp;

    switch (protocol) {
    case IPPROTO_TCP:
        ma = hip_fb_get_mem_area(&tcp6_file);
        break;
    case IPPROTO_UDP:
        ma = hip_fb_get_mem_area(&udp6_file);
        break;
    }
    hip_lp_create(&lp, ma);

    // Note that here we blindly parse whatever is in the file buffer.
    // This may not be up-to-date compared to the actual /proc file.
    // We rely on someone else calling hip_port_bindings_reload() to
    // reload the file contents for us so that we return some at least roughly
    // up-to-date information.
    line = hip_lp_first(&lp);

    // the first line only contains headers, no port information, skip it
    line = hip_lp_next(&lp);

    // is the current line valid and is it long enough to hold a port binding?
    while (line && ma->end > (line + PORT_STR_OFFSET + PORT_STR_LEN)) {
        const unsigned int PORT_BASE_HEX = 16;
        unsigned long      proc_port     = 0;
        // note that strtoul() is about 10 times faster than sscanf().
        errno     = 0;
        proc_port = strtoul(line + PORT_STR_OFFSET, NULL, PORT_BASE_HEX);
        if (0 == errno) {
            if (proc_port == port) {
                result = HIP_PORT_INFO_IPV6BOUND;
                break;
            }
        } else {
            HIP_ERROR("Unable to parse port number in line '%.*s' from /proc/net/%s6, errno = %d\n",
                      PORT_STR_OFFSET + PORT_STR_LEN, line,
                      IPPROTO_TCP == protocol ? "tcp" : "udp", errno);
        }
        line = hip_lp_next(&lp);
    }

    hip_lp_delete(&lp);
    return result;
}

/**
 * Initialize the port binding lookup and allocate any necessary resources.
 *
 * @param enable_cache if not 0, use an internal cache that is consulted on
 *  lookups in favor of parsing the /proc file.
 *  If this lookup cache is not enabled, every lookup results in parsing the
 *  proc file.
 *  Note however, that the /proc file itself is cached in memory and only
 *  reloaded at a certain interval.
 *  Within this interval, hip_port_bindings_get() might return a different
 *  port binding status than the one in the actual /proc file.
 * @return 0 if the function completes successfully.
 *  If enable_cache is true but the cache could not be allocated or initialized
 *  this function returns -1.
 *  If one of the /proc files could not be opened or buffered in memory
 *  successfully, this function returns -2.
 */
int hip_port_bindings_init(const bool enable_cache)
{
    int err;

    // The cache is built such that it can be disabled just by not initializing
    // it here.
    if (enable_cache) {
        HIP_IFEL(init_cache() != 0, -1,
                 "Initializing the port bindings cache failed\n")
    }

    HIP_IFEL(hip_fb_create(&tcp6_file, "/proc/net/tcp6") != 0, -2,
             "Buffering tcp6 proc file in memory failed\n");
    HIP_IFEL(hip_fb_create(&udp6_file, "/proc/net/udp6") != 0, -2,
             "Buffering udp6 proc file in memory failed\n");

    return 0;

out_err:
    hip_port_bindings_uninit();
    return err;
}

/**
 * Release any resources allocated for port binding lookups.
 */
void hip_port_bindings_uninit(void)
{
    hip_fb_delete(&tcp6_file);
    hip_fb_delete(&udp6_file);

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
 * Note that due to internal caching, hip_port_bindings_get() might return for
 * a certain caching interval a different port binding status than the one
 * reported in the actual /proc file (see hip_port_bindings_trigger_reload()).
 *
 * The binary test/fw_port_bindings_performance benchmarks the elements that
 * influence the performance of the hip_port_bindings_* code.
 * Please have a look at the numbers it generates when changing this code under
 * performance aspects.
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
        const uint16_t port_hbo = ntohs(port);

        // Make sure we return (sort of) up-to-date information.
        // This is the one potentially slow operation here.
        // The others (hip_port_bindings_get_from_proc() and the cache access
        // functions) are (intended to be) very fast.
        if (cache_invalidation_flag) {
            // prevent further cache invalidation
            cache_invalidation_flag = 0;
            // invalidate all caches and reload the /proc-file contents
            hip_port_bindings_reload();
            // start a timer that sets cache_invalidation_flag back to 1
            signal(SIGALRM, hip_port_bindings_trigger_reload);
            alarm(INVALIDATION_INTERVAL);
        }

        // check the cache before checking /proc
        // note that the cache might be switched off (see
        // hip_port_bindings_init()) or was just invalidated by
        // hip_port_bindings_reload()
        binding = get_cache_entry(protocol, port_hbo);

        if (HIP_PORT_INFO_UNKNOWN == binding) {
            binding = hip_port_bindings_get_from_proc(protocol, port_hbo);
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
