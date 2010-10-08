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
#include <string.h>     // sscanf()
#include <netinet/in.h>
#include <sys/types.h>  // off_t, size_t
#include <unistd.h>     // lseek(), close(), read()
#include <fcntl.h>      // open()


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
 * The value is a uint8_t representation of an hip_port_info_t value
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
    /* We zero the cache on allocation assuming that HIP_PORT_INFO_UNKNOWN
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
          const hip_port_info_t info)
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
        HIP_ASSERT((const hip_port_info_t)value == info);

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
 *  available, HIP_PORT_INFO_UNKNOWN is returned.
 */
static hip_port_info_t
cache_get(const uint8_t protocol,
          const uint16_t port)
{
    hip_port_info_t info = HIP_PORT_INFO_UNKNOWN;

    // check input paramaters
    HIP_ASSERT(IPPROTO_TCP == protocol || IPPROTO_UDP == protocol);
    
    // fail gracefully if cache is not available
    if (NULL != cache) {
        const unsigned long index = cache_index(protocol, port);

        info = (hip_port_info_t)cache[index];
    }

    // check return value
    HIP_ASSERT(HIP_PORT_INFO_UNKNOWN == info ||
               HIP_PORT_INFO_UNBOUND == info ||
               HIP_PORT_INFO_IPV6 == info ||
               HIP_PORT_INFO_IPV4 == info ||
               HIP_PORT_INFO_LSI == info);

    return info;
}




/**
 * An instance of struct line_parser holds the context of a line parser object.
 */
typedef struct line_parser {
    /**
     * Points to the file contents in memory.
     */
    char *start;
    /**
     * Points to the current parsing position.
     */
    char *cur;
    /**
     * Points to the last byte of file data + 1.
     */
    char *end;
    /**
     * The number of bytes in the allocated buffer.
     */
    size_t size;
    /**
     * The file descriptor this parser operates on.
     */
    int fd;
} line_parser_t;

/**
 * (Re-)allocates a string buffer for a line parser so that it can hold a
 * complete copy of the file in memory.
 *
 * If the size of a file cannot be determined (lseek() does not work on proc
 * files), the buffer size is increased with each invocation.
 *
 * @param lp the line parser to use.
 * @return 0 if the buffer could be allocated, a non-zero value else.
 */
static int
lp__resize(line_parser_t *lp)
{
    off_t file_size = 0;

    HIP_ASSERT(lp != NULL);

    if (lp->start != NULL) {
        free(lp->start);
    }

    /* First, we try to determine the current file size for the new buffer size.
     * If that fails (it does, e.g., for proc files), we just increase the
     * current buffer size. */
    file_size = lseek(lp->fd, 0, SEEK_END);
    if (file_size != -1) {
        lp->size = file_size + 4096; // add a little head room
    } else {
        if (lp->size < 4096) {
            lp->size = 4096;
        } else {
            HIP_ASSERT(lp->size < 1024 * 1024 * 1024);
            lp->size *= 2;
        }
    }

    // allocate the buffer
    lp->start = (char *)malloc(lp->size);
    if (NULL == lp->start) {
        lp->size = 0;
    }

    return (NULL == lp->start);
}

/**
 * Make sure that modifications to the file since the last invocation of
 * lp_new() or lp_refresh() are visible to subsequent calls to lp_next().
 *
 * This function implicitly ends a parsing pass and a call to lp_first() should
 * follow.
 *
 * @param lp the line parser to use.
 * @return 0 if the parser was successfully refreshed. A non-zero value if an
 *  error occurred and lp_next() should not be called.
 */
static int
lp_refresh(line_parser_t *lp)
{
    ssize_t bytes = 0;

    HIP_ASSERT(lp != NULL);

    // force a new parsing pass in any case
    lp->cur = NULL;

    while (1) {
        // can we re-read the whole file into the memory buffer?
        lseek(lp->fd, 0, SEEK_SET);
        bytes = read(lp->fd, lp->start, lp->size);
        if (bytes == -1) {
            // we can't read from the file at all -> return error
            break;
        } else if ((size_t)bytes == lp->size) {
            // we can't fit the file into the memory buffer -> resize it
            if (lp__resize(lp) == 0) {
                // successful resize -> retry reading
                continue;
            } else {
                // error resizing -> return error
                break;
            }
        } else {
            // successfully read the file contents into the buffer
            lp->cur = lp->start;
            lp->end = lp->start + bytes;
            return 0;
        }
    }

    lp->end = NULL;

    return 1;
}

/**
 * Creates a line parser that can parse the specified file.
 *
 * When this function returns successfully, lp_first() can be called immediately
 * without calling lp_refresh() first.
 *
 * @param file_name the name of the file to parse. The line parser only
 *  supports the files tcp, tcp6, udp, and udp6 in /proc/net/.
 * @return a line parser instance if the parser could initialize correctly.
 *  NULL, if the specified file is not supported.
 */
static line_parser_t *
lp_new(const char *file_name)
{
    line_parser_t *lp = NULL;

    HIP_ASSERT(file_name != NULL);

    lp = (line_parser_t *)calloc(1, sizeof(line_parser_t));
    if (lp != NULL) {
        lp->fd = open(file_name, O_RDONLY);
        if (lp->fd != -1) {
            // start, cur, end, size are now NULL/0 thanks to calloc()
            // initialize file mapping/buffer
            if (lp_refresh(lp) == 0) {
                return lp;
            }
        }
        free(lp);
    }

    return NULL;
}

/**
 * Deletes a line parser and releases all resources associated with it.
 */
static void
lp_delete(line_parser_t *lp)
{
    HIP_ASSERT(lp != NULL);
    if (lp->fd != -1) {
        close(lp->fd);
    }
    if (lp->start != NULL) {
        free(lp->start);
    }
    free(lp);
}

/**
 * Start a new parsing pass with a line parser.
 *
 * A parsing pass consists of starting it via lp_first() and iterating over
 * the lines in the file via lp_next() until it returns NULL.
 * If the file contents have changed since the previous parsing pass, they are
 * not guaranteed to be visible in the new parsing pass.
 * To ensure that modifications are visible, by lp_next(), call lp_refresh().
 *
 * @param lp the line parser to use.
 * @return a pointer to the first line in the file or NULL if no line is
 *  available.
 */
static inline char *
lp_first(line_parser_t *lp)
{
    HIP_ASSERT(lp != NULL);

    lp->cur = lp->start;

    return lp->cur;
}

/**
 * Get the next line in a parsing pass with a line parser.
 *
 * Each invocation of this function returns a pointer to consecutive lines in
 * the file to parse.
 * After the last line has been reached, NULL is returned.
 * In that case, parsing can restart by calling lp_first().
 *
 * @param lp the line parser parser to use.
 * @return a pointer to a line in the file or NULL if there are no more lines
 *  available.
 */
static inline char *
lp_next(line_parser_t *lp)
{
    HIP_ASSERT(lp != NULL);

    // have we reached the end of the buffer in a previous invocation?
    if (lp->cur != NULL) {
        size_t remaining;

        // for basic sanity, make sure that lp->cur points somewhere into the buffer
        HIP_ASSERT(lp->cur >= lp->start && lp->cur < lp->end);

        remaining = lp->end - lp->cur;
        lp->cur = (char *)memchr(lp->cur, '\n', remaining);

        // given the rest of the parsing code, we should always find a \n, but
        // let's check to be sure
        if (lp->cur != NULL) {
            // cur should not point to the new-line character but to the next one:
            lp->cur += 1;
            // is there text on the line here or are we at the end?
            if (lp->cur >= lp->end) {
                lp->cur = NULL;
            }
        }
    }

    return lp->cur;
}



static line_parser_t *tcp6_parser = NULL;
static line_parser_t *udp6_parser = NULL;

/**
 * Check from the proc file system whether a local port is attached
 * to an IPv4 or IPv6 address. This is required to determine whether
 * incoming packets should be diverted to an LSI.
 *
 * @param protocol protocol type
 * @param port the port number of the socket
 * @return the traffic type associated with the given port.
 */
static hip_port_info_t
get_port_info_from_proc(const uint8_t protocol,
                        const uint16_t port)
{
    hip_port_info_t result = HIP_PORT_INFO_UNBOUND;
    line_parser_t *lp = NULL;

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

    // TODO: synchronize refreshing the parser buffers with cache invalidation
    lp_refresh(lp);
    char *line = lp_first(lp);
    while (line != NULL) {
        unsigned int proc_port = 0;
        sscanf(line + 39, "%X", &proc_port);
        if (proc_port == port) {
            result = HIP_PORT_INFO_IPV6;
            break;
        }
    }

    HIP_ASSERT(HIP_PORT_INFO_UNBOUND == result ||
               HIP_PORT_INFO_IPV6 == result ||
               HIP_PORT_INFO_IPV4 == result ||
               HIP_PORT_INFO_LSI == result);
    return result;
}

/**
 */
hip_port_info_t
hip_get_port_info(const uint8_t protocol,
                  const in_port_t port)
{
    hip_port_info_t info = HIP_PORT_INFO_UNBOUND;

    // check input parameters
    if (IPPROTO_TCP == protocol ||
        IPPROTO_UDP == protocol) {
        const uint8_t port_hbo = ntohs(port);

        // check the cache before checking /proc
        info = cache_get(protocol, port_hbo);

        if (HIP_PORT_INFO_UNKNOWN == info) {
            info = get_port_info_from_proc(protocol, port_hbo);
            cache_set(protocol, port_hbo, info);
        }
    } else {
        HIP_ERROR("Protocol %d not supported\n", protocol);
    }

    // check return value
    HIP_ASSERT(HIP_PORT_INFO_UNBOUND == info ||
               HIP_PORT_INFO_IPV6 == info ||
               HIP_PORT_INFO_IPV4 == info ||
               HIP_PORT_INFO_LSI == info);

    return info;
}

void hip_init_port_info(void)
{
    cache_init();
    tcp6_parser = lp_new("/proc/net/tcp6");
    udp6_parser = lp_new("/proc/net/udp6");
}

void hip_uninit_port_info(void)
{
    lp_delete(tcp6_parser);
    lp_delete(udp6_parser);
    cache_uninit();
}

