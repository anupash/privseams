/**
 * @file
 * Debugging functions for HIPL userspace applications. Production of quality
 * code prints debugging stuff via syslog, testing code prints interactively on
 * stderr. This is done automatically using DEBUG flag in Makefile (see logtype
 * variable below).
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
 * Examples:
 *<pre>
 * HIP_INFO("test foobar");
 * HIP_INFO("%s\n", "debug test");
 * HIP_ERROR("%s%d\n", "serious error!", 123);
 * HIP_DIE("%s\n", "really bad error, exiting!");
 * HIP_PERROR("socket");
 * HIP_HEXDUMP("foobar", data, len);
 *</pre>
 *
 * Adjusting of log types and format dynamically. (there really should not be a
 * reason to call these in the code, because default settings should be
 * reasonable)
 *
 *<pre>
 * hip_set_logtype(LOGTYPE_STDERR); // set logging output to stderr
 * hip_set_logfmt(LOGFMT_SHORT);    // set short logging format
 *</pre>
 *
 * @todo debug messages should not be compiled at all in a production release
 * @todo set_log{type|format}(XX_DEFAULT)
 * @todo locking (is it really needed?)
 * @todo optimize: openlog() and closelog() called only when needed
 * @todo ifdef gcc (in vararg macro)?
 * @todo production use: disable info messages?
 * @todo move file+line from prefix to the actual message body
 * @todo handle_log_error(): add different policies (exit(), ignore, etc)
 * @todo check what vlog("xx\nxx\n") does with syslog
 * @todo struct info { char *file, int line, char *function } ?
 * @todo macro for ASSERT
 * @todo change char * to void * in hexdump ?
 * @todo HIP_ASSERT()
 *
 * @note About the newlines: PERROR() appends always a newline after message to
 *       be printed as in perror(3). In the rest of the functions, you have to
 *       append a newline (as in fprinf(3)).
 */

#define _BSD_SOURCE

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "lib/core/common.h"
#include "lib/core/list.h"
#include "lib/core/prefix.h"
#include "lib/tool/lutil.h"
#include "builder.h"
#include "ife.h"
#include "state.h"
#include "straddr.h"
#include "debug.h"

#define SYSLOG_OPT        (LOG_PID)
//#define SYSLOG_FACILITY   LOG_DAEMON
#define SYSLOG_FACILITY   LOG_LOCAL6

/* must be in the same order as enum debug_level (straight mapping) */
const int debug2syslog_map[] = { LOG_ALERT,
                                 LOG_ERR,
                                 LOG_INFO,
                                 LOG_DEBUG };

/* must be in the same order as enum debug_level (straight mapping) */
const char *debug_prefix[] = { "die", "error", "info", "debug"};
/* printed just on stderr */

/* Production quality code prints debugging stuff on syslog, testing code
 * prints interactively on stderr. Third type LOGTYPE_NOLOG is not listed
 * here and it should not be used.
 */
#ifdef CONFIG_HIP_DEBUG
static enum logtype_t logtype   = LOGTYPE_STDERR;
#else
static enum logtype_t logtype   = LOGTYPE_SYSLOG;
#endif /* CONFIG_HIP_DEBUG */

#ifdef HIP_LOGFMT_LONG
static enum logfmt_t logfmt     = LOGFMT_LONG;
#else
static enum logfmt_t logfmt     = LOGFMT_SHORT;
#endif /* HIP_LONGFMT */

static enum logdebug_t logdebug = LOGDEBUG_ALL;

/**
 * @brief Sets logging to stderr or syslog.
 *
 * Defines where HIP daemon DEBUG, INFO, ERROR etc. messages are printed.
 *
 * @param new_logtype the type of logging output, either LOGTYPE_STDERR or
 *                    LOGTYPE_SYSLOG
 */
void hip_set_logtype(int new_logtype)
{
    logtype = new_logtype;
}

/**
 * @brief Sets the formatting of log output.
 *
 * Defines whether the messages should include file name and line number or not.
 *
 * @param new_logfmt the format of the log output, either LOGFMT_SHORT or
 *                    LOGFMT_LONG
 */
void hip_set_logfmt(int new_logfmt)
{
    logfmt = new_logfmt;
}

/**
 * @brief Selects what logging messages to display.
 *
 * @param new_logdebug either LOGDEBUG_ALL, LOGDEBUG_MEDIUM or LOGDEBUG_NONE
 * @return             always zero.
 */
int hip_set_logdebug(int new_logdebug)
{
    logdebug = new_logdebug;
    return 0;
}

/**
 * handle errors generated by log handling
 *
 * @param log_type the type of the log that generated the error (LOGTYPE_STDERR or
 *           LOGTYPE_SYSLOG)
 *
 * @note The default policy is to ignore errors (an alternative policy would
 * be to e.g. exit).
 * @note Do not use this function outside of this file at all.
 *
 */
static void hip_handle_log_error(int log_type)
{
    fprintf(stderr, "log (type=%d) failed, ignoring\n", log_type);
}

/**
 * "multiplexer" for correctly outputting all debug messages
 *
 * @param debug_level the urgency of the message (DEBUG_LEVEL_XX)
 * @param file the file from where the debug call was made
 * @param line the line of the debug call in the source file
 * @param function the name of function where the debug call is located
 * @param fmt the output format of the debug message as in printf(3)
 * @param args the variable argument list to be output
 * @note This function is to be used only from the hip_debug(), hip_info(), etc
 * debugging functions. Do not use outside of this file.
 */
static void hip_vlog(int debug_level, const char *file, const int line,
                     const char *function, const char *fmt, va_list args)
{
    char syslog_msg[DEBUG_MSG_MAX_LEN] = "";
    int syslog_level                   = debug2syslog_map[debug_level];
    char prefix[DEBUG_PREFIX_MAX]      = "\0";
    int printed                        = 0;

    if (logfmt == LOGFMT_LONG) {
        /* note: printed is not absolutely necessary to check in this case;
         * worst case is that filename or line number could be shortened */
        printed = snprintf(prefix, DEBUG_PREFIX_MAX, "%s(%s:%d@%s)",
                           debug_prefix[debug_level], file, line, function);
    } else {
        /* LOGFMT_SHORT: no prefix */
    }

    switch (logtype) {
    case LOGTYPE_NOLOG:
        break;
    case LOGTYPE_STDERR:
        if (strlen(prefix) > 0) {
            printed = fprintf(stderr, "%s: ", prefix);
            if (printed < 0) {
                goto err;
            }
        } else {
            /* LOGFMT_SHORT: no prefix */
        }

        printed = vfprintf(stderr, fmt, args);
        if (printed < 0) {
            goto err;
        }
        break;
    case LOGTYPE_SYSLOG:
        openlog(NULL, SYSLOG_OPT, SYSLOG_FACILITY);
        printed = vsnprintf(syslog_msg, DEBUG_MSG_MAX_LEN, fmt, args);
        syslog(syslog_level | SYSLOG_FACILITY, "%s %s", prefix, syslog_msg);
        /* the result of vsnprintf depends on glibc version; handle them both
         * (note about barriers: printed has \0 excluded,
         * DEBUG_MSG_MAX_LEN has \0 included) */
        if (printed < 0 || printed > DEBUG_MSG_MAX_LEN - 1) {
            syslog(syslog_level | SYSLOG_FACILITY,
                   "%s", "previous msg was truncated!!!");
        }
        closelog();
        break;
    default:
        printed = fprintf(stderr, "hip_vlog(): undefined logtype: %d", logtype);
        exit(1);
    }

    /* logging was succesful */
    return;

err:
    hip_handle_log_error(logtype);
}

/**
 * a wrapper that filters unnecessary logging for hip_vlog()
 *
 * @param debug_level the debug level
 * @param file a file handle where to print
 * @param line the line number
 * @param function the calling function
 * @param fmt printf formatting options
 * @param ... variable number of strings or integers to print
 *        according to the @c fmt parameter
 * @note Do not call this function outside of this file at all.
 */
void hip_print_str(int debug_level,
                   const char *file,
                   int line,
                   const char *function,
                   const char *fmt,
                   ...)
{
    va_list args;
    va_start(args, fmt);
    if ((debug_level == DEBUG_LEVEL_INFO && logdebug != LOGDEBUG_NONE) ||
        (debug_level == DEBUG_LEVEL_DEBUG && logdebug == LOGDEBUG_ALL) ||
        (debug_level == DEBUG_LEVEL_ERROR && logdebug != LOGDEBUG_NONE) ||
        (debug_level == DEBUG_LEVEL_DIE)) {
        hip_vlog(debug_level, file, line, function, fmt, args);
    }
    va_end(args);
}

/**
 * @brief output development (low level) debugging messages
 *
 * A debug group and a debug level can be given. Debug
 * messages are only displayed if the debug group matches
 * the current debug group and the debug leven is smaller
 * than the current debug level.
 *
 * @param debug_group the debug group which has to be matched
 * @param debug_level the debug level of the debug output
 * @param file the file from where the debug call was made
 * @param line the line of the debug call in the source file
 * @param function the name of function where the debug call is located
 * @param fmt the output format of the debug message as in printf(3)
 *
 * @note The variable size argument list (...) is used as in printf(3).
 * Do not call this function from the outside of the debug module,
 * use the HIP_DEBUG_GL macro instead.
 */
void hip_debug_gl(int debug_group, int debug_level,
                  const char *file, int line,
                  const char *function, const char *fmt, ...)
{
    if (debug_level <= HIP_DEBUG_LEVEL &&
        (HIP_DEBUG_GROUP == HIP_DEBUG_GROUP_ALL ||
         debug_group == HIP_DEBUG_GROUP) && logdebug == LOGDEBUG_ALL) {
        va_list args;
        va_start(args, fmt);
        hip_vlog(DEBUG_LEVEL_DEBUG, file, line, function, fmt, args);
        va_end(args);
    }
}

/**
 * output a fatal error and exit
 *
 * @param file the file from where the debug call was made
 * @param line the line of the debug call in the source file
 * @param function the name of function where the debug call is located
 * @param fmt the output format of the debug message as in printf(3)
 *
 * @note The variable size argument list (...) is used as in printf(3).
 * Do not call this function from the outside of the debug module,
 * use the HIP_DIE macro instead.
 */
void hip_die(const char *file, int line, const char *function,
             const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    hip_print_str(DEBUG_LEVEL_DIE, file, line, function, fmt, args);
    va_end(args);
    exit(1);
}

/**
 * output an error message (high level)
 *
 * @param file the file from where the debug call was made
 * @param line the line of the debug call in the source file
 * @param function the name of function where the debug call is located
 * @param fmt the output format of the debug message as in printf(3)
 *
 * @note The variable size argument list (...) is used as in printf(3).
 * Do not call this function from the outside of the debug module,
 * use the HIP_ERROR macro instead.
 */
static void hip_error(const char *file, int line, const char *function,
                      const char *fmt, ...)
{
    if (logdebug != LOGDEBUG_NONE) {
        va_list args;
        va_start(args, fmt);
        hip_vlog(DEBUG_LEVEL_ERROR, file, line, function, fmt, args);
        va_end(args);
    }
}

/**
 * a wrapper for perror(3) style calls
 *
 * @param file the file from where the debug call was made
 * @param line the line of the debug call in the source file
 * @param function the name of function where the debug call is located
 * @param s the string as in perror(3)
 *
 * @note The newline is already included after the first line in favour of
 * the perror(3) syntax. Do not call this function from the outside of the
 * debug module, use the HIP_PERROR macro instead.
 */
void hip_perror_wrapper(const char *file, int line, const char *function,
                        const char *s)
{
    hip_error(file, line, function, "%s%s\n", s, strerror(errno));
}

/**
 * Print raw hexdump starting from address @c str of length @c len. Do not call
 * this function from the outside of the debug module, use the HIP_HEXDUMP macro
 * instead.
 *
 * @param file     the file from where the debug call was made
 * @param line     the line of the debug call in the source file
 * @param function the name of function where the debug call is located
 * @param prefix   the prefix string will printed before the hexdump
 * @param str      pointer to the beginning of the data to be hexdumped
 * @param len      the length of the data to be hexdumped
 */
void hip_hexdump(const char *file, int line, const char *function,
                 const char *prefix, const void *str, int len)
{
    int hexdump_max_size = 0;
    int hexdump_count    = 0;
    char *hexdump        = NULL;
    int hexdump_written  = 0;
    int hexdump_index    = 0;
    int char_index       = 0;

    hexdump_max_size = len * 2 + 1;
    hexdump_count    = hexdump_max_size;

    hexdump          = calloc(hexdump_max_size, sizeof(char));
    if (hexdump == NULL) {
        HIP_DIE("hexdump memory allocation failed\n");
    }
    if (len == 0) {
        /* Removed this error message to keep hexdump quiet in
         * HIP_DUMP_MSG for zero length padding. Lauri 22.09.2006 */
        //HIP_ERROR("hexdump length was 0\n");
    } else {
        do {
            /* note: if you change the printing format, adjust also hexdump_count! */
            hexdump_written
                    = snprintf((char *) (hexdump + hexdump_index),
                               hexdump_count,
                               "%02x",
                               (unsigned char) (*(((unsigned char *) str)
                                       + char_index)));
            if (hexdump_written < 0 || hexdump_written > hexdump_max_size - 1) {
                free(hexdump);
                HIP_DIE("hexdump msg too long(%d)", hexdump_written);
            } else {
                hexdump_count -= hexdump_written;
                HIP_ASSERT(hexdump_count >= 0);
                hexdump_index += hexdump_written;
                HIP_ASSERT(hexdump_index + hexdump_count == hexdump_max_size);
            }
            char_index++;
        } while (char_index < len);

        hip_print_str(DEBUG_LEVEL_DEBUG, file, line, function, "%s0x%s\n", prefix, hexdump);
    }

    free(hexdump);
}

/**
 * Print fancy hexdump starting from address @c str of length @c len. Do not call
 * this function from the outside of the debug module, use the HIP_DUMP_PACKET macro
 * instead.
 *
 * Example of the output:
 * <pre>
 * 13 88 94 64 0d b9 89 ff f3 cc 4c a1 80 11 05 94 ...d......L.....
 * 6c 3c 00 00 01 01 08 0a 00 10 a2 58 00 0f 98 30 l<.........X....
 * </pre>
 *
 * @param file     the file from where the debug call was made
 * @param line     the line of the debug call in the source file
 * @param function the name of function where the debug call is located
 * @param prefix   the prefix string will printed before the hexdump
 * @param str      pointer to the beginning of the data to be hexdumped
 * @param len      the length of the data to be hexdumped
 */
int hip_hexdump_parsed(const char *file, int line, const char *function,
                       const char *prefix, const void *str, int len)
{
    int hexdump_total_size = 0;
    int hexdump_count      = 0;
    int hexdump_written    = 0;
    int hexdump_index      = 0;
    int char_index         = 0;
    char *hexdump          = NULL;

    int bytes_per_line     = 16;
    char space             = ' ';
    char nonascii          = '.';
    char *asciidump        = NULL;
    int lines              = 0;
    int line_index         = 0;

    int pad_length         = 0;
    int pad_start_position = 0;

    // Count lines
    if (len % 16 == 0) {
        lines = (int) len / 16;
    } else {
        lines = (int) len / 16 + 1;
    }

    // one byte requires 4 bytes in the output (two for hex, one for ascii and one space)
    hexdump_total_size = lines * 4 * bytes_per_line + 1;
    pad_start_position = len * 3 + ((lines - 1) * bytes_per_line) + 1;
    hexdump_count      = hexdump_total_size;
    pad_length         = (hexdump_total_size - bytes_per_line) - pad_start_position;

    hexdump            = calloc(hexdump_total_size, sizeof(char));
    asciidump          = calloc((bytes_per_line + 2), sizeof(char));

    if (hexdump == NULL || asciidump == NULL) {
        HIP_DIE("memory allocation failed\n");
    }

    if (len > 0) {
        while (char_index < len) {
            // Write the character in hex
            hexdump_written = snprintf((char *) (hexdump + hexdump_index),
                                       hexdump_count, "%02x", (unsigned char) (*(((unsigned char *) str) + char_index)));
            if (hexdump_written < 0 || hexdump_written > hexdump_total_size - 1) {
                free(hexdump);
                HIP_DIE("hexdump msg too long(%d)", hexdump_written);
            }
            char written = (unsigned char) (*(((unsigned char *) str) + char_index));

            // Write space between
            hexdump_index  += hexdump_written;
            hexdump_count  -= hexdump_written;
            hexdump_written = snprintf((char *) (hexdump + hexdump_index),
                                       hexdump_count, "%c", space);
            if (hexdump_written < 0 || hexdump_written > hexdump_total_size - 1) {
                free(hexdump);
                free(asciidump);
                HIP_DIE("hexdump msg too long(%d)", hexdump_written);
            }
            hexdump_count -= hexdump_written;
            HIP_ASSERT(hexdump_count >= 0);
            hexdump_index += hexdump_written;
            HIP_ASSERT(hexdump_index + hexdump_count == hexdump_total_size);

            /* Write the character in ascii to ascii dump line */
            if (written > 32 && written < 127) {
                memset(asciidump + line_index, written, 1);
            } else {
                memset(asciidump + line_index, nonascii, 1);
            }
            line_index++;
            /* If line is full or input is all read, copy data to hexdump */
            if (line_index >= 16 || (char_index + 1) == len) {
                /* Add padding */
                if ((char_index + 1) == len && pad_length > 0
                    && ((hexdump_index + line_index + pad_length) < hexdump_total_size)) {
                    char *padding = calloc(pad_length + 1, sizeof(char));
                    memset(padding, ' ', pad_length);
                    memset(padding + pad_length, '\0', 1);
                    hexdump_written = snprintf((char *) (hexdump + hexdump_index),
                                               hexdump_count, "%s", padding);
                    if (hexdump_written < 0 || hexdump_written > hexdump_total_size - 1) {
                        free(hexdump);
                        free(asciidump);
                        free(padding);
                        HIP_DIE("hexdump msg too long(%d)", hexdump_written);
                    }
                    hexdump_index += hexdump_written;
                    hexdump_count -= hexdump_written;
                    free(padding);
                }
                memset(asciidump + line_index, '\n', 1);
                memset(asciidump + line_index + 1, '\0', 1);
                hexdump_written = snprintf((char *) (hexdump + hexdump_index),
                                           hexdump_count, "%s", asciidump);
                if (hexdump_written < 0 || hexdump_written > hexdump_total_size - 1) {
                    free(hexdump);
                    free(asciidump);
                    HIP_DIE("hexdump msg too long(%d)", hexdump_written);
                }
                hexdump_index += hexdump_written;
                hexdump_count -= hexdump_written;
                line_index     = 0;
                memset(asciidump, 0, bytes_per_line + 2);
            }
            char_index++;
        }
        hip_print_str(DEBUG_LEVEL_DEBUG, file, line, function, "%s%s\n", prefix, hexdump);
    } else {
        HIP_ERROR("hexdump length was 0\n");
    }

    free(hexdump);
    free(asciidump);

    return 0;
}

/**
 * Print a socket address structure.
 *
 * @param file      source file.
 * @param line      the line of the debug call in the source file
 * @param function  the name of function where the debug call is located
 * @param prefix    the prefix string will printed before the sockaddr
 * @param sockaddr  pointer to the sockaddr to be printed
 *
 * @note Do not call this function from the outside of the debug module, use the
 * HIP_DEBUG_SOCKADDR macro instead.
 * @note Currently this function supports only INET and INET6 addresses.
 */
void hip_print_sockaddr(UNUSED const char *file, UNUSED int line,
                        UNUSED const char *function, const char *prefix,
                        const struct sockaddr *sockaddr)
{
    const char *default_str = "<unknown>";
    int maxlen;
    void *addr;
    int family        = sockaddr->sa_family;
    char addr_str[INET6_ADDRSTRLEN + 1];

    switch (family) {
    case AF_INET:
        maxlen = INET_ADDRSTRLEN;
        addr   = &(((struct sockaddr_in *) sockaddr)->sin_addr);
        break;
    case AF_INET6:
        maxlen = INET6_ADDRSTRLEN;
        addr   = &(((struct sockaddr_in6 *) sockaddr)->sin6_addr);
        break;
    default:
        maxlen = 0;
    }

    if (maxlen == 0) {
        memcpy(addr_str, default_str, strlen(default_str) + 1);
    } else {
        if (!inet_ntop(family, addr, addr_str, maxlen)) {
            HIP_ERROR("inet_ntop");
            return;
        }
    }
    if (prefix) {
        HIP_DEBUG("%s: %s\n", prefix, addr_str);
    } else {
        HIP_DEBUG("%s\n", addr_str);
    }
}

/**
 * print an LSI
 *
 * @param debug_level the urgency of the message (DEBUG_LEVEL_XX)
 * @param file the file from where the debug call was made
 * @param line the line of the debug call in the source file
 * @param function the name of function where the debug call is located
 * @param str string to be printed before the HIT
 * @param lsi the LSI to be printed
 * @note Do not call this function directly. Instead, use the
 *       HIP_DEBUG_LSI and HIP_INFO_LSI macros.
 */
void hip_print_lsi(int debug_level, const char *file, int line, const char *function,
                   const char *str, const struct in_addr *lsi)
{
    char dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, lsi, dst, sizeof(dst));
    hip_print_str(debug_level, file, line, function, "%s: %s\n", str, dst);
}

/**
 * print a HIT
 *
 * @param debug_level the urgency of the message (DEBUG_LEVEL_XX)
 * @param file the file from where the debug call was made
 * @param line the line of the debug call in the source file
 * @param function the name of function where the debug call is located
 * @param str string to be printed before the HIT
 * @param hit the HIT to be printed
 * @note Do not call this function directly. Instead, use the
 *       HIP_DEBUG_HIT and HIP_INFO_HIT macros.
 */
void hip_print_hit(int debug_level, const char *file, int line, const char *function,
                   const char *str, const struct in6_addr *hit)
{
    if (hit == NULL) {
        HIP_DEBUG("%s: NULL\n", str);
        return;
    } else {
        char dst[INET6_ADDRSTRLEN];

        if (IN6_IS_ADDR_V4MAPPED(hit)) {
            struct in_addr in_addr;
            IPV6_TO_IPV4_MAP(hit, &in_addr);
            hip_print_lsi(debug_level, file, line, function, str, &in_addr);
        } else {
            hip_in6_ntop(hit, dst);
            hip_print_str(debug_level, file, line, function, "%s: %s\n", str, dst);
        }
        return;
    }
}

/**
 * display a LOCATOR parameter contents in a HIP control message
 *
 * @param in_msg the message where the LOCATOR parameter is located
 */
void hip_print_locator_addresses(struct hip_common *in_msg)
{
    struct hip_locator *locator;
    struct hip_locator_info_addr_item *item   = NULL;
    struct hip_locator_info_addr_item2 *item2 = NULL;
    char *address_pointer;

    locator = hip_get_param((struct hip_common *) in_msg,
                            HIP_PARAM_LOCATOR);
    if (locator) {
        address_pointer = (char *) (locator + 1);

        for (; address_pointer < ((char *) locator) + hip_get_param_contents_len(locator); ) {
            if (((struct hip_locator_info_addr_item *) address_pointer)->locator_type
                == HIP_LOCATOR_LOCATOR_TYPE_UDP) {
                item2            = (struct hip_locator_info_addr_item2 *) address_pointer;
                HIP_DEBUG_HIT("LOCATOR", (struct in6_addr *) &item2->address);
                HIP_DEBUG("Locator address offset is %d\n", address_pointer - (char *) (locator + 1));
                address_pointer += sizeof(struct hip_locator_info_addr_item2);
            } else if (((struct hip_locator_info_addr_item *) address_pointer)->locator_type
                       == HIP_LOCATOR_LOCATOR_TYPE_ESP_SPI) {
                item             = (struct hip_locator_info_addr_item *) address_pointer;
                HIP_DEBUG_HIT("LOCATOR", (struct in6_addr *) &item->address);
                address_pointer += sizeof(struct hip_locator_info_addr_item);
            } else if (((struct hip_locator_info_addr_item *) address_pointer)->locator_type
                       == HIP_LOCATOR_LOCATOR_TYPE_IPV6) {
                item             = (struct hip_locator_info_addr_item *) address_pointer;
                HIP_DEBUG_HIT("LOCATOR", (struct in6_addr *) &item->address);
                address_pointer += sizeof(struct hip_locator_info_addr_item);
            } else {
                address_pointer += sizeof(struct hip_locator_info_addr_item);
            }
        }
    }
}

/**
 * display peer_addr_list_to_be_added structure from a host association
 *
 * @param entry the host association
 */
void hip_print_peer_addresses_to_be_added(hip_ha_t *entry)
{
    hip_list_t *item = NULL, *tmp = NULL;
    struct hip_peer_addr_list_item *addr;
    int i            = 0;

    HIP_DEBUG("All the addresses in the peer_addr_list_to_be_added list:\n");
    if (entry->peer_addr_list_to_be_added == NULL) {
        return;
    }

    list_for_each_safe(item, tmp, entry->peer_addr_list_to_be_added, i)
    {
        addr = (struct hip_peer_addr_list_item *) list_entry(item);
        HIP_DEBUG_HIT("Peer address", &addr->address);
    }
}

/**
 * hip_print_locator - print a locator
 * @param file
 * @param debug_level
 * @param line
 * @param function
 * @param str string to be printed before the HIT
 * @param locator the locator to be printed
 */
void hip_print_locator(UNUSED int debug_level, UNUSED const char *file,
                       UNUSED int line, UNUSED const char *function,
                       DBG const char *str, const struct hip_locator *locator)
{
/* XXTRASHXX Totally useless does anything but what it is supposed to do -SAMU */

    int n_addrs                                               = 0, i = 0;
    struct hip_locator_info_addr_item *first_address_item     = NULL,
    *locator_address_item                                     = NULL;
    struct hip_locator_info_addr_item2 *locator_address_item2 = NULL;
    /* locator = hip_get_param((struct hip_common *)in_msg,
     * HIP_PARAM_LOCATOR);*/
    if (locator) {
        HIP_DEBUG("%s: \n", str);

        n_addrs            = hip_get_locator_addr_item_count(locator);
        HIP_DEBUG("there are  %d locator items \n", n_addrs);
        first_address_item = hip_get_locator_first_addr_item(locator);

        for (i = 0; i < n_addrs; i++) {
            locator_address_item = (struct hip_locator_info_addr_item *)
                                   hip_get_locator_item(first_address_item, i);
            HIP_DEBUG("locator items index %d, type is %d \n", i,
                      locator_address_item->locator_type );
            if (locator_address_item->locator_type == HIP_LOCATOR_LOCATOR_TYPE_IPV6) {
                HIP_INFO_HIT("locator",
                             (struct in6_addr *) &locator_address_item->address);
            }
            if (locator_address_item->locator_type == HIP_LOCATOR_LOCATOR_TYPE_ESP_SPI) {
                HIP_INFO_HIT("LOCATOR from ESP SPI(type 1)",
                             (struct in6_addr *) &locator_address_item->address);
            }
            if (locator_address_item->locator_type == HIP_LOCATOR_LOCATOR_TYPE_UDP) {
                locator_address_item2 = (struct hip_locator_info_addr_item2 *) locator_address_item;
                HIP_INFO_HIT("LOCATOR from UDP",
                             (struct in6_addr *) &locator_address_item2->address);
                HIP_DEBUG("LOCATOR port for UDP: %d\n",  ntohs(locator_address_item2->port));
            }
        }
    }
}
