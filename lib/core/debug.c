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
 * Debugging functions for HIPL userspace applications. Production of quality
 * code prints debugging stuff via syslog, testing code prints interactively on
 * stderr. This is done automatically using DEBUG flag in Makefile (see logtype
 * variable below).
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

#include "lib/tool/lutil.h"
#include "modules/update/hipd/update.h"
#include "builder.h"
#include "common.h"
#include "ife.h"
#include "list.h"
#include "prefix.h"
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
static enum logtype logtype   = LOGTYPE_STDERR;
#else
static enum logtype logtype   = LOGTYPE_SYSLOG;
#endif /* CONFIG_HIP_DEBUG */

#ifdef HIP_LOGFMT_LONG
static enum logfmt logfmt     = LOGFMT_LONG;
#else
static enum logfmt logfmt     = LOGFMT_SHORT;
#endif /* HIP_LONGFMT */

static enum logdebug logdebug = LOGDEBUG_ALL;

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
 * Convert a 4-bit value to a hexadecimal string representation.
 *
 * @param q     the 4-bit value (an integer between 0 and 15) to convert to hex.
 * @return      1 byte of hexadecimal output as a string character.
 */
static char hip_quad2hex(const char q)
{
    HIP_ASSERT(q < 16);

    if (q < 10) {
        return '0' + q;
    } else {
        return 'A' + (q - 10);
    }
}

/**
 * Convert a single byte to a hexadecimal string representation.
 *
 * @param c     the byte to convert to hex.
 * @param bfr   the buffer to write the 2 bytes of hexadecimal output to.
 */
static void hip_byte2hex(const char c, char* bfr)
{
    const int high_quad = (c & 0xF0) >> 4;
    const int low_quad = c & 0x0F;
    *bfr = hip_quad2hex(high_quad);
    *(bfr + 1) = hip_quad2hex(low_quad);
}

/**
 * Write the hexadecimal string representation of a memory area to a buffer.
 * At most @a in_len bytes of the input memory are read and at most @a out_len bytes of the output buffer are written, whichever comes first.
 * If at least one byte was converted, the hexadecimal representation is terminated by 0.
 * If the memory regions of @a in and @a out overlap, the result of the operation is undefined.
 *
 * @param in        the address of the start of the memory area to convert.
 * @param in_len    the size in bytes of the memory area to convert.
 * @param out       the address of the buffer to write the hexadecimal representation to.
 * @param out_len   the size in bytes of the out buffer to write to.
 * @return          the number of bytes from in that were converted.
 */
static size_t hip_mem2hex(const void* in, const size_t in_len, char* out, const size_t out_len)
{
    if (in_len > 0 && out_len > 2) {
        const unsigned char* in_cur = in;
        const unsigned char* in_end = in_cur + in_len;
        char* out_cur = out;
        const char* out_end = out_cur + out_len;

        // terminate if either we reach the end of in or if there is not enough room to write another hex digit and the terminating 0 into out.
        while (in_cur < in_end && out_cur <= (out_end - 3)) {
            hip_byte2hex(*in_cur, out_cur);

            in_cur += 1;
            out_cur += 2;
        }

        *out_cur = '\0';

        return (in_cur - (const unsigned char*)in);
    } else {
        return 0;
    }
}

/**
 * Convert a byte to its printable ASCII representation (e.g. the numeric value 65 is converted to 'A').
 * If it is not printable, convert it to '.'.
 *
 * @param b the byte to convert.
 * @return  the printable ASCII representation of @a b
 */
static char hip_byte2printable(const char b)
{
    if (b >= 32 && b <= 126) {
        return b;
    } else {
        return '.';
    }
}

static const unsigned int HIP_MEM2PRETTY_HEX_INPUT_LINE_LENGTH = 16;
static const unsigned int HIP_MEM2PRETTY_HEX_OUTPUT_LINE_LENGTH = (16 /*HIP_MEM2PRETTY_HEX_INPUT_LINE_LENGTH*/ * 4) + 1;

/**
 * Retrieve the amount of buffer space necessary to hold the pretty printed output produced by hip_mem2pretty_hex().
 *
 * @param in_len    the size of the memory area to convert with hip_mem2pretty_hex()
 * @return          the number of bytes of the hip_mem2pretty_hex() output.
 */
static size_t hip_mem2pretty_hex_size(const size_t in_len)
{
    // for each line, i.e., multiple of 16 input bytes (including partial ones):
    // 32 bytes for hex digits, 16 bytes for spaces, 16 bytes for ascii, 1 line == 65 bytes
    // plus terminating 0 character
    const size_t full_lines = in_len / 16;
    const size_t partial_lines = (in_len % 16) != 0 ? 1 : 0;
    return ((full_lines + partial_lines) * HIP_MEM2PRETTY_HEX_OUTPUT_LINE_LENGTH) + 1;
}

/**
 * Create one line of a pretty-printed hexadecimal string representation of a memory area in the format of the hexdump -C UNIX command to a buffer.
 * At most @a in_len bytes of the memory are read and at most @a out_len bytes are are written, whichever comes first.
 * The function always writes a full line of HIP_MEM2PRETTY_HEX_OUTPUT_LINE_LENGTH bytes including a newline character into out.
 * If the memory regions of @a in and @a out overlap, the result of the operation is undefined.
 *
 * Example of the output:
 * <pre>
 * 13 88 94 64 0d b9 89 ff f3 cc 4c a1 80 11 05 94 ...d......L.....
 * </pre>
 *
 * @param in        the address of the start of the memory area to convert.
 * @param in_len    the size in bytes of the memory area to convert. At most HIP_MEM2PRETTY_HEX_INPUT_LINE_LENGTH bytes are read.
 * @param out       the address of the buffer to write the hexadecimal representation to. Exactly HIP_MEM2PRETTY_HEX_OUTPUT_LINE_LENGTH are written.
 * @param out_len   the size in bytes of the out buffer to write to. This value should be greater or equal to HIP_MEM2PRETTY_HEX_OUTPUT_LINE_LENGTH.
 * @return          1 if a line of output was written to out. 0 and no output is written if @a in_len is 0 or if @a out_len is less than HIP_MEM2PRETTY_HEX_OUTPUT_LINE_LENGTH.
 */
static int hip_mem2pretty_hex_line(const char* in, const size_t in_len, char* out, const size_t out_len)
{
    if (in_len > 0 && out_len >= HIP_MEM2PRETTY_HEX_OUTPUT_LINE_LENGTH) {
        const char* in_cur = in; // incremented with every fully processed input byte
        const char* in_end = in_cur + in_len; // the final input byte + 1, i.e., the first not to read from
        const char* in_line_end = in_cur + HIP_MEM2PRETTY_HEX_INPUT_LINE_LENGTH; // the input byte to iterate 'in_cur' up to
        char* hex = out;
        char* ascii = out + HIP_MEM2PRETTY_HEX_INPUT_LINE_LENGTH * 3;

        // write hex and ascii representations
        while (in_cur < in_line_end) {
            // is there still input data available?
            if (in_cur < in_end) {
                // convert input
                hip_byte2hex(*in_cur, hex);  // add hex digits
                *ascii = hip_byte2printable(*in_cur);    // add printable char
            } else {
                // write dummy output
                *hex = ' ';
                *(hex + 1) = ' ';
                *ascii = ' ';
            }

            *(hex + 2) = ' ';   // add space between hex digits
            hex += 3;   // move to next hex digit position
            ascii += 1; // move to next ascii position
            in_cur += 1; // move to next input byte (it's okay to increment this even if in_cur >= in_end because in that case we do not read from this pointer)
        }

        // at this point, we have written a full line and ascii points to its end - add a newline.
        *ascii = '\n';

        return 1;
    } else {
        return 0;
    }
}

/**
 * Write a pretty-printed hexadecimal string representation of a memory area in the format of the hexdump -C UNIX command to a buffer.
 * At most @a in_len bytes of the memory are read and at most @a out_len bytes are are written, whichever comes first.
 * If at least one byte was converted, the hexadecimal representation is terminated by a null character.
 * If the memory regions of @a in and @a out overlap, the result of the operation is undefined.
 *
 * Example of the output:
 * <pre>
 * 13 88 94 64 0d b9 89 ff f3 cc 4c a1 80 11 05 94 ...d......L.....
 * 6c 3c 00 00 01 01 08 0a 00 10 a2 58 00 0f 98 30 l<.........X....
 * </pre>
 *
 * @param in        the address of the start of the memory area to convert.
 * @param in_len    the size in bytes of the memory area at @a in to convert.
 * @param out       the address of the buffer to write the hexadecimal representation to.
 * @param out_len   the size in bytes of the @a out buffer to write to.
 * @return          the number of bytes from @a in that were converted.
 */
static size_t hip_mem2pretty_hex(const void* in, const size_t in_len, char* out, const size_t out_len)
{
    // Points to where the input for the next line is to be read from. Incremented by HIP_MEM2PRETTY_HEX_INPUT_LINE_LENGTH with every line.
    const char* in_cur = in;
    // Points to where the next line of output is to be written to. Incremented by HIP_MEM2PRETTY_HEX_OUTPUT_LINE_LENGTH with every line.
    char* out_cur = out;
    // Points to the final input byte + 1, i.e., the first input byte not to read from.
    const char* in_end = in_cur + in_len;
    // Points to the final output byte + 1, i.e., the first output byte not to write to.
    const char* out_end = out_cur + out_len;

    // Iterate while there is still input to read and enough room for another full line including the terminating null character.
    while (in_cur < in_end && out_cur <= (out_end - (HIP_MEM2PRETTY_HEX_OUTPUT_LINE_LENGTH + 1))) {
        const size_t in_remaining = in_len - (in_cur - (const char*)in);
        const size_t out_remaining = out_len - (out_cur - (const char*)out);

        // convert one line of input
        const int line_result = hip_mem2pretty_hex_line(in_cur, in_remaining, out_cur, out_remaining);
        // since the loop condition already makes sure that the input to hip_mem2pretty_hex_line() is valid, it must return 1.
        HIP_ASSERT(line_result == 1);

        // advance input pointer by at most the maximum available input so the return value is calculated correctly
        in_cur += (in_remaining > HIP_MEM2PRETTY_HEX_INPUT_LINE_LENGTH ? HIP_MEM2PRETTY_HEX_INPUT_LINE_LENGTH : in_remaining);
        out_cur += HIP_MEM2PRETTY_HEX_OUTPUT_LINE_LENGTH;
    }

    if (out_cur < out_end) {
        *out_cur = '\0';
    }

    return in_cur - (const char*)in;
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
                 const char *prefix, const void *str, const size_t len)
{
    if (len > 0) {
        const size_t buffer_size = (len * 2) + 1;
        char* buffer = malloc(buffer_size);
        if (buffer != NULL) {
            hip_mem2hex(str, len, buffer, buffer_size);
            hip_print_str(DEBUG_LEVEL_DEBUG, file, line, function, "%s0x%s\n", prefix, buffer);
            free(buffer);
        } else {
            HIP_DIE("memory allocation failed\n");
        }
    }
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
void hip_hexdump_parsed(const char *file, int line, const char *function,
                        const char *prefix, const void *str, const size_t len)
{
    if (len > 0) {
        const size_t buffer_size = hip_mem2pretty_hex_size(len);
        char* buffer = malloc(buffer_size);
        if (buffer != NULL) {
            hip_mem2pretty_hex(str, len, buffer, buffer_size);
            hip_print_str(DEBUG_LEVEL_DEBUG, file, line, function, "%s%s\n", prefix, buffer);
            free(buffer);
        } else {
            HIP_DIE("memory allocation failed\n");
        }
    }
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
    const void *addr;
    int family        = sockaddr->sa_family;
    char addr_str[INET6_ADDRSTRLEN + 1];

    switch (family) {
    case AF_INET:
        maxlen = INET_ADDRSTRLEN;
        addr   = &((const struct sockaddr_in *) sockaddr)->sin_addr;
        break;
    case AF_INET6:
        maxlen = INET6_ADDRSTRLEN;
        addr   = &((const struct sockaddr_in6 *) sockaddr)->sin6_addr;
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
void hip_print_locator_addresses(const struct hip_common *in_msg)
{
    const struct hip_locator *locator;
    const struct hip_locator_info_addr_item *ptr    = NULL;
    const struct hip_locator_info_addr_item *item   = NULL;
    const struct hip_locator_info_addr_item2 *item2 = NULL;
    const char *address_pointer;

    locator = hip_get_param(in_msg, HIP_PARAM_LOCATOR);
    if (locator) {
        address_pointer = (const char *) (locator + 1);

        for (; address_pointer < ((const char *) locator) +
                                 hip_get_param_contents_len(locator); ) {
            ptr = (const struct hip_locator_info_addr_item *) address_pointer;
            if (ptr->locator_type == HIP_LOCATOR_LOCATOR_TYPE_UDP) {
                item2 = (const struct hip_locator_info_addr_item2 *)
                        address_pointer;
                HIP_DEBUG_HIT("LOCATOR", &item2->address);
                HIP_DEBUG("Locator address offset is %d\n",
                          address_pointer - (const char *) (locator + 1));
                address_pointer += sizeof(struct hip_locator_info_addr_item2);
            } else if (ptr->locator_type == HIP_LOCATOR_LOCATOR_TYPE_ESP_SPI) {
                item = (const struct hip_locator_info_addr_item *)
                       address_pointer;
                HIP_DEBUG_HIT("LOCATOR", &item->address);
                address_pointer += sizeof(struct hip_locator_info_addr_item);
            } else if (ptr->locator_type == HIP_LOCATOR_LOCATOR_TYPE_IPV6) {
                item = (const struct hip_locator_info_addr_item *)
                       address_pointer;
                HIP_DEBUG_HIT("LOCATOR", &item->address);
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
void hip_print_peer_addresses_to_be_added(struct hip_hadb_state *entry)
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
        addr = list_entry(item);
        HIP_DEBUG_HIT("Peer address", &addr->address);
    }
}
