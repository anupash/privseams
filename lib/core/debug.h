/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 */

#ifndef HIP_LIB_CORE_DEBUG_H
#define HIP_LIB_CORE_DEBUG_H

#include <stdio.h>
#include <errno.h>
#include <stdarg.h>
#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <netinet/in.h>
#include "config.h"
#include "protodefs.h"
#include "prefix.h"
#include "ife.h"

/* includes filename, line number and max(debug_prefix[]) */
#define DEBUG_PREFIX_MAX  64

/* stderror: includes prefix, separator, msg and \0
 * syslog:   includes msg and \0 */
#define DEBUG_MSG_MAX_LEN     1024

#define SYSLOG_OPT        (LOG_PID)
//#define SYSLOG_FACILITY   LOG_DAEMON
// oleg 2006-11-22
#define SYSLOG_FACILITY   LOG_LOCAL6

/**
 * Error handling macros used for checking errors. To use these macros, define a
 * label named @c out_err at the end of the function. For example, memory
 * allocation/deallocation procedure is as follows:
 * <pre>
 * int f(void)
 * {
 *     char *mem = NULL;
 *     HIP_IFEL(!(mem = HIP_ALLOC(256, 0)), -1, "alloc\n");
 *
 * out_err:
 *     if (mem != NULL) {
 *         free(mem);
 *     }
 *     return err;
 * }
 * </pre>
 * All functions should return an error value instead of "ok" value. That, is
 * zero for success and non-zero for failure. Error values are defined in
 * /usr/include/asm-generic/errno-base.h and /usr/include/asm-generic/errno.h
 * as follows:
 *
 * <pre>
 * EPERM            1       Operation not permitted
 * ENOENT           2       No such file or directory
 * ESRCH            3       No such process
 * EINTR            4       Interrupted system call
 * EIO              5       I/O error
 * ENXIO            6       No such device or address
 * E2BIG            7       Argument list too long
 * ENOEXEC          8       Exec format error
 * EBADF            9       Bad file number
 * ECHILD          10       No child processes
 * EAGAIN          11       Try again
 * ENOMEM          12       Out of memory
 * EACCES          13       Permission denied
 * EFAULT          14       Bad address
 * ENOTBLK         15       Block device required
 * EBUSY           16       Device or resource busy
 * EEXIST          17       File exists
 * EXDEV           18       Cross-device link
 * ENODEV          19       No such device
 * ENOTDIR         20       Not a directory
 * EISDIR          21       Is a directory
 * EINVAL          22       Invalid argument
 * ENFILE          23       File table overflow
 * EMFILE          24       Too many open files
 * ENOTTY          25       Not a typewriter
 * ETXTBSY         26       Text file busy
 * EFBIG           27       File too large
 * ENOSPC          28       No space left on device
 * ESPIPE          29       Illegal seek
 * EROFS           30       Read-only file system
 * EMLINK          31       Too many links
 * EPIPE           32       Broken pipe
 * EDOM            33       Math argument out of domain of func
 * ERANGE          34       Math result not representable
 * EDEADLK         35       Resource deadlock would occur
 * ENAMETOOLONG    36       File name too long
 * ENOLCK          37       No record locks available
 * ENOSYS          38       Function not implemented
 * ENOTEMPTY       39       Directory not empty
 * ELOOP           40       Too many symbolic links encountered
 * EWOULDBLOCK     EAGAIN   Operation would block
 * ENOMSG          42       No message of desired type
 * EIDRM           43       Identifier removed
 * ECHRNG          44       Channel number out of range
 * EL2NSYNC        45       Level 2 not synchronized
 * EL3HLT          46       Level 3 halted
 * EL3RST          47       Level 3 reset
 * ELNRNG          48       Link number out of range
 * EUNATCH         49       Protocol driver not attached
 * ENOCSI          50       No CSI structure available
 * EL2HLT          51       Level 2 halted
 * EBADE           52       Invalid exchange
 * EBADR           53       Invalid request descriptor
 * EXFULL          54       Exchange full
 * ENOANO          55       No anode
 * EBADRQC         56       Invalid request code
 * EBADSLT         57       Invalid slot
 * EDEADLOCK       EDEADLK
 * EBFONT          59       Bad font file format
 * ENOSTR          60       Device not a stream
 * ENODATA         61       No data available
 * ETIME           62       Timer expired
 * ENOSR           63       Out of streams resources
 * ENONET          64       Machine is not on the network
 * ENOPKG          65       Package not installed
 * EREMOTE         66       Object is remote
 * ENOLINK         67       Link has been severed
 * EADV            68       Advertise error
 * ESRMNT          69       Srmount error
 * ECOMM           70       Communication error on send
 * EPROTO          71       Protocol error
 * EMULTIHOP       72       Multihop attempted
 * EDOTDOT         73       RFS specific error
 * EBADMSG         74       Not a data message
 * EOVERFLOW       75       Value too large for defined data type
 * ENOTUNIQ        76       Name not unique on network
 * EBADFD          77       File descriptor in bad state
 * EREMCHG         78       Remote address changed
 * ELIBACC         79       Can not access a needed shared library
 * ELIBBAD         80       Accessing a corrupted shared library
 * ELIBSCN         81       .lib section in a.out corrupted
 * ELIBMAX         82       Attempting to link in too many shared libraries
 * ELIBEXEC        83       Cannot exec a shared library directly
 * EILSEQ          84       Illegal byte sequence
 * ERESTART        85       Interrupted system call should be restarted
 * ESTRPIPE        86       Streams pipe error
 * EUSERS          87       Too many users
 * ENOTSOCK        88       Socket operation on non-socket
 * EDESTADDRREQ    89       Destination address required
 * EMSGSIZE        90       Message too long
 * EPROTOTYPE      91       Protocol wrong type for socket
 * ENOPROTOOPT     92       Protocol not available
 * EPROTONOSUPPORT 93       Protocol not supported
 * ESOCKTNOSUPPORT 94       Socket type not supported
 * EOPNOTSUPP      95       Operation not supported on transport endpoint
 * EPFNOSUPPORT    96       Protocol family not supported
 * EAFNOSUPPORT    97       Address family not supported by protocol
 * EADDRINUSE      98       Address already in use
 * EADDRNOTAVAIL   99       Cannot assign requested address
 * ENETDOWN        100      Network is down
 * ENETUNREACH     101      Network is unreachable
 * ENETRESET       102      Network dropped connection because of reset
 * ECONNABORTED    103      Software caused connection abort
 * ECONNRESET      104      Connection reset by peer
 * ENOBUFS         105      No buffer space available
 * EISCONN         106      Transport endpoint is already connected
 * ENOTCONN        107      Transport endpoint is not connected
 * ESHUTDOWN       108      Cannot send after transport endpoint shutdown
 * ETOOMANYREFS    109      Too many references: cannot splice
 * ETIMEDOUT       110      Connection timed out
 * ECONNREFUSED    111      Connection refused
 * EHOSTDOWN       112      Host is down
 * EHOSTUNREACH    113      No route to host
 * EALREADY        114      Operation already in progress
 * EINPROGRESS     115      Operation now in progress
 * ESTALE          116      Stale NFS file handle
 * EUCLEAN         117      Structure needs cleaning
 * ENOTNAM         118      Not a XENIX named type file
 * ENAVAIL         119      No XENIX semaphores available
 * EISNAM          120      Is a named type file
 * EREMOTEIO       121      Remote I/O error
 * EDQUOT          122      Quota exceeded
 * ENOMEDIUM       123      No medium found
 * EMEDIUMTYPE     124      Wrong medium type
 * ECANCELED       125      Operation Canceled
 * ENOKEY          126      Required key not available
 * EKEYEXPIRED     127      Key has expired
 * EKEYREVOKED     128      Key has been revoked
 * EKEYREJECTED    129      Key was rejected by service
 * EOWNERDEAD      130      Owner died
 * ENOTRECOVERABLE 131      State not recoverable
 * </pre>
 * Following error values are defined in /usr/include/netdb.h:
 * <pre>
 * NETDB_INTERNAL  -1       See errno.
 * NETDB_SUCCESS   0        No problem.
 * HOST_NOT_FOUND  1        Authoritative Answer Host not found.
 * TRY_AGAIN       2        Non-Authoritative Host not found, or SERVERFAIL.
 * NO_RECOVERY     3        Non recoverable errors, FORMERR, REFUSED,NOTIMP.
 * NO_DATA         4        Valid name, no data record of requested type.
 * NO_ADDRESS      NO_DATA  No address, look for MX record.
 * EKEYREJECTED    129      Key was rejected by service
 * EOWNERDEAD      130      Owner died
 * ENOTRECOVERABLE 131      State not recoverable
 * </pre>
 * Following error values for `getaddrinfo' function are defined in
 * /usr/include/netdb.h:
 * <pre>
 * EAI_BADFLAGS    -1       Invalid value for `ai_flags' field.
 * EAI_NONAME      -2       NAME or SERVICE is unknown.
 * EAI_AGAIN       -3       Temporary failure in name resolution.
 * EAI_FAIL        -4       Non-recoverable failure in name res.
 * EAI_NODATA      -5       No address associated with NAME.
 * EAI_FAMILY      -6       `ai_family' not supported.
 * EAI_SOCKTYPE    -7       `ai_socktype' not supported.
 * EAI_SERVICE     -8       SERVICE not supported for `ai_socktype'.
 * EAI_ADDRFAMILY  -9       Address family for NAME not supported.
 * EAI_MEMORY      -10      Memory allocation failure.
 * EAI_SYSTEM      -11      System error returned in `errno'.
 * EAI_OVERFLOW    -12      Argument buffer overflow.
 * </pre>
 *
 * @defgroup ife Error handling macros
 * @{
 */
#define HIP_INFO(...) hip_print_str(DEBUG_LEVEL_INFO, __FILE__, __LINE__, __FUNCTION__, __VA_ARGS__)
#define HIP_ERROR(...) hip_print_str(DEBUG_LEVEL_ERROR, __FILE__, __LINE__, __FUNCTION__, __VA_ARGS__)
#define HIP_DIE(...)   hip_die(__FILE__, __LINE__, __FUNCTION__, __VA_ARGS__)
#define HIP_PERROR(s) hip_perror_wrapper(__FILE__, __LINE__, __FUNCTION__, s)
#define HIP_ASSERT(s) { if (!(s)) {HIP_DIE("assertion failed\n"); }}
/** @} */

/** @defgroup debug HIP debug macros
 *
 * Unfortunately Doxygen gets confused when dealing with the extensive '\' and
 * '#' characters that these macros contain. This documentation is therefore
 * messed up. You can find the implementation of these macros from lib/core/debug.h.
 * @{
 */
#ifdef CONFIG_HIP_DEBUG
#define HIP_DEBUG(...) hip_print_str(DEBUG_LEVEL_DEBUG, __FILE__, __LINE__, __FUNCTION__, __VA_ARGS__)
#define HIP_HEXDUMP(prefix, str, len) \
    hip_hexdump(__FILE__, __LINE__, __FUNCTION__, prefix, str, len)
#define HIP_DUMP_PACKET(prefix, str, len) \
    hip_hexdump_parsed(__FILE__, __LINE__, __FUNCTION__, prefix, str, len)
#define HIP_DEBUG_SOCKADDR(prefix, sockaddr) \
    hip_print_sockaddr(__FILE__, __LINE__, __FUNCTION__, prefix, sockaddr)
#define HIP_DUMP_MSG(msg) { hip_print_str(DEBUG_LEVEL_DEBUG, __FILE__, __LINE__, __FUNCTION__, " dump: \n"); hip_dump_msg(msg); }
#define HIP_DEBUG_GL(debug_group, debug_level, ...) \
    hip_debug_gl( debug_group, debug_level, __FILE__, __LINE__, __FUNCTION__, __VA_ARGS__)

#else
#define HIP_DEBUG(...) do {} while (0)
#define HIP_HEXDUMP(prefix, str, len) do {} while (0)
#define HIP_DUMP_PACKET(prefix, str, len) do {} while (0)
#define HIP_DEBUG_SOCKADDR(prefix, sockaddr) do {} while (0)
#define HIP_DUMP_MSG(msg) do {} while (0)
#define HIP_DEBUG_GL(debug_group, debug_level, ...) do {} while (0)
#endif

#ifdef CONFIG_HIP_DEMO
#define HIP_DEMO(...) printf(__VA_ARGS__);
#else
#define HIP_DEMO(...) do {} while (0)
#endif
/* @} */

/* Debug groups define groups of debug messages which belong to the
 * same logical part of hip. Debug messages can be enabled or disabled more
 * finegrained by only printing messages which belong to a debug group */
# define HIP_DEBUG_GROUP_ALL            770
# define HIP_DEBUG_GROUP_DEFAULT        771
# define HIP_DEBUG_GROUP_ADAPT          772
# define HIP_DEBUG_GROUP_INIT           773
# define HIP_DEBUG_GROUP_MSG            774

/* Current debug group */
# define HIP_DEBUG_GROUP HIP_DEBUG_GROUP_INIT

/* Debug messages are divided into several levels. Severe errors
 * or abnormal conditions are the lowest level. Higher levels are
 * considered as less severe or less important. The highest level means
 * every debug message which matches the current switch is printed.
 * The highest debug level number must be assigned to HIP_DEBUG_ALL*/
# define HIP_DEBUG_LEVEL_ERRORS         0
# define HIP_DEBUG_LEVEL_IMPORTANT      10
# define HIP_DEBUG_LEVEL_INFORMATIVE    20
# define HIP_DEBUG_LEVEL_DEFAULT        30
# define HIP_DEBUG_LEVEL_ALL            40

# define HIP_DEBUG_LEVEL HIP_DEBUG_LEVEL_ALL

/* differentiate between die(), error() and debug() error levels */
enum debug_level { DEBUG_LEVEL_DIE, DEBUG_LEVEL_ERROR, DEBUG_LEVEL_INFO,
                   DEBUG_LEVEL_DEBUG, DEBUG_LEVEL_MAX };

#define HIP_INFO_HIT(str, hit)  hip_print_hit(DEBUG_LEVEL_INFO, __FILE__, __LINE__, __FUNCTION__, str, hit)
#define HIP_INFO_IN6ADDR(str, in6) hip_print_hit(DEBUG_LEVEL_INFO, __FILE__, __LINE__, __FUNCTION__, str, in6)
#define HIP_INFO_LSI(str, lsi)  hip_print_lsi(DEBUG_LEVEL_INFO, __FILE__, __LINE__, __FUNCTION__, str, lsi)
#define HIP_INFO_INADDR(str, in)  hip_print_lsi(DEBUG_LEVEL_INFO, __FILE__, __LINE__, __FUNCTION__, str, in)

#define HIP_DEBUG_HIT(str, hit)  hip_print_hit(DEBUG_LEVEL_DEBUG, __FILE__, __LINE__, __FUNCTION__, str, hit)
#define HIP_DEBUG_IN6ADDR(str, in6) hip_print_hit(DEBUG_LEVEL_DEBUG, __FILE__, __LINE__, __FUNCTION__, str, in6)
#define HIP_DEBUG_LSI(str, lsi)  hip_print_lsi(DEBUG_LEVEL_DEBUG, __FILE__, __LINE__, __FUNCTION__, str, lsi)
#define HIP_DEBUG_INADDR(str, in)  hip_print_lsi(DEBUG_LEVEL_DEBUG, __FILE__, __LINE__, __FUNCTION__, str, in)

enum logtype_t { LOGTYPE_NOLOG, LOGTYPE_SYSLOG, LOGTYPE_STDERR };
enum logfmt_t { LOGFMT_SHORT, LOGFMT_LONG };
enum logdebug_t { LOGDEBUG_ALL, LOGDEBUG_MEDIUM, LOGDEBUG_NONE };

void hip_set_logtype(int logtype);
void hip_set_logfmt(int logfmt);
int hip_set_logdebug(int new_logdebug);
int hip_set_auto_logdebug(const char *cfile);

/* Don't use the functions below directly; use the corresponding macros
 * instead */
void hip_handle_log_error(int logtype);
void hip_vlog(int debug_level,
              const char *file,
              int line,
              const char *function,
              const char *fmt,
              va_list args);
void hip_info(const char *file,
              int line,
              const char *function,
              const char *fmt,
              ...);
void hip_die(const char *file,
             int line,
             const char *function,
             const char *fmt,
             ...);
void hip_error(const char *file,
               int line,
               const char *function,
               const char *fmt,
               ...);
void hip_perror_wrapper(const char *file,
                        int line,
                        const char *function,
                        const char *s);
void hip_hexdump(const char *file,
                 int line,
                 const char *function,
                 const char *prefix,
                 const void *str,
                 int len);
int hip_hexdump_parsed(const char *file,
                       int line,
                       const char *function,
                       const char *prefix,
                       const void *str,
                       int len);
void hip_print_packet(const char *file,
                      int line,
                      const char *function,
                      const char *prefix,
                      const void *str,
                      int len);
void hip_print_sockaddr(int line,
                        const char *function,
                        const char *prefix,
                        const struct sockaddr *sockaddr);
void hip_print_hit(int debug_level,
                   const char *file,
                   int line,
                   const char *function,
                   const char *str,
                   const struct in6_addr *hit);
void hip_print_str(int debug_level,
                   const char *file,
                   int line,
                   const char *function,
                   const char *fmt,
                   ...);
void hip_debug_gl(int debug_group,
                  int debug_level,
                  const char *file,
                  int line,
                  const char *function,
                  const char *fmt,
                  ...);
void hip_print_lsi(int debug_level,
                   const char *file,
                   int line,
                   const char *function,
                   const char *str,
                   const struct in_addr *lsi);


/**
 * Gets a binary string representation from an uint8_t value.
 *
 * @val    the value to convert.
 * @buffer a target buffer where to put the binary string.
 * @note   make sure the buffer has at least size of 8 * sizeof(char).
 */
void uint8_to_binstring(uint8_t val, char *buffer);

/**
 * Gets a binary string representation from an uint16_t value.
 *
 * @val    the value to convert.
 * @buffer a target buffer where to put the binary string.
 * @note   make sure the buffer has at least size of 17 * sizeof(char).
 */
void uint16_to_binstring(uint16_t val, char *buffer);

/**
 * Gets a binary string representation from an uint32_t value.
 *
 * @val    the value to convert.
 * @buffer a target buffer where to put the binary string.
 * @note   make sure the buffer has at least size of 33 * sizeof(char).
 */
void uint32_to_binstring(uint32_t val, char *buffer);

void hip_print_locator_addresses(struct hip_common *);
void hip_print_peer_addresses_to_be_added(hip_ha_t *);
void hip_print_peer_addresses(hip_ha_t *);
void hip_print_locator(int debug_level,
                       const char *file,
                       int line,
                       const char *function,
                       const char *str,
                       const struct hip_locator *locator);

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

/**
 * Gets the name of a state.
 *
 * @param  a state state value
 * @return a state name as a string.
 */
static inline const char *hip_state_str(unsigned int state)
{
    const char *str             = "UNKNOWN";
    static const char *states[] =
    {
        "NONE",                          // 0
        "UNASSOCIATED",                  // 1
        "I1-SENT",                       // 2
        "I2-SENT",                       // 3
        "R2-SENT",                       // 4
        "ESTABLISHED",                   // 5
        "UNKNOWN",                       // 6 is not currently used.
        "FAILED",                        // 7
        "CLOSING",                       // 8
        "CLOSED",                        // 9
        "FILTERING"                      // 10
    };
    if (state < ARRAY_SIZE(states)) {
        str = states[state];
    } else {
        HIP_ERROR("invalid state %u\n", state);
    }

    return str;
}

#endif /* HIP_LIB_CORE_DEBUG_H */
