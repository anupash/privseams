#ifndef DEBUG_H
#define DEBUG_H

#include <stdio.h>
#include <errno.h>
#include <stdarg.h>
#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* includes filename, line number and max(debug_prefix[]) */
#define DEBUG_PREFIX_MAX  64

/* stderror: includes prefix, separator, msg and \0
   syslog:   includes msg and \0 */
#define DEBUG_MSG_MAX_LEN     256

#define SYSLOG_OPT        (LOG_PID)
#define SYSLOG_FACILITY   LOG_DAEMON

#define HIP_DEBUG(...) hip_debug(__FILE__, __LINE__, __FUNCTION__, __VA_ARGS__)
#define HIP_INFO(...) hip_info(__FILE__, __LINE__, __FUNCTION__, __VA_ARGS__)
#define HIP_ERROR(...) hip_error(__FILE__, __LINE__, __FUNCTION__, __VA_ARGS__)
#define HIP_DIE(...)   hip_die(__FILE__, __LINE__, __FUNCTION__, __VA_ARGS__)
#define HIP_HEXDUMP(prefix, str, len) \
            hip_hexdump(__FILE__, __LINE__, __FUNCTION__, prefix, str, len)
#define HIP_DEBUG_SOCKADDR(prefix, family, sockaddr) \
 hip_print_sockaddr(__FILE__, __LINE__, __FUNCTION__, prefix, family, sockaddr)
#define HIP_DUMP_MSG(msg) { info(__FILE__, __LINE__, __FUNCTION__, " dump: \n"); hip_dump_msg(msg); }
#define HIP_PERROR(s) hip_perror_wrapper(__FILE__, __LINE__, __FUNCTION__, s)
#define HIP_ASSERT(s) { if (!(s)) HIP_DIE("assertion failed\n"); }

/* these are used for disabling a debugging command temporarily */
#define _HIP_DEBUG(...)
#define _HIP_INFO(...)
#define _HIP_ERROR(...)
#define _HIP_DIE(...)
#define _HIP_HEXDUMP(prefix, str, len)
#define _HIP_DUMP_MSG(msg)
#define _HIP_PERROR(s)
#define _HIP_ASSERT(s)

enum logtype { LOGTYPE_NOLOG, LOGTYPE_SYSLOG, LOGTYPE_STDERR };
enum logfmt { LOGFMT_SHORT, LOGFMT_LONG };

void hip_set_logtype(int logtype);
void hip_set_logfmt(int logfmt);

/* Don't use the functions below directly; use the corresponding macros
   instead */
void hip_handle_log_error(int logtype);
void hip_vlog(int debug_level, char *file, int line, char *function,
	  char *fmt, va_list args);
void hip_info(char *file, int line, char *function, char *fmt, ...);
void hip_die(char *file, int line, char *function, char *fmt, ...);
void hip_error(char *file, int line, char *function, char *fmt, ...);
void hip_perror_wrapper(char *file, int line, char *function, char *s);
void hip_hexdump(char *file, int line, char *function,
		 char *prefix, void *str, int len);
void hip_print_sockaddr(char *file, int line, char *function,
			char *prefix, sa_family_t family,
			struct sockaddr *sockaddr);

#endif /* DEBUG_H */
