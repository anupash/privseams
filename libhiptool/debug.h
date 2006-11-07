#ifndef DEBUG_H
#define DEBUG_H

#include <stdio.h>
#include <errno.h>
#include <stdarg.h>
#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <netinet/in.h>
#include "protodefs.h"
#include "utils.h"

/* includes filename, line number and max(debug_prefix[]) */
#define DEBUG_PREFIX_MAX  64

/* stderror: includes prefix, separator, msg and \0
   syslog:   includes msg and \0 */
#define DEBUG_MSG_MAX_LEN     256

#define SYSLOG_OPT        (LOG_PID)
#define SYSLOG_FACILITY   LOG_DAEMON

#define HIP_INFO(...) hip_info(__FILE__, __LINE__, __FUNCTION__, __VA_ARGS__)
#define HIP_ERROR(...) hip_error(__FILE__, __LINE__, __FUNCTION__, __VA_ARGS__)
#define HIP_DIE(...)   hip_die(__FILE__, __LINE__, __FUNCTION__, __VA_ARGS__)
#define HIP_PERROR(s) hip_perror_wrapper(__FILE__, __LINE__, __FUNCTION__, s)
#define HIP_ASSERT(s) { if (!(s)) HIP_DIE("assertion failed\n"); }

#ifdef CONFIG_HIP_DEBUG
#define HIP_DEBUG(...) hip_debug(__FILE__, __LINE__, __FUNCTION__, __VA_ARGS__)
#define HIP_HEXDUMP(prefix, str, len) \
            hip_hexdump(__FILE__, __LINE__, __FUNCTION__, prefix, str, len)
#define HIP_DEBUG_SOCKADDR(prefix, family, sockaddr) \
 hip_print_sockaddr(__FILE__, __LINE__, __FUNCTION__, prefix, family, sockaddr)
#define HIP_DUMP_MSG(msg) { hip_info(__FILE__, __LINE__, __FUNCTION__, " dump: \n"); hip_dump_msg(msg); }
//#define HIP_DEBUG(...) \
//	hip_debug_gl( HIP_DEBUG_GROUP_DEFAULT, HIP_DEBUG_LEVEL_DEFAULT, __FILE__, __LINE__, __FUNCTION__, __VA_ARGS__)
# define HIP_DEBUG_GL(debug_group, debug_level, ...)\
	hip_debug_gl( debug_group, debug_level, __FILE__, __LINE__, __FUNCTION__, __VA_ARGS__)
#else
#define HIP_DEBUG(...) do {} while(0)
#define HIP_HEXDUMP(prefix, str, len) do {} while(0)
#define HIP_DEBUG_SOCKADDR(prefix, family, sockaddr) do {} while(0)
#define HIP_DUMP_MSG(msg) do {} while(0)
//#define HIP_DEBUG(...) \
//	hip_debug_gl( HIP_DEBUG_GROUP_DEFAULT, HIP_DEBUG_LEVEL_DEFAULT, __FILE__, __LINE__, __FUNCTION__, __VA_ARGS__)
# define HIP_DEBUG_GL(debug_group, debug_level, ...) do {} while(0)
#endif


/* Debug groups define groups of debug messages which belong to the
   same logical part of hip. Debug messages can be enabled or disabled more
   finegrained by only printing messages which belong to a debug group */	
# define HIP_DEBUG_GROUP_ALL		770
# define HIP_DEBUG_GROUP_DEFAULT	771
# define HIP_DEBUG_GROUP_ADAPT		772
# define HIP_DEBUG_GROUP_INIT		773
# define HIP_DEBUG_GROUP_MSG		774

/* Current debug group */
# define HIP_DEBUG_GROUP HIP_DEBUG_GROUP_INIT

/* Debug messages are divided into several levels. Severe errors 
   or abnormal conditions are the lowest level. Higher levels are
   considered as less severe or less important. The highes level means
   every debug message which matches the current switch is printed. 
   The hignes debug level number must be assigned to HIP_DEBUG_ALL*/
# define HIP_DEBUG_LEVEL_ERRORS		0
# define HIP_DEBUG_LEVEL_IMPORTANT	10
# define HIP_DEBUG_LEVEL_INFORMATIVE	20
# define HIP_DEBUG_LEVEL_DEFAULT	30
# define HIP_DEBUG_LEVEL_ALL		40

# define HIP_DEBUG_LEVEL HIP_DEBUG_LEVEL_ALL

/* XX FIXME: implement! */
//#define HIP_DEBUG_HIT(str, hit) do {} while(0)
#define HIP_DEBUG_HIT(str, hit)  hip_print_hit(str, hit)
#define HIP_DEBUG_IN6ADDR(str, in6) hip_print_hit(str, in6)
#define HIP_DEBUG_LSI(str, hit)  hip_print_lsi(str, lsi)
#define HIP_DEBUG_INADDR(str, in)  hip_print_lsi(str, in)
#define HIP_DEBUG_KEY(str, key, key_len) hip_print_key(str, key, key_len)
//#define HIP_DEBUG_IN6ADDR(str, hit) do {} while(0)

/* these are used for disabling a debugging command temporarily */
#define _HIP_DEBUG(...) do {} while(0)
#define _HIP_INFO(...) do {} while(0)
#define _HIP_ERROR(...) do {} while(0)
#define _HIP_DIE(...) do {} while(0)
#define _HIP_HEXDUMP(prefix, str, len) do {} while(0)
#define _HIP_DUMP_MSG(msg) do {} while(0)
#define _HIP_PERROR(s) do {} while(0)
#define _HIP_ASSERT(s) do {} while(0)
#define _HIP_DEBUG_HIT(str, hit) do {} while(0)
#define _HIP_DEBUG_IN6ADDR(str, hit) do {} while(0)
#define _HIP_DEBUG_LSI(str, lsi) do {} while(0)
#define _HIP_DEBUG_INADDR(str, in) do {} while(0)

enum logtype { LOGTYPE_NOLOG, LOGTYPE_SYSLOG, LOGTYPE_STDERR };
enum logfmt { LOGFMT_SHORT, LOGFMT_LONG };

void hip_set_logtype(int logtype);
void hip_set_logfmt(int logfmt);

/* Don't use the functions below directly; use the corresponding macros
   instead */
void hip_handle_log_error(int logtype);
void hip_vlog(int debug_level, const char *file, int line,
	      const char *function, const char *fmt, va_list args);
void hip_info(const char *file, int line, const char *function,
	      const char *fmt, ...);
void hip_die(const char *file, int line, const char *function,
	     const char *fmt, ...);
void hip_error(const char *file, int line, const char *function,
	       const char *fmt, ...);
void hip_perror_wrapper(const char *file, int line, const char *function,
			const char *s);
void hip_hexdump(const char *file, int line, const char *function,
		 const char *prefix, const void *str, int len);
void hip_print_sockaddr(const char *file, int line, const char *function,
			const char *prefix, sa_family_t family,
			const struct sockaddr *sockaddr);

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

/**
 * hip_state_str - get name for a state
 * @state: state value
 *
 * Returns: state name as a string.
 */
static inline const char *hip_state_str(unsigned int state)
{
	const char *str = "UNKNOWN";
        static const char *states[] =
		{
			"NONE",          // 0
			"UNASSOCIATED",  // 1
			"I1-SENT",       // 2
			"I2-SENT",       // 3
			"R2-SENT",       // 4
			"ESTABLISHED",   // 5
			"UNKNOWN",       // 6 is not currently used.
			"FAILED",        // 7
			"CLOSING",       // 8
			"CLOSED",        // 9
			"FILTERING" 	 // 10
		};
        if (state >= 0 && state < ARRAY_SIZE(states))
		str = states[state];
        else
		HIP_ERROR("invalid state %u\n", state);
	
        return str;
}

#endif /* DEBUG_H */
