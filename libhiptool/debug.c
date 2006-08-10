/*
 * Debugging functions for HIPL userspace applications. Use them as follows:
 *
 *   INFO("test foobar");
 *   INFO("%s\n", "debug test");
 *   _INFO("%s\n", "this is not printed, but may be important in future");
 *   ERROR("%s%d\n", "serious error!", 123);
 *   DIE("%s\n", "really bad error, exiting!");
 *   PERROR("socket");
 *   HEXDUMP("foobar", data, len);
 *
 *   adjust log types and format dynamically (there really should not
 *   be a reason to call these in the code, because default settings
 *   should be reasonable)
 *
 *   hip_set_logtype(LOGTYPE_STDERR); // set logging output to stderr
 *   hip_set_logfmt(LOGFMT_SHORT);    // set short logging format
 *
 * Production quality code prints debugging stuff via syslog, testing code
 * prints interactively on stderr. This is done automatically using DEBUG
 * flag in Makefile (see logtype variable below).
 *
 * A note about the newlines: PERROR() appends always a newline after message
 * to be printed as in perror(3). In the rest of the functions, you have to
 * append a newline (as in fprinf(3)).
 *
 * TODO:
 * - debug messages should not be compiled at all in a production release
 * - set_log{type|format}(XX_DEFAULT)
 * - locking (is it really needed?)
 * - optimize: openlog() and closelog() called only when needed
 * - ifdef gcc (in vararg macro)?
 * - production use: disable info messages?
 * - move file+line from prefix to the actual message body
 * - handle_log_error(): add different policies (exit(), ignore, etc)
 * - check what vlog("xx\nxx\n") does with syslog
 * - struct info { char *file, int line, char *function } ?
 * - macro for ASSERT
 * - change char * to void * in hexdump ?
 * - HIP_ASSERT()
 *
 * BUGS:
 * - XX
 *
 */

#include "debug.h"

/* differentiate between die(), error() and debug() error levels */
enum debug_level { DEBUG_LEVEL_DIE,
		   DEBUG_LEVEL_ERROR,
		   DEBUG_LEVEL_INFO,
		   DEBUG_LEVEL_DEBUG,
		   DEBUG_LEVEL_MAX };

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
static int logtype = LOGTYPE_STDERR;
#else
static int logtype = LOGTYPE_SYSLOG;
#endif /* CONFIG_HIP_DEBUG */

#ifdef HIP_LOGFMT_LONG
static int logfmt  = LOGFMT_LONG;
#else
static int logfmt  = LOGFMT_SHORT;
#endif /* HIP_LONGFMT */

/**
 * hip_set_logtype - set logging to to stderr or syslog
 * @new_logtype: the type of logging output, either LOGTYPE_STDERR or
 *               LOGTYPE_SYSLOG 
 *
 */
void hip_set_logtype(int new_logtype) {
  logtype = new_logtype;
}

/**
 * hip_set_logfmt - set the formatting of log output (short or long)
 * @new_logfmt: the format of the log output, either LOGFMT_SHORT or
 *              LOGFMT_LONG
 *
 */
void hip_set_logfmt(int new_logfmt) {
  logfmt = new_logfmt;
}

/**
 * hip_handle_log_error - handle errors generated by log handling
 * @logtype: the type of the log that generated the error (LOGTYPE_STDERR or
 *           LOGTYPE_SYSLOG)
 *
 * The default policy is to ignore errors (an alternative policy would
 * be to e.g. exit).
 *
 */
void hip_handle_log_error(int logtype) {
  fprintf(stderr, "log (type=%d) failed, ignoring", logtype);
}

/**
 * hip_vlog - "multiplexer" for correctly outputting all debug messages
 * @debug_level: the urgency of the message (DEBUG_LEVEL_XX)
 * @file:        the file from where the debug call was made        
 * @line:        the line of the debug call in the source file
 * @function:    the name of function where the debug call is located
 * @fmt:         the output format of the debug message as in printf(3)
 * @args:         the variable argument list to be output
 *
 * This function is to be used only from the hip_debug(), hip_info(), etc
 * debugging functions.
 */
void hip_vlog(int debug_level, const char *file, const int line,
	      const char *function, const char *fmt, va_list args) {
  char syslog_msg[DEBUG_MSG_MAX_LEN] = "";
  int syslog_level = debug2syslog_map[debug_level];
  char prefix[DEBUG_PREFIX_MAX] = "\0";
  int printed = 0;

  if (logfmt == LOGFMT_LONG) {
    /* note: printed is not absolutely necessary to check in this case;
       worst case is that filename or line number could be shortened */
    printed = snprintf(prefix, DEBUG_PREFIX_MAX, "%s(%s:%d@%s)",
		       debug_prefix[debug_level], file, line, function);
  } else {
    /* LOGFMT_SHORT: no prefix */
  }
    
  switch(logtype) {
  case LOGTYPE_NOLOG:
    break;
  case LOGTYPE_STDERR:
    if (strlen(prefix) > 0) {
      printed = fprintf(stderr, "%s: ", prefix);
      if (printed < 0)
	goto err;
    } else {
      /* LOGFMT_SHORT: no prefix */
    }
    printed = vfprintf(stderr, fmt, args);
    if (printed < 0)
      goto err;
    break;
  case LOGTYPE_SYSLOG:
    openlog(prefix, SYSLOG_OPT, SYSLOG_FACILITY);
    printed = vsnprintf(syslog_msg, DEBUG_MSG_MAX_LEN, fmt, args);
    syslog(syslog_level|SYSLOG_FACILITY, "%s", syslog_msg);
    /* the result of vsnprintf depends on glibc version; handle them both
       (note about barriers: printed has \0 excluded,
       DEBUG_MSG_MAX_LEN has \0 included) */
    if (printed < 0 || printed > DEBUG_MSG_MAX_LEN - 1) {
      syslog(syslog_level|SYSLOG_FACILITY,
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
 * hip_info - output informative (medium level) debugging messages
 * @file:        the file from where the debug call was made        
 * @line:        the line of the debug call in the source file
 * @function:    the name of function where the debug call is located
 * @fmt:         the output format of the debug message as in printf(3)
 *
 * The variable size argument list (...) is used as in printf(3).
 * Do not call this function from the outside of the debug module,
 * use the HIP_INFO macro instead.
 */
void hip_info(const char *file, int line, const char *function,
	      const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  hip_vlog(DEBUG_LEVEL_INFO, file, line, function, fmt, args);
  va_end(args);
}

/**
 * hip_debug - output development (low level) debugging messages
 * @file:        the file from where the debug call was made        
 * @line:        the line of the debug call in the source file
 * @function:    the name of function where the debug call is located
 * @fmt:         the output format of the debug message as in printf(3)
 *
 * The variable size argument list (...) is used as in printf(3).
 * Do not call this function from the outside of the debug module,
 * use the HIP_DEBUG macro instead.
 */
void hip_debug(const char *file, int line, const char *function,
	       const char *fmt, ...) {
	va_list args;
	va_start(args, fmt);
	hip_vlog(DEBUG_LEVEL_DEBUG, file, line, function, fmt, args);
	va_end(args);
}

/**
 * hip_debug_gl - output development (low level) debugging messages
 *                a debug group and a debug level can be given. Debug
 *                messages are only displayed if the debug group matches
 *                the current debug group and the debug leven is smaller
 *                than the current debug level.
 * @debug_group:  the debug group which has to be matched
 * @debug_level:  the debug level of the debug output
 * @file:         the file from where the debug call was made        
 * @line:         the line of the debug call in the source file
 * @function:     the name of function where the debug call is located
 * @fmt:          the output format of the debug message as in printf(3)
 *
 * The variable size argument list (...) is used as in printf(3).
 * Do not call this function from the outside of the debug module,
 * use the HIP_DEBUG_GL macro instead.
 */
hip_debug_gl(int debug_group, int debug_level,
	     const char *file, int line,
	     const char *function, const char *fmt, ...) {
	if(debug_level <= HIP_DEBUG_LEVEL && 
	(HIP_DEBUG_GROUP == HIP_DEBUG_GROUP_ALL ||
	 debug_group == HIP_DEBUG_GROUP)) {
		va_list args;
		va_start(args, fmt);
		hip_vlog(DEBUG_LEVEL_DEBUG, file, line, function, fmt, args);
		va_end(args);
	}
}
/**
 * hip_die - output a fatal error and exit
 * @file:        the file from where the debug call was made        
 * @line:        the line of the debug call in the source file
 * @function:    the name of function where the debug call is located
 * @fmt:         the output format of the debug message as in printf(3)
 *
 * The variable size argument list (...) is used as in printf(3).
 * Do not call this function from the outside of the debug module,
 * use the HIP_DIE macro instead.
 */
void hip_die(const char *file, int line, const char *function,
	     const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  hip_vlog(DEBUG_LEVEL_DIE, file, line, function, fmt, args);
  va_end(args);
  exit(1);
}

/**
 * hip_error - output an error message (high level)
 * @file:        the file from where the debug call was made        
 * @line:        the line of the debug call in the source file
 * @function:    the name of function where the debug call is located
 * @fmt:         the output format of the debug message as in printf(3)
 *
 * The variable size argument list (...) is used as in printf(3).
 * Do not call this function from the outside of the debug module,
 * use the HIP_ERROR macro instead.
 */
void hip_error(const char *file, int line, const char *function,
	       const char *fmt, ...) {
	va_list args;
	va_start(args, fmt);
	hip_vlog(DEBUG_LEVEL_ERROR, file, line, function, fmt, args);
	va_end(args);
}

/**
 * hip_perror_wrapper - a wrapper for perror(3) style calls
 * @file:        the file from where the debug call was made        
 * @line:        the line of the debug call in the source file
 * @function:    the name of function where the debug call is located
 * @s:           the string as in perror(3)
 *
 * The newline is already included after the first line in favour of
 * the perror(3) syntax. Do not call this function from the outside of the
 * debug module, use the HIP_PERROR macro instead.
 */
void hip_perror_wrapper(const char *file, int line, const char *function,
			const char *s) {
	hip_error(file, line, function, "%s %s\n", s, strerror(errno));
}

/**
 * hip_hexdump - print hexdump starting from address @str of length @len
 * @file:        the file from where the debug call was made        
 * @line:        the line of the debug call in the source file
 * @function:    the name of function where the debug call is located
 * @prefix:      the prefix string will printed before the hexdump
 * @str:         pointer to the beginning of the data to be hexdumped
 * @len:         the length of the data to be hexdumped
 *
 * Do not call this function from the outside of the debug module,
 * use the HIP_HEXDUMP macro instead.
 */
void hip_hexdump(const char *file, int line, const char *function,
		 const char *prefix, const void *str, int len) {
  int hexdump_max_size = 0;
  int hexdump_count = 0;
  char *hexdump = NULL;
  int hexdump_written = 0;
  int hexdump_index = 0;
  int char_index = 0;

  hexdump_max_size = len * 2 + 1;
  hexdump_count = hexdump_max_size;

  hexdump = (char *) calloc(hexdump_max_size, sizeof(char));
  if (hexdump == NULL) {
    HIP_DIE("hexdump memory allocation failed\n");
  }
  if(len == 0){
  	HIP_ERROR("hexdump length was 0\n");  
	}else{
	do {
	/* note: if you change the printing format, adjust also hexdump_count! */
	hexdump_written = snprintf((char *) (hexdump + hexdump_index),
				hexdump_count, "%02x",
			(unsigned char)(*(((unsigned char *)str) + char_index)));
	if (hexdump_written < 0 || hexdump_written > hexdump_max_size - 1) {
	free(hexdump);
	HIP_DIE("hexdump msg too long(%d)", hexdump_written);
	} else {
	hexdump_count -= hexdump_written;
	assert(hexdump_count >=0);
	hexdump_index += hexdump_written;
	assert(hexdump_index + hexdump_count == hexdump_max_size);
	}
	char_index++;
	} while(char_index < len);
	
	hip_info(file, line, function, "%s0x%s\n", prefix, hexdump);
  }

  free(hexdump);

}

/**
 * hip_print_sockaddr - print a socket address structure
 * @file:        the file from where the debug call was made        
 * @line:        the line of the debug call in the source file
 * @function:    the name of function where the debug call is located
 * @prefix:      the prefix string will printed before the sockaddr
 * @family:      the family of the sockaddr
 * @sockaddr:    pointer to the sockaddr to be printed
 *
 * Do not call this function from the outside of the debug module, use the
 * HIP_DEBUG_SOCKADDR macro instead. Currently this function supports
 * only INET and INET6 addresses. 
 */
void hip_print_sockaddr(const char *file, int line, const char *function,
			const char *prefix, sa_family_t family,
			const struct sockaddr *sockaddr) {
      char *default_str = "<unknown>";
      int maxlen;
      void *addr;
      char addr_str[INET6_ADDRSTRLEN+1];
      
      switch (family) {
      case AF_INET:
	maxlen = INET_ADDRSTRLEN;
	addr = &(((struct sockaddr_in *) sockaddr)->sin_addr);
	break;
      case AF_INET6:
	maxlen = INET6_ADDRSTRLEN;
	addr = &(((struct sockaddr_in6 *) sockaddr)->sin6_addr);
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
      if (prefix)
	HIP_DEBUG("%s: %s\n", prefix, addr_str);
      else
	HIP_DEBUG("%s\n", addr_str);
}

void hip_print_lsi(const char *str, const struct in_addr *lsi)
{
	char dst[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, lsi, dst, sizeof(dst));
	HIP_DEBUG("%s: %s\n", str, dst);
}
/**
 * hip_print_hit - print a HIT
 * @str: string to be printed before the HIT
 * @hit: the HIT to be printed
 */
void hip_print_hit(const char *str, const struct in6_addr *hit)
{
	if(!hit) { // Null check added by Lauri Silvennoinen 27.07.2006 18:47
		HIP_DEBUG("%s: NULL\n", str);
		return;
	}
	else {
		char dst[INET6_ADDRSTRLEN];
		
		if (IN6_IS_ADDR_V4MAPPED(hit)) {
			struct in_addr in_addr;
			IPV6_TO_IPV4_MAP(hit, &in_addr);
			hip_print_lsi(str, &in_addr);
		} else {
			hip_in6_ntop(hit, dst);
			HIP_DEBUG("%s: %s\n", str, dst);
		}
		return;
	}
}
