#ifndef HIP_KERNEL_DEBUG_H
#define HIP_KERNEL_DEBUG_H

#include <linux/ipv6.h>
#include <linux/skbuff.h>

#define HIP_IFE(func, eval) \
{ \
        if (func) { \
                err = eval; \
                goto out_err; \
        } \
}

#define HIP_IFEL(func, eval, args...) \
{ \
        if (func) { \
                HIP_ERROR(args); \
                err = eval; \
                goto out_err; \
        } \
}

#define HIP_IFEB(func, eval, finally) \
{ \
        if (func) { \
                err = eval; \
                finally;\
                goto out_err; \
        } else {\
                finally;\
        }\
}

#define HIP_IFEBL(func, eval, finally, args...) \
{ \
        if (func) { \
                HIP_ERROR(args); \
                err = eval; \
                finally;\
                goto out_err; \
        } else {\
                finally;\
        }\
}

#define HIP_IFEBL2(func, eval, finally, args...) \
{ \
        if (func) { \
                HIP_ERROR(args); \
                err = eval; \
                finally;\
        }\
}

/* for debugging with in6_ntop */
#define INET6_ADDRSTRLEN 46

/* Informational and error messages are always logged */
#define HIP_INFO(fmt, args...) \
     printk(KERN_DEBUG "%s: " fmt , __FUNCTION__ , ##args)
#define HIP_ERROR(fmt, args...) \
     printk(KERN_DEBUG "%s: ***ERROR***: " fmt , __FUNCTION__ , ##args)
#define HIP_ASSERT(s) do {\
     if (!(s)) {                                                 \
         HIP_ERROR("assertion failed on line %d\n", __LINE__); \
         BUG();                                                  \
     }                                                           \
} while(0)

/* Do not remove useful debug lines, just prefix them with an underscore */
#define _HIP_INFO(fmt, args...)
#define _HIP_DEBUG(fmt, args...)
#define _HIP_ERROR(fmt, args...)
#define _HIP_HEXDUMP(tag, data, len)

#define _HIP_DUMP_MSG(msg)
#define _HIP_ASSERT(s)
#define _HIP_DEBUG_IN6ADDR(str, in6)
#define _HIP_DEBUG_HIT(str, hit)

/* Debugging messages are only printed in development code */
#ifdef CONFIG_HIP_DEBUG

#  define HIP_DEBUG(fmt, args...) \
	printk(KERN_DEBUG "HIP %s:%s:%d:  " fmt,__FILE__, __FUNCTION__ , __LINE__ , ## args)
#  define HIP_HEXDUMP(tag, data, len) hip_khexdump(tag, data, len)
#  define HIP_DUMP_MSG(msg) { printk(KERN_DEBUG " %s dump:\n", __FUNCTION__); \
                            hip_dump_msg(msg); }
#  define HIP_DEBUG_IN6ADDR(str, in6) hip_print_hit(str, in6)
#  define HIP_DEBUG_HIT(str, hit) hip_print_hit(str, hit)

#else

  #define HIP_DEBUG(fmt, args...) do { } while(0)
  #define HIP_HEXDUMP(tag, data, len) do { } while(0)
  #define HIP_DUMP_MSG(msg) do { } while(0)
  #define HIP_DEBUG_IN6ADDR(str, in6) do { } while(0)
  #define HIP_DEBUG_HIT(str, hit) do { } while(0)

#endif /* CONFIG_HIP_DEBUG  */

/* Forward declarations */

extern void hip_khexdump(const char *tag, const void *data, const int len);
extern void hip_print_hit(const char *str, const struct in6_addr *hit);

#endif /* HIP_KERNEL_DEBUG_H */

