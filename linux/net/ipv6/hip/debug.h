#ifndef HIP_KERNEL_DEBUG_H
#define HIP_KERNEL_DEBUG_H

#include <linux/ipv6.h>
#include <linux/skbuff.h>
#include <linux/inet.h>
#include <linux/netdevice.h>

/* for debugging with in6_ntop */
#define INET6_ADDRSTRLEN 46

/* Informational and error messages are always logged */
#define HIP_INFO(fmt, args...) \
     printk(KERN_DEBUG "%s: " fmt , __FUNCTION__ , ##args)
#define HIP_ERROR(fmt, args...) \
     printk(KERN_DEBUG "%s: error: " fmt , __FUNCTION__ , ##args)
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
#define _HIP_DEBUG_SKB(hdr, skb)

/* Debugging messages are only printed in development code */
#ifdef CONFIG_HIP_DEBUG

#  define HIP_DEBUG(fmt, args...) \
     printk(KERN_DEBUG "%s: " fmt, __FUNCTION__ , ## args)
#  define HIP_HEXDUMP(tag, data, len) hip_khexdump(tag, data, len)
#  define HIP_DUMP_MSG(msg) { printk(KERN_DEBUG " %s dump:\n", __FUNCTION__); \
                            hip_dump_msg(msg); }
#  define HIP_DEBUG_SKB(hdr, skb) hip_debug_skb(hdr, skb)
#  define HIP_DEBUG_IN6ADDR(str, in6) hip_print_hit(str, in6)
#  define HIP_DEBUG_HIT(str, hit) hip_print_hit(str, hit)

#else

  #define HIP_DEBUG(fmt, args...) do { } while(0)
  #define HIP_HEXDUMP(tag, data, len) do { } while(0)
  #define HIP_DUMP_MSG(msg) do { } while(0)
  #define HIP_DEBUG_SKB(hdr, skb) do { } while(0)
  #define HIP_DEBUG_IN6ADDR(str, in6) do { } while(0)
  #define HIP_DEBUG_HIT(str, hit) do { } while(0)

#endif /* CONFIG_HIP_DEBUG  */

/* Forward declarations */

extern inline void hip_khexdump(const char *tag, const void *data, const int len);
extern inline void hip_print_hit(const char *str, const struct in6_addr *hit);
extern inline void hip_debug_skb(const struct ipv6hdr *hdr,
			  const struct sk_buff *skb);
extern inline const char *hip_state_str(unsigned int state);

#endif /* HIP_KERNEL_DEBUG_H */

