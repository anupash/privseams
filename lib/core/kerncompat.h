#ifndef HIP_LIB_CORE_KERNCOMPAT_H
#define HIP_LIB_CORE_KERNCOMPAT_H

#include <netinet/in.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <asm/types.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <string.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;

#ifndef IPPROTO_HIP
#  define IPPROTO_HIP             139
#endif

#define HIP_MALLOC(size, flags)  malloc(size)
#define HIP_FREE(obj)            free(obj)

#if __BYTE_ORDER == __BIG_ENDIAN
  #define hton64(i) (i)
  #define ntoh64(i) (i)
#else
  #define hton64(i) (((uint64_t) (htonl((i) & 0xffffffff)) << 32) | htonl(((i) >> 32) & 0xffffffff ))
  #define ntoh64 hton64
#endif

#endif /* HIP_LIB_CORE_KERNCOMPAT_H */
