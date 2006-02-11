#ifndef HIP_USER_COMPAT_H
#define  HIP_USER_COMPAT_H

#include <linux/in.h>
#include <linux/in6.h>
#include <linux/socket.h>
#include <linux/time.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <asm/byteorder.h>

#include "hip.h"
#include "debug.h"
#include "misc.h"
#include "builder.h"

typedef uint16_t in_port_t;

#define HIP_MALLOC(a,b) kmalloc(a,b)
#define HIP_FREE(a) kfree(a)

#define PF_HIP 32

inline int is_big_endian(void)
{
	int i = 1;
	char *p = (char *) &i;

	if (p[0] == 1)
		return 0;
	else
		return 1;
}

inline uint64_t hton64(uint64_t i) {
	if (is_big_endian())
		return i;
	else
		return ( ((__u64)(htonl((i) & 0xffffffff)) << 32) | htonl(((i) >> 32) & 0xffffffff) );
}

inline uint64_t ntoh64(uint64_t i) {
	if (is_big_endian())
		return i;
	else
		return hton64(i);
}

#endif /* HIP_USER_COMPAT_H  */
