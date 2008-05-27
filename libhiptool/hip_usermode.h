/*
 * Host Identity Protocol
 * Copyright (C) 2002-04 the Boeing Company
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 *  hip_service.h
 *
 *  Authors: Jeff Ahrenholz <jeffrey.m.ahrenholz@boeing.com>
 * 
 * Definition of HIP Windows service thread functions.
 *
 */
#if 0
#ifndef HIP_USERMODE_H
#define HIP_USERMODE_H

#include <sys/time.h>		/* timeval */
//#include "utils.h"
#include "firewall/firewall.h"


/*
 * Globally-accessible functions
 */
int hip_esp_output(hip_fw_context_t *ctx, hip_sadb_entry *entry, int out_ip_version,
		int udp_encap, struct timeval *now, __u8 *esp_packet, int *esp_packet_len);
int hip_esp_input(struct sockaddr *ss_lsi, u8 *buff, int len);
//void *hip_pfkey(void *arg);
//#define RETNULL NULL;

int init_esp_input(int family, int proto);

int pfkey_send_acquire(struct sockaddr *target);

#if 0
/*
 * Global definitions
 */
#ifndef CONFIG_HIP
#define CONFIG_HIP
#endif

#define DNS_PORT 53
#define HIP_DNS_SUFFIX ".hip"
extern __u64 g_tap_mac;
extern int g_state;


/*
 * Macros from hip.h and elsewhere
 */
/* get pointer to IP from a sockaddr 
 *    useful for inet_ntop calls     */
#define SA2IP(x) hip_cast_sa_addr(x)
#define SALEN(x) hip_sockaddr_len(x)
#define SAIPLEN(x) hip_sa_addr_len(x)

/* Tao add 27th, Feb */
#define SA(x) ((struct sockaddr*)x)

/* The below prefix applies to the uppermost 28 bits only (RFC 4843) */
#define HIT_PREFIX_SHA1_32BITS HIP_HIT_TYPE_MASK_100

#define IS_HIT(x) ipv6_addr_is_hit(x)

#define SA2IP6(x) ( &((struct sockaddr_in6*)x)->sin6_addr )

#if defined(__MACOSX__) && defined(__BIG_ENDIAN__)
#define IS_LSI(a) ( ( ((struct sockaddr*)a)->sa_family == AF_INET) ? \
         (IS_LSI32( ((struct sockaddr_in*)a)->sin_addr.s_addr >> 24)) : \
         (IS_HIT(  &((struct sockaddr_in6*)a)->sin6_addr) ) )
#else /* __MACOSX__ */
#define IS_LSI(a) ( (((struct sockaddr*)a)->sa_family == AF_INET) ? \
                   (IS_LSI32(((struct sockaddr_in*)a)->sin_addr.s_addr)) : \
                   (IS_HIT( &((struct sockaddr_in6*)a)->sin6_addr) )     )

#endif /* __MACOSX__ */
#define VALID_FAM(a) ( (((struct sockaddr*)a)->sa_family == AF_INET) || \
                       (((struct sockaddr*)a)->sa_family == AF_INET6) )

// from linux/include/linux/kernel.h
#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]

#define NIP6(addr) \
	ntohs((addr).s6_addr16[0]), \
	ntohs((addr).s6_addr16[1]), \
	ntohs((addr).s6_addr16[2]), \
	ntohs((addr).s6_addr16[3]), \
	ntohs((addr).s6_addr16[4]), \
	ntohs((addr).s6_addr16[5]), \
	ntohs((addr).s6_addr16[6]), \
	ntohs((addr).s6_addr16[7])
#endif

#endif
#endif

