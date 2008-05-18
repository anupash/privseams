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
#ifdef __WIN32__
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>	/* struct sockaddr */
#endif

#include "utils.h" 


/*
 * Globally-accessible functions
 */
/* Windows _beghinthread() uses different type than pthread_create() */
#ifdef __WIN32__
void hip_esp_output(void *arg);
void hip_esp_input(void *arg);
void hip_pfkey(void *arg);
void tunreader(void *arg);
void hip_dns(void *arg);
void hipd_main(void *arg);
void hip_netlink(void *arg);
void hip_status(void *arg);
extern int socketpair(int, int, int, int sv[2]);
#define RETNULL ;
#else
// void *hip_esp_output(void *arg);
// void *hip_esp_output(struct sockaddr_storage *ss_lsi);
int hip_esp_output(struct sockaddr *ss_lsi, u8 *raw_buff, int len);
int hip_esp_input(struct sockaddr *ss_lsi, u8 *buff, int len);
//void *hip_esp_input(void *arg);
void *hip_pfkey(void *arg);
void *tunreader(void *arg);
void *hip_dns(void *arg);
void *hipd_main(void *arg);
void *hip_netlink(void *arg);
void *hip_status(void *arg);
#define RETNULL NULL;
#endif

int init_esp_input(int family, int proto);
int main_loop(int argc, char **argv);
int str_to_addr(unsigned char *data, struct sockaddr *addr);

int pfkey_send_acquire(struct sockaddr *target);

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



#ifdef __WIN32__
#define IN6_ARE_ADDR_EQUAL IN6_ADDR_EQUAL
#define IS_HIT(x) (( (ntohs(((struct in6_addr*)x)->s6_words[0]) & 0xFFFF) \
                        == ((HIT_PREFIX_SHA1_32BITS >> 4) & 0xFFFF)) && \
                   ( (ntohs(((struct in6_addr*)x)->s6_words[1]) & 0xFFF0) \
                        == ((HIT_PREFIX_SHA1_32BITS & 0xFFFF)) ) )
#elif defined (__MACOSX__)
#define IS_HIT(x) ( (ntohl(((struct in6_addr*)x)->__u6_addr.__u6_addr32[0]) \
                  & 0xFFFFFFF0L) == HIT_PREFIX_SHA1_32BITS )
#else /* Linux */
#define IS_HIT(x) ipv6_addr_is_hit(x)
#endif

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

/* from linux/include/linux/kernel.h */
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

