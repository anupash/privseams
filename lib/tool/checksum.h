#ifndef HIP_LIB_CORE_CHECKSUM_H
#define HIP_LIB_CORE_CHECKSUM_H

#define _BSD_SOURCE

#include <stdint.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>

uint16_t ipv4_checksum(uint8_t protocol, void *s, void *d, void *c, uint16_t len);
uint16_t ipv6_checksum(uint8_t protocol,
                       struct in6_addr *src,
                       struct in6_addr *dst,
                       void *data, uint16_t len);
uint16_t checksum_ip(struct ip *ip_hdr, const unsigned int ip_hl);
uint16_t inchksum(const void *data, uint32_t length);
uint16_t hip_checksum_packet(char *data, struct sockaddr *src, struct sockaddr *dst);

#endif /* HIP_LIB_CORE_CHECKSUM_H */
