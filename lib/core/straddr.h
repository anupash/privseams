#ifndef HIP_LIB_CORE_STRADDR_H
#define HIP_LIB_CORE_STRADDR_H

#include <sys/types.h>
#include <netinet/in.h>

int convert_string_to_address_v4(const char *str, struct in_addr *ip);
int convert_string_to_address(const char *str, struct in6_addr *ip6);
char *hip_in6_ntop(const struct in6_addr *in6, char *buf);
int hip_string_to_lowercase(char *to, const char *from, const size_t count);
int hip_string_is_digit(const char *string);
unsigned char *base64_encode(unsigned char *, unsigned int);

#endif /* HIP_LIB_CORE_STRADDR_H */
