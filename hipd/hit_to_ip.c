/*
 * Check if there are records for 5.7.d.1.c.c.8.d.0.6.3.b.a.4.6.2.5.0.5.2.e.4.7.5.e.1.0.0.1.0.0.2.hit-to-ip.infrahip.net for 2001:1e:574e:2505:264a:b360:d8cc:1d75
 * Oleg Ponomarev, Helsinki Institute for Information Technology
 */
 
#include "hit_to_ip.h"
#include "maintenance.h"
#include "libinet6/include/netdb.h"
#include "libinet6/hipconf.h"
#include <netinet/in.h>
#include <string.h>

int hip_hit_to_ip_status = 1;

char *hip_hit_to_ip_zone = NULL;

void hip_set_hit_to_ip_status(int status) {
  hip_hit_to_ip_status = status;
}

int hip_get_hit_to_ip_status(void) {
  return hip_hit_to_ip_status;
}

void hip_hit_to_ip_set(char *zone) {
  char *tmp = hip_hit_to_ip_zone;

//  hip_hit_to_ip_zone = strndup(zone, HIT_TO_IP_ZONE_MAX_LEN); no strndup without _GNU_SOURCE

  
  hip_hit_to_ip_zone = strdup(zone);

  if (tmp!=NULL)
	free(tmp);
}

static char hex_digits[] = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
};

/*
 * returns "5.7.d.1.c.c.8.d.0.6.3.b.a.4.6.2.5.0.5.2.e.4.7.5.e.1.0.0.1.0.0.2.hit-to-ip.infrahip.net" for 2001:1e:574e:2505:264a:b360:d8cc:1d75
 */ 

char *hip_get_hit_to_ip_hostname(hip_hit_t *hit) {
	if (hit == NULL)
		return NULL;

	#define hostname_LEN 64+HIT_TO_IP_ZONE_MAX_LEN+1
	static char hostname[hostname_LEN];

        uint8_t *bytes = hit->s6_addr;
        char *cp = hostname;
	int i; // no C99 :(
        for (i = 15; i >= 0; i--) {
		*cp++ = hex_digits[bytes[i] & 0x0f];
                *cp++ = '.';
                *cp++ = hex_digits[(bytes[i] >> 4) & 0x0f];
                *cp++ = '.';
        }
	if (hip_hit_to_ip_zone!=NULL)
		strncpy(cp, hip_hit_to_ip_zone, hostname_LEN-64);
	else
		strncpy(cp, HIT_TO_IP_ZONE_DEFAULT,hostname_LEN-64);

	return hostname;
}

/*
 * checks for ip address for hit
 * returns NULL if not found
 */
int hip_hit_to_ip(hip_hit_t *hit, struct in6_addr *ip) {

	if (hit == NULL)
		return NULL;

	char *hit_to_ip_hostname = hip_get_hit_to_ip_hostname(hit);

	if (hit_to_ip_hostname==NULL)
		return NULL;

	struct addrinfo *result = NULL, *rp = NULL, hints;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_DGRAM; /* Datagram socket. Right? */
	hints.ai_flags = AI_PASSIVE;    /* For wildcard IP address */
	hints.ai_protocol = 0;          /* Any protocol */
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;

	/* getaddrinfo is too complex for DNS lookup, but let us use it for now */
	int res = getaddrinfo( hit_to_ip_hostname, NULL, &hints, &result );
	HIP_DEBUG("getaddrinfo(%s) = %d", hit_to_ip_hostname, res);

	if (res!=0)
		return NULL;

	struct in6_addr tmp_in6_addr;
	/* Look at the list and return only one address, let us prefer AF_INET6 */
	for (rp = result; rp != NULL; rp = rp->ai_next) {
		if (rp->ai_family == AF_INET6) {
			struct sockaddr_in6 *tmp_sockaddr_in6_ptr = (struct sockaddr_in6 *) (rp->ai_addr);
			ipv6_addr_copy(ip, &(tmp_sockaddr_in6_ptr->sin6_addr));
			break; // return ipv6 address if found
		} else if (rp->ai_family == AF_INET) {
			struct sockaddr_in *tmp_sockaddr_in_ptr = (struct sockaddr_in *) (rp->ai_addr);
			IPV4_TO_IPV6_MAP(&(tmp_sockaddr_in_ptr->sin_addr), ip)
			  HIP_DEBUG_IN6ADDR("addr", &tmp_in6_addr);
		}
	}

	if (result)
		freeaddrinfo(result);

#if 0 // XX FIXME
	if (hit_to_ip_hostname)
		free(hit_to_ip_hostname);
#endif
	return 0;
}
