#include <netinet/in.h>
#include <net/hip.h>
#include <linux/netfilter_ipv6.h>

//#include "hip.h"
#include "debug.h"
#include "helpers.h"
#include "rule_management.h"
#include "firewall.h"


/**
 * TODO copied, see if available else where
 * get char* out of in6_addr 
 */
char *
addr_to_numeric(const struct in6_addr *addrp)
{
	/* 0000:0000:0000:0000:0000:000.000.000.000
	 * 0000:0000:0000:0000:0000:0000:0000:0000 */
	static char buf[50+1];
	return (char *)inet_ntop(AF_INET6, addrp, buf, sizeof(buf));
}

/**
 * TODO copied, see if available else where
 * get in6_addr out of char* 
 */
struct in6_addr *
numeric_to_addr(const char *num)
{
	static struct in6_addr ap;
	int err;
	if ((err=inet_pton(AF_INET6, num, &ap)) == 1)
		return &ap;
	//#ifdef DEBUG
	//	fprintf(stderr, "\nnumeric2addr: %d\n", err);
	//#endif
	return (struct in6_addr *)NULL;
}


