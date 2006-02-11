/*
 * HIP kernelspace debugging functions
 *
 * Licence: GNU/GPL
 * Authors:
 * - Miika Komu <miika@iki.fi>
 * - Mika Kousa <mkousa@cc.hut.fi>
 */

#include "debug.h"

char* hip_in6_ntop(const struct in6_addr *in6, char *buf)
{
        if (!buf)
                return NULL;
        sprintf(buf,
                "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
                ntohs(in6->s6_addr16[0]), ntohs(in6->s6_addr16[1]),
                ntohs(in6->s6_addr16[2]), ntohs(in6->s6_addr16[3]),
                ntohs(in6->s6_addr16[4]), ntohs(in6->s6_addr16[5]),
                ntohs(in6->s6_addr16[6]), ntohs(in6->s6_addr16[7]));
        return buf;
}

/**
 * hip_print_hit - print a HIT
 * @str: string to be printed before the HIT
 * @hit: the HIT to be printed
 */
inline void hip_print_hit(const char *str, const struct in6_addr *hit)
{
	char dst[INET6_ADDRSTRLEN];

	hip_in6_ntop(hit, dst);
	HIP_DEBUG("%s: %s\n", str, dst);
	return;
}

/**
 * khexdump - hexdumper for HIP kernel module
 * @tag:  a start tag (a string ending in \0) that will be printed before
 *        the actual hexdump
 * @data: the data to be hexdumped
 * @len:  the length of the data to hexdumped
 *
 * Hexdumps data starting from address @data of length @len.
 */
inline void hip_khexdump(const char *tag, const void *data, const int len)
{
	char *buf, *bufpos;
	const void *datapos;
	int buflen, i;
	unsigned char c;

	if (!data || len < 0) {
		HIP_ERROR("NULL data or len < 0 (len=%d)\n", len);
		return;
	}

	/* every hexdump line contains offset+": "+32 bytes of data (space every 4 bytes) */
	buflen = 4+2+2*32+((32-1)/4)+1;
	buf = kmalloc(buflen, GFP_ATOMIC);
	if (!buf)
		return;

	HIP_DEBUG("%s: begin dump %d bytes from 0x%p\n", tag, len, data);
	datapos = data;

	i = 0;
	while (i < len) {
		int j;

		bufpos = buf;
		memset(buf, 0, buflen);
		sprintf(bufpos, "%4d: ", i);
		bufpos += 4+2;
		for (j = 0; i < len && bufpos < buf+buflen-1;
		     j++, i++, bufpos += 2*sizeof(char)) {
			c = (unsigned char)(*(((unsigned char *)data)+i));
			if (j && !(j%4)) {
				sprintf(bufpos, " ");
				bufpos += sizeof(char);
			}
			sprintf(bufpos, "%02x", c);
		}
		printk(KERN_DEBUG "%s\n", buf);
	}

	HIP_DEBUG("end of dump (0x%p)\n", data+len);
	kfree(buf);
	return;
}

