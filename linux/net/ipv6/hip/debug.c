/*
 * HIP kernelspace debugging functions
 *
 * Licence: GNU/GPL
 * Authors:
 * - Miika Komu <miika@iki.fi>
 * - Mika Kousa <mkousa@cc.hut.fi>
 */

#include "debug.h"
#include "misc.h"

inline void hip_debug_skb(const struct ipv6hdr *hdr, const struct sk_buff *skb)
{
  	struct ipv6hdr *ip6hdr;
	char src[INET6_ADDRSTRLEN];
	char dst[INET6_ADDRSTRLEN];
	_HIP_DEBUG("hdr=%p skb=%p\n", hdr, skb);
	if (hdr && skb) {
		ip6hdr = skb->nh.ipv6h;
		_HIP_DEBUG("ip6hdr=%p src %p dst %p skbdev %p\n",
			  ip6hdr, &ip6hdr->saddr, &ip6hdr->daddr,
			  skb->dev);
		hip_in6_ntop(&ip6hdr->saddr, src);
		hip_in6_ntop(&ip6hdr->daddr, dst);
		HIP_DEBUG("pkt out: saddr %s daddr %s\n", src, dst);
		if (skb->dev) {
			HIP_DEBUG("pkt out: dev %s (ifindex %d)\n",
				  skb->dev->name, skb->dev->ifindex);
		}
	}
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

	if (!data) {
		HIP_ERROR("NULL data ptr\n");
		return;
	}

	/* every hexdump line contains offset+": "+32 bytes of data (space every 4 bytes) */
	buflen = 4+2+2*32+((32-1)/4)+1;
	_HIP_DEBUG("hdump buflen = %d\n", buflen);
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


/**
 * hip_state_str - get name for a state
 * @state: state value
 *
 * Returns: state name as a string.
 */
inline const char *hip_state_str(unsigned int state)
{
	const char *str = "UNKNOWN";
	static const char *states[] =
		{ "NONE", "UNASSOCIATED", "I1_SENT",
		  "I2_SENT", "R2_SENT", "ESTABLISHED", "REKEYING",
		  "FAILED" };
	if (state <= (sizeof(states)/sizeof(states[0])))
		str = states[state];

	return str;
}
