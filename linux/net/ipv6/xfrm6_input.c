/*
 * xfrm6_input.c: based on net/ipv4/xfrm4_input.c
 *
 * Authors:
 *	Mitsuru KANDA @USAGI
 * 	Kazunori MIYAZAWA @USAGI
 * 	Kunihiro Ishiguro <kunihiro@ipinfusion.com>
 *	YOSHIFUJI Hideaki @USAGI
 *		IPv6 support
 */

#include <net/inet_ecn.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/xfrm.h>

#if defined(CONFIG_HIP) || defined(CONFIG_HIP_MODULE)
#include <net/hip_glue.h>
#endif

static inline void ipip6_ecn_decapsulate(struct ipv6hdr *iph,
					 struct sk_buff *skb)
{
	if (INET_ECN_is_ce(ip6_get_dsfield(iph)) &&
	    INET_ECN_is_not_ce(ip6_get_dsfield(skb->nh.ipv6h)))
		IP6_ECN_set_ce(skb->nh.ipv6h);
}

int xfrm6_rcv(struct sk_buff **pskb, unsigned int *nhoffp)
{
	struct sk_buff *skb = *pskb;
	int err;
	u32 spi, seq;
	struct sec_decap_state xfrm_vec[XFRM_MAX_DEPTH];
	struct xfrm_state *x;
	int xfrm_nr = 0;
	int decaps = 0;
	int nexthdr = 0;
	u8 *prevhdr = NULL;

	ip6_find_1stfragopt(skb, &prevhdr);
	nexthdr = *prevhdr;
	*nhoffp = prevhdr - skb->nh.raw;

	if ((err = xfrm_parse_spi(skb, nexthdr, &spi, &seq)) != 0)
		goto drop;
	
	do {
		struct ipv6hdr *iph = skb->nh.ipv6h;

		if (xfrm_nr == XFRM_MAX_DEPTH)
			goto drop;

#if defined(CONFIG_HIP) || defined(CONFIG_HIP_MODULE)
		HIP_CALLPROC(hip_handle_esp)(ntohl(spi), iph);
#endif
		x = xfrm_state_lookup((xfrm_address_t *)&iph->daddr, spi, nexthdr, AF_INET6);
		if (x == NULL) {
#if defined(CONFIG_HIP) || defined(CONFIG_HIP_MODULE)
			/* SPI was unknown. Currently Linux IPsec doesn't seem to
			 * do anything. HIP, on the other hand, assumes that the
			 * connection was reset and tries to reestablish it.
			 *
			 * This could lead to DoSes... if birthday check is omitted.
			 */
//			HIP_CALLPROC(hip_unknown_spi)(skb,spi);
#endif
			goto drop;
		}
		spin_lock(&x->lock);
		if (unlikely(x->km.state != XFRM_STATE_VALID))
			goto drop_unlock;

		if (x->props.replay_window && xfrm_replay_check(x, seq))
			goto drop_unlock;

		if (xfrm_state_check_expire(x))
			goto drop_unlock;

		nexthdr = x->type->input(x, &(xfrm_vec[xfrm_nr].decap), skb);
		if (nexthdr <= 0)
			goto drop_unlock;

		if (x->props.replay_window)
			xfrm_replay_advance(x, seq);

		x->curlft.bytes += skb->len;
		x->curlft.packets++;

		spin_unlock(&x->lock);

		xfrm_vec[xfrm_nr++].xvec = x;

		if (x->props.mode == XFRM_MODE_TUNNEL) { 
			if (nexthdr != IPPROTO_IPV6)
				goto drop;
			skb->nh.raw = skb->data;
			if (!(x->props.flags & XFRM_STATE_NOECN))
				ipip6_ecn_decapsulate(iph, skb);
			iph = skb->nh.ipv6h;
			decaps = 1;
			break;
		} else if (x->props.mode == XFRM_MODE_BEET) {
			/* this should be us */
			ipv6_addr_copy(&iph->daddr, (struct in6_addr *)&x->id.daddr);
			/* the original sender */
			ipv6_addr_copy(&iph->saddr, (struct in6_addr *)&x->props.saddr);
		}

		if ((err = xfrm_parse_spi(skb, nexthdr, &spi, &seq)) < 0)
			goto drop;
	} while (!err);

	/* Allocate new secpath or COW existing one. */
	if (!skb->sp || atomic_read(&skb->sp->refcnt) != 1) {
		struct sec_path *sp;
		sp = secpath_dup(skb->sp);
		if (!sp)
			goto drop;
		if (skb->sp)
			secpath_put(skb->sp);
		skb->sp = sp;
	}

	if (xfrm_nr + skb->sp->len > XFRM_MAX_DEPTH)
		goto drop;

	memcpy(skb->sp->x+skb->sp->len, xfrm_vec, xfrm_nr*sizeof(struct sec_decap_state));
	skb->sp->len += xfrm_nr;
	skb->ip_summed = CHECKSUM_NONE;

	if (decaps) {
		if (!(skb->dev->flags&IFF_LOOPBACK)) {
			dst_release(skb->dst);
			skb->dst = NULL;
		}
		netif_rx(skb);
		return -1;
	} else {
		return 1;
	}

drop_unlock:
	spin_unlock(&x->lock);
	xfrm_state_put(x);
drop:
	while (--xfrm_nr >= 0)
		xfrm_state_put(xfrm_vec[xfrm_nr].xvec);
	kfree_skb(skb);
	return -1;
}
