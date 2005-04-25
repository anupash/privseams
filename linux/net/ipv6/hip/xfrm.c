#include "xfrm.h"

// FIXME: this file is to be replaced with an API to NETLINK_XFRM.

/**
 * hip_delete_spd - delete an SPD entry suitable for HIP
 * @dir: SPD direction, %XFRM_POLICY_IN or %XFRM_POLICY_OUT
 *
 * Returns: 0 if successful, else < 0.
 */
int hip_delete_sp(int dir)
{
	int err = 0;
	struct xfrm_selector sel;

	memset(&sel, 0, sizeof(sel));

	sel.family = AF_INET6;
	sel.prefixlen_d = 2;
	sel.prefixlen_s = 2;
	sel.proto = 0;

	sel.saddr.a6[0] = htonl(0x40000000);
	sel.daddr.a6[0] = htonl(0x40000000);

	if (xfrm_policy_bysel(dir, &sel, 1)) { 
		HIP_DEBUG("SPD removed successfully\n");
	} else {
		HIP_DEBUG("No SPD entry found\n");
		err = -ENOENT;
	}
	return err;
}

//extern struct list_head *xfrm_state_bydst;
//extern struct list_head *xfrm_state_byspi;

/**
 * hip_delete_sa - delete a SA
 * @spi: SPI value of SA
 * @dst: destination HIT of SA
 *
 * Returns: 0 if successful, else < 0.
 */
// FIKME: this is basically the same as: xfrm_del_sa(struct sk_buff *skb, struct nlmsghdr *nlh, void **xfrma) (xfrm_user.c)
int hip_delete_sa(u32 spi, struct in6_addr *dst)
{
	struct xfrm_state *xs;
	xfrm_address_t *xaddr;

	if (spi == 0) {
		return -EINVAL;
	}

	HIP_DEBUG("SPI=0x%x\n", spi);
	xaddr = (xfrm_address_t *)dst;
	xs = xfrm_state_lookup(xaddr, htonl(spi), IPPROTO_ESP, AF_INET6);
	if (!xs) {
		HIP_ERROR("Could not find SA for SPI 0x%x (already expired ?)\n", spi);
		return -ENOENT;
	}
	xfrm_state_put(xs);
	xfrm_state_delete(xs);

	return 0;
}

/**
 * hip_setup_sp - setup IPsec SPD entries
 * @src: source HIT
 * @dst: destination HIT
 * @spi: SPI value
 * @dir: SPD direction, %XFRM_POLICY_IN or %XFRM_POLICY_OUT
 *
 * Returns: 0 if successful, else < 0.
 */
int hip_setup_sp(int dir)
{
	int err = 0;
	struct xfrm_policy *xp;
	struct xfrm_tmpl *tmpl;

	/* SP */
	xp = xfrm_policy_alloc(GFP_KERNEL);
	if (!xp) {
		HIP_ERROR("Failed to allocate memory for new SP\n");
		return -ENOMEM;
	}

	memset(&xp->selector.daddr, 0, sizeof(struct in6_addr));
	memset(&xp->selector.saddr, 0, sizeof(struct in6_addr));
	xp->selector.daddr.a6[0] = htonl(0x40000000);
	xp->selector.saddr.a6[0] = htonl(0x40000000);
	xp->selector.family = xp->family = AF_INET6;
	xp->selector.prefixlen_d = 2;
	xp->selector.prefixlen_s = 2;
	xp->selector.proto = 0;
	xp->selector.sport = xp->selector.dport = 0;
	xp->selector.sport_mask = xp->selector.dport_mask = 0;

	/* set policy to never expire */
	xp->lft.soft_byte_limit = XFRM_INF;
	xp->lft.hard_byte_limit = XFRM_INF;
	xp->lft.soft_packet_limit = XFRM_INF;
	xp->lft.hard_packet_limit = XFRM_INF;
	xp->lft.soft_add_expires_seconds = 0;
	xp->lft.hard_add_expires_seconds = 0;
	xp->lft.soft_use_expires_seconds = 0;
	xp->lft.hard_use_expires_seconds = 0;

	/* xp->curlft. add_time and use_time are set in xfrm_policy_insert */

	xp->family = AF_INET6; /* ? */
	xp->action = XFRM_POLICY_ALLOW;
	xp->flags = 0;
	xp->dead = 0;
	xp->xfrm_nr = 1; // one transform? 

	tmpl = &xp->xfrm_vec[0];

	tmpl->id.proto = IPPROTO_ESP;
	tmpl->reqid = 0;
	tmpl->mode = XFRM_MODE_TRANSPORT;
	tmpl->share = 0; // unique. Is this the correct number?
	tmpl->optional = 0; /* check: is 0 ok ? */
	tmpl->aalgos = ~0;
	tmpl->ealgos = ~0;
	tmpl->calgos = ~0;

	err = xfrm_policy_insert(dir, xp, 1);
	if (err) {
		if (err == -EEXIST)
			HIP_ERROR("SP policy already exists, ignore ?\n");
		else
			HIP_ERROR("Could not insert new SP, err=%d\n", err);
		// xfrm_policy_delete(xp); ?
		xfrm_pol_put(xp);
	}

	return err;
}

/* returns 0 if SPI could not  be allocated, SPI is in host byte order */
// xfrm_alloc_userspi(struct sk_buff *skb, struct nlmsghdr *nlh, void **xfrma)?
uint32_t hip_acquire_spi(hip_hit_t *srchit, hip_hit_t *dsthit)
{
	struct xfrm_state *xs;
	uint32_t spi = 0;

	HIP_DEBUG("acquiring a new SPI\n");
	xs = xfrm_find_acq(XFRM_MODE_TRANSPORT, 0, IPPROTO_ESP,
			   (xfrm_address_t *)dsthit, (xfrm_address_t *)srchit,
			   1, AF_INET6);
	if (!xs) {
		HIP_ERROR("Error while acquiring an SA\n");
		goto out_err_noput;
	}

	xfrm_alloc_spi(xs, htonl(256), htonl(0xFFFFFFFF));
	spi = ntohl(xs->id.spi);
	if (!spi) {
		HIP_ERROR("Could not get SPI value for the SA\n");
		goto out_err;
	}
	_HIP_DEBUG("Got SPI value for the SA 0x%x\n", spi);
	
 out_err:
	xfrm_state_put(xs);
 out_err_noput:
	return spi;
}


/**
 * hip_add_sa - set up a new IPsec SA
 * @srcit: source HIT
 * @dsthit: destination HIT
 * @spi: SPI value in host byte order
 * @alg: ESP algorithm to use
 * @enckey: ESP encryption key
 * @authkey: authentication key
 * @already_acquired: true if @spi was already acquired
 * @direction: direction of SA
 *
 * If @spi is 0 the kernel gets a
 * free SPI value for us. If @spi is non-zero we try to get the new SA
 * having @spi as its SPI.
 *
 * On success IPsec security association is set up, and SPI is returned.
 *
 * problems: The SA can be in acquire state, or it can already have timed out.
 *
 * Returns: 0 if fail, otherwise spi.
 */
uint32_t hip_add_sa(struct in6_addr *srchit, struct in6_addr *dsthit,
		    uint32_t spi, int alg, struct hip_crypto_key *enckey, struct hip_crypto_key *authkey,
		    int already_acquired, int direction)
{
	uint32_t err = 0;
	struct xfrm_state *xs = NULL;
	struct xfrm_algo_desc *ead;
	struct xfrm_algo_desc *aad;
	size_t akeylen, ekeylen; /* in bits */

	HIP_DEBUG("SPI=0x%x alg=%d already_acquired=%d direction=%s\n",
		  spi, alg, already_acquired, 
		  direction == HIP_SPI_DIRECTION_IN ? "IN" : "OUT");
	akeylen = ekeylen = 0;

	if (already_acquired) {
		HIP_IFEL(!spi, 0, "No SPI for already acquired SA\n");

		/* should be found (unless expired) */
		xs = xfrm_state_lookup(direction == HIP_SPI_DIRECTION_IN ?
				       (xfrm_address_t *)dsthit : (xfrm_address_t *)srchit,
				       htonl(spi), IPPROTO_ESP, AF_INET6);
		HIP_HEXDUMP("xfrm_state_lookup hit: ", (direction == HIP_SPI_DIRECTION_IN ?
							dsthit : srchit), sizeof(struct in6_addr));
	} else {
		xs = xfrm_find_acq(XFRM_MODE_TRANSPORT, 0, IPPROTO_ESP,
				   (xfrm_address_t *)dsthit, (xfrm_address_t *)srchit,
				   1, AF_INET6);
		HIP_HEXDUMP("xfrm_find_acq hit: ", dsthit, sizeof(struct in6_addr));
	}

	HIP_IFEL(!xs, 0, "Error while acquiring xfrm state.\n");

	/* old comments, todo */
	/* xs is either newly-created or an old one */

	/* allocation of SPI, will wake up possibly sleeping transport layer, but
	 * this is not a problem since it will retry acquiring of an SA, fail and
	 * sleep again.
	 * Allocation of SPI is, however, very important at this stage, so we
	 * either do it like this, or create our own version of xfrm_alloc_spi()
	 * which would do all the same stuff, without waking up.
	 */

	/* should we lock the state? */

	HIP_DEBUG("xs->id.spi=0x%x\n", ntohl(xs->id.spi));

	if (!already_acquired) {
		HIP_DEBUG("Acquiring SPI\n");
		if (spi) {
			xfrm_alloc_spi(xs, htonl(spi), htonl(spi));
		} else {
			/* Try to find a suitable random SPI within the range
			 * in RFC 2406 section 2.1 */
			xfrm_alloc_spi(xs, htonl(256), htonl(0xFFFFFFFF));
		}

		HIP_DEBUG("Allocated xs->id.spi=0x%x\n", ntohl(xs->id.spi));
		if (!xs->id.spi) {
			HIP_IFEL(spi, 0, "Could not allocate SPI value for the SA\n");
			HIP_IFEL(1, 0, "Could not allocate SPI value for the SA\n");
		}

		err = ntohl(xs->id.spi);
	}

	HIP_DEBUG("SPI setup ok, trying to setup enc/auth algorithms.\n");

	switch (alg) {
	case HIP_ESP_AES_SHA1:
		ead = xfrm_ealg_get_byid(SADB_X_EALG_AESCBC);
		HIP_IFEL(!ead, 0, "AES not supported\n");
		aad = xfrm_aalg_get_byid(SADB_AALG_SHA1HMAC);
		HIP_IFEL(!aad, 0, "SHA1 not supported\n");

		xs->props.ealgo = SADB_X_EALG_AESCBC;
		xs->props.aalgo = SADB_AALG_SHA1HMAC;
		break;
	case HIP_ESP_3DES_SHA1:
		ead = xfrm_ealg_get_byid(SADB_EALG_3DESCBC);
		HIP_IFEL(!ead, 0, "3DES not supported\n");
		aad = xfrm_aalg_get_byid(SADB_AALG_SHA1HMAC);
		HIP_IFEL(!aad, 0, "SHA1 not supported\n");

		xs->props.ealgo = SADB_EALG_3DESCBC;
		xs->props.aalgo = SADB_AALG_SHA1HMAC;
		break;
	case HIP_ESP_NULL_SHA1:
		ead = xfrm_ealg_get_byid(SADB_EALG_NULL);
		HIP_IFEL(!ead, 0, "NULL not supported\n");
		aad = xfrm_aalg_get_byid(SADB_AALG_SHA1HMAC);
		HIP_IFEL(!aad, 0, "SHA1 not supported\n");

		xs->props.ealgo = SADB_EALG_NULL;
		xs->props.aalgo = SADB_AALG_SHA1HMAC;
		break;
	default:
		ead = aad = NULL;
		HIP_IFEL(1, 0, "Unsupported algo type: 0x%x\n", alg);
	}

	/*
	 * AES max bits is 256 and IPsec standards recommend only 128 bits,
	 * so we're sticking with 128 bits (min bits). These values could
	 * also be passed as arguments to this function...
	 */
	ekeylen = ead->desc.sadb_alg_minbits;
	akeylen = aad->desc.sadb_alg_minbits;

	HIP_DEBUG("ekeylen=%d, akeylen=%d\n", ekeylen, akeylen);

	xs->ealg = HIP_MALLOC(sizeof(struct xfrm_algo) + (ekeylen + 7)/8, GFP_ATOMIC);
	HIP_IFEL(!xs->ealg, 0, "Out of memory.\n");

	xs->aalg = HIP_MALLOC(sizeof(struct xfrm_algo) + (akeylen + 7)/8, GFP_ATOMIC);
	HIP_IFEL(!xs->aalg, 0, "Out of memory.\n");

	strcpy(xs->aalg->alg_name, aad->name);
	strcpy(xs->ealg->alg_name, ead->name);
	memcpy(xs->aalg->alg_key, authkey, (akeylen + 7)/8);
	memcpy(xs->ealg->alg_key, enckey, (ekeylen + 7)/8);
	xs->aalg->alg_key_len = akeylen;
	xs->ealg->alg_key_len = ekeylen;

	xs->props.replay_window = 32; // XXX: Is this the size of the replay window in bits? 
	xs->sel.dport_mask = 0;
	xs->sel.sport_mask = 0;
	/* XXX: sel.ifindex... could we fail because of this? */

	xs->sel.proto = 0; /* all protos */

//	err = -ENOENT;
	xs->type = xfrm_get_type(IPPROTO_ESP, AF_INET6);
	HIP_IFEL(!xs->type, 0, "Could not get XFRM type\n");

	/* memory leak ? */
	HIP_IFEL(xs->type->init_state(xs, NULL), 0, "Could not initialize XFRM type\n");

	//	spin_lock_bh(&xs->lock);
	xs->km.state = XFRM_STATE_VALID;
	xs->lft.hard_add_expires_seconds = 0;
	//spin_unlock_bh(&xs->lock);

	xfrm_state_put(xs);
	HIP_DEBUG("New SA added successfully (%x)\n", err);
	return err;
 out_err:
	if (xs) {
		if (xs->aalg)
			HIP_FREE(xs->aalg);
		if (xs->ealg)
			HIP_FREE(xs->ealg);
		// xfrm_state_delete(xs) ? see above
		xfrm_state_put(xs);
	}

	HIP_DEBUG("Returning on error.\n");
	return 0;
}
