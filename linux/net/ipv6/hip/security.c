/*
 * HIPL security related functions
 *
 * Authors:
 * - Mika Kousa <mkousa@cc.hut.fi>
 * - Kristian Slavov <ksl@iki.fi>
 */ 

#include <linux/in6.h>
#include "security.h"
#include "crypto/dh.h"

/**
 * hip_delete_spd - delete an SPD entry
 * @hitd: destination HIT (peer's)
 * @hits: source HIT (own)
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

extern struct list_head *xfrm_state_bydst;
extern struct list_head *xfrm_state_byspi;

static void hip_hirmu_kludge(int byspi)
{
	int i;
	char str[256] = {0};
	char meep[64] = {0};
	struct xfrm_state *xs;

	HIP_DEBUG("DUMPING SPI TABLE\n");
	for(i = 0; i < 1024; i++) {
		if (!list_empty(&xfrm_state_byspi[i])) {
			sprintf(meep, "%d: ", i);
			strcat(str, meep);
			list_for_each_entry(xs, &xfrm_state_byspi[i], byspi) {
				sprintf(meep, "-> 0x%x [%s] ", xs->id.spi, xs->km.state == XFRM_STATE_VALID ? " OK" : "NOK");
				strcat(str, meep);
			}
			HIP_DEBUG("%s\n",str);
			memset(str,0,256);
		}
	}
	HIP_DEBUG("END-OF-DUMP\n");
}
/**
 * hip_delete_sa - delete HIP SA which has SPI of @spi
 * @spi: SPI value of SA
 * @dst: destination HIT of SA
 *
 * Returns: 0 if successful, else < 0.
 */
int hip_delete_sa(u32 spi, struct in6_addr *dst)
{
	struct xfrm_state *xs;
	xfrm_address_t *xaddr;

	/* todo: move SPI multiget code from delete_esp here */
	HIP_DEBUG("spi=0x%x\n", spi);
	hip_print_hit("dst address", dst);
	/* todo: return if spi == 0 ? (first time use of hadb_entry) */
	if (spi == 0) {
		return -EINVAL;
	}
	xaddr = (xfrm_address_t *)dst;

	xs = xfrm_state_lookup(xaddr, htonl(spi), IPPROTO_ESP, AF_INET6);
	if (!xs) {
		HIP_ERROR("Could not find SA!\n");
		return -ENOENT;
	}
	/* xfrm_state_put ? (xfrm_state_lookup incs xs's refcount) */
	xfrm_state_delete(xs);
	
	return 0;
}
/**
 * hip_delete_esp - delete entry's IPsec SPD and SA
 * @entry: the entry whose SPD and SA are to be deleted
 *
 * Returns: 0 if successful, else < 0.
 */
int hip_delete_esp(struct in6_addr *own, struct in6_addr *peer)
{
	uint32_t spi_peer, spi_our, new_spi_peer, new_spi_our;
	int getlist[4];
	void *setlist[4];
	int k;

//	hip_hirmu_kludge(1);

	getlist[0] = HIP_HADB_PEER_SPI;
	getlist[1] = HIP_HADB_OWN_SPI;
	getlist[2] = HIP_HADB_PEER_NEW_SPI;
	getlist[3] = HIP_HADB_OWN_NEW_SPI;
	setlist[0] = &spi_peer;
	setlist[1] = &spi_our;
	setlist[2] = &new_spi_peer;
	setlist[3] = &new_spi_our;

	k = hip_hadb_multiget(peer, 4, getlist, setlist, HIP_ARG_HIT);
	if (k != 4) {
		HIP_ERROR("Could not get all SPIs from db (got only %d out of 4)\n", k);
	}

	/* Delete SAs */
	hip_delete_sa(spi_peer, peer);
	hip_delete_sa(spi_our, own);
	hip_delete_sa(new_spi_peer, own);
	hip_delete_sa(new_spi_our, peer);

	k = 0;
	setlist[0] = &k;
	setlist[1] = &k;
	setlist[2] = &k;
	setlist[3] = &k;

	hip_hadb_multiset(peer, 4, getlist, setlist, HIP_ARG_HIT);

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

	xp->lft.soft_byte_limit = XFRM_INF;
	xp->lft.hard_byte_limit = XFRM_INF;
	xp->lft.soft_packet_limit = XFRM_INF;
	xp->lft.hard_packet_limit = XFRM_INF;
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
			HIP_DEBUG("SP policy already exists\n");
		else
			HIP_ERROR("Could not insert new SP policy, err=%d\n", err);
		// xfrm_policy_delete(xp); ?
		xfrm_pol_put(xp);
		return err;
	}

	return 0;
}

/**
 * hip_setup_sa - set up a new IPsec SA
 * @srcit: source HIT
 * @dsthit: destination HIT
 * @spi: SPI value in host byte order
 * @alg: ESP algorithm to use
 * @enckey: ESP encryption key
 * @authkey: authentication key
 *
 * @spi is a value-result parameter. If @spi is 0 the kernel gets a
 * free SPI value for us. If @spi is non-zero we try to get the new SA
 * having @spi as its SPI.
 *
 * On success IPsec security association is set up @spi contains the
 * SPI.
 *
 * problems: The SA can be in acquire state, or it can already have timed out.
 *
 * Returns: 0 if successful, else < 0.
 */
int hip_setup_sa(struct in6_addr *srchit, struct in6_addr *dsthit,
		 uint32_t *spi, int alg, void *enckey, void *authkey, 
		 int is_active)
{
	int err;
	struct xfrm_state *xs;
	struct xfrm_algo_desc *ead;
	struct xfrm_algo_desc *aad;
	size_t akeylen, ekeylen; /* in bits */

	HIP_DEBUG("*spi=0x%x alg=%d is_active=%d\n", *spi, alg, is_active);
	akeylen = ekeylen = 0;
	err = -ENOMEM;

	xs = xfrm_find_acq(XFRM_MODE_TRANSPORT, 0, IPPROTO_ESP,
			   (xfrm_address_t *)dsthit, (xfrm_address_t *)srchit,
			   1, AF_INET6);
	if (!xs) {
		HIP_ERROR("Error while acquiring an SA: %d\n", err);
		return err;
	}

	/* xs is either newly-created or an old one */

	/* allocation of SPI, will wake up possibly sleeping transport layer, but
	 * this is not a problem since it will retry acquiring of an SA, fail and
	 * sleep again.
	 * Allocation of SPI is, however, very important at this stage, so we
	 * either do it like this, or create our own version of xfrm_alloc_spi()
	 * which would do all the same stuff, without waking up.
	 */

	/* should we lock the state? */

	if (*spi != 0) {
		*spi = htonl(*spi);
		xfrm_alloc_spi(xs, *spi, *spi);
	} else {
		/* Try to find a suitable random SPI within the range
		 * in RFC 2406 section 2.1 */
		xfrm_alloc_spi(xs, htonl(256), htonl(0xFFFFFFFF));
	}

	if (xs->id.spi == 0) {
		HIP_ERROR("Could not get SPI value for the SA\n");
		if (*spi != 0) {
			err = -EEXIST;
			goto out;
		} else {
			err = -EAGAIN;
			goto out;
		}
	}

	*spi = ntohl(xs->id.spi);

	HIP_DEBUG("SPI setup ok, trying to setup enc/auth algos\n");

	err = -ENOENT;
	switch (alg) {
	case HIP_ESP_3DES_SHA1:
		ead = xfrm_ealg_get_byid(SADB_EALG_3DESCBC);
		if (!ead) {
			HIP_ERROR("3DES not supported\n");
			goto out;
		}

		aad = xfrm_aalg_get_byid(SADB_AALG_SHA1HMAC);
		if (!aad) {
			HIP_ERROR("SHA1 not supported\n");
			goto out;
		}

		xs->props.ealgo = SADB_EALG_3DESCBC;
		xs->props.aalgo = SADB_AALG_SHA1HMAC;
		break;
	case HIP_ESP_NULL_SHA1:
		ead = xfrm_ealg_get_byid(SADB_EALG_NULL);
		if (!ead) {
			HIP_ERROR("NULL not supported\n");
			goto out;
		}

		aad = xfrm_aalg_get_byid(SADB_AALG_SHA1HMAC);
		if (!aad) {
			HIP_ERROR("SHA1 not supported\n");
			goto out;
		}

		xs->props.ealgo = SADB_EALG_NONE;
		xs->props.aalgo = SADB_AALG_SHA1HMAC;
		break;
	default:
		err = -EINVAL;
		ead = aad = NULL;
		HIP_ERROR("Unsupported algo type: 0x%x\n", alg);
		HIP_ASSERT(0);
	}

	ekeylen = ead->desc.sadb_alg_maxbits;
	akeylen = aad->desc.sadb_alg_maxbits;

	err = -ENOMEM;
	xs->ealg = kmalloc(sizeof(struct xfrm_algo) + (ekeylen + 7)/8, GFP_KERNEL);
	if (!xs->ealg)
		goto out;
	xs->aalg = kmalloc(sizeof(struct xfrm_algo) + (akeylen + 7)/8, GFP_KERNEL);
	if (!xs->aalg)
		goto out;

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

	err = -ENOENT;
	xs->type = xfrm_get_type(IPPROTO_ESP, AF_INET6);
	if (xs->type == NULL) {
		HIP_ERROR("Could not get XFRM type\n");
		goto out;
	}

	if (xs->type->init_state(xs, NULL)) {
		HIP_ERROR("Could not initialize XFRM type\n");
		goto out;
	}

	xfrm_state_put(xs);
	HIP_DEBUG("New SA added successfully\n");
	return 0;
 out:
	if (xs) {
		if (xs->aalg)
			kfree(xs->aalg);
		if (xs->ealg)
			kfree(xs->ealg);
		// xfrm_state_delete(xs) ? see above
		xfrm_state_put(xs);
	}

	HIP_DEBUG("returning, err=%d\n", err);
	return err;
}

/* spi in HOST BYTE ORDER!
 */
void hip_finalize_sa(struct in6_addr *hit, u32 spi)
{
	struct xfrm_state *xs;

	HIP_DEBUG("Searching for spi: %x (%x)\n",spi, htonl(spi));

	xs = xfrm_state_lookup((xfrm_address_t *)hit, htonl(spi),
			       IPPROTO_ESP, AF_INET6);
	if (!xs) {
		HIP_ERROR("Could not finalize SA\n");
		/* do what? */
		return;
	}
	
	spin_lock_bh(&xs->lock);
	xs->km.state = XFRM_STATE_VALID;
	xs->lft.hard_add_expires_seconds = 0;
	spin_unlock_bh(&xs->lock);

	xfrm_state_put(xs);
	wake_up(&km_waitq);
}
      

/**
 * hip_setup_esp - setup IPsec SPD and SA entries having given parameters
 * @dst: destination address
 * @src: source address
 * @spi: SPI value
 * @encalg: encryption algorithm to use
 * @enckey: encryption key
 * @authkey: authentication key
 *
 * Returns error codes. 
 * 0         = no error
 * -ENOMEM   = Memory allocation error
 * -EEXISTS  = Requested SPI already in use
 * -EAGAIN   = Couldn't assign any SPI. Try again?
 * -ENOENT   = Could find requested element (transform states etc.)
 */
#if 0
int hip_setup_esp(struct in6_addr *srchit, struct in6_addr *dsthit,
		  uint32_t *spi, int alg, void *enckey, void *authkey, 
		  int is_active)
{
/* dstip is useless ? */
	int err;

	err = hip_setup_sa(srchit, dsthit, spi, alg, enckey,
			   authkey, is_active);
	if (err) {
		HIP_DEBUG("Setting up %s SA: [FAILED] (err=%d)\n",
			  (dir == XFRM_POLICY_OUT) ? "outgoing" : "incoming", 
			  err);
		return err;
	}

	HIP_DEBUG("Setting up %s SA: [OK] (SPI=%x)\n",
		  (dir == XFRM_POLICY_OUT) ? "outgoing" : "incoming", *spi);

	return 0;
}
#endif

/**
 * hip_insert_dh - Insert the current DH-key into the buffer
 *
 * If a DH-key does not exist, we will create one.
 * Returns: >0 if ok, -1 if errors
 */
int hip_insert_dh(u8 *buffer, int bufsize, int group_id)
{
	size_t res;
	DH *tmp;

/*
 * First check that we have the key available.
 * Then encode it into the buffer
 */

	if (dh_table[group_id] == NULL) 
	{
		tmp = hip_generate_dh_key(group_id);

		spin_lock(&dh_table_lock);
		dh_table[group_id] = tmp;
		spin_unlock(&dh_table_lock);

		if (dh_table[group_id] == NULL) {
			HIP_ERROR("DH key %d not found and could not create it\n",
				  group_id);
			return -1;
		}
	}

/* argh... dh_clone does kmalloc(GFP_KERNEL) :( */
//	spin_lock(&dh_table_lock);
	tmp = hip_dh_clone(dh_table[group_id]);
//	spin_unlock(&dh_table_lock);

	if (!tmp) {
		HIP_ERROR("Could not clone DH-key\n");
		return -2;
	}

	res = hip_encode_dh_publickey(tmp,buffer,bufsize);
	if (res < 0) {
		HIP_ERROR("Encoding error\n");
		hip_free_dh_structure(tmp);
		return -3;
	}

	hip_free_dh_structure(tmp);
	return res;
}

int hip_generate_shared_secret(int group_id, u8* peerkey, size_t peer_len, u8 *out, size_t outlen)
{
	DH *tmp;
	int k;

	if (dh_table[group_id] == NULL) {
		HIP_ERROR("No DH-key found for group_id: %d\n",group_id);
		return -1;
	}

	spin_lock(&dh_table_lock);
	tmp = hip_dh_clone(dh_table[group_id]);
	spin_unlock(&dh_table_lock);

	if (!tmp) {
		HIP_ERROR("Error cloning DH key\n");
		return -3;
	}

	k = hip_gen_dh_shared_key(tmp,peerkey,peer_len,out,outlen);
	if (k < 0) {
		HIP_ERROR("Shared key failed\n");
		hip_free_dh_structure(tmp);
		return -2;
	}

	hip_free_dh_structure(tmp);
	return k;
}       

/*
 * Use only this function to generate DH keys.
 *
 */
void hip_regen_dh_keys(u32 bitmask)
{
	DH *tmp,*okey;
	int maxmask,i;
	int cnt = 0;

	/* if MAX_DH_GROUP_ID = 4 --> maxmask = 0...01111 */
	maxmask = (1 << (HIP_MAX_DH_GROUP_ID+1)) - 1;
	bitmask &= maxmask;

	for(i=1; i<=HIP_MAX_DH_GROUP_ID; i++) {
		if (bitmask & (1 << i)) {
			tmp = hip_generate_dh_key(i);
			if (!tmp) {
				HIP_INFO("Error while generating group: %d\n",i);
				continue;
			}

			spin_lock(&dh_table_lock);
			okey = dh_table[i];
			dh_table[i] = tmp;
			spin_unlock(&dh_table_lock);

			hip_free_dh_structure(okey);

			cnt++;

			HIP_DEBUG("DH key for group %d generated\n",i);
		} 
	}
	HIP_DEBUG("%d keys generated\n",cnt);
}

/*
	tmp = gen_key();
	oldkey = dhtable[gid];
	sl;
	dhtable_[gid] = tmp;
	sul;
	free(oldkey);
	
	sl;
	encode_pubkey(buffer,dhtable[gid]);
	sul;

	sl;
	tmp = dh_clone(dhtable[gid]);
	sul;
	shared_secret(tmp,peerkey));

*/	
