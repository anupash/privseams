/*
 * security related functions
 */ 

#include "security.h"

/**
 * hip_delete_spd - delete an SPD entry
 * @hitd: destination HIT (peer's)
 * @hits: source HIT (own)
 *
 *
 * Returns: 0 if successful, else < 0.
 */
int hip_delete_spd(struct in6_addr *hitd, struct in6_addr *hits, int dir)
{
	int err = 0;
	struct xfrm_selector sel;

	memset(&sel, 0, sizeof(sel));

	sel.family = AF_INET6;
	sel.prefixlen_d = 128;
	sel.prefixlen_s = 128;
	sel.proto = 0; // what here?

	ipv6_addr_copy((struct in6_addr *)&sel.saddr, hits);
	ipv6_addr_copy((struct in6_addr *)&sel.daddr, hitd);

	if (xfrm_policy_bysel(dir, &sel, 1)) { 
		HIP_DEBUG("spd_remove was successful\n");
	} else {
		HIP_DEBUG("No SPD entry found\n");
		err = -ENOENT;
	}
	return err;
}

/**
 * hip_delete_sa - delete HIP SA which has SPI of @spi
 * @spi: SPI value of SA
 * @dst: destination HIT of SA
 * @src: destination HIT of SA
 *
 * Returns: 0 if successful, else < 0.
 */
int hip_delete_sa(u32 spi, struct in6_addr *dst)
{
	struct xfrm_state *xs;
	xfrm_address_t *xaddr;


	/* todo: return if spi == 0 ? (first time use of sdb_entry) */

	xaddr = (xfrm_address_t *)dst;

	xs = xfrm_state_lookup(xaddr, spi, IPPROTO_ESP, AF_INET6);
	if (!xs) {
		HIP_ERROR("Could not find SA!\n");
		return -ENOENT;
	}

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
		HIP_ERROR("Could not get SPIs from db\n");
//		return -EINVAL;
	}

	/* Delete SPDs */
	hip_delete_spd(peer, own, XFRM_POLICY_OUT);
	hip_delete_spd(own, peer, XFRM_POLICY_IN);

	/* Delete SAs */
	hip_delete_sa(spi_peer, own);
	hip_delete_sa(spi_our, peer);
	if (k > 2) {
		hip_delete_sa(new_spi_peer, own);
		hip_delete_sa(new_spi_our, peer);
	}

	return 0;
}



static int hip_setup_sp(struct in6_addr *src, struct in6_addr *dst,
			int spi, int dir)
{
	int err = 0;
	struct xfrm_policy *xp;
	struct xfrm_tmpl *tmpl;

	/* SP... */

	xp = xfrm_policy_alloc(GFP_KERNEL);
	if (!xp) {
		HIP_ERROR("Failed ipsec_sa_kmalloc\n");
		return -ENOBUFS;
	}

	xp->action = XFRM_POLICY_ALLOW;

	memcpy(&xp->selector.daddr, dst, sizeof(struct in6_addr));
	memcpy(&xp->selector.saddr, src, sizeof(struct in6_addr));
	xp->selector.family = xp->family = AF_INET6;
	xp->selector.prefixlen_d = 128;
	xp->selector.prefixlen_s = 128;
	xp->selector.proto = 0; // any?
	xp->selector.sport = xp->selector.dport = xp->selector.sport_mask = 0;
	xp->selector.dport_mask = 0;

	xp->lft.soft_byte_limit = XFRM_INF;
	xp->lft.hard_byte_limit = XFRM_INF;
	xp->lft.soft_packet_limit = XFRM_INF;	 
	xp->lft.hard_packet_limit = XFRM_INF;	 

	xp->xfrm_nr = 1; // one transform?
	
	tmpl = &xp->xfrm_vec[0];

	ipv6_addr_copy((struct in6_addr *)&tmpl->id.daddr, dst);
	tmpl->id.spi = spi;
	tmpl->id.proto = IPPROTO_ESP;
	tmpl->reqid = 666;
	tmpl->mode = XFRM_MODE_TRANSPORT;
	tmpl->share = 0; // unique. Is this the correct number?
	tmpl->aalgos = ~0;
	tmpl->ealgos = ~0;

	err = xfrm_policy_insert(dir, xp, 1);
	if (err) {
		kfree(xp);
		return err;
	}

	xfrm_pol_put(xp); // really?
	return 0;
}

static
int hip_setup_sa(struct in6_addr *srchit, struct in6_addr *dsthit,
		 struct in6_addr *dstip, uint32_t *spi, int alg,
		 void *enckey, void *authkey, int is_active)
{
	int err;
	struct xfrm_state *xs;
	struct xfrm_algo_desc *ead;
	struct xfrm_algo_desc *aad;
	size_t 	akeylen,ekeylen;

	akeylen = ekeylen = 0;
	err = -ENOMEM;

	xs = xfrm_state_alloc();
	if (!xs) {
		HIP_ERROR("No memory\n");
		return err;
	}
	
	/* will fill like a pfkey_add would fill */

	xs->id.proto = IPPROTO_ESP;
	if (*spi != 0) 
		xfrm_alloc_spi(xs, *spi, *spi);
	else
		xfrm_alloc_spi(xs, 256, 0xFFFFFFFF); // XXX: ok spi values?

	if (xs->id.spi == 0) {
		if (*spi != 0) {
			err = -EEXIST;
			goto out;
		} else {
			err = -EAGAIN;
			goto out;
		}
	}
		
	*spi = xs->id.spi; 
	xs->props.replay_window = 0; // XXX: Is this the size of the replay window in bits? 
	

	switch (alg) {
	case HIP_ESP_3DES_SHA1:
		err = -ENOENT;

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
		err = -ENOENT;
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

	default:
		ead = aad = NULL;
		HIP_ERROR("Unsupported type: 0x%x\n",alg);
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

	xs->props.family = AF_INET6;
	memcpy(&xs->id.daddr, dsthit, sizeof(struct in6_addr));
	memcpy(&xs->props.saddr, srchit, sizeof(struct in6_addr));

	xs->props.mode = XFRM_MODE_TRANSPORT; //transport
	xs->props.reqid = 666; // SP has to know which SA to use
	
	err = -ENOENT;
	xs->type = xfrm_get_type(IPPROTO_ESP, AF_INET6);
	if (xs->type == NULL) {
		HIP_ERROR("COuld not get XFRM type\n");
		goto out;
	}

	if (xs->type->init_state(xs, NULL)) {
		HIP_ERROR("Could not initialize XFRM type\n");
		goto out;
	}

	xs->km.seq = 0;
	if (is_active)
		xs->km.state = XFRM_STATE_VALID;
	else
		xs->km.state = XFRM_STATE_VOID;

	/* SA policy ok??? */

	err = xfrm_state_add(xs);
	if (err) {
		xs->km.state = XFRM_STATE_DEAD;
		HIP_ERROR("Adding SA failed\n");
		goto out;
	}

	return 0;
 out:
	if (xs) {
		if (xs->aalg)
			kfree(xs->aalg);
		if (xs->ealg)
			kfree(xs->ealg);
		kfree(xs);
	}

	return err;
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
int hip_setup_esp(struct in6_addr *srchit, struct in6_addr *dsthit,
		  struct in6_addr *dstip, uint32_t *spi, int alg, 
		  void *enckey, void *authkey, int dir, int is_active)
{
	int err;

	err = hip_setup_sa(srchit, dsthit, dstip, spi, alg, enckey,
			   authkey, is_active);
	if (err) {
		HIP_DEBUG("Setting up %s SA: [FAILED] (err=%d)",
			  (dir == XFRM_POLICY_OUT) ? "outgoing" : "incoming", 
			  err);
		return err;
	}

	HIP_DEBUG("Setting up %s SA: [OK] (SPI=%x)\n",
		  (dir == XFRM_POLICY_OUT) ? "outgoing" : "incoming", *spi);

	err = hip_setup_sp(srchit, dsthit, *spi, dir);
	if (err) {
		HIP_DEBUG("Setting up %s SA: [FAILED] (err=%d)",
			  (dir == XFRM_POLICY_OUT) ? "outgoing" : "incoming", 
			  err);
		/* delete SA */
		hip_delete_sa(*spi, dsthit);
		return err;
	}

	HIP_DEBUG("Setting up %s SP: [OK] (SPI=%x)\n",
		  (dir == XFRM_POLICY_OUT) ? "outgoing" : "incoming", *spi);

	return 0;
}






/**
 * Inserts the current DH-key into the buffer. If a DH-key does not exist, we will create
 * one.
 * returns >0 if ok, -1 if errorz
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

	spin_lock(&dh_table_lock);
	tmp = hip_dh_clone(dh_table[group_id]);
	spin_unlock(&dh_table_lock);

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
