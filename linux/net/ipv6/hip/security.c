/*
 * security related functions
 */ 

#include "security.h"

/**
 * hip_delete_spd - delete an SPD entry
 * @hitd: destination HIT of SPD
 * @hits: source HIT of SPD
 *
 * Returns: 0 if successful, else < 0.
 */
int hip_delete_spd(struct in6_addr *hitd, struct in6_addr *hits)
{
	int err = 0;

	struct selector selector;
	struct sockaddr_in6 *sin6_d = ((struct sockaddr_in6*) &selector.dst);
	struct sockaddr_in6 *sin6_s = ((struct sockaddr_in6*) &selector.src);

	memset(&selector, 0, sizeof(selector));

	/* Delete both SPDs first */
	sin6_d->sin6_family = AF_INET6; 
	ipv6_addr_copy(&sin6_d->sin6_addr, hitd);

	sin6_s->sin6_family = AF_INET6;
	ipv6_addr_copy(&sin6_s->sin6_addr, hits);

	selector.proto = 0;
	selector.mode = IPSEC_MODE_TRANSPORT;
	selector.prefixlen_d = 128;
	selector.prefixlen_s = 128;

	err = spd_remove(&selector);
	if (err == -ESRCH) {
		HIP_ERROR("Error while deleting SPD: SPD not found\n");
		goto out_err;
	} else if (err) {
		HIP_ERROR("Error while deleting SPD: err=%d\n", err);
	} else
		HIP_DEBUG("spd_remove was successful\n");

 out_err:
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
int hip_delete_sa(u32 spi, struct in6_addr *dst, struct in6_addr *src)
{
	int err = 0;
	struct sockaddr_in6 sin6_d;
	struct sockaddr_in6 sin6_s;

	struct ipsec_sa *sa;

	/* todo: return if spi == 0 ? (first time use of sdb_entry) */

	hip_set_sockaddr(&sin6_d, dst);
	hip_set_sockaddr(&sin6_s, src);

	if (sadb_find_by_address_proto_spi((struct sockaddr*) &sin6_s, 128, 
					   (struct sockaddr*) &sin6_d, 128, 
					   SADB_SATYPE_ESP,
					   htonl(spi),
					   &sa) == -EEXIST) {
		HIP_DEBUG("Found matching SA. SPI: 0x%x\n", spi); 
		/* sadb_find_by_address_proto_spi increases sa's
		   reference counter, so decrement it before removing
		   the sa (see sadb.c) */
		ipsec_sa_put(sa);
		sadb_remove(sa);
	} else {
		HIP_ERROR("Did not find matching SA. SPI: 0x%x\n", spi);
		err = -1;
	}

	return err;
}
/**
 * hip_delete_esp - delete entry's IPsec SPD and SA
 * @entry: the entry whose SPD and SA are to be deleted
 *
 * Returns: 0 if successful, else < 0.
 */
int hip_delete_esp(struct in6_addr *own, struct in6_addr *peer)
{
	uint32_t spi_peer,spi_our;
	int tlist[2];
	int k;

	tlist[0] = HIP_HADB_PEER_SPI;
	tlist[1] = HIP_HADB_OWN_SPI;

	k = hip_hadb_multiget(peer,tlist,2,&spi_peer,&spi_our,NULL,NULL,
			  HIP_ARG_HIT);
	if (k < 2) {
		HIP_ERROR("Could not get spis from db\n");
		return -EINVAL;
	}

	/* Delete SPDs */
	hip_delete_spd(peer, own);
	hip_delete_spd(own, peer);

	/* Delete SAs */
	hip_delete_sa(spi_peer, peer, own);
	hip_delete_sa(spi_our, own, peer);

	return 0;
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
 * Returns: 0 if successful, else < 0.
 */
int hip_setup_esp(struct in6_addr *dst, struct in6_addr *src,
		  uint32_t spi, int encalg, void *enckey,
		  void *authkey)
{
	int tmp;
	int err = 0;
	struct ipsec_sp *policy = NULL;
	struct ipsec_sa *sa_entry = NULL;
	
	struct sadb_key *ext_msg = NULL;
	struct sadb_key *auth_msg = NULL;

	sa_entry = ipsec_sa_kmalloc();
	if (!sa_entry) {
		HIP_ERROR("Failed ipsec_sa_kmalloc\n");
		err = -1;
		goto out_err_nofree;
	}

	sa_entry->ipsec_proto = SADB_SATYPE_ESP;
	sa_entry->spi = htonl(spi);

	hip_set_sockaddr( (struct sockaddr_in6*) &sa_entry->dst, dst);
	hip_set_sockaddr( (struct sockaddr_in6*) &sa_entry->src, src);
	
	sa_entry->proto = 0;
	sa_entry->prefixlen_s = 128;
	sa_entry->prefixlen_d = 128;

	switch(encalg) {

	case HIP_ESP_3DES_SHA1:
		ext_msg = kmalloc(sizeof(struct sadb_key) + (ESP_3DES_KEY_BITS >> 3),
				  GFP_ATOMIC);
		if (!ext_msg)
			goto out_err_malloc_key;
		ext_msg->sadb_key_bits = ESP_3DES_KEY_BITS;
		memcpy( ((char*)ext_msg) + sizeof(struct sadb_key), enckey,
			ESP_3DES_KEY_BITS >> 3);

		tmp = sadb_key_to_esp(SADB_EALG_3DESCBC, ext_msg, sa_entry);
		if (tmp) {
			HIP_ERROR("Failed key_to_esp: %d\n", tmp);
			err = -1;
			goto out_err_key_to_esp;
		}
		break;

	case HIP_ESP_NULL_SHA1:
	case HIP_ESP_NULL_NULL:
		if (sadb_key_to_esp(SADB_EALG_NULL, NULL, sa_entry) != 0) {
			HIP_ERROR("Failed key_to_esp\n");
			err = -1;
			goto out_err_key_to_esp;
		}
		break;

	default:
		HIP_ASSERT(0);
		HIP_ERROR("Attempted to use unsupported encryption algorithm (algo=%d)\n",
			  encalg);
		err = -1;
		goto out_err_key_to_esp;
		break;
	}

	HIP_DEBUG("Entering auth setup\n");

	switch(encalg) {

	case HIP_ESP_3DES_SHA1:
	case HIP_ESP_NULL_SHA1:
		auth_msg = kmalloc(sizeof(struct sadb_key) + (AUTH_SHA1HMAC_KEY_BITS >> 3),
				   GFP_ATOMIC);
		if (!auth_msg)
			goto out_err_key_to_esp; 
		auth_msg->sadb_key_bits = AUTH_SHA1HMAC_KEY_BITS;
		memcpy( ((char*)auth_msg) + sizeof(struct sadb_key), authkey,
			AUTH_SHA1HMAC_KEY_BITS >> 3);

		tmp = sadb_key_to_auth(SADB_AALG_SHA1HMAC, auth_msg, sa_entry);
		if (tmp) {
			HIP_ERROR("Failed key_to_auth: %d\n", tmp);
			err = -1;
			goto out_err_malloc_auth;
		}
		break;

	case HIP_ESP_NULL_NULL:
		/* jlu XXX: Does NULL authentication work, if we just
		 * skip the setup ? */
		HIP_DEBUG("Took the NULL path\n");
		break;

	default:
		HIP_ERROR("Attempted to use unsupported authentication algorithm (algo=%d)\n", encalg);
		err = -1;
		goto out_err_malloc_auth;
		break;

	}

	sa_entry->state = SADB_SASTATE_MATURE;
	err = sadb_append(sa_entry);	
	if (err != 0) {
		/* SA already exists ? */
		HIP_ERROR("sadb_append failed, error=%d\n", err);
		/* no error setting again here ? */
		err = -EEXIST;
//		err = -1;
		goto out_err_append;
	}

	/* SPD */
	/* We should check if the entry already exists... */
	policy = ipsec_sp_kmalloc();
	if (!policy) {
		HIP_ERROR("Failed ipsec_sp_kmalloc\n");
		err = -1;
		goto out_err_sp_kmalloc;
	}

	policy->selector.mode = IPSEC_MODE_TRANSPORT;
	policy->selector.proto = 0;
	hip_set_sockaddr( (struct sockaddr_in6*) &policy->selector.dst, dst);
	hip_set_sockaddr( (struct sockaddr_in6*) &policy->selector.src, src);
	policy->selector.prefixlen_s = 128;
	policy->selector.prefixlen_d = 128;
	policy->policy_action = IPSEC_POLICY_APPLY;

	policy->esp_sa_idx = sa_index_kmalloc();
	if (!policy->esp_sa_idx) {
		err = -1;
		HIP_ERROR("Failed to sa_index_kmalloc\n");
		goto out_err_sa_index;
	}
	hip_set_sockaddr((struct sockaddr_in6*) &policy->esp_sa_idx->dst, dst);
	policy->esp_sa_idx->prefixlen_d = 128;
	policy->esp_sa_idx->ipsec_proto = SADB_SATYPE_ESP;
	policy->esp_sa_idx->spi = htonl(spi);

	err = spd_append(policy);
	if (err != 0) {
		HIP_ERROR("spd_append failed\n");
		err = -1;
		goto out_err_spd_append;
	}

	ipsec_sp_put(policy);

	if (ext_msg)
		kfree(ext_msg);

	return err;

 out_err_spd_append:
	sa_index_kfree(policy->esp_sa_idx);
 out_err_sa_index:
 out_err_sp_kmalloc:
	sadb_remove(sa_entry);
 out_err_append:
 out_err_malloc_auth:
	if (auth_msg)
		kfree(auth_msg);
 out_err_key_to_esp:
	if (ext_msg)
		kfree(ext_msg);
 out_err_malloc_key:
	ipsec_sa_kfree(sa_entry);
 out_err_nofree:
	return err;

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


