#include "debug.h"
#include "hidb.h"
#include "hadb.h"

#include "bos.h"



#if (defined __KERNEL__ && !defined CONFIG_HIP_USERSPACE) || !defined __KERNEL__

#include "netdev.h"
#include "list.h"

extern int address_count;
extern struct list_head addresses;

/**
 * hip_create_signature - Calculate SHA1 hash over the data and sign it.
 * @buffer_start: Pointer to start of the buffer over which the hash is
 *                calculated.
 * @buffer_length: Length of the buffer.
 * @host_id: DSA private key.
 * @signature: Place for signature.
 *
 * Signature size for DSA is 41 bytes.
 *
 * Returns 1 if success, otherwise 0.
 */
int hip_create_bos_signature(struct hip_host_id *priv, int algo, struct hip_common *bos)
{
	int err = 0;
	
	if (algo == HIP_HI_DSA) {
		HIP_DEBUG("Creating DSA signature\n");
		err = hip_dsa_sign(priv, bos);
	} else if (algo == HIP_HI_RSA) {
		HIP_DEBUG("Creating RSA signature\n");
		err = hip_rsa_sign(priv, bos);
	} else {
		HIP_ERROR("Unsupported algorithm:%d\n", algo);
		err = -1;
	}

	return err;
}


/** hip_socket_send_bos - send a BOS packet
 * @msg: input message (should be empty)
 *
 * Generate a signed HIP BOS packet containing our HIT, and send
 * the packet out each network device interface.
 *
 * Returns: zero on success, or negative error value on failure
 */
int hip_send_bos(const struct hip_common *msg)
{
	int err = 0, i = 0;
	struct hip_common *bos = NULL;
	struct in6_addr hit_our;
	struct in6_addr daddr;
 	struct hip_host_id  *host_id_pub = NULL;
	struct hip_host_id *host_id_private = NULL;
	u8 signature[HIP_RSA_SIGNATURE_LEN]; // assert RSA > DSA
	struct net_device *saddr_dev;
	struct inet6_dev *idev;
	int addr_count = 0;
	struct inet6_ifaddr *ifa = NULL;
	struct hip_xfrm_t *x;
	struct netdev_address *n;
	
	HIP_DEBUG("\n");
	
	/* Extra consistency test */
	if (hip_get_msg_type(msg) != SO_HIP_BOS) {
		err = -EINVAL;
		HIP_ERROR("Bad message type\n");
		goto out_err;
	}
	
	/* allocate space for new BOS */
	bos = hip_msg_alloc();
	if (!bos) {
		HIP_ERROR("Allocation of BOS failed\n");
		err = -ENOMEM;
		goto out_err;
	}

#if 0
	x = hip_xfrm_try_to_find_by_peer_hit(NULL);
	if (!x) {
		HIP_ERROR("Could not find dst HIT\n");
		err = -ENOENT;
		goto out_err;
	}
	memcpy(&hit_our, x->hit_our, sizeof(hip_hit_t));
#endif

	/* Determine our HIT */
	if (hip_get_any_localhost_hit(&hit_our, HIP_HI_DEFAULT_ALGO) < 0) {
		HIP_ERROR("Our HIT not found\n");
		err = -EINVAL;
		goto out_err;
	}

	/* Determine our HOST ID public key */
	host_id_pub = hip_get_any_localhost_public_key(HIP_HI_DEFAULT_ALGO);
	if (!host_id_pub) {
		HIP_ERROR("Could not acquire localhost public key\n");
		goto out_err;
	}

	/* Determine our HOST ID private key */
	host_id_private = hip_get_host_id(HIP_DB_LOCAL_HID, NULL, HIP_HI_DEFAULT_ALGO);
	if (!host_id_private) {
		err = -EINVAL;
		HIP_ERROR("No localhost private key found\n");
		goto out_err;
	}

 	/* Ready to begin building the BOS packet */
 	hip_build_network_hdr(bos, HIP_BOS, HIP_CONTROL_NONE, &hit_our, NULL);

	/********** HOST_ID *********/
	_HIP_DEBUG("This HOST ID belongs to: %s\n",
		   hip_get_param_host_id_hostname(host_id_pub));
	err = hip_build_param(bos, host_id_pub);
 	if (err) {
 		HIP_ERROR("Building of host id failed\n");
 		goto out_err;
 	}

 	/********** SIGNATURE **********/
	HIP_ASSERT(host_id_private);
	/* HIP_HI_DEFAULT_ALGO corresponds to HIP_HI_DSA therefore the
	   signature will be dsa */
	/* Build a digest of the packet built so far. Signature will
	   be calculated over the digest. */

	if (hip_create_bos_signature(host_id_private, HIP_HI_DEFAULT_ALGO, bos)) {
		HIP_ERROR("Could not create signature\n");
		err = -EINVAL;
		goto out_err;
	}
#if 0
	/* Only DSA supported currently */
	_HIP_ASSERT(hip_get_host_id_algo(host_id_private) == HIP_HI_DSA);

	err = hip_build_param_signature_contents(bos,
						 signature,
						 ((HIP_SIG_DEFAULT_ALGO == HIP_HI_RSA) ?
						  HIP_RSA_SIGNATURE_LEN  : HIP_DSA_SIGNATURE_LEN),
						 HIP_SIG_DEFAULT_ALGO);
	if (err) {
		HIP_ERROR("Building of signature failed (%d)\n", err);
		goto out_err;
	}
#endif
 	/************** BOS packet ready ***************/
	/* Use All Nodes Addresses (link-local) from RFC2373 */
	daddr.s6_addr32[0] = htonl(0xFF020000);
	daddr.s6_addr32[1] = 0;
	daddr.s6_addr32[2] = 0;
	daddr.s6_addr32[3] = htonl(0x1);
	HIP_HEXDUMP("dst addr:", &daddr, 16);

	list_for_each_entry(n, &addresses, next) {
		HIP_HEXDUMP("BOS src address:", SA2IP(&n->addr), SAIPLEN(&n->addr));
		err = hip_csum_send(SA2IP(&n->addr), &daddr, bos);
		if (err)
		        HIP_ERROR("sending of BOS failed, err=%d\n", err);
	}
	err = 0;

out_err:
	if (host_id_private)
		HIP_FREE(host_id_private);
	if (host_id_pub)
		HIP_FREE(host_id_pub);
	if (bos)
		HIP_FREE(bos);
	return err;
}


/** hip_verify_packet_signature - verify the signature in the bos packet
 * @bos: the bos packet
 * @peer_host_id: peer host id
 *
 * Depending on the algorithm it checks whether the signature is correct
 *
 * Returns: zero on success, or negative error value on failure
 */
int hip_verify_packet_signature(struct hip_common *bos, 
				struct hip_host_id *peer_host_id)
{
	int err;
	if (peer_host_id->rdata.algorithm == HIP_HI_DSA){
		err = hip_dsa_verify(peer_host_id, bos);
	} else if(peer_host_id->rdata.algorithm == HIP_HI_DSA){
		err = hip_rsa_verify(peer_host_id, bos);
	} else {
		HIP_ERROR("Unknown algorithm\n");
		err = -1;
	}
	return err;
}

/**
 * hip_handle_bos - handle incoming BOS packet
 * @skb: sk_buff where the HIP packet is in
 * @entry: HA
 *
 * This function is the actual point from where the processing of BOS
 * is started.
 *
 * On success (BOS payloads are checked) 0 is returned, otherwise < 0.
 */

int hip_handle_bos(struct hip_common *bos,
		   struct in6_addr *bos_saddr,
		   struct in6_addr *bos_daddr,
		   hip_ha_t *entry)
{
	int err = 0, len;
	struct hip_host_id *peer_host_id;
	struct hip_lhi peer_lhi;
	struct in6_addr peer_hit;
	char *str;
	struct in6_addr *dstip;
	char src[INET6_ADDRSTRLEN];

	HIP_DEBUG("\n");

	/* according to the section 8.6 of the base draft,
	 * we must first check signature
	 */
	HIP_IFEL(!(peer_host_id = hip_get_param(bos, HIP_PARAM_HOST_ID)), -ENOENT,
		 "No HOST_ID found in BOS\n");

	HIP_IFEL(hip_verify_packet_signature(bos, peer_host_id), -EINVAL,
		 "Verification of BOS signature failed\n");


	/* Validate HIT against received host id */	
	hip_host_id_to_hit(peer_host_id, &peer_hit, HIP_HIT_TYPE_HASH126);
	HIP_IFEL(ipv6_addr_cmp(&peer_hit, &bos->hits) != 0, -EINVAL,
		 "Sender HIT does not match the advertised host_id\n");
	
	HIP_HEXDUMP("Advertised HIT:", &bos->hits, 16);
	
	/* Everything ok, first save host id to db */
	HIP_IFE(hip_get_param_host_id_di_type_len(peer_host_id, &str, &len) < 0, -1);
	HIP_DEBUG("Identity type: %s, Length: %d, Name: %s\n",
		  str, len, hip_get_param_host_id_hostname(peer_host_id));

#if 0
 	peer_lhi.anonymous = 0;
	ipv6_addr_copy(&peer_lhi.hit, &bos->hits);
 	err = hip_add_host_id(HIP_DB_PEER_HID, &peer_lhi, peer_host_id,
			      NULL, NULL, NULL);
 	if (err == -EEXIST) {
 		HIP_INFO("Host ID already exists. Ignoring.\n");
 		err = 0;
 	} else {
		HIP_IFEL(err, -1, "Failed to add peer host id to the database\n");
  	}
#endif

	/* Now save the peer IP address */
	dstip = bos_saddr;
	hip_in6_ntop(dstip, src);
	HIP_DEBUG("BOS sender IP: saddr %s\n", src);

	if (entry) {
		struct in6_addr daddr;

		HIP_DEBUG("I guess we should not even get here ...\n");
		HIP_DEBUG("I think so!\n");

		/* The entry may contain the wrong address mapping... */
		HIP_DEBUG("Updating existing entry\n");
		hip_hadb_get_peer_addr(entry, &daddr);
		if (ipv6_addr_cmp(&daddr, dstip) != 0) {
			HIP_DEBUG("Mapped address doesn't match received address\n");
			HIP_DEBUG("Assuming that the mapped address was actually RVS's.\n");
			HIP_HEXDUMP("Mapping", &daddr, 16);
			HIP_HEXDUMP("Received", dstip, 16);
			hip_hadb_delete_peer_addrlist_one(entry, &daddr);
			HIP_ERROR("assuming we are doing base exchange\n");
			hip_hadb_add_peer_addr(entry, dstip, 0, 0, 0);
		}
	} else {
		// FIXME: just add it here and not via workorder.

		/* we have no previous infomation on the peer, create
		 * a new HIP HA */		
		HIP_IFEL((hip_hadb_add_peer_info(&bos->hits, dstip)<0), KHIPD_ERROR,
			 "Failed to insert new peer info");
		HIP_DEBUG("HA entry created.");

#if 0
		struct hip_work_order * hwo;
		HIP_DEBUG("Adding new peer entry\n");
                hip_in6_ntop(&bos->hits, src);
		HIP_DEBUG("map HIT: %s\n", src);
		hip_in6_ntop(dstip, src);
		HIP_DEBUG("map IP: %s\n", src);

		HIP_IFEL(!(hwo = hip_init_job(GFP_ATOMIC)), -1, 
			 "Failed to insert peer map work order\n");
		HIP_INIT_WORK_ORDER_HDR(hwo->hdr, HIP_WO_TYPE_MSG,
					HIP_WO_SUBTYPE_ADDMAP,
					dstip, &bos->hits, NULL, 0, 0, 0);
		hip_insert_work_order(hwo);
#endif
	}

 out_err:
	return err;
}

#endif /*(defined __KERNEL__ && !defined CONFIG_HIP_USERSPACE) || !defined __KERNEL__ */

//extern int hip_hadb_list_peers_func(hip_ha_t *entry, void *opaque);

/* really ugly hack ripped from rea.c, must convert to list_head asap */
struct hip_bos_kludge {
	hip_ha_t **array;
	int count;
	int length;
};

int hip_bos_get_all_valid(hip_ha_t *entry, void *op)
{
#if 0
	struct hip_bos_kludge *rk = op;
	if (rk->count >= rk->length)
		return -1;

	if (entry->state == HIP_STATE_UNASSOCIATED || entry->state == HIP_STATE_NONE) {
		rk->array[rk->count] = entry;
		hip_hold_ha(entry);
		rk->count++;
	} else
		HIP_DEBUG("skipping HA entry 0x%p (state=%s)\n",
			  entry, hip_state_str(entry->state));
#endif
	HIP_DEBUG("Entered hip_bos_get_all_valid.... \n");
	return 0;
}

/**
 * hip_socket_handle_get_peer_list - handle creation of list of known peers
 * @msg: message containing information about which unit tests to execute
 *
 * Process a request for the list of known peers
 *
 * Returns: zero on success, or negative error value on failure
 */
int handle_bos_peer_list(int family, struct my_addrinfo **pai, int msg_len)
{
	int err = 0;
	hip_peer_opaque_t pr;
	int fail;
	int i, j;
//	struct hip_host_id *peer_host_id = NULL;
	struct hip_lhi lhi;
	char buf[46];
        hip_peer_entry_opaque_t *entry, *next;
	hip_peer_addr_opaque_t *addr, *anext;
	int socklen = sizeof (struct sockaddr_in6);
	struct my_addrinfo **end = (struct my_addrinfo **)pai;
	/* Number of elements allocated in the list */
	int num_elems = (int)(msg_len / sizeof(struct my_addrinfo));
	hip_ha_t *entries[HIP_MAX_HAS] = {0};
	struct hip_bos_kludge rk;
	
	HIP_DEBUG("\n");

	/* Initialize the data structure for the peer list */
	//	memset(&rk, 0, sizeof(struct hip_bos_kludge));

	HIP_DEBUG("Got into the handle_bos_peer_list\n");

	rk.array = entries;
	rk.count = 0;
	rk.length = HIP_MAX_HAS;
#if 0
	/* Iterate through the hadb db entries, collecting addresses */
	//	fail = hip_for_each_ha(hip_hadb_list_peers_func, &rk);
	fail = hip_for_each_ha(hip_bos_get_all_valid, &rk);
	if (fail) {
		err = -EINVAL;
		HIP_ERROR("Peer list creation failed\n");
		goto out_err;
	}
#endif
	//	HIP_DEBUG("pr.count=%d headp=0x%p end=0x%p\n", pr.count, pr.head, pr.end);
#if 0
	if (pr.count <= 0) {
		HIP_ERROR("No usable entries found\n");
		err = -EINVAL;
		goto out_err;
	}

	/* Complete the list by iterating through the list and
	   recording the peer host id. This is done separately from
	   list creation because it involves calling a function that
	   may sleep (can't be done while holding locks!) */
	memset(&lhi, 0, sizeof(struct hip_lhi)); /* Zero flags, etc. */
	for (i = 0, entry = pr.head; i < pr.count; i++, entry = entry->next) {

//		*end = malloc (sizeof (struct addrinfo) + socklen);
		if (i >= num_elems) {
			err = -EINVAL;
			HIP_ERROR("The allocated memory is not enough\n");
			goto out_err;
		}
		(*end)->ai_family = family;
		(*end)->ai_addr = (void *) (*end) + sizeof(struct my_addrinfo);
		
		if (family == AF_INET6) {
			struct sockaddr_in6 *sin6p =
				(struct sockaddr_in6 *) (*end)->ai_addr;
		
			sin6p->sin6_flowinfo = 0;
			/* Get the HIT */
			memcpy (&sin6p->sin6_addr, &(entry->hit), sizeof (struct in6_addr));
		} else {
			/* TODO: is there any possibility to get here having family == AF_INET ? */
		}

		(*end)->ai_next = NULL;
		end = &((*end)->ai_next);
	}
#endif
 out_err:
#if 0
	/* Recurse through structure, freeing memory */
	entry = .head;
	_HIP_DEBUG("free mem, pr.head=0x%p\n", pr.head);
	while (entry) {
		_HIP_DEBUG("entry=0x%p\n", entry);
		next = entry->next;
		_HIP_DEBUG("next=0x%p\n", next);
		_HIP_DEBUG("entry->host_id=0x%p\n", entry->host_id);
		if (entry->host_id)
			HIP_FREE(entry->host_id);
		addr = entry->addr_list;
		_HIP_DEBUG("addrlist=0x%p\n", addr);
		while (addr) {
			_HIP_DEBUG("addr=0x%p\n", addr);
			anext = addr->next;
			HIP_FREE(addr);
			addr = anext;
		}
		HIP_FREE(entry);
		entry = next;
	}
	_HIP_DEBUG("done freeing mem, err = %d\n", err);
#endif
	return err;
}


