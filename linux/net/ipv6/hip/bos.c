#include "debug.h"
#include "hidb.h"

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
//	int use_rsa = 0;
//	u8 sha1_digest[HIP_AH_SHA_LEN];
	
	
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
	
#if 0
/* this has to be modified so that other signature algorithms
	   are accepted
	*/

	if (hip_get_host_id_algo(host_id) == HIP_HI_RSA)
		use_rsa = 1;
	else if (hip_get_host_id_algo(host_id) != HIP_HI_DSA) {
		HIP_ERROR("Unsupported algorithm:%d\n", hip_get_host_id_algo(host_id));
		goto out_err;
	}


	_HIP_HEXDUMP("Signature data (create)", buffer_start, buffer_length);

	if (hip_build_digest(HIP_DIGEST_SHA1, buffer_start, buffer_length,
			     sha1_digest) < 0)
	{
		HIP_ERROR("Building of SHA1 digest failed\n");
		goto out_err;
	}

	HIP_HEXDUMP("create digest", sha1_digest, HIP_AH_SHA_LEN);
	_HIP_HEXDUMP("dsa key", (u8 *)(host_id + 1), ntohs(host_id->hi_length));

	if (use_rsa) {
		err = hip_rsa_sign(sha1_digest, (u8 *)(host_id + 1), signature, 
				   3+128*2+64+64
				   /*e+n+d+p+q*/
				   /*1 + 3 + 128 * 3*/ );
	} else {
		err = hip_dsa_sign(sha1_digest,(u8 *)(host_id + 1), signature);
	}

	if (err) {
		HIP_ERROR("DSA Signing error\n");
		return 0;
	}

	
	if(use_rsa) {
	  _HIP_HEXDUMP("signature",signature,HIP_RSA_SIGNATURE_LEN);
	} else {
	  /* 1 + 20 + 20 */
	  _HIP_HEXDUMP("signature",signature,HIP_DSA_SIGNATURE_LEN);
	}

	err = 1;
#endif
out_err:
	return err;
}





/* hip_socket_send_bos - send a BOS packet
 * @msg: input message (should be empty)
 *
 * Generate a signed HIP BOS packet containing our HIT, and send
 * the packet out each network device interface. Note that there
 * is a limit of MAX_SRC_ADDRS (128) total addresses.
 *
 * Returns: zero on success, or negative error value on failure
 */

int hip_send_bos(const struct hip_common *msg)
{
	int err = 0;

	struct hip_common *bos = NULL;
	struct in6_addr hit_our;
	struct in6_addr daddr;
 	int i=0, mask;
 	struct hip_host_id  *host_id_pub = NULL;
	struct hip_host_id *host_id_private = NULL;
	u8 signature[HIP_RSA_SIGNATURE_LEN]; // assert RSA > DSA
	struct net_device *saddr_dev;
	struct inet6_dev *idev;
	struct in6_addr saddr[MAX_SRC_ADDRS];
	int if_idx[MAX_SRC_ADDRS];
	int addr_count = 0;
//	struct flowi fl;
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
	if (hip_get_any_localhost_hit(&hit_our, HIP_ANY_ALGO) < 0) {
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
	/*
	    IP ( HIP ( HOST_ID,
              HIP_SIGNATURE ) )
	 */
	mask = HIP_CONTROL_NONE;

 	hip_build_network_hdr(bos, HIP_BOS, mask, &hit_our, NULL);

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
	/* HIP_HI_DEFAULT_ALGO corresponds to HIP_HI_DSA therefore the signature will be dsa */
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
	HIP_DEBUG("sending BOS\n");
	/* Use All Nodes Addresses (link-local) RFC2373
 	   FF02:0:0:0:0:0:0:1 as the destination multicast address */
 	//ipv6_addr_all_nodes(&daddr);
	
	daddr.s6_addr32[0] = 0xFF020000;
	daddr.s6_addr32[0] = 0;
	daddr.s6_addr32[0] = 0;
	daddr.s6_addr32[0] = 0x1;
//	daddr = {{{0xff,0x02,0,0,0,0,0,0,0,0,0,0,0,0,0,0x1}}};

	/* Iterate through all the network devices, recording source
	 * addresses for BOS packets */

	/* Now, iterate through the list */

	/* Record the interface's non-link local IPv6 addresses */
	HIP_DEBUG("Before Listing n...\n");
	if (list_empty(&addresses)) {
		HIP_DEBUG("addresses is empty\n");
		return(-1);
	}
	HIP_DEBUG("Going through List...\n");
	list_for_each_entry(n, &addresses, next) {
	}
	HIP_DEBUG("Going through List...\n");
	list_for_each_entry(n, &addresses, next) {
		HIP_DEBUG("Listing n...\n");
		//for (i=0, ifa=idev->addr_list; ifa; i++, ifa = ifa->if_next) {
		if (addr_count >= MAX_SRC_ADDRS) {
			HIP_DEBUG("too many source addresses\n");
			break;
		}

		HIP_HEXDUMP("address=", SA2IP(&n->addr), SAIPLEN(&n->addr));
//		if (!filter_address((struct sockaddr*)&n->addr, 0)) {
		//if_idx[addr_count] = n->ifindex;
		memcpy(&(saddr[addr_count]), SA2IP(&n->addr), SAIPLEN(&n->addr));
		addr_count++;
//		}
	}
	HIP_DEBUG("After Listing n...\n");
	HIP_DEBUG("address list count=%d\n", addr_count);


	HIP_DEBUG("final address list count=%d\n", addr_count);

	HIP_DEBUG_IN6ADDR("dest mc address", &daddr);

	/* Loop through the saved addresses, sending the BOS packets 
	   out the correct interface */
	for (i = 0; i < addr_count; i++) {
	        /* got a source addresses, send BOS */
	        HIP_DEBUG_IN6ADDR("selected source address", &(saddr[i]));
		err = hip_csum_send(&saddr[i], &daddr, bos);
#if 0
		/* Set up the routing structure to use the correct
		   interface, source addr, and destination addr */
		fl.proto = IPPROTO_HIP;
		fl.oif = if_idx[i];
		fl.fl6_flowlabel = 0;
		fl.fl6_dst = daddr;
		fl.fl6_src = saddr[i];

		HIP_DEBUG("pre csum totlen=%u\n", hip_get_msg_total_len(bos));
		/* Send it! */
		err = hip_csum_send_fl(&(saddr[i]), &daddr, bos, &fl);
#endif
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

#endif /*(defined __KERNEL__ && !defined CONFIG_HIP_USERSPACE) || !defined __KERNEL__ */
