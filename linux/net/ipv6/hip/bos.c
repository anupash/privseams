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

#endif /*(defined __KERNEL__ && !defined CONFIG_HIP_USERSPACE) || !defined __KERNEL__ */
