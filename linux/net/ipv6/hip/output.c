/*
 * HIP output
 *
 * Licence: GNU/GPL
 * Authors: Janne Lundberg <jlu@tcs.hut.fi>
 *          Miika Komu <miika@iki.fi>
 *          Mika Kousa <mkousa@cc.hut.fi>
 *          Kristian Slavov <kslavov@hiit.fi>
 *
 */

#include "output.h"

/**
 * hip_csum_verify - verify HIP header checksum
 * @skb: the socket buffer which contains the HIP header
 *
 * Returns: the checksum of the HIP header.
 */
int hip_csum_verify(struct sk_buff *skb)
{
	struct hip_common *hip_common;
	int len;
	int csum;

	hip_common = (struct hip_common*) skb->h.raw;
        len = hip_get_msg_total_len(hip_common);

	_HIP_HEXDUMP("hip_csum_verify data", skb->h.raw, len);
	_HIP_DEBUG("len=%d\n", len);
	_HIP_HEXDUMP("saddr", &(skb->nh.ipv6h->saddr),
		     sizeof(struct in6_addr));
	_HIP_HEXDUMP("daddr", &(skb->nh.ipv6h->daddr),
		     sizeof(struct in6_addr));

        csum = csum_partial((char *) hip_common, len, 0);

	return csum_ipv6_magic(&(skb->nh.ipv6h->saddr),
			       &(skb->nh.ipv6h->daddr),
			       len, IPPROTO_HIP, csum);
}



/**
 * hip_send_i1 - send an I1 packet to the responder
 * @entry: the HIP database entry reserved for the peer
 *
 * Send an I1 packet to the responder if an IPv6 address for the peer
 * is known.
 *
 * Returns: 0 on success, otherwise < 0 on error.
 */
int hip_send_i1(struct in6_addr *dsthit, hip_ha_t *entry)
{
	struct hip_common i1;
	struct in6_addr daddr;
	struct in6_addr hit_our;
	int mask;
	int err = 0;

	HIP_DEBUG("\n");

	/* TODO: we must use the same algorithm that is used in the dsthit */
	if (hip_copy_any_localhost_hit_by_algo(&hit_our, HIP_HI_DEFAULT_ALGO) < 0) {
		HIP_ERROR("Out HIT not found\n");
		err = -EINVAL;
		goto out_err;
	}
	HIP_DEBUG_HIT("DEFAULT ALGO HIT: ", &hit_our);
#if 0
	if (hip_copy_any_localhost_hit(&hit_our) < 0) {
		HIP_ERROR("Out HIT not found\n");
		err = -EINVAL;
		goto out_err;
	}
	HIP_DEBUG_HIT("ANY HIT: ", &hit_our);
#endif
	mask = HIP_CONTROL_NONE;
#ifdef CONFIG_HIP_RVS
	if ((entry->local_controls & HIP_PSEUDO_CONTROL_REQ_RVS))
		mask |= HIP_CONTROL_RVS_CAPABLE;
#endif

	//HIP_DEBUG("mask pre=0x%x\n", mask);
	//mask |= (HIP_CONTROL_SHT_TYPE1 << HIP_CONTROL_SHT_SHIFT);
	//HIP_DEBUG("mask post=0x%x\n", mask);

	mask = hip_create_control_flags(0, 0, HIP_CONTROL_SHT_TYPE1,
					HIP_CONTROL_DHT_TYPE1);
	hip_build_network_hdr((struct hip_common* ) &i1, HIP_I1,
			      mask, &hit_our,
			      dsthit);
	/* Eight octet units, not including first */
	i1.payload_len = (sizeof(struct hip_common) >> 3) - 1;

	HIP_HEXDUMP("HIT SOURCE in send_i1", &i1.hits,
		    sizeof(struct in6_addr));
	HIP_HEXDUMP("HIT DEST in send_i1", &i1.hitr,
		    sizeof(struct in6_addr));

	err = hip_hadb_get_peer_addr(entry, &daddr);
	if (err) {
		HIP_ERROR("hip_sdb_get_peer_address returned error = %d\n",
			  err);
		goto out_err;
	}

	_HIP_DEBUG("hip: send I1 packet\n");	
	err = hip_csum_send(NULL, &daddr, (struct hip_common*) &i1);

 out_err:
	return err;
}

/**
 * hip_create_r1 - construct a new R1-payload
 * @src_hit: source HIT used in the packet
 *
 * Returns 0 on success, or negative on error
 */
struct hip_common *hip_create_r1(const struct in6_addr *src_hit)
{
 	struct hip_common *msg;
 	int err = 0;
	int use_rsa = 0;
 	u8 *dh_data = NULL;
 	int dh_size,written, mask;
 	/* Supported HIP and ESP transforms. */
 	hip_transform_suite_t transform_hip_suite[] = {
		HIP_HIP_AES_SHA1,
		HIP_HIP_3DES_SHA1,
		HIP_HIP_NULL_SHA1

	};

 	hip_transform_suite_t transform_esp_suite[] = {
		HIP_ESP_AES_SHA1,
		HIP_ESP_NULL_SHA1,
		HIP_ESP_3DES_SHA1

	};
 	struct hip_host_id  *host_id_private = NULL;
 	struct hip_host_id  *host_id_pub = NULL;
 	u8 *signature = NULL;

 	msg = hip_msg_alloc();
 	if (!msg) {
		err = -ENOMEM;
		HIP_ERROR("msg alloc failed\n");
		goto out_err;
	}

 	/* allocate memory for writing Diffie-Hellman shared secret */
 	dh_size = hip_get_dh_size(HIP_DEFAULT_DH_GROUP_ID);
 	if (dh_size == 0) {
 		HIP_ERROR("Could not get dh size\n");
 		goto out_err;
 	}

 	dh_data = HIP_MALLOC(dh_size, GFP_ATOMIC);
 	if (!dh_data) {
 		HIP_ERROR("Failed to alloc memory for dh_data\n");
  		goto out_err;
  	}
	memset(dh_data, 0, dh_size);

	_HIP_DEBUG("dh_size=%d\n", dh_size);
 	/* Get a localhost identity, allocate memory for the public key part
 	   and extract the public key from the private key. The public key is
 	   needed for writing the host id parameter in R1. */

	host_id_private = hip_get_any_localhost_host_id(HIP_HI_DEFAULT_ALGO);
 	if (!host_id_private) {
 		HIP_ERROR("Could not acquire localhost host id\n");
 		goto out_err;
 	}

	HIP_DEBUG("private hi len: %d\n",
		  hip_get_param_total_len(host_id_private));

	HIP_HEXDUMP("Our pri host id\n", host_id_private,
		    hip_get_param_total_len(host_id_private));

	host_id_pub = hip_get_any_localhost_public_key(HIP_HI_DEFAULT_ALGO);
	if (!host_id_pub) {
		HIP_ERROR("Could not acquire localhost public key\n");
		goto out_err;
	}

	HIP_HEXDUMP("Our pub host id\n", host_id_pub,
		    hip_get_param_total_len(host_id_pub));
	
	/* check for the used algorithm */
	if (hip_get_host_id_algo(host_id_pub) == HIP_HI_RSA) {
			use_rsa = 1;
	} else if (hip_get_host_id_algo(host_id_pub) != HIP_HI_DSA) {
			HIP_ERROR("Unsupported algorithm:%d\n", 
					  hip_get_host_id_algo(host_id_pub));
			goto out_err;
	}

	signature = HIP_MALLOC(MAX(HIP_DSA_SIGNATURE_LEN,
				HIP_RSA_SIGNATURE_LEN), 
			    GFP_KERNEL);
	if(!signature) {
		HIP_ERROR("Could not allocate signature \n");
		goto out_err;
	}
	
 	/* Ready to begin building of the R1 packet */
	//mask = HIP_CONTROL_NONE;
	//mask = HIP_CONTROL_SHT_MASK | HIP_CONTROL_DHT_MASK;
	mask = HIP_CONTROL_SHT_TYPE1 << HIP_CONTROL_SHT_SHIFT;
	HIP_DEBUG("mask 1=0x%x\n", mask);
	mask |= HIP_CONTROL_DHT_TYPE1 << HIP_CONTROL_DHT_SHIFT;
	HIP_DEBUG("mask 2=0x%x\n", mask);
#ifdef CONFIG_HIP_RVS
	mask |= HIP_CONTROL_RVS_CAPABLE; //XX: FIXME
#endif
	HIP_DEBUG("mask 3=0x%x\n", mask);
 	hip_build_network_hdr(msg, HIP_R1, mask, src_hit, NULL);

	/********** R1_COUNTER (OPTIONAL) *********/

 	/********** PUZZLE ************/
	{
		err = hip_build_param_puzzle(msg, HIP_DEFAULT_COOKIE_K,
					     42 /* 2^(42-32) sec lifetime */, 0, 0);
		if (err) {
			HIP_ERROR("Cookies were burned. Bummer!\n");
			goto out_err;
		}
	}

 	/********** Diffie-Hellman **********/
	written = hip_insert_dh(dh_data,dh_size,HIP_DEFAULT_DH_GROUP_ID);
	if (written < 0) {
 		HIP_ERROR("Could not extract DH public key\n");
 		goto out_err;
 	} 

 	err = hip_build_param_diffie_hellman_contents(msg,
						      HIP_DEFAULT_DH_GROUP_ID,
						      dh_data, written);
 	if (err) {
 		HIP_ERROR("Building of DH failed (%d)\n", err);
 		goto out_err;
 	}

 	/********** HIP transform. **********/
 	err = hip_build_param_transform(msg,
 					HIP_PARAM_HIP_TRANSFORM,
 					transform_hip_suite,
 					sizeof(transform_hip_suite) /
 					sizeof(hip_transform_suite_t));
 	if (err) {
 		HIP_ERROR("Building of HIP transform failed\n");
 		goto out_err;
 	}

 	/********** ESP-ENC transform. **********/
 	err = hip_build_param_transform(msg,
 					HIP_PARAM_ESP_TRANSFORM,
 					transform_esp_suite,
 					sizeof(transform_esp_suite) /
 					sizeof(hip_transform_suite_t));
 	if (err) {
 		HIP_ERROR("Building of ESP transform failed\n");
 		goto out_err;
 	}

 	/********** Host_id **********/

	_HIP_DEBUG("This HOST ID belongs to: %s\n", 
		   hip_get_param_host_id_hostname(host_id_pub));
	err = hip_build_param(msg, host_id_pub);
 	if (err) {
 		HIP_ERROR("Building of host id failed\n");
 		goto out_err;
 	}

	/********** ECHO_REQUEST_SIGN (OPTIONAL) *********/

 	/********** Signature 2 **********/
 	if (!hip_create_signature(msg,
 				  hip_get_msg_total_len(msg),
 				  host_id_private,
 				  signature)) {
 		HIP_ERROR("Signing of R1 failed.\n");
 		goto out_err;
 	}		

	_HIP_HEXDUMP("R1", msg, hip_get_msg_total_len(msg));

	if (use_rsa) {
	  err = hip_build_param_signature2_contents(msg,	     
						    signature,
						    HIP_RSA_SIGNATURE_LEN,
						    HIP_SIG_RSA);
	} else {
	  err = hip_build_param_signature2_contents(msg,
						    signature,
						    HIP_DSA_SIGNATURE_LEN,
						    HIP_SIG_DSA);
	}
	
 	if (err) {
 		HIP_ERROR("Building of signature failed (%d) on R1\n", err);
 		goto out_err;
 	}

	/********** ECHO_REQUEST (OPTIONAL) *********/

	/* Fill puzzle parameters */
	{
		struct hip_puzzle *pz;
		uint64_t random_i;

		pz = hip_get_param(msg, HIP_PARAM_PUZZLE);
		if (!pz) {
			HIP_ERROR("Internal error\n");
			goto out_err;
		}

		// FIX ME: this does not always work:
		//get_random_bytes(pz->opaque, HIP_PUZZLE_OPAQUE_LEN);

		/* hardcode kludge */
		pz->opaque[0] = 'H';
		pz->opaque[1] = 'I';
		//pz->opaque[2] = 'P';
		/* todo: remove random_i variable */
		get_random_bytes(&random_i,sizeof(random_i));
		pz->I = random_i;
	}

 	/************** Packet ready ***************/

 	if (host_id_pub)
 		HIP_FREE(host_id_pub);
 	if (dh_data)
 		HIP_FREE(dh_data);

	HIP_HEXDUMP("r1", msg, hip_get_msg_total_len(msg));

	return msg;

  out_err:
	if (signature) 
		HIP_FREE(signature);
	if (host_id_pub)
		HIP_FREE(host_id_pub);
 	if (host_id_private)
 		HIP_FREE(host_id_private);
 	if (msg)
 		HIP_FREE(msg);
 	if (dh_data)
 		HIP_FREE(dh_data);

  	return NULL;
}

/**
 * hip_xmit_r1 - transmit an R1 packet to the network
 * @dst_addr: the destination IPv6 address where the R1 should be sent
 * @dst_hit:  the destination HIT of peer
 *
 * Sends an R1 to the peer and stores the cookie information that was sent.
 *
 * Returns: zero on success, or negative error value on error.
 */
int hip_xmit_r1(struct sk_buff *skb, struct in6_addr *dst_ip,
		struct in6_addr *dst_hit)
{
	struct hip_common *r1pkt;
	struct in6_addr *own_addr;
	struct in6_addr *dst_addr;
	int err = 0;

	HIP_DEBUG("\n");

	own_addr = &skb->nh.ipv6h->daddr;
	if (!dst_ip || ipv6_addr_any(dst_ip)) {
		dst_addr = &skb->nh.ipv6h->saddr;
	} else {
		dst_addr = dst_ip;
	}

	/* dst_addr is the IP address of the Initiator... */
	r1pkt = hip_get_r1(dst_addr, own_addr);
	if (!r1pkt) {
		HIP_ERROR("No precreated R1\n");
		err = -ENOENT;
		goto out_err;
	}

	if (dst_hit) 
		ipv6_addr_copy(&r1pkt->hitr, dst_hit);
	else
		memset(&r1pkt->hitr, 0, sizeof(struct in6_addr));

	/* set cookie state to used (more or less temporary solution ?) */
	_HIP_HEXDUMP("R1 pkt", r1pkt, hip_get_msg_total_len(r1pkt));

	err = hip_csum_send(NULL, dst_addr, r1pkt);	
	if (err) {
		HIP_ERROR("hip_csum_send failed, err=%d\n", err);
		goto out_err;
	}

	HIP_ASSERT(!err);
	return 0;

 out_err:
	HIP_ERROR("hip_xmit_r1 failed, err=%d\n", err);
	return err;
}

/**
 * hip_send_r1 - send an R1 to the peer
 * @skb: the socket buffer for the received I1
 *
 * Send an I1 to the peer. The addresses and HITs will be digged
 * out from the @skb.
 *
 * Returns: zero on success, or a negative error value on failure.
 */
int hip_send_r1(struct sk_buff *skb) 
{
	int err = 0;
	struct in6_addr *dst;
	dst = &(((struct hip_common *)skb->h.raw)->hits);

	err = hip_xmit_r1(skb, NULL, dst);

	return err;
}


void hip_send_notify(hip_ha_t *entry)
{
	int err = 0; /* actually not needed, because we can't do
		      * anything if packet sending fails */
	struct hip_common *notify_packet;
	struct in6_addr daddr;

	HIP_DEBUG("\n");

	notify_packet = hip_msg_alloc();
	if (!notify_packet) {
		HIP_DEBUG("notify_packet alloc failed\n");
		err = -ENOMEM;
		goto out_err;
	}
	hip_build_network_hdr(notify_packet, HIP_NOTIFY, 0,
			      &entry->hit_our, &entry->hit_peer);

	err = hip_build_param_notify(notify_packet, 1234, "ABCDEFGHIJ", 10);
	if (err) {
		HIP_ERROR("building of NOTIFY failed (err=%d)\n", err);
		goto out_err;
	}

        err = hip_hadb_get_peer_addr(entry, &daddr);
        if (err) {
                HIP_DEBUG("hip_sdb_get_peer_address err = %d\n", err);
                goto out_err;
        }
        HIP_DEBUG("Sending NOTIFY packet\n");
	err = hip_csum_send(NULL, &daddr, notify_packet);

 out_err:
	if (notify_packet)
		HIP_FREE(notify_packet);
	return;
}

struct hip_rea_kludge {
	hip_ha_t **array;
	int count;
	int length;
};

static int hip_get_all_valid(hip_ha_t *entry, void *op)
{
	struct hip_rea_kludge *rk = op;

	if (rk->count >= rk->length)
		return -1;

	/* should we check the established status also? */
	if ((entry->hastate & HIP_HASTATE_VALID) == HIP_HASTATE_VALID) {
		rk->array[rk->count] = entry;
		hip_hold_ha(entry);
		rk->count++;
	}

	return 0;
}

void hip_send_notify_all(void)
{
        int err = 0, i;
        hip_ha_t *entries[HIP_MAX_HAS] = {0};
        struct hip_rea_kludge rk;

        HIP_DEBUG("\n");

        rk.array = entries;
        rk.count = 0;
        rk.length = HIP_MAX_HAS;

        err = hip_for_each_ha(hip_get_all_valid, &rk);
        if (err) {
                HIP_ERROR("for_each_ha err=%d\n", err);
                return;
        }

        for (i = 0; i < rk.count; i++) {
                if (rk.array[i] != NULL) {
                        hip_send_notify(rk.array[i]);
                        hip_put_ha(rk.array[i]);
                }
        }

        return;
}
