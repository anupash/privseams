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
 * hip_send_i1 - send an I1 packet to the responder
 * @entry: the HIP database entry reserved for the peer
 *
 * Send an I1 packet to the responder if an IPv6 address for the peer
 * is known.
 *
 * Returns: 0 on success, otherwise < 0 on error.
 */
int hip_send_i1(hip_hit_t *dsthit, hip_ha_t *entry)
{
	struct hip_common i1;
	struct in6_addr daddr;
	int mask;
	int err = 0;

	mask = HIP_CONTROL_NONE;
#ifdef CONFIG_HIP_RVS
	if ((entry->local_controls & HIP_PSEUDO_CONTROL_REQ_RVS))
		mask |= HIP_CONTROL_RVS_CAPABLE;
#endif
	mask = hip_create_control_flags(0, 0, HIP_CONTROL_SHT_TYPE1,
					HIP_CONTROL_DHT_TYPE1);

	/* Assign a local private key, public key and HIT to HA */
	HIP_IFEL(hip_init_us(entry, NULL), -EINVAL, "Could not assign a local host id\n");

	entry->hadb_misc_func->hip_build_network_hdr((struct hip_common* ) &i1, HIP_I1,
			      mask, &entry->hit_our,
			      dsthit);
	/* Eight octet units, not including first */
	i1.payload_len = (sizeof(struct hip_common) >> 3) - 1;

	HIP_HEXDUMP("HIT source", &i1.hits, sizeof(struct in6_addr));
	HIP_HEXDUMP("HIT dest", &i1.hitr, sizeof(struct in6_addr));

	HIP_IFEL(hip_hadb_get_peer_addr(entry, &daddr), -1, 
		 "No preferred IP address for the peer.\n");

	err = entry->hadb_xmit_func->hip_csum_send(&entry->local_address,
						   &daddr,
						   (struct hip_common*) &i1,
						   entry, 1);
	HIP_DEBUG("err = %d\n", err);
	if (!err) {
		HIP_LOCK_HA(entry);
		entry->state = HIP_STATE_I1_SENT;
		HIP_UNLOCK_HA(entry);
	}
 out_err:
	return err;
}

/**
 * hip_create_r1 - construct a new R1-payload
 * @src_hit: source HIT used in the packet
 *
 * Returns 0 on success, or negative on error
 */
struct hip_common *hip_create_r1(const struct in6_addr *src_hit, 
				 int (*sign)(struct hip_host_id *p, struct hip_common *m),
				 struct hip_host_id *host_id_priv,
				 const struct hip_host_id *host_id_pub)
{
 	struct hip_common *msg;
 	int err = 0,dh_size,written, mask;
 	u8 *dh_data = NULL;
 	/* Supported HIP and ESP transforms. */
 	hip_transform_suite_t transform_hip_suite[] = {
		HIP_HIP_AES_SHA1,
		HIP_HIP_3DES_SHA1,
		HIP_HIP_NULL_SHA1
	};
 	hip_transform_suite_t transform_esp_suite[] = {
		HIP_ESP_AES_SHA1,
		HIP_ESP_3DES_SHA1,
		HIP_ESP_NULL_SHA1
	};
	//	struct hip_host_id  *host_id_pub = NULL;
	HIP_IFEL(!(msg = hip_msg_alloc()), -ENOMEM, "Out of memory\n");

 	/* Allocate memory for writing Diffie-Hellman shared secret */
	HIP_IFEL((dh_size = hip_get_dh_size(HIP_DEFAULT_DH_GROUP_ID)) == 0, 
		 -1, "Could not get dh size\n");
	HIP_IFEL(!(dh_data = HIP_MALLOC(dh_size, GFP_ATOMIC)), 
		 -1, "Failed to alloc memory for dh_data\n");
	memset(dh_data, 0, dh_size);

	_HIP_DEBUG("dh_size=%d\n", dh_size);
	//	HIP_IFEL(!(host_id_pub = hip_get_any_localhost_public_key(HIP_HI_DEFAULT_ALGO)),
	//	 -1, "Could not acquire localhost public key\n");
	//HIP_HEXDUMP("Our pub host id\n", host_id_pub,
	//	    hip_get_param_total_len(host_id_pub));
	
 	/* Ready to begin building of the R1 packet */
	mask = HIP_CONTROL_SHT_TYPE1 << HIP_CONTROL_SHT_SHIFT;
	mask |= HIP_CONTROL_DHT_TYPE1 << HIP_CONTROL_DHT_SHIFT;
#ifdef CONFIG_HIP_RVS
	mask |= HIP_CONTROL_RVS_CAPABLE; //XX: FIXME
#endif
	HIP_DEBUG("mask=0x%x\n", mask);
	/* TODO: TH: hip_build_network_hdr has to be replaced with an apprporiate function pointer */
 	hip_build_network_hdr(msg, HIP_R1, mask, src_hit, NULL);

	/********** R1_COUNTER (OPTIONAL) *********/

 	/********** PUZZLE ************/
	HIP_IFEL(hip_build_param_puzzle(msg, HIP_DEFAULT_COOKIE_K,
					42 /* 2^(42-32) sec lifetime */, 
					0, 0),  -1, 
		 "Cookies were burned. Bummer!\n");

 	/********** Diffie-Hellman **********/
	HIP_IFEL((written = hip_insert_dh(dh_data, dh_size,
					  HIP_DEFAULT_DH_GROUP_ID)) < 0,
		 -1, "Could not extract DH public key\n");
	
	HIP_IFEL(hip_build_param_diffie_hellman_contents(msg,
							 HIP_DEFAULT_DH_GROUP_ID,
							 dh_data, written), -1,
		 "Building of DH failed.\n");

 	/********** HIP transform. **********/
 	HIP_IFEL(hip_build_param_transform(msg, HIP_PARAM_HIP_TRANSFORM,
					   transform_hip_suite,
					   sizeof(transform_hip_suite) /
					   sizeof(hip_transform_suite_t)), -1, 
		 "Building of HIP transform failed\n");

 	/********** ESP-ENC transform. **********/
 	HIP_IFEL(hip_build_param_transform(msg, HIP_PARAM_ESP_TRANSFORM,  
					   transform_esp_suite,
					   sizeof(transform_esp_suite) /
					   sizeof(hip_transform_suite_t)), -1, 
		 "Building of ESP transform failed\n");

 	/********** Host_id **********/

	_HIP_DEBUG("This HOST ID belongs to: %s\n", 
		   hip_get_param_host_id_hostname(host_id_pub));
	HIP_IFEL(hip_build_param(msg, host_id_pub), -1, 
		 "Building of host id failed\n");

	/********** ECHO_REQUEST_SIGN (OPTIONAL) *********/

	//HIP_HEXDUMP("Pubkey:", host_id_pub, hip_get_param_total_len(host_id_pub));

 	/********** Signature 2 **********/	
 	HIP_IFEL(sign(host_id_priv, msg), -1, "Signing of R1 failed.\n");
	_HIP_HEXDUMP("R1", msg, hip_get_msg_total_len(msg));

	/********** ECHO_REQUEST (OPTIONAL) *********/

	/* Fill puzzle parameters */
	{
		struct hip_puzzle *pz;
		uint64_t random_i;

		HIP_IFEL(!(pz = hip_get_param(msg, HIP_PARAM_PUZZLE)), -1, 
			 "Internal error\n");

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

// 	if (host_id_pub)
	//		HIP_FREE(host_id_pub);
 	if (dh_data)
 		HIP_FREE(dh_data);

	//HIP_HEXDUMP("r1", msg, hip_get_msg_total_len(msg));

	return msg;

  out_err:
	//	if (host_id_pub)
	//	HIP_FREE(host_id_pub);
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
int hip_xmit_r1(struct in6_addr *i1_saddr, struct in6_addr *i1_daddr,
		struct in6_addr *src_hit,  struct in6_addr *dst_ip,
		struct in6_addr *dst_hit)
{
	struct hip_common *r1pkt = NULL;
	struct in6_addr *own_addr, *dst_addr;
	int err = 0;

	HIP_DEBUG("\n");
	own_addr = i1_daddr;
	dst_addr = ((!dst_ip || ipv6_addr_any(dst_ip)) ? i1_saddr : dst_ip);

	/* dst_addr is the IP address of the Initiator... */
	HIP_DEBUG_HIT("!!!! hip_xmit_r1:: src_hit", src_hit);
	// it sould not be null hit, null hit has been replaced by real local hit
	HIP_ASSERT(!hit_is_opportunistic_hit(src_hit));
	
	HIP_IFEL(!(r1pkt = hip_get_r1(dst_addr, own_addr, src_hit, dst_hit)), -ENOENT, 
		 "No precreated R1\n");
	HIP_DEBUG_HIT("!!!! hip_xmit_r1:: dst_hit", dst_hit);
	if (dst_hit)
		ipv6_addr_copy(&r1pkt->hitr, dst_hit);
	else
		memset(&r1pkt->hitr, 0, sizeof(struct in6_addr));
	HIP_DEBUG_HIT("!!!! hip_xmit_r1:: ripkt->hitr", &r1pkt->hitr);

	/* set cookie state to used (more or less temporary solution ?) */
	_HIP_HEXDUMP("R1 pkt", r1pkt, hip_get_msg_total_len(r1pkt));

	HIP_IFEL(hip_csum_send(own_addr, dst_addr, r1pkt, NULL, 0), -1, 
		 "hip_xmit_r1 failed.\n");
 out_err:
	if (r1pkt)
		HIP_FREE(r1pkt);
	return err;
}

void hip_send_notify(hip_ha_t *entry)
{
	int err = 0; /* actually not needed, because we can't do
		      * anything if packet sending fails */
	struct hip_common *notify_packet;
	struct in6_addr daddr;

	HIP_IFE(!(notify_packet = hip_msg_alloc()), -ENOMEM);
	entry->hadb_misc_func->hip_build_network_hdr(notify_packet, HIP_NOTIFY, 0,
			      &entry->hit_our, &entry->hit_peer);
	HIP_IFEL(hip_build_param_notify(notify_packet, 1234, "ABCDEFGHIJ", 10), 0, 
		 "Building of NOTIFY failed.\n");

        HIP_IFE(hip_hadb_get_peer_addr(entry, &daddr), 0);
	entry->hadb_xmit_func->hip_csum_send(NULL, &daddr, notify_packet,
					     entry, 0);

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

        rk.array = entries;
        rk.count = 0;
        rk.length = HIP_MAX_HAS;

        HIP_IFEL(hip_for_each_ha(hip_get_all_valid, &rk), 0, 
		 "for_each_ha failed.\n");
        for (i = 0; i < rk.count; i++) {
                if (rk.array[i] != NULL) {
                        hip_send_notify(rk.array[i]);
                        hip_put_ha(rk.array[i]);
                }
        }

 out_err:
        return;
}

