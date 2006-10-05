/** @file
 * This file defines handling functions for incoming packets for the Host
 * Identity Protocol (HIP).
 * 
 * @author  Janne Lundberg <jlu_tcs.hut.fi>
 * @author  Miika Komu <miika_iki.fi>
 * @author  Mika Kousa <mkousa_cc.hut.fi>
 * @author  Kristian Slavov <kslavov_hiit.fi>
 * @author  Anthony D. Joseph <adj_hiit.fi>
 * @author  Bing Zhou <bingzhou_cc.hut.fi>
 * @author  Tobias Heer <heer_tobibox.de>
 * @note    Distributed under <a href="http://www.gnu.org/licenses/gpl.txt">GNU/GPL</a>.
 */
#include "input.h"

#ifdef CONFIG_HIP_OPPORTUNISTIC
extern unsigned int opportunistic_mode;
#endif

extern int hip_build_param_esp_info(struct hip_common *msg, uint16_t keymat_index,
			     uint32_t old_spi, uint32_t new_spi);
/*
 * function checksum_packet() 
 *
 * Calculates the checksum of a HIP packet with pseudo-header
 * src and dst are IPv4 or IPv6 addresses in network byte order
 *
 * Checksumming is from Boeing's HIPD.
 */
u16 checksum_packet(char *data, struct sockaddr *src, struct sockaddr *dst)
{
	u16 checksum = 0;
	unsigned long sum = 0;
	int count = 0, length = 0;
	unsigned short *p = NULL; /* 16-bit */
	struct pseudo_header pseudoh;
	struct pseudo_header6 pseudoh6;
	u32 src_network, dst_network;
	struct in6_addr *src6, *dst6;
	struct hip_common *hiph = (struct hip_common *) data;
	
	if (src->sa_family == AF_INET) {
		/* IPv4 checksum based on UDP-- Section 6.1.2 */
		src_network = ((struct sockaddr_in*)src)->sin_addr.s_addr;
		dst_network = ((struct sockaddr_in*)dst)->sin_addr.s_addr;
		
		memset(&pseudoh, 0, sizeof(struct pseudo_header));
		memcpy(&pseudoh.src_addr, &src_network, 4);
		memcpy(&pseudoh.dst_addr, &dst_network, 4);
		pseudoh.protocol = IPPROTO_HIP;
		length = (hiph->payload_len + 1) * 8;
		pseudoh.packet_length = htons(length);
		
		count = sizeof(struct pseudo_header); /* count always even number */
		p = (unsigned short*) &pseudoh;
	} else {
		/* IPv6 checksum based on IPv6 pseudo-header */
		src6 = &((struct sockaddr_in6*)src)->sin6_addr;
		dst6 = &((struct sockaddr_in6*)dst)->sin6_addr;
		
		memset(&pseudoh6, 0, sizeof(struct pseudo_header6));
		memcpy(&pseudoh6.src_addr[0], src6, 16);
		memcpy(&pseudoh6.dst_addr[0], dst6, 16);
		length = (hiph->payload_len + 1) * 8;
		pseudoh6.packet_length = htonl(length);
		pseudoh6.next_hdr = IPPROTO_HIP;
                
		count = sizeof(struct pseudo_header6); /* count always even number */
		p = (unsigned short*) &pseudoh6;
	}
	/* 
	 * this checksum algorithm can be found 
	 * in RFC 1071 section 4.1
	 */
	
	/* sum the psuedo-header */
	/* count and p are initialized above per protocol */
	while (count > 1) {
		sum += *p++;
		count -= 2;
	}

	/* one's complement sum 16-bit words of data */
	HIP_DEBUG("Checksumming %d bytes of data.\n", length);
	count = length;
	p = (unsigned short*) data;
	while (count > 1) {
		sum += *p++;
		count -= 2;
	}
	/* add left-over byte, if any */
	if (count > 0)
		sum += (unsigned char)*p;
	
	/*  Fold 32-bit sum to 16 bits */
	while (sum>>16)
		sum = (sum & 0xffff) + (sum >> 16);
	/* take the one's complement of the sum */ 
	checksum = ~sum;
	
	return(checksum);
}

int hip_verify_network_header(struct hip_common *hip_common,
			      struct sockaddr *src, struct sockaddr *dst, int len)
{
	int err = 0;

        /* Currently no support for piggybacking */
        HIP_IFEL(len != hip_get_msg_total_len(hip_common), -EINVAL, 
		 "Invalid HIP packet length. Dropping\n");
        HIP_IFEL(hip_common->payload_proto != IPPROTO_NONE, -EOPNOTSUPP,
		 "Protocol in packet (%u) was not IPPROTO_NONE. Dropping\n",
		 hip_common->payload_proto);
	HIP_IFEL(hip_common->ver_res & HIP_VER_MASK != HIP_VER_RES, -EPROTOTYPE,
		 "Invalid version in received packet. Dropping\n");
	HIP_IFEL(!ipv6_addr_is_hit(&hip_common->hits), -EAFNOSUPPORT,
		 "Received a non-HIT in HIT-source. Dropping\n");
	HIP_IFEL(!ipv6_addr_is_hit(&hip_common->hitr) && !ipv6_addr_any(&hip_common->hitr),
		 -EAFNOSUPPORT, "Received a non-HIT or non NULL in HIT-receiver. Dropping\n");
	HIP_IFEL(ipv6_addr_any(&hip_common->hits), -EAFNOSUPPORT,
		 "Received a NULL in HIT-sender. Dropping\n");

        /** @todo handle the RVS case better. */
        if (ipv6_addr_any(&hip_common->hitr)) {
                /* Required for e.g. BOS */
                HIP_DEBUG("Received opportunistic HIT\n");
	} else {
#ifdef CONFIG_HIP_RVS
                HIP_DEBUG("Received HIT is ours or we are RVS\n");
#else
		HIP_IFEL(!hip_hadb_hit_is_our(&hip_common->hitr), -EFAULT,
			 "Receiver HIT is not ours\n");
#endif
	}

        HIP_IFEL(!ipv6_addr_cmp(&hip_common->hits, &hip_common->hitr), -ENOSYS,
		 "Dropping HIP packet. Loopback not supported.\n");

        /* Check checksum. */
	HIP_IFEL(checksum_packet((char*)hip_common, src, dst), -EBADMSG, 
		 "HIP checksum failed.\n");
	
out_err:
        return err;
}

/**
 * hip_verify_hmac - verify HMAC
 * @param buffer the packet data used in HMAC calculation
 * @param hmac the HMAC to be verified
 * @param hmac_key integrity key used with HMAC
 * @param hmac_type type of the HMAC digest algorithm.
 *
 * @return 0 if calculated HMAC is same as @hmac, otherwise < 0. On
 * error < 0 is returned.
 *
 * FIX THE PACKET LEN BEFORE CALLING THIS FUNCTION
 */
static int hip_verify_hmac(struct hip_common *buffer, u8 *hmac,
			   void *hmac_key, int hmac_type)
{
	int err = 0;
	u8 *hmac_res = NULL;

	HIP_IFEL(!(hmac_res = HIP_MALLOC(HIP_AH_SHA_LEN, GFP_ATOMIC)), -ENOMEM,
		 "HIP_MALLOC failed\n");

	_HIP_HEXDUMP("HMAC data", buffer, hip_get_msg_total_len(buffer));

	HIP_IFEL(!hip_write_hmac(hmac_type, hmac_key, buffer,
				 hip_get_msg_total_len(buffer), hmac_res), -EINVAL,
		 "Could not build hmac\n");

	_HIP_HEXDUMP("HMAC", hmac_res, HIP_AH_SHA_LEN);
	HIP_IFE(memcmp(hmac_res, hmac, HIP_AH_SHA_LEN), -EINVAL);

 out_err:
	if (hmac_res)
		HIP_FREE(hmac_res);

	return err;
}

/**
 * hip_verify_packet_hmac - verify packet HMAC
 * @param msg HIP packet
 * @param entry HA
 *
 * @return 0 if HMAC was validated successfully, < 0 if HMAC could
 * not be validated.
 */
int hip_verify_packet_hmac(struct hip_common *msg,
			   struct hip_crypto_key *crypto_key)
{
	HIP_DEBUG("hip_verify_packet_hmac() invoked.\n");
	int err = 0, len, orig_len;
	u8 orig_checksum;
	struct hip_crypto_key tmpkey;
	struct hip_hmac *hmac;

	HIP_IFEL(!(hmac = hip_get_param(msg, HIP_PARAM_HMAC)),
		 -ENOMSG, "No HMAC parameter\n");

	/* hmac verification modifies the msg length temporarile, so we have
	   to restore the length */
	orig_len = hip_get_msg_total_len(msg);

	/* hmac verification assumes that checksum is zero */
	orig_checksum = hip_get_msg_checksum(msg);
	hip_zero_msg_checksum(msg);

	len = (u8 *) hmac - (u8*) msg;
	hip_set_msg_total_len(msg, len);

	HIP_HEXDUMP("HMAC key", crypto_key->key,
		    hip_hmac_key_length(HIP_ESP_AES_SHA1));

	HIP_HEXDUMP("HMACced data", msg, len);
	memcpy(&tmpkey, crypto_key, sizeof(tmpkey));

	HIP_IFEL(hip_verify_hmac(msg, hmac->hmac_data, tmpkey.key,
				 HIP_DIGEST_SHA1_HMAC), 
		 -1, "HMAC validation failed\n");

	/* revert the changes to the packet */
	hip_set_msg_total_len(msg, orig_len);
	hip_set_msg_checksum(msg, orig_checksum);

 out_err:
	return err;
}

/**
 * Verifies packet RVS_HMAC
 * @param msg HIP packet
 * @param entry HA
 *
 * @return 0 if HMAC was validated successfully, < 0 if HMAC could
 * not be validated.
 */
int hip_verify_packet_rvs_hmac(struct hip_common *msg,
			   struct hip_crypto_key *crypto_key)
{
	HIP_DEBUG("hip_verify_packet_rvs_hmac() invoked.\n");
	int err = 0, len, orig_len;
	u8 orig_checksum;
	struct hip_crypto_key tmpkey;
	struct hip_hmac *hmac;

	HIP_IFEL(!(hmac = hip_get_param(msg, HIP_PARAM_RVS_HMAC)),
		 -ENOMSG, "No HMAC parameter\n");

	/* hmac verification modifies the msg length temporarily, so we have
	   to restore the length */
	orig_len = hip_get_msg_total_len(msg);

	/* hmac verification assumes that checksum is zero */
	orig_checksum = hip_get_msg_checksum(msg);
	hip_zero_msg_checksum(msg);

	len = (u8 *) hmac - (u8*) msg;
	hip_set_msg_total_len(msg, len);

	HIP_HEXDUMP("HMAC key", crypto_key->key,
		    hip_hmac_key_length(HIP_ESP_AES_SHA1));

	HIP_HEXDUMP("HMACced data", msg, len);
	memcpy(&tmpkey, crypto_key, sizeof(tmpkey));

	HIP_IFEL(hip_verify_hmac(msg, hmac->hmac_data, tmpkey.key,
				 HIP_DIGEST_SHA1_HMAC), 
		 -1, "HMAC validation failed\n");

	/* revert the changes to the packet */
	hip_set_msg_total_len(msg, orig_len);
	hip_set_msg_checksum(msg, orig_checksum);

 out_err:
	return err;
}

/**
 * hip_verify_packet_hmac2 - verify packet HMAC
 * @param msg HIP packet
 * @param entry HA
 *
 * @return 0 if HMAC was validated successfully, < 0 if HMAC could
 * not be validated. Assumes that the hmac includes only the header
 * and host id.
 */
int hip_verify_packet_hmac2(struct hip_common *msg,
			    struct hip_crypto_key *crypto_key,
			    struct hip_host_id *host_id)
{
	HIP_DEBUG("hip_verify_packet_hmac2() invoked.\n");
	int err = 0;
	struct hip_crypto_key tmpkey;
	struct hip_hmac *hmac;
	struct hip_common *msg_copy = NULL;
	struct hip_esp_info *esp_info;

	HIP_IFE(!(msg_copy = hip_msg_alloc()), -ENOMEM);
	memcpy(msg_copy, msg, sizeof(struct hip_common));
	hip_set_msg_total_len(msg_copy, 0);
	hip_zero_msg_checksum(msg_copy);

	esp_info = hip_get_param(msg, HIP_PARAM_ESP_INFO);
	HIP_ASSERT(esp_info);
	HIP_IFE(hip_build_param(msg_copy, esp_info), -EFAULT);
	hip_build_param(msg_copy, host_id);

	HIP_IFEL(!(hmac = hip_get_param(msg, HIP_PARAM_HMAC2)), -ENOMSG, "Packet contained no HMAC parameter\n");
	HIP_HEXDUMP("HMAC data", msg_copy, hip_get_msg_total_len(msg_copy));
	memcpy(&tmpkey, crypto_key, sizeof(tmpkey));

	HIP_IFEL(hip_verify_hmac(msg_copy, hmac->hmac_data, tmpkey.key, HIP_DIGEST_SHA1_HMAC), 
		-1, "HMAC validation failed\n");

 out_err:
	if (msg_copy)
		HIP_FREE(msg_copy);

	return err;
}

/**
 * hip_produce_keying_material - Create shared secret and produce keying material 
 * @param msg the HIP packet received from the peer
 * @param ctx context
 *
 * The initial ESP keys are drawn out of the keying material.
 *
 *
 * Returns zero on success, or negative on error.
 */
int hip_produce_keying_material(struct hip_common *msg,
				struct hip_context *ctx,
				uint64_t I,
				uint64_t J)
{
	HIP_DEBUG("hip_produce_keying_material() invoked.\n");
	char *dh_shared_key = NULL;
	int hip_transf_length, hmac_transf_length;
	int auth_transf_length, esp_transf_length, we_are_HITg = 0;
	int hip_tfm, esp_tfm, err = 0, dh_shared_len = 1024;
	struct hip_keymat_keymat km;
	struct hip_esp_info *esp_info;
	char *keymat = NULL;
	size_t keymat_len_min; /* how many bytes we need at least for the KEYMAT */
	size_t keymat_len; /* note SHA boundary */
	struct hip_tlv_common *param = NULL;
	uint16_t esp_keymat_index, esp_default_keymat_index;
	struct hip_diffie_hellman * dhf;

	/* Perform light operations first before allocating memory or
	 * using lots of CPU time */
	HIP_IFEL(!(param = hip_get_param(msg, HIP_PARAM_HIP_TRANSFORM)),
		 -EINVAL, 
		 "Could not find HIP transform\n");
	HIP_IFEL((hip_tfm = hip_select_hip_transform((struct hip_hip_transform *) param)) == 0, 
		 -EINVAL, "Could not select HIP transform\n");
	HIP_IFEL(!(param = hip_get_param(msg, HIP_PARAM_ESP_TRANSFORM)),
		 -EINVAL, 
		 "Could not find ESP transform\n");
	HIP_IFEL((esp_tfm = hip_select_esp_transform((struct hip_esp_transform *) param)) == 0, 
		 -EINVAL, "Could not select proper ESP transform\n");

	hip_transf_length = hip_transform_key_length(hip_tfm);
	hmac_transf_length = hip_hmac_key_length(esp_tfm);
	esp_transf_length = hip_enc_key_length(esp_tfm);
	auth_transf_length = hip_auth_key_length_esp(esp_tfm);

	HIP_DEBUG("transform lengths: hip=%d, hmac=%d, esp=%d, auth=%d\n",
		  hip_transf_length, hmac_transf_length, esp_transf_length,
		  auth_transf_length);

	HIP_DEBUG("I=0x%llx J=0x%llx\n", I, J);

	/* Create only minumum amount of KEYMAT for now. From draft
	 * chapter HIP KEYMAT we know how many bytes we need for all
	 * keys used in the base exchange. */
	keymat_len_min = hip_transf_length + hmac_transf_length +
		hip_transf_length + hmac_transf_length + esp_transf_length +
		auth_transf_length + esp_transf_length + auth_transf_length;

	/* assume esp keys are after authentication keys */
	esp_default_keymat_index = hip_transf_length + hmac_transf_length +
		hip_transf_length + hmac_transf_length;

	/* R1 contains no ESP_INFO */
	esp_info = hip_get_param(msg, HIP_PARAM_ESP_INFO);
	if (esp_info)
		esp_keymat_index = ntohs(esp_info->keymat_index);
	else
		esp_keymat_index = esp_default_keymat_index;

	if (esp_keymat_index != esp_default_keymat_index) {
		/* XX FIXME */
		HIP_ERROR("Varying keymat slices not supported yet\n");
		err = -1;
		goto out_err;
	}

	keymat_len = keymat_len_min;
	if (keymat_len % HIP_AH_SHA_LEN)
		keymat_len += HIP_AH_SHA_LEN - (keymat_len % HIP_AH_SHA_LEN);

	HIP_DEBUG("keymat_len_min=%u keymat_len=%u\n", keymat_len_min,
		  keymat_len);
	HIP_IFEL(!(keymat = HIP_MALLOC(keymat_len, GFP_KERNEL)), -ENOMEM,
		 "No memory for KEYMAT\n");

	/* 1024 should be enough for shared secret. The length of the
	 * shared secret actually depends on the DH Group. */
	/*! \todo 1024 -> hip_get_dh_size ? */
	HIP_IFEL(!(dh_shared_key = HIP_MALLOC(dh_shared_len, GFP_KERNEL)),
		 -ENOMEM,  "No memory for DH shared key\n");
	memset(dh_shared_key, 0, dh_shared_len);
	HIP_IFEL(!(dhf= (struct hip_diffie_hellman*)hip_get_param(msg, HIP_PARAM_DIFFIE_HELLMAN)),
		 -ENOENT,  "No Diffie-Hellman param found\n");

	HIP_IFEL((htons(dhf->pub_len) != hip_get_diffie_hellman_param_public_value_len(dhf)), -1,
		 "Bad DHF len or multiple DHF not supported\n");

	HIP_IFEL((dh_shared_len = hip_calculate_shared_secret(dhf->public_value, 
							      dhf->group_id,
							      ntohs(dhf->pub_len), 
							      dh_shared_key,
							      dh_shared_len)) < 0,
		 -EINVAL, "Calculation of shared secret failed\n");
	_HIP_DEBUG("dh_shared_len=%u\n", dh_shared_len);
	_HIP_HEXDUMP("DH SHARED PARAM", param, hip_get_param_total_len(param));
	_HIP_HEXDUMP("DH SHARED KEY", dh_shared_key, dh_shared_len);
	hip_make_keymat(dh_shared_key, dh_shared_len,
			&km, keymat, keymat_len,
			&msg->hits, &msg->hitr, &ctx->keymat_calc_index, I, J);

	/* draw from km to keymat, copy keymat to dst, length of
	 * keymat is len */

#if 0
	/* removed this because the cts is already set to 0 when it is
	   created */
	bzero(&ctx->hip_enc_in.key, sizeof(struct hip_crypto_key));
	bzero(&ctx->hip_enc_out.key, sizeof(struct hip_crypto_key));
	bzero(&ctx->hip_hmac_in.key, sizeof(struct hip_crypto_key));
	bzero(&ctx->hip_hmac_out.key, sizeof(struct hip_crypto_key));
	bzero(&ctx->esp_in.key, sizeof(struct hip_crypto_key));
	bzero(&ctx->esp_out.key, sizeof(struct hip_crypto_key));
	bzero(&ctx->auth_in.key, sizeof(struct hip_crypto_key));
	bzero(&ctx->auth_out.key, sizeof(struct hip_crypto_key));
#endif
	/* Draw keys: */
	we_are_HITg = hip_hit_is_bigger(&msg->hitr, &msg->hits);
	HIP_DEBUG("we are HIT%c\n", we_are_HITg ? 'g' : 'l');
	if (we_are_HITg) {
		hip_keymat_draw_and_copy(ctx->hip_enc_out.key, &km,	hip_transf_length);
		hip_keymat_draw_and_copy(ctx->hip_hmac_out.key,&km,	hmac_transf_length);
		hip_keymat_draw_and_copy(ctx->hip_enc_in.key, 	&km,	hip_transf_length);
 		hip_keymat_draw_and_copy(ctx->hip_hmac_in.key, &km,	hmac_transf_length);
		hip_keymat_draw_and_copy(ctx->esp_out.key, 	&km,	esp_transf_length);
 		hip_keymat_draw_and_copy(ctx->auth_out.key, 	&km,	auth_transf_length);
 		hip_keymat_draw_and_copy(ctx->esp_in.key, 	&km,	esp_transf_length);
 		hip_keymat_draw_and_copy(ctx->auth_in.key, 	&km,	auth_transf_length);
 	} else {
 	 	hip_keymat_draw_and_copy(ctx->hip_enc_in.key, 	&km,	hip_transf_length);
 		hip_keymat_draw_and_copy(ctx->hip_hmac_in.key,	&km,	hmac_transf_length);
 		hip_keymat_draw_and_copy(ctx->hip_enc_out.key,	&km,	hip_transf_length);
 		hip_keymat_draw_and_copy(ctx->hip_hmac_out.key,&km,	hmac_transf_length);
 		hip_keymat_draw_and_copy(ctx->esp_in.key, 	&km,	esp_transf_length);
 		hip_keymat_draw_and_copy(ctx->auth_in.key, 	&km,	auth_transf_length);
 		hip_keymat_draw_and_copy(ctx->esp_out.key, 	&km,	esp_transf_length);
 		hip_keymat_draw_and_copy(ctx->auth_out.key, 	&km,	auth_transf_length);
 	}
 	HIP_HEXDUMP("HIP-gl encryption:", &ctx->hip_enc_out.key, hip_transf_length);
 	HIP_HEXDUMP("HIP-gl integrity (HMAC) key:", &ctx->hip_hmac_out.key,
 		    hmac_transf_length);
 	_HIP_DEBUG("skipping HIP-lg encryption key, %u bytes\n", hip_transf_length);
	HIP_HEXDUMP("HIP-lg encryption:", &ctx->hip_enc_in.key, hip_transf_length);
 	HIP_HEXDUMP("HIP-lg integrity (HMAC) key:", &ctx->hip_hmac_in.key, hmac_transf_length);
 	HIP_HEXDUMP("SA-gl ESP encryption key:", &ctx->esp_out.key, esp_transf_length);
 	HIP_HEXDUMP("SA-gl ESP authentication key:", &ctx->auth_out.key, auth_transf_length);
 	HIP_HEXDUMP("SA-lg ESP encryption key:", &ctx->esp_in.key, esp_transf_length);
 	HIP_HEXDUMP("SA-lg ESP authentication key:", &ctx->auth_in.key, auth_transf_length);

#undef KEYMAT_DRAW_AND_COPY

	/* the next byte when creating new keymat */
	ctx->current_keymat_index = keymat_len_min; /* offset value, so no +1 ? */
	ctx->keymat_calc_index = (ctx->current_keymat_index / HIP_AH_SHA_LEN) + 1;
	ctx->esp_keymat_index = esp_keymat_index;

	memcpy(ctx->current_keymat_K, keymat+(ctx->keymat_calc_index-1)*HIP_AH_SHA_LEN, HIP_AH_SHA_LEN);

	_HIP_DEBUG("ctx: keymat_calc_index=%u current_keymat_index=%u\n",
		   ctx->keymat_calc_index, ctx->current_keymat_index);
	_HIP_HEXDUMP("CTX CURRENT KEYMAT", ctx->current_keymat_K, HIP_AH_SHA_LEN);

	/* store DH shared key */
	ctx->dh_shared_key = dh_shared_key;
	ctx->dh_shared_key_len = dh_shared_len;

	/* on success HIP_FREE for dh_shared_key is called by caller */
 out_err:
	if (err && dh_shared_key)
		HIP_FREE(dh_shared_key);
	if (keymat)
		HIP_FREE(keymat);

	return err;
}


/*****************************************************************************
 *                           PACKET/PROTOCOL HANDLING                        *
 *****************************************************************************/

int hip_receive_control_packet(struct hip_common *msg,
			       struct in6_addr *src_addr,
			       struct in6_addr *dst_addr,
	                       struct hip_stateless_info *msg_info)
{
	HIP_DEBUG("hip_receive_control_packet() invoked.\n");
	hip_ha_t tmp, *entry;
	int err = 0, type, skip_sync = 0;

	type = hip_get_msg_type(msg);
	
	HIP_DEBUG("Received packet type %d\n", type);
	_HIP_DUMP_MSG(msg);
	_HIP_HEXDUMP("dumping packet", msg,  40);
	/** @todo Check packet csum.*/

	/* fetch the state from the hadb database to be able to choose the
	   appropriate message handling functions */
	entry = hip_hadb_find_byhits(&msg->hits, &msg->hitr);

#ifdef CONFIG_HIP_OPPORTUNISTIC
	if (!entry && opportunistic_mode && (type == HIP_I1 || type == HIP_R1))
	    entry = hip_oppdb_get_hadb_entry_i1_r1(msg, src_addr, dst_addr,
						   msg_info);
#endif

        if (entry) {
		err = entry->hadb_input_filter_func->hip_input_filter(msg);
        } else {
	        err = ((hip_input_filter_func_set_t *)
		       hip_get_input_filter_default_func_set())->hip_input_filter(msg);
	}
	
	if (err == -ENOENT) {
		HIP_DEBUG("No agent running, continuing\n");
		err = 0;
	} else if (err == 0) {
		HIP_DEBUG("Agent accepted packet\n");
	} else if (err) {
		HIP_ERROR("Agent reject packet\n");
	}
	
	switch(type) {
	case HIP_I1:
		/* no state */
	  err = ((hip_rcv_func_set_t *)
		 hip_get_rcv_default_func_set())->hip_receive_i1(msg,
								 src_addr,
								 dst_addr,
								 entry,
								 msg_info);
	  break;
		
	case HIP_I2:
		// possibly state
		HIP_DEBUG("\n-- RECEIVED I2. State: %d--\n");
		if(entry){
			err = entry->hadb_rcv_func->
				hip_receive_i2(msg, src_addr, dst_addr, entry,
					       msg_info);
		} else {
			err = ((hip_rcv_func_set_t *)
			   hip_get_rcv_default_func_set())->hip_receive_i2(msg,
								     src_addr,
								     dst_addr,
								     entry,
								     msg_info);
		}
		break;
		
	case HIP_R1:
	  	// state
	  	HIP_DEBUG("\n-- RECEIVED R1. State: %d--\n");
		HIP_ASSERT(entry);
		HIP_IFCS(entry,
			 err = entry->hadb_rcv_func->hip_receive_r1(msg,
			 				src_addr,
							dst_addr,
							entry,
							msg_info))

		//err = hip_receive_r1(msg, src_addr, dst_addr);
		break;
		
	case HIP_R2:
		HIP_DEBUG("\n-- RECEIVED R2. State: %d--\n");
		HIP_IFCS(entry,
			 err = entry->hadb_rcv_func->hip_receive_r2(msg,
			 				src_addr,
							dst_addr,
							entry,
							msg_info))
		//err = hip_receive_r2(msg, src_addr, dst_addr);
		HIP_STOP_TIMER(KMM_GLOBAL,"Base Exchange");
		break;
		
	case HIP_UPDATE:
		HIP_DEBUG("\n-- RECEIVED Update message. State: %d--\n");
		HIP_IFCS(entry,
			 err = entry->hadb_rcv_func->hip_receive_update(msg,
			 				src_addr,
							dst_addr,
							entry,
							msg_info))
		break;
		
	case HIP_NOTIFY:
		HIP_DEBUG("\n-- RECEIVED Notify message --\n");
		HIP_IFCS(entry,
			 err = entry->hadb_rcv_func->hip_receive_notify(
							msg,
							src_addr,
							dst_addr,
							entry))
		break;
		
	case HIP_BOS:
		HIP_DEBUG("\n-- RECEIVED BOS message --\n");
		HIP_IFCS(entry,
			 err = entry->hadb_rcv_func->hip_receive_bos(msg,
							src_addr,
							dst_addr,
							entry,
							msg_info))
		/*In case of BOS the msg->hitr is null, therefore it is replaced
		  with our own HIT, so that the beet state can also be
		  synchronized */
		ipv6_addr_copy(&tmp.hit_peer, &msg->hits);
		hip_init_us(&tmp, NULL);
		ipv6_addr_copy(&msg->hitr, &tmp.hit_our);
		skip_sync = 0;
		break;
		
	case HIP_CLOSE:
		HIP_DEBUG("\n-- RECEIVED CLOSE message --\n");
		HIP_IFCS(entry,
			 err = entry->hadb_rcv_func->hip_receive_close(msg,
							entry))
		break;
		
	case HIP_CLOSE_ACK:
		HIP_DEBUG("\n-- RECEIVED CLOSE_ACK message --\n");
		HIP_IFCS(entry,
			 err = entry->hadb_rcv_func->hip_receive_close_ack(
							msg,
							entry))
		break;
		
	default:
		HIP_ERROR("Unknown packet %d\n", type);
		err = -ENOSYS;
	}

	HIP_DEBUG("Done with control packet, err is %d.\n", err);
	HIP_DEBUG_HIT("hip_receive_control_packet(): msg->hits", &msg->hits);
	HIP_DEBUG_HIT("hip_receive_control_packet(): msg->hitr", &msg->hitr);
	
	if (err)
		goto out_err;

 out_err:

	return err;
}

/**
 * hip_create_i2 - Create I2 packet and send it
 * @param ctx Context that includes the incoming R1 packet
 * @param solved_puzzle Value that solves the puzzle
 * @param entry HA
 *
 * @return zero on success, non-negative on error.
 */
int hip_create_i2(struct hip_context *ctx, uint64_t solved_puzzle, 
		  struct in6_addr *r1_saddr,
		  struct in6_addr *r1_daddr,
		  hip_ha_t *entry,
	          struct hip_stateless_info *r1_info)
{
	HIP_DEBUG("hip_create_i2() invoked.\n");
	int err = 0, dh_size = 0, written, host_id_in_enc_len;
	uint32_t spi_in = 0;
	hip_transform_suite_t transform_hip_suite, transform_esp_suite; 
	char *enc_in_msg = NULL, *host_id_in_enc = NULL;
	unsigned char *iv = NULL;
	struct in6_addr daddr;
	u8 *dh_data = NULL;
	struct hip_esp_info *esp_info;
	struct hip_common *i2 = NULL;
	struct hip_param *param;
	struct hip_diffie_hellman *dh_req;
	struct hip_spi_in_item spi_in_data;
	uint16_t mask = 0;
	int type_count = 0, request_rvs = 0, request_escrow = 0;

	HIP_DEBUG("\n");

	HIP_ASSERT(entry);

	/* allocate space for new I2 */
	HIP_IFEL(!(i2 = hip_msg_alloc()), -ENOMEM, "Allocation of I2 failed\n");

	/* allocate memory for writing Diffie-Hellman shared secret */
	HIP_IFEL(!(dh_size = hip_get_dh_size(HIP_DEFAULT_DH_GROUP_ID)), -EINVAL,
		 "Could not get dh size\n");
	HIP_IFEL(!(dh_data = HIP_MALLOC(dh_size, GFP_KERNEL)), -ENOMEM, 
		 "Failed to alloc memory for dh_data\n");

	/* TLV sanity checks are are already done by the caller of this
	   function. Now, begin to build I2 piece by piece. */

	/* Delete old SPDs and SAs, if present */
	hip_hadb_delete_inbound_spi(entry, 0);
	hip_hadb_delete_outbound_spi(entry, 0);

	/* create I2 */
	entry->hadb_misc_func->hip_build_network_hdr(i2, HIP_I2, mask,
			      &(ctx->input->hitr),
			      &(ctx->input->hits));

	/********** ESP_INFO **********/
	/* SPI is set below */
	HIP_IFEL(hip_build_param_esp_info(i2,
					  ctx->esp_keymat_index,
					  0, 0),
		 -1, "building of ESP_INFO failed.\n");

	/********** R1 COUNTER (OPTIONAL) ********/
	/* we build this, if we have recorded some value (from previous R1s) */
	{
		uint64_t rtmp;

		HIP_LOCK_HA(entry);
		rtmp = entry->birthday;
		HIP_UNLOCK_HA(entry);

		HIP_IFEL(rtmp && hip_build_param_r1_counter(i2, rtmp), -1, 
			 "Could not build R1 GENERATION parameter\n");
	}

	/********** SOLUTION **********/
	{
		struct hip_puzzle *pz;
		
		HIP_IFEL(!(pz = hip_get_param(ctx->input, HIP_PARAM_PUZZLE)), -ENOENT, 
			 "Internal error: PUZZLE parameter mysteriously gone\n");
		HIP_IFEL(hip_build_param_solution(i2, pz, ntoh64(solved_puzzle)), -1, 
			 "Building of solution failed\n");
	}

	/********** Diffie-Hellman *********/
	HIP_IFEL(!(dh_req = hip_get_param(ctx->input, HIP_PARAM_DIFFIE_HELLMAN)), -ENOENT, "Internal error\n");
	HIP_IFEL((written = hip_insert_dh(dh_data, dh_size, dh_req->group_id)) < 0, -ENOENT, 
		 "Error while extracting DH key\n");

	_HIP_HEXDUMP("Own DH key: ", dh_data, dh_size);

	HIP_IFEL(hip_build_param_diffie_hellman_contents(i2,dh_req->group_id,
							 dh_data, written), -1, 
		 "Building of DH failed\n");

        /********** HIP transform. **********/
	HIP_IFE(!(param = hip_get_param(ctx->input, HIP_PARAM_HIP_TRANSFORM)), -ENOENT);
	HIP_IFEL((transform_hip_suite =
		  hip_select_hip_transform((struct hip_hip_transform *) param)) == 0, 
		 -EINVAL, "Could not find acceptable hip transform suite\n");
	entry->hip_transform = transform_hip_suite;
	
	/* Select only one transform */
	HIP_IFEL(hip_build_param_transform(i2, HIP_PARAM_HIP_TRANSFORM,
					   &transform_hip_suite, 1), -1, 
		 "Building of HIP transform failed\n");

	/********** ESP-ENC transform. **********/
	HIP_IFE(!(param = hip_get_param(ctx->input, HIP_PARAM_ESP_TRANSFORM)), -ENOENT);

	/* Select only one transform */
	HIP_IFEL((transform_esp_suite =
		  hip_select_esp_transform((struct hip_esp_transform *) param)) == 0,
		 -1, "Could not find acceptable hip transform suite\n");
	HIP_IFEL(hip_build_param_transform(i2, HIP_PARAM_ESP_TRANSFORM,
					   &transform_esp_suite, 1), -1,
		 "Building of ESP transform failed\n");

	/************ Encrypted ***********/
	switch (transform_hip_suite) {
	case HIP_HIP_AES_SHA1:
		HIP_IFEL(hip_build_param_encrypted_aes_sha1(i2, (struct hip_tlv_common *)entry->our_pub), 
			 -1, "Building of param encrypted failed.\n");
		enc_in_msg = hip_get_param(i2, HIP_PARAM_ENCRYPTED);
		HIP_ASSERT(enc_in_msg); /* Builder internal error. */
 		iv = ((struct hip_encrypted_aes_sha1 *) enc_in_msg)->iv;
		get_random_bytes(iv, 16);
 		host_id_in_enc = enc_in_msg +
			sizeof(struct hip_encrypted_aes_sha1);
		break;
	case HIP_HIP_3DES_SHA1:
		HIP_IFEL(hip_build_param_encrypted_3des_sha1(i2, (struct hip_tlv_common *)entry->our_pub), 
			 -1, "Building of param encrypted failed.\n");
		enc_in_msg = hip_get_param(i2, HIP_PARAM_ENCRYPTED);
		HIP_ASSERT(enc_in_msg); /* Builder internal error. */
 		iv = ((struct hip_encrypted_3des_sha1 *) enc_in_msg)->iv;
		get_random_bytes(iv, 8);
 		host_id_in_enc = enc_in_msg +
 			sizeof(struct hip_encrypted_3des_sha1);
		break;
	case HIP_HIP_NULL_SHA1:
		HIP_IFEL(hip_build_param_encrypted_null_sha1(i2, (struct hip_tlv_common *)entry->our_pub), 
			 -1, "Building of param encrypted failed.\n");
		enc_in_msg = hip_get_param(i2, HIP_PARAM_ENCRYPTED);
		HIP_ASSERT(enc_in_msg); /* Builder internal error. */
 		iv = NULL;
 		host_id_in_enc = enc_in_msg +
 			sizeof(struct hip_encrypted_null_sha1);
		break;
	default:
 		HIP_IFEL(1, -ENOSYS, "HIP transform not supported (%d)\n",
			 transform_hip_suite);
	}

	HIP_HEXDUMP("enc(host_id)", host_id_in_enc,
		    hip_get_param_total_len(host_id_in_enc));

	/* Calculate the length of the host id inside the encrypted param */
	host_id_in_enc_len = hip_get_param_total_len(host_id_in_enc);

	/* Adjust the host id length for AES (block size 16).
	   build_param_encrypted_aes has already taken care that there is
	   enough padding */
	if (transform_hip_suite == HIP_HIP_AES_SHA1) {
		int remainder = host_id_in_enc_len % 16;
		if (remainder) {
			HIP_DEBUG("Remainder %d (for AES)\n", remainder);
			host_id_in_enc_len += remainder;
		}
	}

	_HIP_HEXDUMP("hostidinmsg", host_id_in_enc,
		    hip_get_param_total_len(host_id_in_enc));
	_HIP_HEXDUMP("encinmsg", enc_in_msg,
		    hip_get_param_total_len(enc_in_msg));
	HIP_HEXDUMP("enc key", &ctx->hip_enc_out.key, HIP_MAX_KEY_LEN);
	_HIP_HEXDUMP("IV", iv, 16); // or 8
	HIP_DEBUG("host id type: %d\n",
		  hip_get_host_id_algo((struct hip_host_id *)host_id_in_enc));
	_HIP_HEXDUMP("hostidinmsg 2", host_id_in_enc, x);

	HIP_IFEL(hip_crypto_encrypted(host_id_in_enc, iv,
				      transform_hip_suite,
				      host_id_in_enc_len,
				      &ctx->hip_enc_out.key,
				      HIP_DIRECTION_ENCRYPT), -1, 
		 "Building of param encrypted failed\n");

	_HIP_HEXDUMP("encinmsg 2", enc_in_msg,
		     hip_get_param_total_len(enc_in_msg));
	_HIP_HEXDUMP("hostidinmsg 2", host_id_in_enc, x);

        /* Now that almost everything is set up except the signature, we can
	 * try to set up inbound IPsec SA, similarly as in hip_create_r2 */

	HIP_DEBUG("src %d, dst %d\n", r1_info->src_port, r1_info->dst_port);


	/* let the setup routine give us a SPI. */
	HIP_IFEL(hip_add_sa(r1_saddr, r1_daddr,
			    &ctx->input->hits, &ctx->input->hitr,
			    &spi_in, transform_esp_suite, 
			    &ctx->esp_in, &ctx->auth_in, 0,
			    HIP_SPI_DIRECTION_IN, 0,
			    r1_info->src_port, r1_info->dst_port), -1, 
		 "Failed to setup IPsec SPD/SA entries, peer:src\n");
	/* XXX: -EAGAIN */
	HIP_DEBUG("set up inbound IPsec SA, SPI=0x%x (host)\n", spi_in);

	HIP_IFEL(hip_setup_hit_sp_pair(&ctx->input->hits,
				       &ctx->input->hitr,
				       r1_saddr, r1_daddr, IPPROTO_ESP, 1, 1), -1,
		 "Setting up SP pair failed\n");

 	esp_info = hip_get_param(i2, HIP_PARAM_ESP_INFO);
 	HIP_ASSERT(esp_info); /* Builder internal error */
	esp_info->new_spi = htonl(spi_in);
	/* LSI not created, as it is local, and we do not support IPv4 */


	/* Check if the incoming R1 has a REG_REQUEST parameter. */

	/* Add service types to which the current machine wishes to
	   register into the outgoing I2 packet. Each service type
	   should check here if the current machines hadb is in correct
	   state regarding to registering. This state is set before
	   sending the I1 packet to peer (registrar). */

	/** @todo This is just a temporary kludge until something more 
	    elegant is build. Rationalize this. */

#ifdef CONFIG_HIP_RVS	
	/* RVS */
	/* Check that we have requested rvs service and that the 
	   peer is rvs capable. */
	if ((entry->local_controls & HIP_PSEUDO_CONTROL_REQ_RVS) &&
	    (entry->peer_controls & HIP_CONTROL_RVS_CAPABLE)){
		HIP_DEBUG_HIT("HIT being registered to rvs", &i2->hits);
		request_rvs = 1;
		type_count++;
	}
#endif /* CONFIG_HIP_RVS */
#ifdef CONFIG_HIP_ESCROW	
	/* ESCROW */
	HIP_KEA *kea;
	kea = hip_kea_find(&entry->hit_our);
	if (kea && kea->keastate == HIP_KEASTATE_REGISTERING) {
		request_escrow = 1;
		type_count++;
	}
	if (kea) {
		hip_keadb_put_entry(kea);
	}
#endif /* CONFIG_HIP_ESCROW */

	/* Have to use malloc() here, otherwise the macros will
	   "jump into scope of identifier with variably modified type". */
	int *reg_type = NULL;
	HIP_IFEL(!(reg_type = HIP_MALLOC(type_count * sizeof(int), 0)),
		 -ENOMEM, "Not enough memory to rvs_addresses.");

	if(type_count == 2){
		reg_type[0] = HIP_ESCROW_SERVICE;
		reg_type[1] = HIP_RENDEZVOUS_SERVICE;
	}
	else if(request_escrow){
		reg_type[0] = HIP_ESCROW_SERVICE;
	}
	else if(request_rvs){
		reg_type[0] = HIP_RENDEZVOUS_SERVICE;
	}
		
	if (type_count > 0) {
		HIP_DEBUG("Adding REG_REQUEST parameter with %d reg types.\n", type_count);
		HIP_IFEL(hip_build_param_reg_request(
				 i2, 0, reg_type, type_count, 1),
			 -1, "Could not build REG_REQUEST parameter\n");
	}
		
	/********** ECHO_RESPONSE_SIGN (OPTIONAL) **************/
	/* must reply... */
	{
		struct hip_echo_request *ping;

		ping = hip_get_param(ctx->input, HIP_PARAM_ECHO_REQUEST_SIGN);
		if (ping) {
			int ln = hip_get_param_contents_len(ping);
			HIP_IFEL(hip_build_param_echo(i2, ping + 1, ln, 1, 0), -1, 
				 "Error while creating echo reply parameter\n");
		}
	}

	/************* HMAC ************/
	HIP_IFEL(hip_build_param_hmac_contents(i2, &ctx->hip_hmac_out),
		 -1, "Building of HMAC failed\n");

	/********** Signature **********/
	/* Build a digest of the packet built so far. Signature will
	   be calculated over the digest. */
	HIP_IFEL(entry->sign(entry->our_priv, i2), -EINVAL, "Could not create signature\n");

	/********** ECHO_RESPONSE (OPTIONAL) ************/
	/* must reply */
	{
		struct hip_echo_request *ping;

		ping = hip_get_param(ctx->input, HIP_PARAM_ECHO_REQUEST);
		if (ping) {
			int ln = hip_get_param_contents_len(ping);
			HIP_IFEL(hip_build_param_echo(i2, (ping + 1), ln, 0, 0), -1, "Error while creating echo reply parameter\n");
		}
	}

      	/********** I2 packet complete **********/
	memset(&spi_in_data, 0, sizeof(struct hip_spi_in_item));
	spi_in_data.spi = spi_in;
	spi_in_data.ifindex = hip_devaddr2ifindex(r1_daddr);
	HIP_LOCK_HA(entry);
	HIP_IFEB(hip_hadb_add_spi(entry, HIP_SPI_DIRECTION_IN, &spi_in_data), -1, HIP_UNLOCK_HA(entry));

	entry->esp_transform = transform_esp_suite;
	
	/* Store the keys until we receive R2 */
	HIP_IFEB(hip_store_base_exchange_keys(entry, ctx, 1), -1, HIP_UNLOCK_HA(entry));

	/* todo: Also store the keys that will be given to ESP later */
	HIP_IFE(hip_hadb_get_peer_addr(entry, &daddr), -1); 

	/* State E1: Receive R1, process. If successful, send I2 and go to E2.
	   No retransmission here, the packet is sent directly because this
	   is the last packet of the base exchange. */
	
	/* If the peer is behind a NAT, UDP is used. */
	if(entry->nat_mode) {
		/* Destination port of R1 becomes the source port of I2, and the
		   destination port of I2 is set as 50500. */
		/** @todo Source port should be NAT-P'. */
		HIP_IFEL(entry->hadb_xmit_func->
			 hip_send_udp(r1_daddr, &daddr, r1_info->dst_port, 
				      HIP_NAT_UDP_PORT, i2, entry, 0),
			 -ECOMM, "Sending I2 packet on UDP failed.\n");
	}
	/* If there's no NAT between, raw HIP is used. */
	else {
		HIP_IFEL(entry->hadb_xmit_func->
			 hip_send_raw(r1_daddr, &daddr, 0, 0, i2, entry, 0),
			 -ECOMM, "Sending I2 packet on raw HIP failed.\n");
	}

 out_err:
	if (i2)
		HIP_FREE(i2);
	if (dh_data)
		HIP_FREE(dh_data);
	if (reg_type)
		HIP_FREE(reg_type);

	return err;
}

/**
 * Handles an incoming R1 packet.
 *
 * Handles an incoming R1 packet and calls hip_create_i2() if the R1 packet
 * passes all tests.
 *
 * @param r1       a pointer to the received R1 HIP packet common header with
 *                 source and destination HITs.
 * @param r1_saddr a pointer to the source address from where the R1 packet was
 *                 received.
 * @param r1_daddr a pointer to the destination address where to the R1 packet
 *                 was sent to (own address).
 * @param entry    a pointer to the current host association database state.
 * @param r1_info  a pointer to the source and destination ports (when NAT is
 *                 in use).
 * @return         zero on success, or negative error value on error.
 * @todo           When rendezvous service is used, the I1 packet is relayed
 *                 to the responder via the rendezvous server. Responder then
 *                 replies directly to the initiator with an R1 packet that has
 *                 a @c VIA_RVS parameter. This parameter contains the IP
 *                 addresses of the travesed RVSes (usually just one). The
 *                 initiator should store these addresses to cope with the
 *                 double jump problem.
 */
int hip_handle_r1(struct hip_common *r1,
		  struct in6_addr *r1_saddr,
		  struct in6_addr *r1_daddr,
		  hip_ha_t *entry,
		  struct hip_stateless_info *r1_info)
{
	HIP_DEBUG("hip_handle_r1() invoked.\n");
	HIP_DUMP_MSG(r1);
	int err = 0, retransmission = 0;
	uint64_t solved_puzzle;
	uint64_t I;

	struct hip_context *ctx = NULL;
	struct hip_host_id *peer_host_id;
	struct hip_r1_counter *r1cntr;

	struct hip_reg_info *reg_info;

	if (entry->state == HIP_STATE_I2_SENT) {
		HIP_DEBUG("Retransmission\n");
		retransmission = 1;
	} else {
		HIP_DEBUG("Not a retransmission\n");
	}

	HIP_DEBUG("\n");
	HIP_IFEL(!(ctx = HIP_MALLOC(sizeof(struct hip_context), GFP_KERNEL)), -ENOMEM,
		 "Could not allocate memory for context\n");
	memset(ctx, 0, sizeof(struct hip_context));
	ctx->input = r1;

	/* according to the section 8.6 of the base draft, we must first check
	   signature. */
	
	/* Store the peer's public key to HA and validate it */
	/** @todo Do not store the key if the verification fails. */
	HIP_IFEL(!(peer_host_id = hip_get_param(r1, HIP_PARAM_HOST_ID)), -ENOENT,
		 "No HOST_ID found in R1\n");
	HIP_IFE(hip_init_peer(entry, r1, peer_host_id), -EINVAL); 
	HIP_IFEL(entry->verify(entry->peer_pub, r1), -EINVAL,
		 "Verification of R1 signature failed\n");

	/* Check if the incoming R1 has a REG_INFO parameter. */
	reg_info = hip_get_param(r1, HIP_PARAM_REG_INFO);

	if (reg_info) {
		int i;
		uint8_t current_reg_type = 0;
		uint8_t size_of_lifetimes = sizeof(reg_info->min_lifetime)
			+ sizeof(reg_info->max_lifetime);
		int typecount;
	
		/* Registration types begin after "Min Lifetime" and "Max
		   Lifetime" fields. */
		uint8_t *reg_types = (uint8_t *)
			(hip_get_param_contents_direct(reg_info)) + size_of_lifetimes;

		typecount = hip_get_param_contents_len(reg_info) - size_of_lifetimes;

		/* Check draft-ietf-hip-registration-02 chapter 3.1. */
		if(typecount == 0){
			HIP_DEBUG("REG_INFO had no services listed.\n");
			HIP_INFO("Responder is currently unable to provide "\
				 "services due to transient conditions.\n");
		}

		HIP_DEBUG("Responder offers %d %s.\n", typecount,
			  (typecount == 1) ? "service" : "services");
		HIP_HEXDUMP("Reg types are (one byte each): ", reg_types, typecount);

		/* Loop through all the registration types found in REG_INFO parameter. */ 
		for(i = 0; i < typecount; i++){
			current_reg_type = reg_types[i];
			
			switch(current_reg_type){
#ifdef CONFIG_HIP_ESCROW
			case HIP_ESCROW_SERVICE:
				HIP_INFO("Responder offers escrow service.\n");
						
				HIP_KEA *kea;
				kea = hip_kea_find(&entry->hit_our);
				if (kea && kea->keastate == HIP_KEASTATE_REGISTERING) {
					HIP_DEBUG("Registering to escrow service.\n");
				} 
				else if(kea){
					kea->keastate = HIP_KEASTATE_INVALID;
					HIP_DEBUG("Not doing escrow registration, "\
						  "invalid kea state.\n");
				}
				else{
					HIP_DEBUG("Not doing escrow registration.\n");
				}

				break;
#endif /* CONFIG_HIP_ESCROW */
#ifdef CONFIG_HIP_RVS
			case HIP_RENDEZVOUS_SERVICE:
				HIP_INFO("Responder offers rendezvous service.\n");
				/** @todo Check if we have requested for
				    rendezvous service in I1 packet. */
				break;
#endif /* CONFIG_HIP_RVS */
			default:
				HIP_INFO("Responder offers unsupported service.\n");
			}
		}
	}
#ifdef CONFIG_HIP_ESCROW
	else {
		/* No REG_INFO parameter found. Cancelling registration attempt. */
		HIP_DEBUG("No REG_INFO found in R1: no services available \n");
		HIP_KEA *kea;
		kea = hip_kea_find(&entry->hit_our);
		if (kea && (kea->keastate == HIP_KEASTATE_REGISTERING))
			kea->keastate = HIP_KEASTATE_INVALID;
	}
#endif /* CONFIG_HIP_ESCROW */

	/* R1 generation check */

	/* we have problems with creating precreated R1s in reasonable
	   fashion... so we don't mind about generations */
	r1cntr = hip_get_param(r1, HIP_PARAM_R1_COUNTER);

	/* Do control bit stuff here... */

	/* We must store the R1 generation counter, _IF_ it exists */
	if (r1cntr) {
		HIP_DEBUG("Storing R1 generation counter\n");
		HIP_LOCK_HA(entry);
		entry->birthday = r1cntr->generation;
		HIP_UNLOCK_HA(entry);
	}

	/* solve puzzle: if this is a retransmission, we have to preserve
	   the old solution */
	if (!retransmission) {
		struct hip_puzzle *pz = NULL;

		HIP_IFEL(!(pz = hip_get_param(r1, HIP_PARAM_PUZZLE)), -EINVAL,
			 "Malformed R1 packet. PUZZLE parameter missing\n");
		HIP_IFEL((solved_puzzle =
			  entry->hadb_misc_func->hip_solve_puzzle(pz, r1, HIP_SOLVE_PUZZLE)) == 0, 
			 -EINVAL, "Solving of puzzle failed\n");
		I = pz->I;
		entry->puzzle_solution = solved_puzzle;
		entry->puzzle_i = pz->I;
	} else {
		I = entry->puzzle_i;
		solved_puzzle = entry->puzzle_solution;
	}

	/* calculate shared secret and create keying material */
	ctx->dh_shared_key = NULL;
	/* note: we could skip keying material generation in the case
	   of a retransmission but then we'd had to fill ctx->hmac etc */
	HIP_IFEL(entry->hadb_misc_func->hip_produce_keying_material(r1, ctx, I,
								solved_puzzle),
			 -EINVAL, "Could not produce keying material\n");

	/* Everything ok, save host id to HA */
	{
		char *str;
		int len;
		HIP_IFE(hip_get_param_host_id_di_type_len(peer_host_id, &str, &len) < 0, -1);
		HIP_DEBUG("Identity type: %s, Length: %d, Name: %s\n",
			  str, len, hip_get_param_host_id_hostname(peer_host_id));
	}

	entry->peer_controls = ntohs(r1->control);
 	HIP_IFEL(entry->hadb_misc_func->hip_create_i2(ctx, solved_puzzle, r1_saddr, r1_daddr, entry, r1_info), -1, 
		 "Creation of I2 failed\n");

	if (entry->state == HIP_STATE_I1_SENT) {
		entry->state = HIP_STATE_I2_SENT;
	}

 out_err:
	if (ctx->dh_shared_key)
		HIP_FREE(ctx->dh_shared_key);
	if (ctx)
		HIP_FREE(ctx);
	return err;
}

/**
 * Determines the action to be executed for an incoming R1 packet.
 *
 * This function is called when a HIP control packet is received by
 * hip_receive_control_packet()-function and the packet is detected to be
 * a R1 packet. First it is checked, if the corresponding I1 packet has
 * been sent. If yes, then the received R1 packet is handled in
 * hip_handle_r1(). The R1 packet is handled also in @c HIP_STATE_ESTABLISHED.
 * Otherwise the packet is dropped and not handled in any way.
 * 
 * @param r1       a pointer to the received I1 HIP packet common header with
 *                 source and destination HITs.
 * @param r1_saddr a pointer to the source address from where the R1 packet
 *                 was received.
 * @param i1_daddr a pointer to the destination address where to the R1 packet
 *                 was sent to (own address).
 * @param entry    a pointer to the current host association database state.
 * @param r1_info  a pointer to the source and destination ports (when NAT is
 *                 in use).
 * @return         zero on success, or negative error value on error.
 * @warning        This code does not work correctly if there are @b both
 *                 @c FROM and @c FROM_NAT parameters in the incoming I1 packet.
 */
int hip_receive_r1(struct hip_common *r1,
		   struct in6_addr *r1_saddr,
		   struct in6_addr *r1_daddr,
		   hip_ha_t *entry,
		   struct hip_stateless_info *r1_info)
{
	HIP_DEBUG("hip_receive_r1() invoked.\n");
	int state, mask = HIP_CONTROL_HIT_ANON, err = 0;

#ifdef CONFIG_HIP_RVS
	mask |= HIP_CONTROL_RVS_CAPABLE; /** @todo: Fix this kludge. */
#endif
	if (ipv6_addr_any(&r1->hitr)) {
		HIP_DEBUG("Received NULL receiver HIT in R1. Not dropping\n");
	}

 	HIP_IFEL(!hip_controls_sane(ntohs(r1->control), mask), 0, 
		 "Received illegal controls in R1: 0x%x Dropping\n",
		 ntohs(r1->control));
	HIP_IFEL(!entry, -EFAULT, 
		 "Received R1 with no local state. Dropping\n");
	/* An implicit and insecure REA. If sender's address is different than
	 * the one that was mapped, then we will overwrite the mapping with
	 * the newer address.
	 * This enables us to use the rendezvous server, while not supporting
	 * the REA TLV.
	 */
	{
		struct in6_addr daddr;
		
		hip_hadb_get_peer_addr(entry, &daddr);
		if (ipv6_addr_cmp(&daddr, r1_saddr) != 0) {
			HIP_DEBUG("Mapped address didn't match received address\n");
			HIP_DEBUG("Assuming that the mapped address was actually RVS's.\n");
			HIP_HEXDUMP("Mapping", &daddr, 16);
			HIP_HEXDUMP("Received", r1_saddr, 16);
			hip_hadb_delete_peer_addrlist_one(entry, &daddr);
			hip_hadb_add_peer_addr(entry, r1_saddr, 0, 0,
					       PEER_ADDR_STATE_ACTIVE);
		}
	}

	/* since the entry is in the hit-list and since the previous
	 * function increments by one, we must have at least 2 references
	 */
	HIP_ASSERT(atomic_read(&entry->refcnt) >= 2);

	/* I hope wmb() takes care of the locking needs */
	wmb();
	state = entry->state;
	
	HIP_DEBUG("Received R1 in state %s\n", hip_state_str(state));
	switch(state) {
	case HIP_STATE_I1_SENT:
	case HIP_STATE_I2_SENT:
	case HIP_STATE_CLOSING:
	case HIP_STATE_CLOSED:
		/* E1. The normal case. Process, send I2, goto E2. */
		err = entry->hadb_handle_func->hip_handle_r1(r1, r1_saddr, r1_daddr, entry, r1_info);
		HIP_LOCK_HA(entry);
		if (err < 0)
			HIP_ERROR("Handling of R1 failed\n");
		HIP_UNLOCK_HA(entry);
		break;
	case HIP_STATE_R2_SENT:
	case HIP_STATE_ESTABLISHED:
		break;
	case HIP_STATE_NONE:
	case HIP_STATE_UNASSOCIATED:
	default:
		/* Can't happen. */
		err = -EFAULT;
		HIP_ERROR("R1 received in odd state: %d. Dropping.\n", state); 
		break;
	}

	hip_put_ha(entry);
 out_err:
	return err;
}

/**
 * hip_create_r2 - Creates and transmits R2 packet.
 * @param ctx Context of processed I2 packet.
 * @param entry HA
 *
 * @return 0 on success, < 0 on error.
 */
int hip_create_r2(struct hip_context *ctx,
		  struct in6_addr *i2_saddr,
		  struct in6_addr *i2_daddr,
		  hip_ha_t *entry,
		  struct hip_stateless_info *i2_info)
{
	HIP_DEBUG("hip_create_r2() invoked.\n");
	uint32_t spi_in;
 	struct hip_common *r2 = NULL, *i2;
 	int err = 0, clear = 0;
	uint16_t mask = 0;
#ifdef CONFIG_HIP_RVS
	int create_rva = 0;
#endif
	/* Assume already locked entry */
	i2 = ctx->input;

	/* Build and send R2: IP ( HIP ( SPI, HMAC, HIP_SIGNATURE ) ) */
	HIP_IFEL(!(r2 = hip_msg_alloc()), -ENOMEM, "No memory for R2\n");

	/* Just swap the addresses to use the I2's destination HIT as
	 * the R2's source HIT */
	entry->hadb_misc_func->
		hip_build_network_hdr(r2, HIP_R2, mask, &entry->hit_our,
				      &entry->hit_peer);

 	/********** ESP_INFO **********/
	//barrier();
	spi_in = hip_hadb_get_latest_inbound_spi(entry);
	HIP_IFEL(hip_build_param_esp_info(r2, ctx->esp_keymat_index,
					  0, spi_in), -1,
		 "building of ESP_INFO failed.\n");

	/* Check if the incoming I2 has a REG_REQUEST parameter. */

	HIP_DEBUG("Checking I2 for REG_REQUEST parameter.\n");
	HIP_DUMP_MSG(i2);

	uint8_t lifetime;
	struct hip_reg_request *reg_request;
	reg_request = hip_get_param(i2, HIP_PARAM_REG_REQUEST);
				
	if (reg_request) {
		HIP_DEBUG("Found REG_REQUEST parameter.\n");

		int *accepted_requests, *rejected_requests;
		int request_count, my_request_count, accepted_count, rejected_count;
		uint8_t *types = (uint8_t *)(hip_get_param_contents(i2, HIP_PARAM_REG_REQUEST));
			
		/** @todo - sizeof(reg_request->lifetime) instead of - 1 ?*/
		request_count = hip_get_param_contents_len(reg_request) - 1; // leave out lifetime field
		my_request_count = hip_get_param_contents_len(reg_request)
			- sizeof(reg_request->lifetime); // leave out lifetime field
			
		HIP_DEBUG("request_count: %d\n", request_count);
		HIP_DEBUG("my_request_count: %d\n", my_request_count);

		accepted_count = hip_check_service_requests(&entry->hit_our, (types + 1),
							    request_count, &accepted_requests,
							    &rejected_requests);
		rejected_count = request_count - accepted_count;
			
		HIP_DEBUG("Accepted %d, rejected: %d\n", accepted_count, rejected_count);
		if (accepted_count > 0) {
			lifetime = reg_request->lifetime;
			HIP_DEBUG("Building REG_RESPONSE parameter.\n");
			HIP_IFEL(hip_build_param_reg_request(r2, lifetime, accepted_requests, 
							     accepted_count, 0), -1, "Building of REG_RESPONSE failed\n");
		}
		if (rejected_count > 0) {
			lifetime = reg_request->lifetime;
			HIP_DEBUG("Building REG_FAILED parameter");
			HIP_IFEL(hip_build_param_reg_failed(r2, 1, rejected_requests, 
							    rejected_count), -1, "Building of REG_FAILED failed\n");
		}
	}
	else {
		HIP_DEBUG("No REG_REQUEST found in I2.\n");
	}	

 	/* HMAC2 */
	{
		struct hip_crypto_key hmac;
		if (entry->our_pub == NULL) HIP_DEBUG("entry->our_pub is null\n");
		else HIP_HEXDUMP("host id for HMAC2", entry->our_pub,
			    hip_get_param_total_len(entry->our_pub));

		memcpy(&hmac, &entry->hip_hmac_out, sizeof(hmac));
		HIP_IFEL(hip_build_param_hmac2_contents(r2, &hmac, entry->our_pub), -1,
			 "Building of hmac failed\n");
	}

	HIP_IFEL(entry->sign(entry->our_priv, r2), -EINVAL, "Could not sign R2. Failing\n");

 	/* If the peer is behind a NAT, UDP is used. */
	if(entry->nat_mode) {
		HIP_IFEL(entry->hadb_xmit_func->
			 hip_send_udp(i2_daddr, i2_saddr, HIP_NAT_UDP_PORT,
				      entry->peer_udp_port, r2, entry, 0),
			 -ECOMM, "Sending R2 packet on UDP failed.\n");
	}
	/* If there's no NAT between, raw HIP is used. */
	else {
		/** @todo remove ports. */
		HIP_IFEL(entry->hadb_xmit_func->
			 hip_send_raw(i2_daddr, i2_saddr, 0, 0, r2, entry, 0),
			 -ECOMM, "Sending R2 packet on raw HIP failed.\n");
	}

#ifdef CONFIG_HIP_ESCROW
	// Add escrow association to database
	// TODO: definition
	HIP_KEA *kea;	
	HIP_IFE(!(kea = hip_kea_create(&entry->hit_peer, GFP_KERNEL)), -1);
	HIP_HEXDUMP("Created kea base entry with peer hit: ", &entry->hit_peer, 16);
	kea->keastate = HIP_KEASTATE_VALID;
	HIP_IFEBL(hip_keadb_add_entry(kea), -1, hip_keadb_put_entry(kea), 
		"Error while inserting KEA to keatable");
	HIP_DEBUG("Added kea entry");
#endif /* CONFIG_HIP_ESCROW */
#ifdef CONFIG_HIP_RVS
	/* Insert rendezvous association with appropriate xmit-function to
	   rendezvous database. */
	/** @todo Insert only if REG_REQUEST parameter with Reg Type
	    RENDEZVOUS was received. */
	HIP_RVA *rva;
	if(entry->nat_mode) {
		HIP_IFE(!(rva =
			  hip_rvs_ha2rva(entry,
					 entry->hadb_xmit_func->hip_send_udp)),
			-ENOSYS);
	}
	else {
		HIP_IFE(!(rva =
			  hip_rvs_ha2rva(entry,
					 entry->hadb_xmit_func->hip_send_raw)),
			-ENOSYS);
	}
	HIP_IFEBL(hip_rvs_put_rva(rva), -1, hip_put_rva(rva),
		  "Error while inserting RVA into hash table\n");
#endif /* CONFIG_HIP_RVS */

 out_err:
	if (r2)
		HIP_FREE(r2);
	if (clear && entry) {/* Hmm, check */
		HIP_ERROR("TODO: about to do hip_put_ha, should this happen here ?\n");
		hip_put_ha(entry);
	}
	return err;
}

/**
 * hip_handle_i2 - handle incoming I2 packet
 * @param skb sk_buff where the HIP packet is in
 * @param ha HIP HA corresponding to the peer
 *
 * This function is the actual point from where the processing of I2
 * is started and corresponding R2 is created.
 *
 * On success (I2 payloads are checked and R2 is created and sent) 0 is
 * returned, otherwise < 0.
 */
int hip_handle_i2(struct hip_common *i2,
		  struct in6_addr *i2_saddr,
		  struct in6_addr *i2_daddr,		  
		  hip_ha_t *ha,
		  struct hip_stateless_info *i2_info)
{
	HIP_DEBUG("hip_handle_i2() invoked.\n");
	int err = 0, retransmission = 0, replay = 0;
	struct hip_context *ctx = NULL;
 	struct hip_tlv_common *param;
	char *tmp_enc = NULL, *enc = NULL;
	unsigned char *iv;
	struct hip_host_id *host_id_in_enc = NULL;
	struct hip_r1_counter *r1cntr;
	struct hip_esp_info *esp_info = NULL;
	hip_ha_t *entry = ha;
	hip_transform_suite_t esp_tfm, hip_tfm;
	uint32_t spi_in, spi_out;
	uint16_t crypto_len;
	struct hip_spi_in_item spi_in_data;
	uint64_t I, J;

 	HIP_DEBUG("\n");

	/* Assume already locked ha, if ha is not NULL */
	HIP_IFEL(!(ctx = HIP_MALLOC(sizeof(struct hip_context), 0)), -ENOMEM,
		 "Alloc failed\n");
	memset(ctx, 0, sizeof(struct hip_context));

	/* Check packet validity */
	/* We MUST check that the responder HIT is one of ours. */
	/* check the generation counter */
	/* We do not support generation counter (our precreated R1s suck) */
	ctx->input = i2;
	r1cntr = hip_get_param(ctx->input, HIP_PARAM_R1_COUNTER);

	/* check solution for cookie */
	{
		struct hip_solution *sol;
		HIP_IFEL(!(sol = hip_get_param(ctx->input, HIP_PARAM_SOLUTION)), -EINVAL,
			 "Invalid I2: SOLUTION parameter missing\n");
		I = sol->I;
		J = sol->J;
		HIP_IFEL(!hip_verify_cookie(i2_saddr, i2_daddr, i2, sol), -ENOMSG,
			 "Cookie solution rejected\n");
	}

 	HIP_DEBUG("Cookie accepted\n");

	if (entry) {
		/* If the I2 packet is a retransmission, we need reuse
		   the the SPI/keymat that was setup already when the
		   first I2 was received. */
		retransmission = 
			((entry->state == HIP_STATE_R2_SENT ||
			  entry->state == HIP_STATE_ESTABLISHED) ? 1 : 0);
		/* If the initiator is in established state (it has possibly
		   sent duplicate I2 packets), we must make sure that we are
		   reusing the old SPI as the initiator will just drop the
		   R2, thus discarding any new SPIs we create. Notice that
		   this works also in the case when initiator is not in
		   established state, as the initiator just picks up the SPI
		   from the R2. */
		if (entry->state == HIP_STATE_ESTABLISHED)
			spi_in = hip_hadb_get_latest_inbound_spi(entry);
	}

	/* Check HIP and ESP transforms, and produce keying material  */
	ctx->dh_shared_key = NULL;
	/* note: we could skip keying material generation in the case
	   of a retransmission but then we'd had to fill ctx->hmac etc 
	   
	   TH: I'm not sure if this could be replaced with a function pointer
	   which is set from hadb. Usually you shouldn'y have state here, right?*/
	HIP_IFEL(hip_produce_keying_material(ctx->input, ctx, I, J), -1,
		 "Unable to produce keying material. Dropping I2\n");

	/* verify HMAC */
	HIP_IFEL(hip_verify_packet_hmac(i2, &ctx->hip_hmac_in), -ENOENT,
		 "HMAC validation on i2 failed\n");
	
	/* decrypt the HOST_ID and verify it against the sender HIT */
	HIP_IFEL(!(enc = hip_get_param(ctx->input, HIP_PARAM_ENCRYPTED)),
		 -ENOENT, "Could not find enc parameter\n");

	HIP_IFEL(!(tmp_enc = HIP_MALLOC(hip_get_param_total_len(enc),
					GFP_KERNEL)), -ENOMEM,
		 "No memory for temporary host_id\n");

	/* little workaround...
	 * We have a function that calculates sha1 digest and then verifies the
	 * signature. But since the sha1 digest in I2 must be calculated over
	 * the encrypted data, and the signature requires that the encrypted
	 * data to be decrypted (it contains peer's host identity),
	 * we are forced to do some temporary copying...
	 * If ultimate speed is required, then calculate the digest here as
	 * usual and feed it to signature verifier. 
	 */
	memcpy(tmp_enc, enc, hip_get_param_total_len(enc));

	/* Decrypt ENCRYPTED field*/
	_HIP_HEXDUMP("Recv. Key", &ctx->hip_enc_in.key, 24);
	HIP_IFEL(!(param = hip_get_param(ctx->input, HIP_PARAM_HIP_TRANSFORM)), 
		 -ENOENT, "Did not find HIP transform\n");
	HIP_IFEL((hip_tfm = hip_get_param_transform_suite_id(param, 0)) == 0,
		 -EFAULT, "Bad HIP transform\n");

	switch (hip_tfm) {
	case HIP_HIP_AES_SHA1:
 		host_id_in_enc = (struct hip_host_id *)
		  (tmp_enc + sizeof(struct hip_encrypted_aes_sha1));
 		iv = ((struct hip_encrypted_aes_sha1 *) tmp_enc)->iv;
 		/* 4 = reserved, 16 = iv */
 		crypto_len = hip_get_param_contents_len(enc) - 4 - 16;
		HIP_DEBUG("aes crypto len: %d\n", crypto_len);
		break;
	case HIP_HIP_3DES_SHA1:
 		host_id_in_enc = (struct hip_host_id *)
		  (tmp_enc + sizeof(struct hip_encrypted_3des_sha1));
 		iv = ((struct hip_encrypted_3des_sha1 *) tmp_enc)->iv;
 		/* 4 = reserved, 8 = iv */
 		crypto_len = hip_get_param_contents_len(enc) - 4 - 8;
		break;
	case HIP_HIP_NULL_SHA1:
		host_id_in_enc = (struct hip_host_id *)
			(tmp_enc + sizeof(struct hip_encrypted_null_sha1));
 		iv = NULL;
 		/* 4 = reserved */
 		crypto_len = hip_get_param_contents_len(enc) - 4;
		break;
	default:
		HIP_IFEL(1, -EINVAL, "Unknown HIP transform: %d\n", hip_tfm);
	}

	HIP_DEBUG("Crypto encrypted\n");
	_HIP_HEXDUMP("IV: ", iv, 16); /* Note: iv can be NULL */
	
	HIP_IFEL(hip_crypto_encrypted(host_id_in_enc, iv, hip_tfm,
				      crypto_len, &ctx->hip_enc_in.key,
				      HIP_DIRECTION_DECRYPT), -EINVAL,
		 "Decryption of Host ID failed\n");
	HIP_IFEL(hip_get_param_type(host_id_in_enc) != HIP_PARAM_HOST_ID, -EINVAL,
		 "The decrypted parameter is not a host id\n");

	HIP_HEXDUMP("Decrypted HOST_ID", host_id_in_enc,
		     hip_get_param_total_len(host_id_in_enc));

	/* HMAC cannot be validated until we draw key material */

	/* NOTE! The original packet has the data still encrypted. But this is
	 * not a problem, since we have decrypted the data into a temporary
	 * storage and nobody uses the data in the original packet.
	 */

	/* Create host association state (if not previously done). */
	if (!entry) {
		int if_index;
		struct sockaddr_storage ss_addr;
		struct sockaddr *addr;
		addr = (struct sockaddr*) &ss_addr;
		/* we have no previous infomation on the peer, create
		   a new HIP HA */
		HIP_DEBUG("No entry, creating new\n");
		HIP_IFEL(!(entry = hip_hadb_create_state(GFP_KERNEL)), -ENOMSG,
			 "Failed to create or find entry\n");

		/* the rest of the code assume already locked entry,
		   so lock the newly created entry as well */
		HIP_LOCK_HA(entry);
		ipv6_addr_copy(&entry->hit_peer, &i2->hits);
		/* ipv6_addr_copy(&entry->hit_our, &i2->hitr); */
		hip_init_us(entry, &i2->hitr);

		ipv6_addr_copy(&entry->local_address, i2_daddr);
		HIP_IFEL(!(if_index = hip_devaddr2ifindex(&entry->local_address)), -1, 
			 "if_index NOT determined\n");

		memset(addr, 0, sizeof(struct sockaddr_storage));
		addr->sa_family = AF_INET6;
		memcpy(SA2IP(addr), &entry->local_address, SAIPLEN(addr));
		add_address_to_list(addr, if_index);
                /* if_index = addr2ifindx(entry->local_address); */

		/* If the incoming I2 packet has a source other than zero, we
		   set "on" the NAT state of current machine (the responder)
		   and store the source port of the incoming I2 packet. This
		   port is the NAT-P' of [draft-schmitt-hip-nat-traversal-01]
		   section 3.3.1. */
		/** @todo This is a temporary fix. Need to think on this a bit.
		    Add other info here. --Abi */
		if(i2_info->src_port != 0)
		{
			entry->nat_mode = 1;
			entry->peer_udp_port = i2_info->src_port;
		}

		hip_hadb_insert_state(entry);
		hip_hold_ha(entry);

		_HIP_DEBUG("HA entry created.");
	}
	entry->hip_transform = hip_tfm;
	
	/** @todo the above should not be done if signature fails...
	    or it should be cancelled. */
	
	/* Store peer's public key and HIT to HA */
	HIP_IFEL(hip_init_peer(entry, i2, host_id_in_enc), -EINVAL,
		 "init peer failed\n");		

	/* Validate signature */
	HIP_IFEL(entry->verify(entry->peer_pub, ctx->input), -EINVAL,
		 "Verification of I2 signature failed\n");

	/* If we have old SAs with these HITs delete them */
	hip_hadb_delete_inbound_spi(entry, 0);
	hip_hadb_delete_outbound_spi(entry, 0);
	{
		struct hip_esp_transform *esp_tf;
		struct hip_spi_out_item spi_out_data;

		HIP_IFEL(!(esp_tf = hip_get_param(ctx->input,
						  HIP_PARAM_ESP_TRANSFORM)),
			 -ENOENT, "Did not find ESP transform on i2\n");
		HIP_IFEL(!(esp_info = hip_get_param(ctx->input,
						    HIP_PARAM_ESP_INFO)),
			 -ENOENT, "Did not find SPI LSI on i2\n");

		if (r1cntr)
			entry->birthday = r1cntr->generation;
		entry->peer_controls |= ntohs(i2->control);
		// FIXME: why these are here? tkoponen... HA is found
		// by XOR(src_hit, dst_hit) soon, no need to write
		// again.
		//ipv6_addr_copy(&entry->hit_our, &i2->hitr);
		//ipv6_addr_copy(&entry->hit_peer, &i2->hits);

		/* move this below setup_sa */
		memset(&spi_out_data, 0, sizeof(struct hip_spi_out_item));
		spi_out_data.spi = ntohl(esp_info->new_spi);
		HIP_DEBUG("Adding spi 0x%x\n", spi_out_data.spi);
		HIP_IFE(hip_hadb_add_spi(entry, HIP_SPI_DIRECTION_OUT,
					 &spi_out_data), -1);
		entry->esp_transform = hip_select_esp_transform(esp_tf);
		HIP_IFEL((esp_tfm = entry->esp_transform) == 0, -1,
			 "Could not select proper ESP transform\n");
	}

	HIP_IFEL(hip_hadb_add_peer_addr(entry, i2_saddr, 0, 0,
					PEER_ADDR_STATE_ACTIVE), -1,
		 "Error while adding the preferred peer address\n");

	HIP_DEBUG("retransmission: %s\n", (retransmission ? "yes" : "no"));
	HIP_DEBUG("replay: %s\n", (replay ? "yes" : "no"));
	HIP_DEBUG("src %d, dst %d\n", i2_info->src_port, i2_info->dst_port);

	/* Set up IPsec associations */
	err = hip_add_sa(i2_saddr, i2_daddr,
			 &ctx->input->hits, &ctx->input->hitr,
			 &spi_in,
			 esp_tfm,  &ctx->esp_in, &ctx->auth_in,
			 retransmission, HIP_SPI_DIRECTION_IN, 0, i2_info->src_port, 
				i2_info->dst_port);
	if (err) {
		HIP_ERROR("Failed to setup inbound SA with SPI=%d\n", spi_in);
		/* if (err == -EEXIST)
		   HIP_ERROR("SA for SPI 0x%x already exists, this is perhaps a bug\n",
		   spi_in); */
		err = -1;
		hip_hadb_delete_inbound_spi(entry, 0);
		hip_hadb_delete_outbound_spi(entry, 0);
		goto out_err;
	}
	/* XXX: Check -EAGAIN */
	
	/* ok, found an unused SPI to use */
	HIP_DEBUG("set up inbound IPsec SA, SPI=0x%x (host)\n", spi_in);

	spi_out = ntohl(esp_info->new_spi);
	HIP_DEBUG("Setting up outbound IPsec SA, SPI=0x%x\n", spi_out);

	HIP_DEBUG("src %d, dst %d\n", i2_info->src_port, i2_info->dst_port);


	err = hip_add_sa(i2_daddr, i2_saddr,
			 &ctx->input->hitr, &ctx->input->hits,
			 &spi_out, esp_tfm, 
			 &ctx->esp_out, &ctx->auth_out,
			 1, HIP_SPI_DIRECTION_OUT, 0, i2_info->dst_port, i2_info->src_port);
	if (err) {
		HIP_ERROR("Failed to setup outbound SA with SPI=%d\n",
			  spi_out);

         /* HIP_DEBUG("SA already exists for the SPI=0x%x\n", spi_out);
	    HIP_DEBUG("TODO: what to do ? currently ignored\n");
	    } else if (err) {
	    HIP_ERROR("Failed to setup IPsec SPD/SA entries, peer:dst (err=%d)\n", err);
	 */
		/* delete all IPsec related SPD/SA for this entry*/
		hip_hadb_delete_inbound_spi(entry, 0);
		hip_hadb_delete_outbound_spi(entry, 0);
		goto out_err;
	}
	/* XXX: Check if err = -EAGAIN... */
	HIP_DEBUG("set up outbound IPsec SA, SPI=0x%x\n", spi_out);

	HIP_IFEL(hip_setup_hit_sp_pair(&ctx->input->hits,
				       &ctx->input->hitr,
				       i2_saddr, i2_daddr, IPPROTO_ESP, 1, 1),
		 -1, "Setting up SP pair failed\n");

	/* source IPv6 address is implicitly the preferred
	 * address after the base exchange */
	HIP_IFEL(hip_hadb_add_addr_to_spi(entry, spi_out, i2_saddr, 1, 0, 1),
		 -1,  "Failed to add an address to SPI list\n");

	memset(&spi_in_data, 0, sizeof(struct hip_spi_in_item));
	spi_in_data.spi = spi_in;
	spi_in_data.ifindex = hip_devaddr2ifindex(i2_daddr);
	if (spi_in_data.ifindex) {
		HIP_DEBUG("ifindex=%d\n", spi_in_data.ifindex);
	} else
		HIP_ERROR("Couldn't get device ifindex of address\n");

	err = hip_hadb_add_spi(entry, HIP_SPI_DIRECTION_IN, &spi_in_data);
	if (err) {
		HIP_UNLOCK_HA(entry);
		HIP_ERROR("Adding of SPI failed\n");
		goto out_err;
	}

	entry->default_spi_out = spi_out;
	HIP_DEBUG("set default SPI out=0x%x\n", spi_out);

	
	HIP_IFE(hip_store_base_exchange_keys(entry, ctx, 0), -1);

	hip_hadb_insert_state(entry);
	HIP_DEBUG("state %s\n", hip_state_str(entry->state));
	HIP_IFEL(entry->hadb_misc_func->hip_create_r2(ctx, i2_saddr, i2_daddr, entry, i2_info), -1, 
		 "Creation of R2 failed\n");

	/* change SA state from ACQ -> VALID, and wake up sleepers */
	//hip_finalize_sa(&entry->hit_peer, spi_out);
	//hip_finalize_sa(&entry->hit_our, spi_in);

	/* we cannot do this outside (in hip_receive_i2) since we don't have
	   the entry there and looking it up there would be unneccesary waste
	   of cycles */

	HIP_DEBUG("state is %d\n", entry->state);
	
	if (entry) {
		wmb();
#ifdef CONFIG_HIP_RVS
		/* XX FIX: this should be dynamic (the rvs information should
		   be stored in the HADB) instead of static */
		entry->state = HIP_STATE_ESTABLISHED;
#else
		if (entry->state == HIP_STATE_UNASSOCIATED) {
			HIP_DEBUG("TODO: should wait for ESP here or "
				  "wait for implementation specific time, "
				  "moving to ESTABLISHED\n");
			entry->state = HIP_STATE_ESTABLISHED;
		} else if (entry->state == HIP_STATE_ESTABLISHED) {
			HIP_DEBUG("Initiator rebooted, but base exchange completed\n");
			HIP_DEBUG("Staying in ESTABLISHED.\n");
		} else {
			entry->state = HIP_STATE_R2_SENT;
		}
#endif /* CONFIG_HIP_RVS */
	}

	HIP_DEBUG("Reached %s state\n", hip_state_str(entry->state));

 out_err:
	/* ha is not NULL if hip_receive_i2() fetched the HA for us.
	 * In that case we must not release our reference to it.
	 * Otherwise, if 'ha' is NULL, then we created the HIP HA in this
	 * function and we should free the reference.
	 */
	if (!ha && entry) {
		/* unlock the entry created in this function */
		HIP_UNLOCK_HA(entry);
		hip_put_ha(entry);
	}
	if (tmp_enc)
		HIP_FREE(tmp_enc);
	if (ctx->dh_shared_key)
		HIP_FREE(ctx->dh_shared_key);
	if (ctx)
		HIP_FREE(ctx);

	return err;
}

/**
 * hip_receive_i2 - receive I2 packet
 * @param skb sk_buff where the HIP packet is in
 *
 * This is the initial function which is called when an I2 packet is
 * received. If we are in correct state, the packet is handled to
 * hip_handle_i2() for further processing.
 *
 * Returns always 0.
 *
 * TODO: check if it is correct to return always 0 
 */
int hip_receive_i2(struct hip_common *i2,
		   struct in6_addr *i2_saddr,
		   struct in6_addr *i2_daddr,
		   hip_ha_t *entry,
		  struct hip_stateless_info *i2_info)
{
	HIP_DEBUG("hip_receive_i2() invoked.\n");
	int state = 0, err = 0;
	uint16_t mask = HIP_CONTROL_HIT_ANON;
	HIP_IFEL(ipv6_addr_any(&i2->hitr), 0,
		 "Received NULL receiver HIT in I2. Dropping\n");

	HIP_IFEL(!hip_controls_sane(ntohs(i2->control), mask), 0, 
		 "Received illegal controls in I2: 0x%x. Dropping\n",
		 ntohs(i2->control));

	if (!entry) {
		state = HIP_STATE_UNASSOCIATED;
	} else {
		barrier();
		HIP_LOCK_HA(entry);
		state = entry->state;
	}

	HIP_DEBUG("Received I2 in state %s\n", hip_state_str(state));

 	switch(state) {
 	case HIP_STATE_UNASSOCIATED:
		/* possibly no state created yet, entry == NULL */
		err = ((hip_handle_func_set_t *)hip_get_handle_default_func_set())->hip_handle_i2(i2, i2_saddr, i2_daddr, entry, i2_info); //as there is no state established function pointers can't be used here
		break;
	case HIP_STATE_I2_SENT:
		if (hip_hit_is_bigger(&entry->hit_our, &entry->hit_peer)) {
			HIP_DEBUG("Our HIT is bigger\n");
			err = ((hip_handle_func_set_t *)hip_get_handle_default_func_set())->hip_handle_i2(i2, i2_saddr, i2_daddr, entry, i2_info);
		} else {
			HIP_DEBUG("Dropping i2 (two hosts iniating base exchange at the same time?)\n");
		}
		break;
	case HIP_STATE_I1_SENT:
	case HIP_STATE_R2_SENT:
		err = hip_handle_i2(i2, i2_saddr, i2_daddr, entry, i2_info);
 		break;
 	case HIP_STATE_ESTABLISHED:
 		HIP_DEBUG("Received I2 in state ESTABLISHED\n");
		err = entry->hadb_handle_func->hip_handle_i2(i2, i2_saddr,
							     i2_daddr, entry, i2_info);

 		break;
 	case HIP_STATE_CLOSING:
 	case HIP_STATE_CLOSED:
		HIP_DEBUG("Received I2 in state CLOSED/CLOSING\n");
		err = entry->hadb_handle_func->hip_handle_i2(i2, i2_saddr,
							     i2_daddr, entry, i2_info);
		break;
	default:
		HIP_ERROR("Internal state (%d) is incorrect\n", state);
		break;
	}

	if (entry) {
		HIP_UNLOCK_HA(entry);
		hip_put_ha(entry);
	}
 out_err:
	if (err) {
		HIP_ERROR("error (%d) occurred\n", err);
	}

	return err;
}


/**
 * hip_handle_r2 - handle incoming R2 packet
 * @param skb sk_buff where the HIP packet is in
 * @param entry HA
 *
 * This function is the actual point from where the processing of R2
 * is started.
 *
 * On success (payloads are created and IPsec is set up) 0 is
 * returned, otherwise < 0.
 */
int hip_handle_r2(struct hip_common *r2,
		  struct in6_addr *r2_saddr,
		  struct in6_addr *r2_daddr,
		  hip_ha_t *entry,
		  struct hip_stateless_info *r2_info)
{
	HIP_DEBUG("hip_handle_r2() invoked.\n");
	struct hip_context *ctx = NULL;
 	struct hip_esp_info *esp_info = NULL;
	struct hip_spi_out_item spi_out_data;
	int tfm, err = 0;
	uint32_t spi_recvd, spi_in;
	int retransmission = 0;

	if (entry->state == HIP_STATE_ESTABLISHED) {
		retransmission = 1;
		HIP_DEBUG("Retransmission\n");
	} else {
		HIP_DEBUG("Not a retransmission\n");
	}

	/* assume already locked entry */
	HIP_IFE(!(ctx = HIP_MALLOC(sizeof(struct hip_context), GFP_ATOMIC)), -ENOMEM);
	memset(ctx, 0, sizeof(struct hip_context));
        ctx->input = r2;

        /* Verify HMAC */
	HIP_IFEL(hip_verify_packet_hmac2(r2, &entry->hip_hmac_in, entry->peer_pub), -1, 
		 "HMAC validation on R2 failed\n");
	_HIP_DUMP_MSG(r2);

	/* Assign a local private key to HA */
	//HIP_IFEL(hip_init_our_hi(entry), -EINVAL, "Could not assign a local host id\n");

	/* Signature validation */
 	HIP_IFEL(entry->verify(entry->peer_pub, r2), -EINVAL, "R2 signature verification failed\n");

        /* The rest */
 	HIP_IFEL(!(esp_info = hip_get_param(r2, HIP_PARAM_ESP_INFO)), -EINVAL,
		 "Parameter SPI not found\n");

	spi_recvd = ntohl(esp_info->new_spi);
	memset(&spi_out_data, 0, sizeof(struct hip_spi_out_item));
	spi_out_data.spi = spi_recvd;
	HIP_IFE(hip_hadb_add_spi(entry, HIP_SPI_DIRECTION_OUT, &spi_out_data), -1);

	memcpy(&ctx->esp_out, &entry->esp_out, sizeof(ctx->esp_out));
	memcpy(&ctx->auth_out, &entry->auth_out, sizeof(ctx->auth_out));
	HIP_DEBUG("entry should have only one spi_in now, test\n");
	spi_in = hip_hadb_get_latest_inbound_spi(entry);
	tfm = entry->esp_transform;

	HIP_DEBUG("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^\n");
	HIP_DEBUG("src %d, dst %d\n", r2_info->src_port, r2_info->dst_port);

	err = hip_add_sa(r2_daddr, r2_saddr,
			 &ctx->input->hitr, &ctx->input->hits,
			 &spi_recvd, tfm,
			 &ctx->esp_out, &ctx->auth_out, 1,
			 HIP_SPI_DIRECTION_OUT, 0, r2_info->src_port, r2_info->dst_port);
	/*
	if (err == -EEXIST) {
		HIP_DEBUG("SA already exists for the SPI=0x%x\n", spi_recvd);
		HIP_DEBUG("TODO: what to do ? currently ignored\n");
	} else 	if (err) {
	*/

	if (err) {
		HIP_ERROR("hip_add_sa failed, peer:dst (err=%d)\n", err);
		HIP_ERROR("** TODO: remove inbound IPsec SA**\n");
		err = -1;
		goto out_err;
	}
	/* XXX: Check for -EAGAIN */
	HIP_DEBUG("set up outbound IPsec SA, SPI=0x%x (host)\n", spi_recvd);

	/* source IPv6 address is implicitly the preferred
	 * address after the base exchange */
	err = hip_hadb_add_addr_to_spi(entry, spi_recvd, r2_saddr,
				       1, 0, 1);
	if (err)
		HIP_ERROR("hip_hadb_add_addr_to_spi err=%d not handled\n", err);
	entry->default_spi_out = spi_recvd;
	HIP_DEBUG("set default SPI out=0x%x\n", spi_recvd);
	_HIP_DEBUG("add spi err ret=%d\n", err);
	//if(IN6_IS_ADDR_V4MAPPED(r2_daddr))
	//	err = hip_ipv4_devaddr2ifindex(r2_daddr);
	//else
		err = hip_devaddr2ifindex(r2_daddr);
	if (err != 0) {
		HIP_DEBUG("ifindex=%d\n", err);
		hip_hadb_set_spi_ifindex(entry, spi_in, err);
	} else
		HIP_ERROR("Couldn't get device ifindex of address\n");
	err = 0;

	/*
	  HIP_DEBUG("clearing the address used during the bex\n");
	  ipv6_addr_copy(&entry->bex_address, &in6addr_any);
	*/

	/* Check if the incoming R2 has a REG_RESPONSE parameter. */
		
	HIP_DEBUG("Checking R2 for REG_RESPONSE parameter.\n");
	struct hip_reg_request *rresp;
	uint8_t reg_types[1] = { HIP_ESCROW_SERVICE };
	rresp = hip_get_param(r2, HIP_PARAM_REG_RESPONSE);
	uint8_t lifetime;
	if (!rresp) {
		HIP_DEBUG("No REG_RESPONSE found in R2.\n");
		HIP_DEBUG("Checking r2 for REG_FAILED parameter.\n");
		rresp = hip_get_param(r2, HIP_PARAM_REG_FAILED);
		if (rresp) {
			HIP_DEBUG("Registration failed!.\n");
		}	
		else 
			HIP_DEBUG("Server not responding to registration attempt.\n");
			
		/** @todo Should the base entry be removed when registration fails?
		    Registration unsuccessful - removing base keas
		    hip_kea_remove_base_entries(); */
			
	}
	else {
		HIP_DEBUG("Found REG_RESPONSE parameter.\n");
		uint8_t *types = (uint8_t *)(hip_get_param_contents(r2, HIP_PARAM_REG_RESPONSE));
		int typecnt = hip_get_param_contents_len(rresp);
		int accept = 0;
		int i;
		if (typecnt >= 1) { 
			for (i = 1; i < typecnt; i++) {
				HIP_DEBUG("Service type: %d.\n", types[i]);
				if (types[i] == HIP_ESCROW_SERVICE) {
					accept = 1;
				}
			}	
		}
		if (accept) {
			HIP_DEBUG("Registration to escrow service completed!\n");
			HIP_KEA *kea;	
			HIP_IFE(!(kea = hip_kea_find(&entry->hit_our)), -1);
			HIP_DEBUG("Found kea base entry.\n");
			kea->keastate = HIP_KEASTATE_VALID;
			hip_keadb_put_entry(kea); 
		}
	}
	
	/* these will change SAs' state from ACQUIRE to VALID, and
	 * wake up any transport sockets waiting for a SA */
	//	hip_finalize_sa(&entry->hit_peer, spi_recvd);
	//hip_finalize_sa(&entry->hit_our, spi_in);

	entry->state = HIP_STATE_ESTABLISHED;
	hip_hadb_insert_state(entry);
	HIP_DEBUG("Reached ESTABLISHED state\n");
	
 out_err:
	if (ctx)
		HIP_FREE(ctx);
	return err;
}

/**
 * Handles an incoming I1 packet.
 *
 * Handles an incoming I1 packet and parses @c FROM or @c FROM_NAT parameter
 * from the packet. If a @c FROM or a @c FROM_NAT parameter is found, there must
 * also be a @c RVS_HMAC parameter present. This hmac is first verified. If the
 * verification fails, a negative error value is returned and hip_xmit_r1() is
 * not invoked. If verification succeeds,
 * <ol>
 * <li>and a @c FROM parameter is found, the IP address obtained from the
 * parameter is passed to hip_xmit_r1() as the destination IP address. The
 * source IP address of the received I1 packet is passed to hip_xmit_r1() as
 * the IP of RVS.</li>
 * <li>and a @c FROM_NAT parameter is found, the IP address and
 * port number obtained from the parameter is passed to hip_xmit_r1() as the
 * destination IP address and destination port. The source IP address and source
 * port of the received I1 packet is passed to hip_xmit_r1() as the IP and port
 * of RVS.</li>
 * <li>If no @c FROM or @c FROM_NAT parameters are found, this function does
 * nothing else but calls hip_xmit_r1().</li>
 * </ol>
 *
 * @param i1       a pointer to the received I1 HIP packet common header with
 *                 source and destination HITs.
 * @param i1_saddr a pointer to the source address from where the I1 packet was
 *                 received.
 * @param i1_daddr a pointer to the destination address where to the I1 packet
 *                 was sent to (own address).
 * @param entry    a pointer to the current host association database state.
 * @param i1_info  a pointer to the source and destination ports (when NAT is
 *                 in use).
 * @return         zero on success, or negative error value on error.
 * @warning        This code only handles a single @c FROM or @c FROM_NAT
 *                 parameter. If there is a mix of @c FROM and @c FROM_NAT
 *                 parameters, only the first @c FROM parameter is parsed. Also,
 *                 if there are multiple @c FROM or @c FROM_NAT parameters
 *                 present in the incoming I1 packet, only the first of a kind
 *                 is parsed.
 */
int hip_handle_i1(struct hip_common *i1,
		  struct in6_addr *i1_saddr,
		  struct in6_addr *i1_daddr,
		  hip_ha_t *entry,
		  struct hip_stateless_info *i1_info)
{
	int err = 0, is_via_rvs_nat = 0;
	struct in6_addr *dst_ip = NULL;
	in_port_t dst_port = 0;
	void *rvs_address = NULL;
	hip_tlv_type_t param_type = 0;
	hip_ha_t *rvs_ha_entry = NULL;
	struct hip_from_nat *from_nat;
	struct hip_from *from;
		
	HIP_DEBUG("hip_handle_i1() invoked.\n");
	HIP_DEBUG_HIT("&i1->hits", &i1->hits);
	HIP_DEBUG_HIT("&i1->hitr", &i1->hitr);
	HIP_DEBUG("I1 source port: %u, destination port: %u\n",
		  i1_info->src_port, i1_info->dst_port);
	HIP_DUMP_MSG(i1);

#ifdef CONFIG_HIP_RVS
	
	/* Note that this code effectively takes place at the responder of
	   I->RVS->R hierachy, not at the RVS itself. 
	   
	   We have five cases:
	   1. I1 was received on UDP and a FROM parameter was found.
	   2. I1 was received on raw HIP and a FROM parameter was found.
	   3. I1 was received on UDP and a FROM_NAT parameter was found.
	   4. I1 was received on raw HIP and a FROM_NAT parameter was found.
	   5. Neither FROM nor FROM_NAT parameter was not found. */
	
	/* Check if the incoming I1 packet has a FROM or FROM_NAT parameters at
	   all. */
	from_nat = hip_get_param(i1, HIP_PARAM_FROM_NAT);
	from = hip_get_param(i1, HIP_PARAM_FROM);
	
	if (!(from || from_nat)) {
		/* Case 5. */
		HIP_DEBUG("Didn't find FROM parameter in I1.\n");
		goto skip_nat;
	}
	
	HIP_DEBUG("Found %s parameter in I1.\n",
		  from ? "FROM" : "FROM_NAT");
	
	if(from) {
		/* Cases 1. & 2. */
		param_type = HIP_PARAM_FROM;
		dst_ip = (struct in6_addr *)&from->address;
	}
	else {
		/* Cases 3. & 4. */
		param_type = HIP_PARAM_FROM_NAT;
		dst_ip = (struct in6_addr *)&from_nat->address;
		dst_port = ntohs(from_nat->port);
	}
	
	/* The relayed I1 packet has the initiators HIT as source HIT,
	   and the responder HIT as destination HIT. We would like to
	   verify the HMAC againts the host association that was created
	   when the responder registered to the rvs. That particular
	   host association has the responders HIT as source HIT and the
	   rvs' HIT as destination HIT. Let's get that host association
	   using the responder's HIT and the IP address of the RVS as
	   search keys. */
	HIP_IFEL(((rvs_ha_entry =
		   hip_hadb_find_rvs_candidate_entry(&i1->hitr, i1_saddr)) == NULL),
		 -1, "A matching host association was not found for "\
		 "responder HIT / RVS IP.");
	
	HIP_DEBUG("RVS host association entry found.\n");
	
	/* Verify the RVS hmac. */
	HIP_IFEL(hip_verify_packet_rvs_hmac(i1, &rvs_ha_entry->hip_hmac_out),
		 -1, "RVS_HMAC verification on the relayed i1 failed.\n");
	
	/* I1 packet was received on UDP destined to port 50500.
	   R1 packet will have a VIA_RVS_NAT parameter.
	   Cases 1. & 3. */
	if(i1_info->src_port == HIP_NAT_UDP_PORT) {
		
		struct hip_in6_addr_port our_addr_port;
		is_via_rvs_nat = 1;
		
		HIP_IFEL(!(rvs_address = 
			   HIP_MALLOC(sizeof(struct hip_in6_addr_port),
				      0)),
			 -ENOMEM, "Not enough memory to rvs_address.");
		
		/* Insert source IP address and source port from the
		   received I1 packet to "rvs_address". For this purpose
		   a temporary hip_in6_addr_port struct is needed. */
		memcpy(&our_addr_port.sin6_addr, i1_saddr,
		       sizeof(struct in6_addr));
		our_addr_port.sin6_port = htons(i1_info->src_port);
		
		memcpy(rvs_address, &our_addr_port,
		       sizeof(struct hip_in6_addr_port));
	} else {
		/* I1 packet was received on raw IP/HIP.
		   Cases 2. & 4. */
		HIP_IFEL(!(rvs_address = 
			   HIP_MALLOC(sizeof(struct in6_addr), 0)),
			 -ENOMEM, "Not enough memory to rvs_address.");
		
		/* Insert source IP address from the received I1 packet
		   to "rvs_address". */
		memcpy(rvs_address, i1_saddr, sizeof(struct in6_addr));
	}
 skip_nat:
#endif
	
	err = hip_xmit_r1(i1_saddr, i1_daddr, &i1->hitr, dst_ip, dst_port,
			  &i1->hits, i1_info, rvs_address, is_via_rvs_nat);
 out_err:
	if(rvs_address) {
		HIP_FREE(rvs_address);
	}
	
	return err;
}

/**
 * Determines the action to be executed for an incoming I1 packet.
 *
 * This function is called when a HIP control packet is received by
 * hip_receive_control_packet()-function and the packet is detected to be
 * an I1 packet. The operation of this function depends on whether the current
 * machine is a rendezvous server or not.
 * 
 * <ol>
 * <li>If the current machine is @b NOT a rendezvous server:</li> 
 * <ul>
 * <li>hip_handle_i1() is invoked.</li>
 * </ul>
 * <li>If the current machine @b IS a rendezvous server:</li>
 * <ul>
 * <li>if a valid rendezvous association is found from the server's rva table,
 * the I1 packet is relayed by invoking hip_rvs_relay_i1().</li> 
 * <li>If no valid valid rendezvous association is found, hip_handle_i1() is
 * invoked.</li>
 * </ul>
 * </ol>
 *
 * @param i1       a pointer to the received I1 HIP packet common header with
 *                 source and destination HITs.
 * @param i1_saddr a pointer to the source address from where the I1 packet was
 *                 received.
 * @param i1_daddr a pointer to the destination address where to the I1 packet
 *                 was sent to (own address).
 * @param entry    a pointer to the current host association database state.
 * @param i1_info  a pointer to the source and destination ports (when NAT is
 *                 in use).
 * @return         zero on success, or negative error value on error.
 * @warning        This code does not work correctly if there are @b both
 *                 @c FROM and @c FROM_NAT parameters in the incoming I1 packet.
 */
int hip_receive_i1(struct hip_common *i1,
		   struct in6_addr *i1_saddr,
		   struct in6_addr *i1_daddr,
		   hip_ha_t *entry,
		   struct hip_stateless_info *i1_info)
{
	HIP_DEBUG("hip_receive_i1() invoked.\n");
       	int err = 0, state, mask = 0;
#ifdef CONFIG_HIP_RVS
 	HIP_RVA *rva;
	mask |= HIP_CONTROL_RVS_CAPABLE;
#endif
	HIP_IFEL(ipv6_addr_any(&i1->hitr), -EPROTONOSUPPORT, 
		 "Received NULL receiver HIT. Opportunistic HIP is not supported yet in I1. Dropping\n");

	/* we support checking whether we are rvs capable even with RVS support not enabled */
 	HIP_IFEL(!hip_controls_sane(ntohs(i1->control), mask), -1, 
		 "Received illegal controls in I1: 0x%x. Dropping\n", ntohs(i1->control));
	
	if (entry) {
		wmb();
		state = entry->state;
		hip_put_ha(entry);
	} else {
#ifdef CONFIG_HIP_RVS
		HIP_DEBUG_HIT("Searching rendezvous association on HIT",
			      &i1->hitr);
 		rva = hip_rvs_get_valid(&i1->hitr);
		HIP_DEBUG("Valid rendezvous association found: %s \n",
			  (rva ? "yes" : "no"));
 		if (rva) {
			err = hip_rvs_relay_i1(i1, i1_saddr, i1_daddr, rva, i1_info);
			return err;
 		}
#endif
		state = HIP_STATE_NONE;
	}

	HIP_DEBUG("HIP_LOCK_HA ?\n");
	HIP_DEBUG("Received I1 in state %s\n", hip_state_str(state));

	switch(state) {
	case HIP_STATE_NONE:
		err = ((hip_handle_func_set_t *)hip_get_handle_default_func_set())->hip_handle_i1(i1, i1_saddr, i1_daddr, entry, i1_info);
		break;
	case HIP_STATE_I1_SENT:
                if (hip_hit_is_bigger(&entry->hit_our, &entry->hit_peer)) {
			HIP_DEBUG("Our HIT is bigger\n");
			err = ((hip_handle_func_set_t *)hip_get_handle_default_func_set())->hip_handle_i1(i1, i1_saddr, i1_daddr, entry, i1_info);
		} else {
			HIP_DEBUG("Dropping i1 (two hosts iniating base exchange at the same time?)\n");
		}
		break;
	case HIP_STATE_UNASSOCIATED:
	case HIP_STATE_I2_SENT:
	case HIP_STATE_R2_SENT:
	case HIP_STATE_ESTABLISHED:
	case HIP_STATE_CLOSED:
	case HIP_STATE_CLOSING:
		err = ((hip_handle_func_set_t *)hip_get_handle_default_func_set())->hip_handle_i1(i1, i1_saddr, i1_daddr, entry, i1_info);
		break;
	default:
		/* should not happen */
		HIP_IFEL(1, -EINVAL, "DEFAULT CASE, UNIMPLEMENTED STATE HANDLING OR A BUG\n");
	}

	HIP_DEBUG("HIP_UNLOCK_HA ?\n");
 out_err:
	return err;
}

/**
 * hip_receive_r2 - receive R2 packet
 * @param skb sk_buff where the HIP packet is in
 *
 * This is the initial function which is called when an R1 packet is
 * received. If we are in correct state, the packet is handled to
 * hip_handle_r2() for further processing.
 *
 * @return 0 if R2 was processed succesfully, < 0 otherwise.
 */
int hip_receive_r2(struct hip_common *hip_common,
		   struct in6_addr *r2_saddr,
		   struct in6_addr *r2_daddr,
		   hip_ha_t *entry,
		   struct hip_stateless_info *r2_info)
{
	HIP_DEBUG("hip_receive_i2() invoked.\n");
	int err = 0, state;
	uint16_t mask = 0;

	HIP_IFEL(ipv6_addr_any(&hip_common->hitr), -1, 
		 "Received NULL receiver HIT in R2. Dropping\n");
	
	HIP_IFEL(!hip_controls_sane(ntohs(hip_common->control), mask), -1,
		 "Received illegal controls in R2: 0x%x. Dropping\n", ntohs(hip_common->control));
	//HIP_IFEL(!(entry = hip_hadb_find_byhits(&hip_common->hits, 
	//					&hip_common->hitr)), -EFAULT,
	//	 "Received R2 by unknown sender\n");

	HIP_IFEL(!entry, -EFAULT,
		 "Received R2 by unknown sender\n");
		 
	HIP_LOCK_HA(entry);
	state = entry->state;

	HIP_DEBUG("Received R2 in state %s\n", hip_state_str(state));
 	switch(state) {
 	case HIP_STATE_I2_SENT:
 		/* The usual case. */
 		err = entry->hadb_handle_func->hip_handle_r2(hip_common, r2_saddr, r2_daddr, entry, r2_info);
		if (err) {
			HIP_ERROR("hip_handle_r2 failed (err=%d)\n", err);
			goto out_err;
 		}
	break;

	case HIP_STATE_R2_SENT:
 	case HIP_STATE_ESTABLISHED:
	case HIP_STATE_UNASSOCIATED:
 	case HIP_STATE_I1_SENT:
 	default:
		HIP_IFEL(1, -EFAULT, "Dropping\n");
 	}

 out_err:
	if (entry) {
		HIP_UNLOCK_HA(entry);
		hip_put_ha(entry);
	}
	return err;
}


/**
 * hip_receive_notify - receive NOTIFY packet
 * @param skb sk_buff where the HIP packet is in
 *
 * This is the initial function which is called when an NOTIFY packet is
 * received.
 *
 * @return 0 if R2 was processed succesfully, < 0 otherwise.
 */
int hip_receive_notify(struct hip_common *hip_common,
		       struct in6_addr *notify_saddr,
		       struct in6_addr *notity_daddr,
		       hip_ha_t* entry)
{
	HIP_DEBUG("hip_receive_notify() invoked.\n");
	int err = 0;
	struct hip_notify *notify_param;
	uint16_t mask = HIP_CONTROL_HIT_ANON;

	HIP_HEXDUMP("Incoming NOTIFY", hip_common,
		    hip_get_msg_total_len(hip_common));

	HIP_IFEL(!hip_controls_sane(ntohs(hip_common->control), mask), -1, 
		 "Received illegal controls in NOTIFY: 0x%x. Dropping\n",
		 ntohs(hip_common->control));
	HIP_IFEL( !entry , -EFAULT, "Received NOTIFY by unknown sender\n");

	/* lock here */
	/* todo: check state */

	/* while (notify_param = hip_get_nth_param(msg, HIP_PARAM_NOTIFY, i)) { .. */

	notify_param = hip_get_param(hip_common, HIP_PARAM_NOTIFY);
	if (notify_param) {
		HIP_DEBUG("NOTIFY parameter:\n");
		HIP_DEBUG(" msgtype=%u\n", ntohs(notify_param->msgtype));
	}

 out_err:
	if (entry)
		hip_put_ha(entry);

	return err;
}

/**
 * hip_receive_bos - receive BOS packet
 * @param skb sk_buff where the HIP packet is in
 *
 * This function is called when a BOS packet is received. We add the
 * received HIT and HOST_ID to the database.
 *
 * Returns always 0.
 *
 * TODO: check if it is correct to return always 0 
 */
int hip_receive_bos(struct hip_common *bos,
		   struct in6_addr *bos_saddr,
		   struct in6_addr *bos_daddr,
		   hip_ha_t *entry,
		  struct hip_stateless_info *bos_info)
{
	HIP_DEBUG("hip_receive_bos() invoked.\n");
	int err = 0, state = 0;

	HIP_DEBUG("\n");

	HIP_IFEL(ipv6_addr_any(&bos->hits), 0, 
		 "Received NULL sender HIT in BOS.\n");
	HIP_IFEL(!ipv6_addr_any(&bos->hitr), 0, 
		 "Received non-NULL receiver HIT in BOS.\n");
	HIP_DEBUG("Entered in hip_receive_bos...\n");
	state = entry ? entry->state : HIP_STATE_UNASSOCIATED;

	/*! \todo If received BOS packet from already known sender
           should return right now */
	HIP_DEBUG("Received BOS packet in state %s\n", hip_state_str(state));
 	switch(state) {
 	case HIP_STATE_UNASSOCIATED:
	case HIP_STATE_I1_SENT:
	case HIP_STATE_I2_SENT:
		/* Possibly no state created yet */
		err = entry->hadb_handle_func->hip_handle_bos(bos, bos_saddr, bos_daddr, entry, bos_info);
		break;
	case HIP_STATE_R2_SENT:
 	case HIP_STATE_ESTABLISHED:
		HIP_DEBUG("BOS not handled in state %s\n", hip_state_str(state));
		break;
	default:
		HIP_IFEL(1, 0, "Internal state (%d) is incorrect\n", state);
	}

	if (entry)
		hip_put_ha(entry);
 out_err:
	return err;
}
