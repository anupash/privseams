/*
 * HIP input
 *
 * Authors: Janne Lundberg <jlu@tcs.hut.fi>
 *          Miika Komu <miika@iki.fi>
 *          Mika Kousa <mkousa@cc.hut.fi>
 *          Kristian Slavov <kslavov@hiit.fi>
 *
 * TODO:
 * - hip_inbound: the state should be changed in hip_inbound, not in the
 *   functions that are called from hip_inbound!
 * - If a function returns a value, we MUST NOT ignore it
 * - hip_handle_i2_finish_sig, hip_handle_r2_finish: check return values of
 *   hip_setup_ipsec
 * - make null-cipher optional, so that the module can be loaded without it
 * - decrypt encrypted field in handle_i2
 * - check buffer overflow (ctx->htpr) issues in building of R1
 * - convert building of r1 to use only builder functions
 * - later on everything should be built/parsed using builder
 * - No hip packets should be sent or received before autosetup
 *   is finished:
 *     if (hipd_get_auto_setup_state() != HIPD_AUTO_SETUP_STATE_FINISHED)
 *       fail_somehow();
 * - verify signatures in base exchange handlers
 * - separate the tlv checking code into an own function from handle_r1?
 * - LOCKING TO REA
 * - AC/ACR: more accurate RTT timing than jiffies ?
 * - cancel sent rea timer when ACR is received
 *
 * BUGS:
 * - possible kernel panic if module is rmmod'd and REA timer
 *   expires after that
 * - It should be signalled somehow when building of R1 is 100 %
 *   complete. Otherwise an incomplete packet could be sent for
 *   the initiator?
 * - handle_i2 trusts the source HIT in the received I2 packet: DoS?
 * - the functions in this file probably leak memory (skbs?)
 *
 */

#include <net/ipv6.h>
#include <net/checksum.h>

#include "input.h"
#include "debug.h"
#include "hadb.h"
#include "keymat.h"
#include "crypto/dsa.h"
#include "rea.h"
#include "builder.h"
#include "hip.h"
#include "security.h"
#include "misc.h"
#include "workqueue.h"
#include "db.h"
#include "cookie.h"
#include "output.h"

#ifdef MAX
#undef MAX
#endif

#define MAX(a, b) (((a) > (b)) ? (a) : (b))

static int hip_verify_hmac(struct hip_common *buffer, u8 *hmac, 
			   void *hmac_key, int hmac_type);

/*****************************************************************************
 *                            UTILITY FUNCTIONS                              *
 *****************************************************************************/

/**
 * hip_controls_sane - check for illegal controls
 * @controls: control value to be checked
 * @legal: legal control values to check @controls against
 *
 * Controls are given in host byte order.
 *
 * Returns 1 is there are no illegal control values in @controls,
 * otherwise 0.
 */
int hip_controls_sane(u16 controls, u16 legal)
{
	u16 known;

	known = controls & 
		(HIP_CONTROL_PIGGYBACK_ALLOW |
		 HIP_CONTROL_CERTIFICATES |
		 HIP_CONTROL_ESP_64 |
		 HIP_CONTROL_HIT_ANON);

	if ((known | legal) != legal)
		return 0;

	return 1;
}


/**
 * hip_handle_esp - handle incoming ESP packet
 * @hdr: IPv6 header of the packet
 *
 * If the packet's SPI belongs to a HIP connection, the IPv6 addresses
 * are replaced with the corresponding HITs before the packet is
 * delivered to ESP.
 */
void hip_handle_esp(uint32_t spi, struct ipv6hdr *hdr)
{
	hip_ha_t *ha;

	/* We are called only from bh.
	 * No locking will take place since the data
	 * that we are copying is very static
	 */

	ha = hip_hadb_find_byspi(spi);
	if (!ha) {
		HIP_INFO("Unknown SPI: 0x%x\n",spi);
		return;
	}

	ipv6_addr_copy(&hdr->daddr, &ha->hit_our);
	ipv6_addr_copy(&hdr->saddr, &ha->hit_peer);
	hip_put_ha(ha);

	return;
}

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
int hip_create_signature(void *buffer_start, int buffer_length, 
			 struct hip_host_id *host_id, u8 *signature)
{
	int err = 0;
	u8 sha1_digest[HIP_AH_SHA_LEN];

	/* this has to be modified so that other signature algorithms
	   are accepted
	*/

	if (hip_get_host_id_algo(host_id) != HIP_HI_DSA) {
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

	err = hip_dsa_sign(sha1_digest,(u8 *)(host_id + 1),signature);
	if (err) {
		HIP_ERROR("DSA Signing error\n");
		return 0;
	}

	/* 1 + 20 + 20 */
	HIP_HEXDUMP("signature",signature,41);

	err = 1;
 out_err:
	return err;
}


/**
 * hip_verify_signature - Verifies that the signature matches the data it has 
 * been calculated over.
 * @buffer_start: Pointer to the start of the buffer over which to calculate
 *                SHA1-160 digest.
 * @buffer_length: Length of the buffer at @buffer_start
 * @host_id: Pointer to HOST_ID (as specified by the HIP draft).
 * @signature: Pointer to the signature
 *
 * Returns true (1) if ok, false (0) otherwise.
 */
int hip_verify_signature(void *buffer_start, int buffer_length, 
			 struct hip_host_id *host_id, u8 *signature)
{
	u8 *public_key = (u8 *) (host_id + 1);
	int tmp, err;
	unsigned char sha1_digest[HIP_AH_SHA_LEN];
	size_t public_key_len;

	err = 0;

	/* check for all algorithms */

	if (hip_get_host_id_algo(host_id) != HIP_HI_DSA) {
		HIP_ERROR("Unsupported algorithm:%d\n", hip_get_host_id_algo(host_id));
		return 0;
	}

	_HIP_HEXDUMP("Signature data (verify)",buffer_start,buffer_length);

	if (hip_build_digest(HIP_DIGEST_SHA1,buffer_start,buffer_length,sha1_digest)) 
	{
		HIP_ERROR("Could not calculate SHA1 digest\n");
		goto out_err;
	}

	_HIP_HEXDUMP("Verify hexdump", sha1_digest, HIP_AH_SHA_LEN);

	public_key_len = hip_get_param_contents_len(host_id) - 4;
	public_key_len = ntohs(host_id->hi_length);

	_HIP_HEXDUMP("verify key", public_key, public_key_len);

	_HIP_HEXDUMP("Verify hexdump sig **", signature, 42);

	tmp = hip_dsa_verify(sha1_digest, public_key, signature);

	switch(tmp) 
	{
	case 0:
		HIP_INFO("Signature: [CORRECT]\n");
		break;
	case 1:
		HIP_INFO("Signature: [INCORRECT]\n");
		HIP_HEXDUMP("digest",sha1_digest,20);
		HIP_HEXDUMP("signature",signature,41);
		HIP_HEXDUMP("public key",public_key,public_key_len);
		//break; // uncomment if you don't care about the correctness of the DSA signature
	default:
		HIP_ERROR("Signature verification failed: %d\n", tmp);

		goto out_err;
	}

	err = 1;

 out_err:
	return err;
}

/**
 * hip_verify_packet_hmac - verify packet HMAC
 * @msg: HIP packet
 * @entry: HA
 *
 * Returns: 0 if HMAC was validated successfully, < 0 if HMAC could
 * not be validated.
 */
int hip_verify_packet_hmac(struct hip_common *msg, hip_ha_t *entry)
{
	int err;
	int len;
	struct hip_crypto_key tmpkey;
	struct hip_hmac *hmac;

	hmac = hip_get_param(msg, HIP_PARAM_HMAC);
	if (!hmac) {
		HIP_ERROR("Packet contained no HMAC parameter\n");
		err = -ENOMSG;
		goto out_err;
	}
	_HIP_DEBUG("HMAC found\n");

	len = (u8 *) hmac - (u8*) msg;
	hip_set_msg_total_len(msg, len);

	_HIP_HEXDUMP("HMACced data", msg, len);

	HIP_LOCK_HA(entry);
	memcpy(&tmpkey, &entry->hmac_peer, sizeof(tmpkey));
	HIP_UNLOCK_HA(entry);

	err = hip_verify_hmac(msg, hmac->hmac_data,
			      tmpkey.key, HIP_DIGEST_SHA1_HMAC);
	if (err) {
		HIP_ERROR("HMAC validation failed\n");
		goto out_err;
	} 

 out_err:
	return err;
}

/**
 * hip_verify_packet_signature - verify packet SIGNATURE
 * @msg: HIP packet
 * @hid: HOST ID
 *
 * Returns: 0 if SIGNATURE was validated successfully, < 0 if SIGNATURE could
 * not be validated.
 */
int hip_verify_packet_signature(struct hip_common *msg,
				struct hip_host_id *hid)
{
	int err = 0;
	struct hip_sig *sig;
 	int len;

 	sig = hip_get_param(msg, HIP_PARAM_HIP_SIGNATURE);
 	if (!sig) {
 		err = -ENOENT;
		HIP_ERROR("Could not find signature\n");
 		goto out_err;
 	}

	HIP_HEXDUMP("SIG", sig, hip_get_param_total_len(sig));

 	len = ((u8 *) sig) - ((u8 *) msg);
 	hip_zero_msg_checksum(msg);
 	hip_set_msg_total_len(msg, len);

 	if (len < 0) {
 		err = -ENOENT;
		HIP_ERROR("Invalid signature len\n");
 		goto out_err;
 	}

 	if (!hip_verify_signature(msg, len, hid,
 				  (u8 *) (sig + 1))) {
 		HIP_ERROR("Verification of signature failed\n");
		err = -EINVAL;
 		goto out_err;
	}

 out_err:
	return err;
}

/**
 * hip_verify_packet_signature2 - verify packet SIGNATURE2
 * @msg: HIP packet
 * @hid: HOST ID
 *
 * Returns: 0 if SIGNATURE2 was validated successfully, < 0 if SIGNATURE2 could
 * not be validated.
 */
int hip_verify_packet_signature2(struct hip_common *msg,
				struct hip_host_id *hid)
{
	int err = 0;
	struct hip_sig2 *sig2;
	int origlen, len;
	struct in6_addr tmpaddr;

	sig2 = hip_get_param(msg, HIP_PARAM_HIP_SIGNATURE2);
	if (!sig2) {
		HIP_ERROR("No SIGNATURE2 found\n");
		err = -ENOENT;
		goto out_err;
	}
	
	len = (((u8 *)sig2 - ((u8 *) msg)));

 	ipv6_addr_copy(&tmpaddr, &msg->hitr);
 	memset(&msg->hitr, 0, sizeof(struct in6_addr));

	origlen = hip_get_msg_total_len(msg);
	hip_set_msg_total_len(msg, len);
	msg->checksum = 0;

	if (!hip_verify_signature(msg, len, hid,
				  (u8 *)(sig2 + 1))) {
		HIP_ERROR("Signature verification failed\n");
		err = -EINVAL;
		goto out_err;
	}

 	ipv6_addr_copy(&msg->hitr, &tmpaddr);
 	hip_set_msg_total_len(msg, origlen);

 	/* the checksum is not restored because it was already checked in
 	   hip_inbound */

 out_err:
	return err;
}


/**
 * hip_calculate_shared_secret - Creates a shared secret based on the
 * public key of the peer (passed as an argument) and own DH private key
 * (created beforehand).
 * @dhf: Peer's Diffie-Hellman public key
 * @buffer: Buffer that holds enough space for the shared secret.
 *
 * Returns the length of the shared secret in octets if successful,
 * or -1 if an error occured.
 */
int hip_calculate_shared_secret(struct hip_diffie_hellman *dhf, u8* buffer, 
				int bufsize)
{
	signed int len;
	int err;

	if (dh_table[dhf->group_id] == NULL) {
		HIP_ERROR("Unsupported DH group: %d\n",dhf->group_id);
		return -1;
        }
	
	len = hip_get_param_contents_len(dhf) - 1;

	_HIP_HEXDUMP("PEER DH key:",(dhf + 1),len);

	err = hip_gen_dh_shared_key(dh_table[dhf->group_id], (u8*)(dhf+1), len,
				    buffer, bufsize);
	if (err < 0) {
                HIP_ERROR("Could not create shared secret\n");
		return -1;
        }

	return err;
}

/**
 * hip_produce_keying_material - Create shared secret and produce keying material 
 * @msg: the HIP packet received from the peer
 *
 * The initial ESP keys are drawn out of the keying material.
 *
 * Returns zero on success, or negative on error.
 */
int hip_produce_keying_material(struct hip_common *msg,
				struct hip_context *ctx)
{
	u8 *dh_shared_key = NULL;
	int hip_transf_length;
	int esp_transf_length;
	int hmac_transf_length;
	int auth_transf_length;
	int hip_tfm;
	int esp_tfm;
	
	int dh_shared_len = 1024;
	int err = 0;

	struct hip_keymat_keymat km;

	char *keymat = NULL;
	size_t keymat_len_min; /* how many bytes we need at least for the KEYMAT */
	size_t keymat_len; /* note SHA boundary */

	struct hip_tlv_common *param = NULL;

	/* perform light operations first before allocating memory or
	 * using lots of cpu time */
	param = hip_get_param(msg, HIP_PARAM_HIP_TRANSFORM);
	if (!param) {
		HIP_ERROR("Could not find HIP transform\n");
		err = -EINVAL;
		goto out_err;
	}
	hip_tfm = hip_select_hip_transform((struct hip_hip_transform *) param);
	if (hip_tfm == 0) {
		HIP_ERROR("Could not select proper HIP transform\n");
		err = -EINVAL;
		goto out_err;
	}

	param = hip_get_param(msg, HIP_PARAM_ESP_TRANSFORM);
	if (!param) {
		HIP_ERROR("Could not find ESP transform\n");
		err = -EINVAL;
		goto out_err;
	}
	esp_tfm = hip_select_esp_transform((struct hip_esp_transform *) param);
	if (esp_tfm == 0) {
		HIP_ERROR("Could not select proper ESP transform\n");
		err = -EINVAL;
		goto out_err;
	}

	hip_transf_length = hip_transform_key_length(hip_tfm);
	hmac_transf_length = hip_hmac_key_length(esp_tfm);
	esp_transf_length = hip_enc_key_length(esp_tfm);
	auth_transf_length = hip_auth_key_length_esp(esp_tfm);

	/* Create only minumum amount of KEYMAT for now. From draft
	 * chapter HIP KEYMAT we know how many bytes we need for all
	 * keys used in the base exchange. */
	keymat_len_min = hip_transf_length + hmac_transf_length + hip_transf_length +
		hmac_transf_length + esp_transf_length + auth_transf_length +
		esp_transf_length + auth_transf_length;

	keymat_len = keymat_len_min;
	if (keymat_len % HIP_AH_SHA_LEN)
		keymat_len += HIP_AH_SHA_LEN - (keymat_len % HIP_AH_SHA_LEN);

	HIP_DEBUG("keymat_len_min=%u keymat_len=%u\n", keymat_len_min, keymat_len);

	keymat = kmalloc(keymat_len, GFP_KERNEL);
	if (!keymat) {
		HIP_ERROR("No memory for KEYMAT\n");
		err = -ENOMEM;
		goto out_err;
	}

	/* 1024 should be enough for shared secret. The length of the
	 * shared secret actually depends on the DH Group. */

	/* TODO: 1024 -> hip_get_dh_size ? */

	dh_shared_key = kmalloc(dh_shared_len, GFP_KERNEL);
	if (!dh_shared_key) {
		HIP_ERROR("No memory for DH shared key\n");
		err = -ENOMEM;
		goto out_err;
	}
	memset(dh_shared_key, 0, dh_shared_len);

	param = hip_get_param(msg, HIP_PARAM_DIFFIE_HELLMAN);
	if (!param) {
		err = -ENOENT;
		HIP_ERROR("No Diffie-Hellman param found\n");
		goto out_err;
	}

	dh_shared_len = hip_calculate_shared_secret((struct hip_diffie_hellman *) param, 
						    dh_shared_key, dh_shared_len);
	if (dh_shared_len < 0) {
		HIP_ERROR("Calculation of shared secret failed\n");
		err = -EINVAL;
		goto out_err;
	}

	HIP_DEBUG("dh_shared_len=%u\n", dh_shared_len);
	HIP_HEXDUMP("DH SHARED KEY", dh_shared_key, dh_shared_len);

	hip_make_keymat(dh_shared_key, dh_shared_len,
			&km, keymat, keymat_len,
			&msg->hits, &msg->hitr, &ctx->keymat_calc_index);

	/* draw from km to keymat, copy keymat to dst, length of
	 * keymat is len */

#define KEYMAT_DRAW_AND_COPY(dst, len)				\
         {							\
	   void *p = hip_keymat_draw(&km, len);		        \
	   if (!p) {						\
		 HIP_ERROR("Could not draw from keymat\n");	\
		 err = -EINVAL;					\
		 goto out_err;					\
	   }							\
	   memcpy(dst, p, len);					\
        }

	/* Draw keys: */

	/* HIP-IR encryption key */
	KEYMAT_DRAW_AND_COPY(&ctx->hip_i.key, hip_transf_length);
	HIP_HEXDUMP("HIP-IR encryption", &ctx->hip_i.key, hip_transf_length);
	
	/* HIP-IR integrity (HMAC) key */
	KEYMAT_DRAW_AND_COPY(&ctx->hip_hmaci.key, hmac_transf_length);
	HIP_HEXDUMP("HIP-IR integrity (HMAC) key", &ctx->hip_hmaci.key,
		    hmac_transf_length);

	/* HIP-RI encryption key (currently unused). Discard the
	 * result. */
	(void) hip_keymat_draw(&km, hip_transf_length);
	HIP_DEBUG("skipping HIP_RI encryption key, %u bytes\n", hip_transf_length);

	/* HIP-RI integrity (HMAC) key */
	KEYMAT_DRAW_AND_COPY(&ctx->hip_hmacr.key, hmac_transf_length);
	HIP_HEXDUMP("HIP-RI integrity (HMAC) key", &ctx->hip_hmacr.key,
		    hmac_transf_length);

	/* SA-IR ESP encryption key */
	KEYMAT_DRAW_AND_COPY(&ctx->hip_espi.key, esp_transf_length);
	HIP_HEXDUMP("SA-IR ESP encryption key", &ctx->hip_espi.key,
		     esp_transf_length);

	/* SA-IR ESP authentication key */
	KEYMAT_DRAW_AND_COPY(&ctx->hip_authi.key, auth_transf_length);
	HIP_HEXDUMP("SA-IR ESP authentication key", &ctx->hip_authi.key,
		     auth_transf_length);

	/* SA-RI ESP encryption key */
	KEYMAT_DRAW_AND_COPY(&ctx->hip_espr.key, esp_transf_length);
	HIP_HEXDUMP("SA-RI ESP encryption key", &ctx->hip_espr.key,
		     esp_transf_length);

	/* SA-RI ESP authentication key */
	KEYMAT_DRAW_AND_COPY(&ctx->hip_authr.key, auth_transf_length);
	HIP_HEXDUMP("SA-RI ESP authentication key", &ctx->hip_authr.key,
		     auth_transf_length);

#undef KEYMAT_DRAW_AND_COPY

	ctx->current_keymat_index = keymat_len_min;
	ctx->keymat_calc_index = (ctx->current_keymat_index / HIP_AH_SHA_LEN) + 1;

	memcpy(ctx->current_keymat_K, keymat+(ctx->keymat_calc_index-1)*HIP_AH_SHA_LEN, HIP_AH_SHA_LEN);

	HIP_DEBUG("ctx: keymat_calc_index=%u current_keymat_index=%u\n",
		  ctx->keymat_calc_index, ctx->current_keymat_index);
	HIP_HEXDUMP("CTX CURRENT KEYMAT", ctx->current_keymat_K, HIP_AH_SHA_LEN);

	/* store DH shared key */
	ctx->dh_shared_key = dh_shared_key;
	ctx->dh_shared_key_len = dh_shared_len;

	/* on success kfree for dh_shared_key is called by caller */
 out_err:
	if (err) {
		if (dh_shared_key)
			kfree(dh_shared_key);
	}
	if (keymat)
		kfree(keymat);

	return err;
}


/*****************************************************************************
 *                           PACKET/PROTOCOL HANDLING                        *
 *****************************************************************************/


/**
 * hip_create_i2 - Create I2 packet and send it
 * @ctx: Context that includes the incoming R1 packet
 * @solved_puzzle: Value that solves the puzzle
 *
 * Returns: zero on success, non-negative on error.
 */
int hip_create_i2(struct hip_context *ctx, uint64_t solved_puzzle, 
		  hip_ha_t *entry)
{
	int err = 0;
	uint32_t spi_in = 0;
	int dh_size = 0;
	int written;
	hip_transform_suite_t transform_hip_suite, transform_esp_suite; 
	struct hip_host_id *host_id_pub = NULL;
	struct hip_host_id *host_id_private = NULL;
	//struct hip_host_id *host_id_in_enc = NULL;
	char *host_id_in_enc = NULL;
	struct hip_encrypted *enc_in_msg = NULL;
	struct in6_addr daddr;
	u8 *dh_data = NULL;
	struct hip_spi_lsi *spi_lsi;
	struct hip_common *i2 = NULL;
	struct hip_param *param;
	struct hip_birthday_cookie *bc = NULL;
	struct hip_diffie_hellman *dh_req;
	u8 signature[HIP_DSA_SIGNATURE_LEN];

	HIP_DEBUG("\n");

	HIP_ASSERT(entry);

	/* allocate space for new I2 */
	i2 = hip_msg_alloc();
	if (!i2) {
		HIP_ERROR("Allocation of I2 failed\n");
		err = -ENOMEM;
		goto out_err;
	}

	/* allocate memory for writing Diffie-Hellman shared secret */
	dh_size = hip_get_dh_size(HIP_DEFAULT_DH_GROUP_ID);
	if (dh_size == 0) {
		HIP_ERROR("Could not get dh size\n");
		err = -EINVAL;
		goto out_err;
	}
	dh_data = kmalloc(dh_size, GFP_KERNEL);
	if (!dh_data) {
		HIP_ERROR("Failed to alloc memory for dh_data\n");
		err = -ENOMEM;
		goto out_err;
	}

	/* Get a localhost identity, allocate memory for the public key part
	   and extract the public key from the private key. The public key is
	   needed in the ESP-ENC below. */

	host_id_pub = hip_get_any_localhost_public_key();
	if (host_id_pub == NULL) {
		err = -EINVAL;
		HIP_ERROR("No localhost public key found\n");
		goto out_err;
	}

	host_id_private = hip_get_any_localhost_host_id();
	if (!host_id_private) {
		err = -EINVAL;
		HIP_ERROR("No localhost private key found\n");
		goto out_err;
	}

	/* TLV sanity checks are are already done by the caller of this
	   function. Now, begin to build I2 piece by piece. */

	/* Delete old SPDs and SAs, if present */
	//hip_delete_esp(&ctx->input->hitr,&ctx->input->hits);
	hip_delete_esp(entry);

	hip_build_network_hdr(i2, HIP_I2, 0,
			      &(ctx->input->hitr),
			      &(ctx->input->hits));

	/********** SPI_LSI **********/

	/* SPI and LSI are set below where IPsec is set up */
	err = hip_build_param_spi_lsi(i2, 0, 0);
	if (err) {
		HIP_ERROR("building of SPI_LSI failed (err=%d)\n", err);
		goto out_err;
	}

	/********** Birthday cookie **********/

	bc = hip_get_param(ctx->input,
			   HIP_PARAM_BIRTHDAY_COOKIE_R1);
	if (!bc) {
		err = -ENOENT;
		goto out_err;
	}

	err = hip_build_param_cookie(i2, 1,
		     hip_get_current_birthday(),
		     hip_get_param_i_val((struct hip_birthday_cookie *) bc),
		     ntoh64(solved_puzzle));
	if (err) {
		HIP_ERROR("Building of birtday cookie failed (%d)\n", err);
		goto out_err;
	}
	
	/********** Diffie-Hellman *********/

  	dh_req = hip_get_param(ctx->input, HIP_PARAM_DIFFIE_HELLMAN);
	if (!dh_req) {
		err = -ENOENT;
		HIP_ERROR("Internal error\n");
		goto out_err;
	}

	written = hip_insert_dh(dh_data, dh_size, dh_req->group_id);
	if (written < 0) {
		err = -ENOENT;
		HIP_ERROR("Error while extracting DH key\n");
		goto out_err;
	}
	
	_HIP_HEXDUMP("Own DH key", dh_data, n);
	
	err = hip_build_param_diffie_hellman_contents(i2,dh_req->group_id,
						      dh_data, written);
	if (err) {
		HIP_ERROR("Building of DH failed (%d)\n", err);
		goto out_err;
	}
	
        /********** HIP transform. **********/

	param = hip_get_param(ctx->input, HIP_PARAM_HIP_TRANSFORM);
	if (!param) {
		err = -ENOENT;
		goto out_err;
	}

	transform_hip_suite =
		hip_select_hip_transform((struct hip_hip_transform *) param);
	if (transform_hip_suite == 0) {
		HIP_ERROR("Could not find acceptable hip transform suite\n");
		err = -EINVAL;
		goto out_err;
	}
	
	/* Select only one transform */
	err = hip_build_param_transform(i2, HIP_PARAM_HIP_TRANSFORM,
					&transform_hip_suite, 1);
	if (err) {
		HIP_ERROR("Building of HIP transform failed\n");
		goto out_err;
	}

	/********** ESP-ENC transform. **********/

	param = hip_get_param(ctx->input, HIP_PARAM_ESP_TRANSFORM);
	if (!param) {
		err = -ENOENT;
		goto out_err;
	}
	
	/* Select only one transform */
	transform_esp_suite =
		hip_select_esp_transform((struct hip_esp_transform *) param);
	if (transform_esp_suite == 0) {
		HIP_ERROR("Could not find acceptable hip transform suite\n");
		goto out_err;
	}
	err = hip_build_param_transform(i2, HIP_PARAM_ESP_TRANSFORM,
					&transform_esp_suite, 1);
	if (err) {
		HIP_ERROR("Building of ESP transform failed\n");
		goto out_err;
	}

	/************ Encrypted ***********/
	
	err = hip_build_param_encrypted(i2, host_id_pub);
 	if (err) {
 		HIP_ERROR("Building of param encrypted failed (%d)\n",
 			  err);
 		goto out_err;
 	}

 	enc_in_msg = hip_get_param(i2, HIP_PARAM_ENCRYPTED);
 	HIP_ASSERT(enc_in_msg); /* Builder internal error. */

 	host_id_in_enc = (char *) (enc_in_msg + 1);

	err = hip_crypto_encrypted(host_id_in_enc,
				   enc_in_msg->iv,
				   /* hip transform was selected above */
				   transform_hip_suite,
				   hip_get_param_total_len(host_id_in_enc),
				   &ctx->hip_i.key,
				   HIP_DIRECTION_ENCRYPT);
	if (err) {
		HIP_ERROR("Building of param encrypted failed %d\n", err);
		goto out_err;
	}

	/* it appears as the crypto function overwrites the IV field, which
	 * definitely breaks our 2.4 responder... Perhaps 2.6 and 2.4 cryptos
	 * are not interoprable or we screw things pretty well in 2.4 :)
	 */
	memset((u8 *)enc_in_msg->iv, 0, 8);
        /* Now that almost everything is set up except the signature, we can
	 * try to set up inbound IPsec SA, similarly as in hip_create_r2 */

	{
		int err;

		/* let the setup routine give us a spi. */
		spi_in = 0;

		err = hip_setup_sa(&ctx->input->hits, &ctx->input->hitr,
				    &spi_in, transform_esp_suite, 
				    &ctx->hip_espr.key, &ctx->hip_authr.key, 1);

		if (err) {
			HIP_ERROR("failed to setup IPsec SPD/SA entries, peer:src (err=%d)\n", err);
			/* hip_delete_spd/hip_delete_sa ? */
			goto out_err;
		}
		/* XXX: -EAGAIN */

		HIP_DEBUG("set up inbound IPsec SA, SPI=0x%x (host)\n", spi_in);
	}

	/* update SPI_LSI parameter because it has not been filled with SPI
	 * and LSI values yet */
 	spi_lsi = hip_get_param(i2, HIP_PARAM_SPI_LSI);
 	HIP_ASSERT(spi_lsi); /* Builder internal error */
 	hip_set_param_spi_value(spi_lsi, spi_in);
 	hip_set_param_lsi_value(spi_lsi, 0x01000000 |
 		 (ntohl(ctx->input->hitr.in6_u.u6_addr32[3]) & 0x00ffffff));

	HIP_DEBUG("lsi in i2: %.8x\n", hip_get_param_lsi_value(spi_lsi));
 
	/* Do not modify the packet after this point or signature
	 * will not validate */

	/********** Signature **********/

        /* Should have been fetched during making of hip_encrypted */
	HIP_ASSERT(host_id_private);

	/* Build a digest of the packet built so far. Signature will
	   be calculated over the digest. */

	if (!hip_create_signature(i2, hip_get_msg_total_len(i2), 
				  host_id_private, signature)) {
		HIP_ERROR("Could not create signature\n");
		err = -EINVAL;
		goto out_err;
	}

	/* Only DSA supported currently */
	HIP_ASSERT(hip_get_host_id_algo(host_id_private) == HIP_HI_DSA);

	err = hip_build_param_signature_contents(i2,
					signature,
					HIP_DSA_SIGNATURE_LEN,
					HIP_SIG_DSA);
	if (err) {
		HIP_ERROR("Building of signature failed (%d)\n", err);
		goto out_err;
	}

      	/********** I2 packet complete **********/

	/* jlu XXX: WRITE: The only place in R1 handlers where entry
	   is being written to */
	{
		struct hip_birthday_cookie *bc;

		bc = hip_get_param(ctx->input, HIP_PARAM_BIRTHDAY_COOKIE_R1);
		if (!bc) {
			err = -ENOENT;
			goto out_err;
		}
		
		
		HIP_LOCK_HA(entry);
		entry->spi_in = hip_get_param_spi_value(spi_lsi);
		entry->lsi_our = hip_get_param_lsi_value(spi_lsi);
		entry->birthday = ntoh64(bc->birthday);
		entry->esp_transform = transform_esp_suite;

		/* Store the keys until we receive R2 */
		err = hip_store_base_exchange_keys(entry,ctx,1);
		HIP_UNLOCK_HA(entry);

		if (err) {
			HIP_DEBUG("hip_store_base_exchange_keys failed\n");
			goto out_err;
		}
	}

	/* todo: Also store the keys that will be given to ESP later */

	HIP_DEBUG("sending I2\n");

	err = hip_hadb_get_peer_addr(entry, &daddr);
	if (err) {
		HIP_DEBUG("hip_sdb_get_peer_address failed, err = %d\n", err);
		goto out_err;
	}

	/* state E1: Receive R1, process. If successful,
	   send I2 and go to E2. */
	err = hip_csum_send(NULL, &daddr, i2);
	if (err) {
		HIP_ERROR("sending of I2 failed, err=%d\n", err);
		goto out_err;
	}

	/* rmb() = make sure all readers have read the value, before
	 * continuing?.
	 */
	rmb();
	entry->state = HIP_STATE_I2_SENT;

	HIP_DEBUG("moved to state I2_SENT\n");

 out_err:
	if (host_id_private)
		kfree(host_id_private);
	if (host_id_pub)
		kfree(host_id_pub);
	if (i2)
		kfree(i2);
	if (dh_data)
		kfree(dh_data);
		
	return err;
}


/**
 * hip_handle_r1 - handle incoming R1 packet
 * @skb: sk_buff where the HIP packet is in
 *
 * This function is the actual point from where the processing of R1
 * is started and corresponding I2 is created.
 *
 * On success (R1 payloads are checked and daemon is called) 0 is
 * returned, otherwise < 0.
 */
int hip_handle_r1(struct sk_buff *skb, hip_ha_t *entry)
{
	int err = 0;
	struct hip_common *r1 = NULL;
	struct hip_context *ctx = NULL;
	struct hip_birthday_cookie *bc;
	uint64_t solved_puzzle;
	struct hip_host_id *peer_host_id;
	struct hip_lhi peer_lhi;
	int64_t birthday;

	ctx = kmalloc(sizeof(struct hip_context), GFP_KERNEL);
	if (!ctx) {
		HIP_ERROR("Could not allocate memory for context\n");
		err = -ENOMEM;
		goto out_err;
	}
	memset(ctx, 0, sizeof(struct hip_context));

	r1 = (struct hip_common*) skb->h.raw;
	ctx->input = r1;
	ctx->skb_in = skb;

	/* If R1 was sent without our HIT as a receiver, we'll dig
	 * our HIT now
	 */
	if (ipv6_addr_any(&ctx->input->hitr)) {
		/* fill own HIT */
		hip_copy_any_localhost_hit(&ctx->input->hitr);
	}

 	bc = hip_get_param(r1, HIP_PARAM_BIRTHDAY_COOKIE_R1);
 	if (!bc) {
 		err = -ENOENT;
 		HIP_ERROR("Birthday cookie missing from R1\n");
		goto out_err;
	}
	  
	HIP_LOCK_HA(entry);
	birthday = entry->birthday;
	HIP_UNLOCK_HA(entry);

	/* Do the obvious quick-discard tests: Birthday, ... */
	if (!hip_birthday_success(birthday, ntoh64(bc->birthday))) {
		HIP_ERROR("Received birthday with old date. Dropping\n");
//		err = -EINVAL;
//		goto out_err;
	}


	/* validate SIGNATURE2 */

 	peer_host_id = hip_get_param(r1, HIP_PARAM_HOST_ID);
 	if (!peer_host_id) {
 		HIP_ERROR("No HOST_ID found in R1\n");
 		err = -ENOENT;
 		goto out_err;
 	}

	err = hip_verify_packet_signature2(r1, peer_host_id);
	if (err) {
 		HIP_ERROR("Verification of R1 signature failed\n");
		err = -EINVAL;
 		goto out_err;
	}
	HIP_DEBUG("SIGNATURE in R1 ok\n");

	/* signature is ok, now save the host id to db */
 	peer_lhi.anonymous = 0;
	ipv6_addr_copy(&peer_lhi.hit, &r1->hits);
 	
 	err = hip_add_host_id(HIP_DB_PEER_HID, &peer_lhi,
			      peer_host_id);
 	if (err == -EEXIST) {
 		HIP_INFO("Host id already exists. Ignoring.\n");
 		err = 0;
 	} else if (err) {
 		HIP_ERROR("Failed to add peer host id to the database\n");
 		goto out_err;
  	}

	/* calculate shared secret and create keying material */
	ctx->dh_shared_key = NULL;
	err = hip_produce_keying_material(r1, ctx);
	if (err) {
		HIP_ERROR("Could not produce keying material\n");
		err = -EINVAL;
		goto out_err;
	}

	/* keying material ready */

	if (!hip_solve_puzzle(bc, r1 ,&solved_puzzle,
			      HIP_SOLVE_PUZZLE)) {
		HIP_ERROR("Solving of puzzle failed\n");
		err = -EINVAL;
		goto out_err;
	}
	
	/* Puzzle solved. We should be ready to create I2.
	 * I2 requires the value that solved the puzzle so we'll give it.
	 */
	
	HIP_INFO("R1 Successfully received\n");
 	err = hip_create_i2(ctx, solved_puzzle, entry);
 	if (err) {
 		HIP_ERROR("Creation of I2 failed (%d)\n", err);
 	}
 	
 out_err:
	if (ctx->dh_shared_key)
		kfree(ctx->dh_shared_key);
	if (ctx)
		kfree(ctx);
	return err;
}

/**
 * hip_receive_r1 - receive an R1 packet
 * @skb: sk_buff that contains the HIP packet
 * @hip_common: pointer to the HIP header
 *
 * This is the initial function which is called when an R1 packet is
 * received. First we check if we have sent the corresponding I1. If
 * yes, then the received R1 is handled in hip_handle_r1. In
 * established state we also handle the R1. Otherwise the packet is
 * dropped and not handled in any way.
 *
 * Always frees the skb
 */
int hip_receive_r1(struct sk_buff *skb)
{
	struct hip_common *hip_common;
	hip_ha_t *entry;
	int state;
	int err = 0;

	HIP_DEBUG("Received R1\n");

	hip_common = (struct hip_common*) (skb)->h.raw;

	if (ipv6_addr_any(&hip_common->hitr)) {
		HIP_DEBUG("Received NULL receiver HIT in R1. Not dropping\n");
	}

	_HIP_HEXDUMP("searching", &hip_common->hits, sizeof(struct in6_addr));

	entry = hip_hadb_find_byhit(&hip_common->hits);
	if (!entry) {
		err = -EFAULT;
		HIP_ERROR("Received R1 with no local state. Dropping\n");
		goto out_drop;
	}

	/* since the entry is in the hit-list and since the previous
	 * function increments by one, we must have at least 2 references
	 */
	HIP_ASSERT(atomic_read(&entry->refcnt) >= 2);

	/* I hope wmb() takes care of the locking needs */
	wmb();
	state = entry->state;

	HIP_DEBUG("entry->state is %s\n", hip_state_str(state));
	switch(state) {
	case HIP_STATE_I1_SENT:
		/* E1. The normal case. Process, send I2, goto E2. */
		err = hip_handle_r1(skb, entry);
		if (err < 0)
			HIP_ERROR("Handling of R1 failed\n");
		break;
	case HIP_STATE_I2_SENT:
		/* E2. Drop and stay. */
		HIP_ERROR("Received R1 in state I2_SENT. Dropping\n");
		break;
	case HIP_STATE_ESTABLISHED:
		/* E3. jlu XXX: TBD. Birthday, I2, goto E2. */
		HIP_DEBUG("Received R1 in ESTABLISHED.\n");
		/* Birthday is checked in hip_handle_r1 (but ignored for now) */
		err = hip_handle_r1(skb, entry);
		if (!err) {
			/* if fail, start at E3 */
 			HIP_ERROR("hip_handle_r1 failed (%d)\n", err);
 		} else {
 			/* TODO: draft-08: Successful: prepare to drop old SA
 			   and cycle at E3. Note that handle_r1 changes
 			   the state. This may not be reasonable! */
 		}
 		break;
 	case HIP_STATE_REKEYING:
 		/* TODO: process with SA and birthday check */
		err = hip_handle_r1(skb, entry);
 		if (err) {
 			HIP_ERROR("hip_handle_r1 failed (%d)\n", err);
 		} else {
 			/* TODO: draft-08 If successful, send I2, prepare to
 			   drop old SA and go to E3. Is this reasonable? */
 		}
 
		break;
	default:
		/* Can't happen. */
		err = -EFAULT;
		HIP_ERROR("R1 received. Receiver is confused about its own state. Dropping\n");
		break;
	}
	
	hip_put_ha(entry);
 out_drop:
	return err;
}

/**
 * hip_create_r2 - Creates and transmits R2 packet.
 * @ctx: Context of processed I2 packet.
 *
 * Returns: 0 on success, < 0 on error.
 */
int hip_create_r2(struct hip_context *ctx, hip_ha_t *entry)
{
	struct in6_addr tmp_hitr;
	uint32_t spi_in, spi_out;
	uint32_t lsi;
	int esptfm;
 	struct hip_host_id *host_id_private;
	struct hip_tlv_common *param;
 	struct hip_common *r2 = NULL;
	struct hip_common *i2;
 	int err = 0;
	int clear = 0;
 	u8 signature[HIP_DSA_SIGNATURE_LEN];

	HIP_DEBUG("\n");

	i2 = ctx->input;

	/* why? */
	ipv6_addr_copy(&tmp_hitr, &ctx->input->hitr);

	/* If we have old SAs and SPDs with these HITs delete them
	 * ignoring the return value */
	/* keep this here or move this to prev else ? */
	hip_delete_esp(entry);

 	param = hip_get_param(ctx->input, HIP_PARAM_BIRTHDAY_COOKIE_I2);
 	if (!param) {
 		err = -ENOENT;
		HIP_ERROR("Did not find birthday cookie on i2\n");
 		goto out_err;
 	}

	{
		struct hip_spi_lsi *spi_lsi;
		struct hip_esp_transform *esp_tf;

		esp_tf = hip_get_param(ctx->input, HIP_PARAM_ESP_TRANSFORM);
		if (!esp_tf) {
			err = -ENOENT;
			HIP_ERROR("Did not find ESP transform on i2\n");
			goto out_err;
		}

		spi_lsi = hip_get_param(ctx->input, HIP_PARAM_SPI_LSI);
		if (!spi_lsi) {
			err = -ENOENT;
			HIP_ERROR("Did not find SPI LSI on i2\n");
			goto out_err;
		}

		HIP_LOCK_HA(entry);
		entry->peer_controls = ntohs(i2->control);
		entry->birthday = ntoh64(((struct hip_birthday_cookie *)param)->birthday);
		/* todo: check if this is really our HIT? */
		ipv6_addr_copy(&entry->hit_our, &tmp_hitr);
		ipv6_addr_copy(&entry->hit_peer, &i2->hits);
		entry->spi_out = ntohl(spi_lsi->spi);
		entry->lsi_peer = ntohl(spi_lsi->lsi);
		entry->esp_transform = hip_select_esp_transform(esp_tf);
		esptfm = entry->esp_transform;
		HIP_UNLOCK_HA(entry);

		if (entry->esp_transform == 0) {
			HIP_ERROR("Could not select proper ESP transform\n");
			goto out_err;
		}
	}

	hip_hadb_delete_peer_addrlist(entry);
	/* todo: what are the default values for initial address ?
	   some flags to indicate that this address if the initial
	   address ? */
	err = hip_hadb_add_peer_addr(entry, &(ctx->skb_in->nh.ipv6h->saddr), 0, 0);
	if (err) {
		HIP_ERROR("error while adding a new peer address\n");
		goto out_err;
	}

	/* Set up IPsec associations */
	{
		spi_in = 0;

		err = hip_setup_sa(&i2->hits, &i2->hitr, &spi_in, esptfm, 
				   &ctx->hip_espi.key, &ctx->hip_authi.key, 1);

		if (err) {
			HIP_ERROR("failed to setup IPsec SPD/SA entries, peer:src (err=%d)\n", err);
			hip_delete_esp(entry);
			goto out_err;
		}
		/* XXX: Check -EAGAIN */

		HIP_DEBUG("set up inbound IPsec SA, SPI=0x%x (host)\n", spi_in);
		/* ok, found an unused SPI to use */
	}

	wmb();
	spi_out = entry->spi_out;
	
	HIP_DEBUG("setting up outbound IPsec SA, SPI=0x%x (host [db])\n", spi_out);

	err = hip_setup_sa(&i2->hitr, &i2->hits, &spi_out, esptfm, 
			   &ctx->hip_espr.key, &ctx->hip_authr.key, 1);

	if (err == -EEXIST) {
		HIP_DEBUG("SA already exists for the SPI=0x%x\n", spi_out);
		HIP_DEBUG("TODO: what to do ? currently ignored\n");
	} else if (err) {
		HIP_ERROR("failed to setup IPsec SPD/SA entries, peer:dst (err=%d)\n", err);
		/* delete all IPsec related SPD/SA for this entry */
		hip_delete_esp(entry);
		goto out_err;
	}
	/* XXX: Check if err = -EAGAIN... */


	HIP_DEBUG("set up outbound IPsec SA, SPI=0x%x\n", spi_out);

	/* source IPv6 address is implicitly the preferred
	 * address after the base exchange */
	err = hip_hadb_add_addr_to_spi(entry, spi_out, &ctx->skb_in->nh.ipv6h->saddr,
				       0, PEER_ADDR_STATE_ACTIVE, 0, 1);
	HIP_DEBUG("add spi err ret=%d\n", err);
	if (err) {
		HIP_ERROR("failed to add an address to SPI list\n");
		goto out_err;
	}
	entry->default_spi_out = spi_out;
	HIP_DEBUG("set default SPI out=0x%x\n", spi_out);
	hip_hadb_dump_spi_list(entry, NULL);

	{
		/* this is a delayed "insertion" from some 20 lines above */
		HIP_LOCK_HA(entry);
		entry->spi_in = spi_in;
		entry->state = HIP_STATE_ESTABLISHED;

		err = hip_store_base_exchange_keys(entry, ctx, 0);
		HIP_UNLOCK_HA(entry);

		if (err) {
			HIP_DEBUG("hip_store_base_exchange_keys failed\n");
			goto out_err;
		}

		HIP_DEBUG("Inserting state again (SPI initialized)\n");
		hip_hadb_insert_state(entry);

		hip_finalize_sa(&i2->hits, spi_out);
		hip_finalize_sa(&i2->hitr, spi_in);
	}

	HIP_DEBUG("Reached ESTABLISHED state\n");
	/* jlu XXX: WRITE: Entry not touched after this */

	/* Build and send R2 */
	r2 =  hip_msg_alloc();
	if (!r2) {
		err = -ENOMEM;
		HIP_ERROR("No memory for R2\n");
		goto out_err;
	}

	/* just swap the addresses to use the I2's destination HIT as
	 * the R2's source HIT */
	hip_build_network_hdr(r2, HIP_R2, 0,
			      &ctx->input->hitr, &ctx->input->hits);

 	/********** SPI_LSI **********/
 
	/* LSI: 1.x.y.z */
	lsi = 0x01000000 | (ntohl(ctx->input->hitr.s6_addr32[3]) 
			    & 0x00ffffff);

	rmb();
	entry->lsi_our = lsi;

	err = hip_build_param_spi_lsi(r2, lsi, spi_in);
 	if (err) {
 		HIP_ERROR("building of SPI_LSI failed (err=%d)\n", err);
 		goto out_err;
	}

	/*********** HMAC ************/

	{
		struct hip_crypto_key hmac;

		HIP_LOCK_HA(entry);
		memcpy(&hmac, &entry->hmac_our, sizeof(hmac));
		HIP_UNLOCK_HA(entry);

		err = hip_build_param_hmac_contents(r2, &hmac);
		if (err) {
			HIP_ERROR("Building of hmac failed (%d)\n", err);
			goto out_err;
		}
	}


	/********** SIGNATURE *********/

	host_id_private = hip_get_any_localhost_host_id();
	if (!host_id_private) {
		HIP_ERROR("Could not get own host identity. Can not sign data\n");
		goto out_err;
	}

	if (!hip_create_signature(r2, hip_get_msg_total_len(r2),
				  host_id_private, signature)) {
		HIP_ERROR("Could not sign R2. Failing\n");
		err = -EINVAL;
		goto out_err;
	}
	    
	err = hip_build_param_signature_contents(r2, signature,
						 HIP_DSA_SIGNATURE_LEN,
 						 HIP_SIG_DSA);
 	if (err) {
 		HIP_ERROR("Building of signature failed (%d)\n", err);
 		goto out_err;
 	}
 	
 	/* Send the packet */
	    
	HIP_DEBUG("sending R2\n");
	err = hip_csum_send(NULL, &(ctx->skb_in->nh.ipv6h->saddr), r2);
	if (err) {
		HIP_ERROR("csum_send failed\n");
	}

 out_err:
	if (r2)
		kfree(r2);
	if (clear && entry)
		hip_put_ha(entry);
	return err;
}


/**
 * hip_handle_i2 - handle incoming I2 packet
 * @skb: sk_buff where the HIP packet is in
 *
 * This function is the actual point from where the processing of I2
 * is started and corresponding R2 is created.
 *
 * On success (I2 payloads are checked and R2 is created and sent) 0 is
 * returned, otherwise < 0.
 */
int hip_handle_i2(struct sk_buff *skb)
{
	int err = 0;
	struct hip_common *i2 = NULL;
	struct hip_context *ctx = NULL;
	struct hip_encrypted *tmp_host_id = NULL;
 	struct hip_tlv_common *param;
 	struct hip_birthday_cookie *bc;
 	struct in6_addr *src;
 	struct in6_addr *dst;
 	struct hip_encrypted *enc = NULL;
 	struct hip_lhi lhi;
 	struct hip_host_id *host_id_in_enc = NULL;
	hip_ha_t *entry = NULL;
	int64_t birthday;
 
 	HIP_DEBUG("\n");

	ctx = kmalloc(sizeof(struct hip_context), GFP_KERNEL);
	if (!ctx) {
		err = -ENOMEM;
		goto out_err;
	}
	memset(ctx, 0, sizeof(struct hip_context));

	ctx->skb_in = skb;
	i2 = (struct hip_common*) skb->h.raw;
	ctx->input = (struct hip_common*) skb->h.raw;

	/* Check packet validity */

 	enc = hip_get_param(ctx->input, HIP_PARAM_ENCRYPTED);
 	if (!enc) {
 		err = -ENOENT;
		HIP_ERROR("Could not find enc parameter\n");
 		goto out_err;
 	}
 
 	tmp_host_id = kmalloc(hip_get_param_total_len(enc),
 			      GFP_KERNEL);
 	if (!tmp_host_id) {
 		HIP_ERROR("No memory for temporary host_id\n");
 		err = -ENOMEM;
  		goto out_err;
  	}

	/* Birthday check
	   draft: 5.3 Reboot and SA timeout restart of HIP: The I2
	   packet MUST have a Birthday greater than the current SA's
	   Birthday. */

 	bc = hip_get_param(ctx->input, HIP_PARAM_BIRTHDAY_COOKIE_I2);
 	if (!bc) {
 		err = -ENOENT;
		HIP_ERROR("Could not find i2 birthday cookie\n");
 		goto out_err;
 	}


	entry = hip_hadb_find_byhit(&i2->hits);
	if (!entry) {
		HIP_DEBUG("No previous entry found.\n");
		birthday = 0;
	} else {
		HIP_DEBUG("Previous entry found, checking birthday\n");

		HIP_LOCK_HA(entry);
		birthday = entry->birthday;
		HIP_UNLOCK_HA(entry);

		if (!hip_birthday_success(birthday, ntoh64(bc->birthday))) {
			HIP_ERROR("Failed birthday. Did not drop\n");
//			err = -EINVAL;
//			goto out_err;
		}
	}

	HIP_DEBUG("Birthday ok\n");

	/* validate cookie */

	src = &skb->nh.ipv6h->saddr;
	dst = &skb->nh.ipv6h->daddr;

	if (!hip_verify_cookie(src, dst, i2, bc)) {
		HIP_ERROR("Birthday cookie checks failed\n");
		err = -ENOMSG;
		goto out_err;
	}

	/* produce keying material */
	ctx->dh_shared_key = NULL;
 	err = hip_produce_keying_material(ctx->input, ctx);
 	if (err) {
 		HIP_ERROR("Unable to produce keying material. Dropping I2\n");
 		goto out_err;
 	}

	/* little workaround...
	 * We have a function that calculates sha1 digest and then verifies the
	 * signature. But since the sha1 digest in I2 must be calculated over
	 * the encrypted data, and the signature requires that the encrypted
	 * data to be decrypted (it contains peer's host identity (DSA key)),
	 * we are forced to do some temporary copying...
	 * If ultimate speed is required, then calculate the digest here as
	 * usual and feed it to signature verifier. 
	 */

	memcpy(tmp_host_id, enc, hip_get_param_total_len(enc));

	/* Decrypt ENCRYPTED field*/

	_HIP_HEXDUMP("Recv. Key", &ctx->hip_i.key, 24);

	param = hip_get_param(ctx->input, HIP_PARAM_HIP_TRANSFORM);
	if (!param) {
		err = -ENOENT;
		HIP_ERROR("Did not find HIP transform\n");
		goto out_err;
	}

        /* Get the encapsulated host id in the encrypted parameter */
	host_id_in_enc = (struct hip_host_id *) (tmp_host_id + 1);

	err = hip_crypto_encrypted(host_id_in_enc,
				   tmp_host_id->iv,
				   hip_get_param_transform_suite_id(param, 0),
				   hip_get_param_total_len(tmp_host_id),
				   &ctx->hip_i.key,
				   HIP_DIRECTION_DECRYPT);
	if (err) {
		err = -EINVAL;
		HIP_ERROR("Decryption of Host ID failed\n");
		goto out_err;
	}

	_HIP_HEXDUMP("Encrypted after decrypt", host_id_in_enc,
		     hip_get_param_total_len(tmp_host_id));

	/* NOTE! The original packet has the data still encrypted. But this is
	 * not a problem, since we have decrypted the data into a temporary
	 * storage and nobody uses the data in the original packet.
	 */

	/* validate signature */
	err = hip_verify_packet_signature(ctx->input, host_id_in_enc);
	if (err) {
 		HIP_ERROR("Verification of I2 signature failed\n");
		err = -EINVAL;
 		goto out_err;
	}
	HIP_DEBUG("SIGNATURE in I2 ok\n");

  	/* Add peer's host id to peer_id database (is there need to
  	   do this?) */
 	lhi.anonymous = 0;
	ipv6_addr_copy(&lhi.hit, &ctx->input->hits);

 	err = hip_add_host_id(HIP_DB_PEER_HID, &lhi, host_id_in_enc);
 	if (err == -EEXIST) {
 		err = 0;
 		HIP_INFO("Host id already exists. Ignoring.\n");
 	} else if (err) {
 		HIP_ERROR("Could not store peer's identity\n");
 		goto out_err;
  	}

	/* I2 Handled, create and send R2 */
	if (!entry) {
		/* we have no previous infomation on the peer, create
		 * a new HIP HA */

		
		entry = hip_hadb_create_state(GFP_KERNEL);
		if (!entry) {
			HIP_ERROR("Failed to create or find entry\n");
			err = -ENOMSG;
			goto out_err;
		}

		ipv6_addr_copy(&entry->hit_peer,&i2->hits);
		ipv6_addr_copy(&entry->hit_our,&i2->hitr);
		
		hip_hadb_insert_state(entry);
		hip_hold_ha(entry);
		/* insert automatically holds for the data structure
		 * references, but since we continue to use the entry,
		 * we have to hold for our own usage too
		 */
	} else {
		/* now what.. birthday check was ok... so? */
	}

	err = hip_create_r2(ctx, entry);
	HIP_DEBUG("hip_handle_r2 returned %d\n", err);
	if (err) {
		HIP_ERROR("Creation of R2 failed\n");
	}

 out_err:
	if (entry)
		hip_put_ha(entry);
	if (tmp_host_id)
		kfree(tmp_host_id);
	if (ctx->dh_shared_key)
		kfree(ctx->dh_shared_key);
	if (ctx)
		kfree(ctx);

	return err;
}

/**
 * hip_receive_i2 - receive I2 packet
 * @skb: sk_buff where the HIP packet is in
 * @hip_common: pointer to HIP header
 *
 * This is the initial function which is called when an I2 packet is
 * received. If we are in correct state, the packet is handled to
 * hip_handle_i2() for further processing.
 *
 * Returns always 0.
 *
 * TODO: check if it is correct to return always 0 
 */
int hip_receive_i2(struct sk_buff *skb) 
{
	struct hip_common *i2;
	int state;
	int err = 0;
	hip_ha_t *entry;

	i2 = (struct hip_common*) (skb)->h.raw;

	HIP_DEBUG("\n");

	if (ipv6_addr_any(&i2->hitr)) {
		HIP_ERROR("Received NULL receiver HIT in I2. Dropping\n");
		goto out;
	}

	state = 0;

	entry = hip_hadb_find_byhit(&i2->hits);
	if (!entry) {
		state = HIP_STATE_UNASSOCIATED;
	} else {
		wmb();
		state = entry->state;
		hip_put_ha(entry);
	}

 	switch(state) {
 	case HIP_STATE_UNASSOCIATED:
 		err = hip_handle_i2(skb);
 		break;
 	case HIP_STATE_I1_SENT:
 		err = hip_handle_i2(skb);
 		break;
 	case HIP_STATE_I2_SENT:
 		err = hip_handle_i2(skb);
 		break;
 	case HIP_STATE_ESTABLISHED:
 		/* jlu XXX: 
 		   TBD: Do birthday check,
 		   TBD: Drop old SA,
 		   Done: Send R2 
 		*/
 		HIP_DEBUG("Received I2 in state ESTABLISHED. Did not do birthday\n");
 		err = hip_handle_i2(skb);
 		break;
 	case HIP_STATE_REKEYING:
 		/* XX TODO: check birthday */
 		err = hip_handle_i2(skb);
 		if (err < 0) {
 			/* XX TODO: prepare to drop old SA and go to E3 */
		}
		break;
	default:
		HIP_ERROR("Internal state (%d) is incorrect\n", state);
		break;
	}

 out:
	return err;
}


/**
 * hip_handle_r2 - handle incoming R2 packet
 * @skb: sk_buff where the HIP packet is in
 *
 * This function is the actual point from where the processing of R2
 * is started.
 *
 * On success (payloads are created and IPsec is set up) 0 is
 * returned, otherwise < 0.
 */
int hip_handle_r2(struct sk_buff *skb, hip_ha_t *entry)
{
	int err = 0;
	uint16_t len;
	struct hip_context *ctx = NULL;
	struct in6_addr *sender;
 	struct hip_host_id *peer_id = NULL;
 	struct hip_lhi peer_lhi;
 	struct hip_spi_lsi *spi_lsi = NULL;
 	struct hip_sig *sig = NULL;
	struct hip_common *r2 = NULL;

	HIP_DEBUG("Entering handle_r2\n");

	ctx = kmalloc(sizeof(struct hip_context), GFP_KERNEL);
	if (!ctx) {
		err = -ENOMEM;
		goto out_err;
	}
	memset(ctx, 0, sizeof(struct hip_context));
	ctx->skb_in = skb;
        ctx->input = (struct hip_common*) skb->h.raw;
	r2 = ctx->input;

	sender = &r2->hits;

	// jlu XXX: Should check birthday.
	// jlu XXX: Should check if whole packet was processed...

	// set checksum to zero as in Jokela draft before sha1 hashing

        /* verify HMAC */
	err = hip_verify_packet_hmac(r2,entry);
	if (err) {
		HIP_ERROR("HMAC validation on R2 failed\n");
		goto out_err;
	}
	HIP_DEBUG("HMAC in R2 ok\n");

	/* signature validation */

 	sig = hip_get_param(r2, HIP_PARAM_HIP_SIGNATURE);
 	if (!sig) {
 		err = -ENOENT;
 		goto out_err;
 	}
 	
 	hip_zero_msg_checksum(r2);
 	len = (u8*) sig - (u8*) r2;
 	hip_set_msg_total_len(r2, len);
 	
 	peer_lhi.anonymous = 0;
 	ipv6_addr_copy(&peer_lhi.hit, &r2->hits);
 	
 	peer_id = hip_get_host_id(HIP_DB_PEER_HID, &peer_lhi);
 	if (!peer_id) {
 		HIP_ERROR("Unknown peer (no identity found)\n");
 		err = -EINVAL;
 		goto out_err;
 	}
 	
 	if (!hip_verify_signature(r2, len, peer_id,
 				  (u8*)(sig + 1))) {
 		HIP_ERROR("R2 signature verification failed\n");
 		err = -EINVAL;
 		goto out_err;
 	}

        /* The rest */

 	spi_lsi = hip_get_param(r2, HIP_PARAM_SPI_LSI);
 	if (!spi_lsi) {
		HIP_ERROR("Parameter SPI_LSI not found\n");
 		err = -EINVAL;
 		goto out_err;
 	}

	{
		int tfm;
		uint32_t spi_recvd, spi_in;

		spi_recvd = ntohl(spi_lsi->spi);

		HIP_LOCK_HA(entry);
		entry->spi_out = spi_recvd;
		entry->lsi_peer = ntohl(spi_lsi->lsi);
		memcpy(&ctx->hip_espi, &entry->esp_our, sizeof(ctx->hip_espi));
		memcpy(&ctx->hip_authi, &entry->auth_our, sizeof(ctx->hip_authi));
		spi_in = entry->spi_in;
		tfm = entry->esp_transform;

		err = hip_setup_sa(&r2->hitr, sender, &spi_recvd, tfm, 
				   &ctx->hip_espi.key, &ctx->hip_authi.key, 1);
		if (err == -EEXIST) {
			HIP_DEBUG("SA already exists for the SPI=0x%x\n", spi_recvd);
			HIP_DEBUG("TODO: what to do ? currently ignored\n");
		} else 	if (err) {
			HIP_ERROR("hip_setup_sa failed, peer:dst (err=%d)\n", err);
			HIP_ERROR("** TODO: remove inbound IPsec SA**\n");
		}
		/* XXX: Check for -EAGAIN */

		/* source IPv6 address is implicitly the preferred
		 * address after the base exchange */
		err = hip_hadb_add_addr_to_spi(entry, spi_recvd, &skb->nh.ipv6h->saddr,
					       0, PEER_ADDR_STATE_ACTIVE, 0, 1);
		entry->default_spi_out = spi_recvd;
		HIP_DEBUG("set default SPI out=0x%x\n", spi_recvd);
		HIP_DEBUG("add spi err ret=%d\n", err);
		hip_hadb_dump_spi_list(entry, NULL);
		HIP_UNLOCK_HA(entry);

		smp_rmb();
		entry->state = HIP_STATE_ESTABLISHED;

		HIP_DEBUG("Reached ESTABLISHED state\n");
		
		hip_hadb_insert_state(entry);
		
		/* these will change SAs' state from ACQUIRE to VALID, and
		 * wake up any transport sockets waiting for a SA
		 */
		hip_finalize_sa(&r2->hits, spi_recvd);
		hip_finalize_sa(&r2->hitr, spi_in);
	}

 out_err:
	if (ctx)
		kfree(ctx);
	return err;
}

/**
 * hip_receive_i1 - receive I1 packet
 * @skb: sk_buff where the HIP packet is in
 * @hip_common: pointer to HIP header
 *
 * This is the initial function which is called when an I1 packet is
 * received. If we are in correct state we reply with an R1 packet.
 *
 * This function never writes into hip_sdb_state entries.
 *
 * Returns: zero on success, or negative error value on error.
 */
int hip_receive_i1(struct sk_buff *skb) 
{
	struct hip_i1 *hip_i1 = (struct hip_i1*) skb->h.raw;
	struct hip_common *r1;
	int ok = 0;
	int err = 0;
	int state;
	hip_ha_t *entry;

	HIP_DEBUG("\n");

	r1 = (struct hip_common*) (skb)->h.raw;
	if (ipv6_addr_any(&r1->hitr)) {
		HIP_ERROR("Received NULL receiver HIT. Opportunistic HIP is not supported yet in I1. Dropping\n");
		err = -EPROTONOSUPPORT;
		goto out;
	}

	if (!hip_controls_sane(ntohs(hip_i1->control),
			       HIP_CONTROL_PIGGYBACK_ALLOW)) {
		HIP_ERROR("Received illegal controls in I1. Dropping\n");
		goto out;
	}
	entry = hip_hadb_find_byhit(&r1->hits);
	if (entry) {
		smp_wmb();
		state = entry->state;
		hip_put_ha(entry);
	} else
		state = HIP_STATE_NONE;
	
	HIP_DEBUG("Received I1 in state %s\n", hip_state_str(state));
	switch(state) {
	case HIP_STATE_NONE:
		ok = hip_send_r1(skb);
		//HIP_DEBUG("Received I1 in no state. Sent R1\n");
		break;
	case HIP_STATE_UNASSOCIATED:
		ok = hip_send_r1(skb);
		//HIP_DEBUG("Received I1 in state UNASSOCIATED. Sent R1\n");
		break;
	case HIP_STATE_I1_SENT:
		ok = hip_send_r1(skb);
		//HIP_DEBUG("Received I1 in state I1_SENT. Sent R1\n");
		break;
	case HIP_STATE_I2_SENT:
		ok = hip_send_r1(skb);
		//HIP_DEBUG("Received I1 in state I2_SENT. Sent R1\n");
		break;
	case HIP_STATE_ESTABLISHED:
		ok = hip_send_r1(skb);
		//HIP_DEBUG("Special: Received I1 in state ESTABLISHED. Sent R1\n");
		break;
	case HIP_STATE_REKEYING:
		ok = hip_send_r1(skb);
		//HIP_DEBUG("Received I1 in state REKEYING. Sent R1.\n");
		break;
	default:
		HIP_ERROR("DEFAULT CASE, UNIMPLEMENTED STATE HANDLING");
		ok = -EINVAL;
		break;
	}

 out:
	return ok;
}

/**
 * hip_receive_r2 - receive R2 packet
 * @skb: sk_buff where the HIP packet is in
 * @hip_common: pointer to HIP header
 *
 * This is the initial function which is called when an R1 packet is
 * received. If we are in correct state, the packet is handled to
 * hip_handle_r2() for further processing.
 *
 * Returns always 0.
 *
 * TODO: check if it is correct to return always 0 
 */
int hip_receive_r2(struct sk_buff *skb) 
{
	struct hip_common *hip_common;
	hip_ha_t *entry = NULL;
	int err = 0;
	int state;

	hip_common = (struct hip_common *)skb->h.raw;
	HIP_DEBUG("\n");

	if (ipv6_addr_any(&hip_common->hitr)) {
		HIP_ERROR("Received NULL receiver HIT in R2. Dropping\n");
		goto out_err;
	}


	entry = hip_hadb_find_byhit(&hip_common->hits);
	if (!entry) {
		HIP_ERROR("Received R2 by unknown sender\n");
//		HIP_PRINT_HIT("Sender", &hip_common->hits);
		err = -EFAULT;
		goto out_err;
	}

	state = entry->state;

 	switch(state) {
 	case HIP_STATE_I1_SENT:
 		HIP_ERROR("Received R2 in I1_SENT. Dropping\n");
 		err = -EFAULT;
 		break;
 	case HIP_STATE_I2_SENT:
 		/* The usual case. */
 		err = hip_handle_r2(skb, entry);
 		if (err != 0) {
			HIP_ERROR("hip_handle_r2 failed(%d)\n", err);
 		}
 		break;
 	case HIP_STATE_ESTABLISHED:
 		HIP_ERROR("Received R2 in ESTABLISHED. Dropping\n");
 		err = -EFAULT;
 		break;
 	case HIP_STATE_REKEYING:
 		HIP_ERROR("Received R2 in REKEYING. Dropping.\n");
 		err = -EFAULT;
 		break;
 	default:
 		/* Cannot happen. */
 		HIP_ERROR("Received R2. The state machine is confused. Dropping\n");
 		err = -EFAULT;
 		break;
 	}
	
 out_err:
	if (entry)
		hip_put_ha(entry);
	return err;
}

/**
 * hip_verify_hmac - verify HMAC
 * @buffer: the packet data used in HMAC calculation
 * @hmac: the HMAC to be verified
 * @hmac_key: integrity key used with HMAC
 * @hmac_type: type of the HMAC digest algorithm.
 *
 * Returns: 0 if calculated HMAC is same as @hmac, otherwise < 0. On
 * error < 0 is returned.
 *
 * FIX THE PACKET LEN BEFORE CALLING THIS FUNCTION
 */
static int hip_verify_hmac(struct hip_common *buffer, u8 *hmac,
			   void *hmac_key, int hmac_type)
{
	int err = 0;
	u8 *hmac_res = NULL;

	hmac_res = kmalloc(HIP_AH_SHA_LEN, GFP_KERNEL);
	if (!hmac_res) {
		HIP_ERROR("kmalloc failed\n");
		err = -ENOMEM;
		goto out_err;
	}

	_HIP_HEXDUMP("HMAC data", buffer, hip_get_msg_total_len(buffer));

	if (!hip_write_hmac(hmac_type, hmac_key, buffer,
			    hip_get_msg_total_len(buffer), hmac_res))
	{
		HIP_ERROR("Could not build hmac\n");
		err = -EINVAL;
		goto out_err;
	}

	_HIP_HEXDUMP("HMAC", hmac_res, HIP_AH_SHA_LEN);

	if (memcmp(hmac_res, hmac, HIP_AH_SHA_LEN) != 0) {
		HIP_DEBUG("invalid HMAC\n");
		err = -EINVAL;
		goto out_err;
	}

 out_err:
	if (hmac_res)
		kfree(hmac_res);

	return err;
}


/**
 * hip_check_network_header - validate an incoming HIP header
 * @hip_common: pointer to the HIP header
 *
 * Returns: zero if the HIP message header was ok, or negative error value on
 *          failure
 */
int hip_verify_network_header(struct hip_common *hip_common,
			      struct sk_buff **skb)
{
	int err = 0;
	uint16_t csum;

	HIP_DEBUG("skb len=%d, v6hdr payload_len=%d/hip hdr pkt total len=%d\n",
		  (*skb)->len, ntohs((*skb)->nh.ipv6h->payload_len),
		  (hip_common->payload_len+1)*8);

	if ( ntohs((*skb)->nh.ipv6h->payload_len) !=
	     (hip_common->payload_len+1)*8 )  {
		HIP_ERROR("Invalid HIP packet length (IPv6 hdr payload_len=%d/HIP pkt len=%d). Dropping\n",
			  ntohs((*skb)->nh.ipv6h->payload_len),
			  (hip_common->payload_len+1)*8);
		err = -EINVAL;
		goto out_err;
	}

	/* Currently no support for piggybacking */
	if (hip_common->payload_proto != IPPROTO_NONE) {
		HIP_ERROR("Protocol in packet was not IPPROTO_NONE. Dropping\n");
		err = -EOPNOTSUPP;
		goto out_err;
	}

	if ((hip_common->ver_res & HIP_VER_MASK) != HIP_VER_RES) {
		HIP_ERROR("Invalid version in received packet. Dropping\n");
		err = -EPROTOTYPE;
		goto out_err;
	}


	if (!hip_is_hit(&hip_common->hits)) {
		HIP_ERROR("Received a non-HIT in HIT-source. Dropping\n");
		err = -EAFNOSUPPORT;
		goto out_err;
	}

	if (!hip_is_hit(&hip_common->hitr) &&
	    !ipv6_addr_any(&hip_common->hitr)) {
		HIP_ERROR("Received a non-HIT or non NULL in HIT-receiver. Dropping\n");
		err = -EAFNOSUPPORT;
		goto out_err;
	}

        /* Check checksum. */
	/* jlu XXX: We should not write into received skbuffs! */
	csum = hip_common->checksum;
	hip_zero_msg_checksum(hip_common);
	/* Interop with Julien: no htons here */
	if (hip_csum_verify(*skb) != csum) {
	       HIP_ERROR("HIP checksum failed (0x%x). Should have been: 0x%x\n", 
			 csum, ntohs(hip_csum_verify(*skb)) );
		err = -EBADMSG;
	}

 out_err:
	return err;
}

/**
 * hip_inbound - entry point for processing of an incoming HIP packet
 * @skb: sk_buff containing the HIP packet
 * @unused:
 *
 * This function if the entry point for all incoming HIP packet. First
 * we try to parse and validate the HIP header, and if it is valid the
 * packet type is determined and control is passed to corresponding
 * handler function which processes the packet.
 *
 * We must free the skb by ourselves, if an error occures!
 *
 * Return 0, if packet accepted
 *       <0, if error
 *       >0, if other protocol payload (piggybacking)
 */
int hip_inbound(struct sk_buff **skb, unsigned int *nhoff)
{
	struct hip_common *hip_common;
	struct hip_work_order *hwo;
	int err = 0;

	/* See if there is at least the HIP header in the packet */
	if (!pskb_may_pull(*skb, sizeof(struct hip_common))) {
		HIP_ERROR("Received packet too small. Dropping\n");
		goto out_err;
	}

	hip_common = (struct hip_common*) (*skb)->h.raw;
	HIP_DEBUG("Received HIP packet type %d\n", hip_common->type_hdr);

	_HIP_DEBUG_SKB((*skb)->nh.ipv6h, skb);

	_HIP_HEXDUMP("HIP PACKET", hip_common,
		     (hip_common->payload_len+1) << 3);

	err = hip_verify_network_header(hip_common, skb);
	if (err) {
		HIP_ERROR("Verifying of the network header failed\n");
		goto out_err;
	}

	err = hip_check_network_msg(hip_common);
	if (err) {
		HIP_ERROR("HIP packet is invalid\n");
		goto out_err;
	}

	hwo = hip_init_job(GFP_ATOMIC);
	if (!hwo) {
		HIP_ERROR("No memory, dropping packet\n");
		err = -ENOMEM;
		goto out_err;
	}

	hwo->destructor = hip_hwo_input_destructor;

	/* should we do some early state processing now?
	 * we could prevent further DoSsing by dropping
	 * illegal packets right now.
	 */

	_HIP_DEBUG("Entering switch\n");
	hwo->type = HIP_WO_TYPE_INCOMING;
	hwo->arg1 = *skb;

	switch(hip_get_msg_type(hip_common)) {
	case HIP_I1:
		HIP_DEBUG("Received HIP I1 packet\n");
		hwo->subtype = HIP_WO_SUBTYPE_RECV_I1;
		break;
	case HIP_R1:
		HIP_DEBUG("Received HIP R1 packet\n");
		hwo->subtype = HIP_WO_SUBTYPE_RECV_R1;
		break;
	case HIP_I2:
		HIP_DEBUG("Received HIP I2 packet\n");
		hwo->subtype = HIP_WO_SUBTYPE_RECV_I2;
		break;
	case HIP_R2:
		HIP_DEBUG("Received HIP R2 packet\n");
		hwo->subtype = HIP_WO_SUBTYPE_RECV_R2;
		break;
	case HIP_UPDATE:
		HIP_DEBUG("Received HIP UPDATE packet\n");
		hwo->subtype = HIP_WO_SUBTYPE_RECV_UPDATE;
		break;
	case HIP_REA:
		HIP_DEBUG("Received HIP REA packet\n");
		hwo->subtype = HIP_WO_SUBTYPE_RECV_REA;
		break;
	case HIP_AC:
		HIP_DEBUG("Received HIP AC packet\n");
		hwo->subtype = HIP_WO_SUBTYPE_RECV_AC;
		break;
	case HIP_ACR:
		HIP_DEBUG("Received HIP ACR packet\n");
		hwo->subtype = HIP_WO_SUBTYPE_RECV_ACR;
		break;
	default:
		HIP_ERROR("Received HIP packet of unknown/unimplemented type %d\n",
			  hip_common->type_hdr);
		kfree_skb(*skb);  /* sic */
		kfree(hwo);
		/*  KRISUXXX: return value? */
		return -1;
		break;
	}

	hip_insert_work_order(hwo);

 out_err:
	/* We must not use kfree_skb here... (worker thread releases) */

	return 0;
}

/* Assumes that, arg1 is an SKB and arg2 any other allocated pointer.
 */
void hip_hwo_input_destructor(struct hip_work_order *hwo)
{
	if (hwo) {
		if (hwo->arg1)
			kfree_skb(hwo->arg1);
		if (hwo->arg2)
			kfree(hwo->arg2);
	}
}
