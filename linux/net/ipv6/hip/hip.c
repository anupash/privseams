/*
 * HIP init/uninit and other miscellaneous functions
 *
 * Authors: Janne Lundberg <jlu@tcs.hut.fi>
 *          Miika Komu <miika@iki.fi>
 *          Mika Kousa <mkousa@cc.hut.fi>
 *          Kristian Slavov <kslavov@hiit.fi>
 *
 *
 * TODO:
 * - sdb accessors and locking
 * - hip_init and unit: check and rewrite!
 * - Mika: locks are missing from proc_xx functions
 * - add, find, del host id: modify to take care of peer addresses also
 * - lhi naming convention is used incorrectly in peer_info stuff?
 * - check network byte ordering in hip_{add|del|get}_lhi
 * - separate the tlv checking code into an own function from handle_r1?
 * - All context->{hip_in|hip_out}->pointers are not filled. Currently
 *   this is not a problem, but may cause bugs later?
 * - locking to hip_proc_read_lhi and others
 * - EEXIST -> ENOMSG ?
 * - hip_inet6addr_event_handler and hip_netdev_event_handler
 *   share a lot of same looking code
 */

#include "hip.h"

static int hip_working = 0; /* 1 when thread is active */

static time_t         load_time;          /* Wall clock time at module load */

static struct notifier_block hip_notifier_block;
static struct notifier_block hip_netdev_notifier;
static void hip_uninit_cipher(void); // forward decl.

/* All cipher and digest implementations we support. */
static struct crypto_tfm *impl_3des_cbc = NULL;


/* global variables */
struct socket *hip_socket;
struct crypto_tfm *impl_null = NULL;
struct crypto_tfm *impl_sha1 = NULL;
spinlock_t dh_table_lock = SPIN_LOCK_UNLOCKED;
DH *dh_table[HIP_MAX_DH_GROUP_ID] = {0};
#ifdef KRISUS_THESIS
struct timeval gtv_start;
struct timeval gtv_stop;
struct timeval gtv_result;
int gtv_inuse;
int kmm; // krisu_measurement_mode
#endif

DECLARE_MUTEX_LOCKED(hip_work);
spinlock_t hip_workqueue_lock = SPIN_LOCK_UNLOCKED;

#ifdef CONFIG_PROC_FS
static struct proc_dir_entry *hip_proc_root = NULL;
#endif /* CONFIG_PROC_FS */

LIST_HEAD(hip_sent_rea_info_pkts);
LIST_HEAD(hip_sent_ac_info_pkts);


/**
 * hip_get_dh_size - determine the size for required to store DH shared secret
 * @hip_dh_group_type: the group type from DIFFIE_HELLMAN parameter
 *
 * Returns: 0 on failure, or the size for storing DH shared secret in bytes
 */
uint16_t hip_get_dh_size(uint8_t hip_dh_group_type)
{
	/* the same values as are supported ? HIP_DH_.. */
	int dh_size[] = { 0, 384, 768, 1536, 3072, 6144, 8192 };
	uint16_t ret = -1;

	HIP_DEBUG("dh_group_type=%u\n", hip_dh_group_type);
	if (hip_dh_group_type == 0) 
		HIP_ERROR("Trying to use reserved DH group type 0\n");
	else if (hip_dh_group_type == HIP_DH_384)
		HIP_ERROR("draft-09: Group ID 1 does not exist yet\n");
	else if (hip_dh_group_type > (sizeof(dh_size) / sizeof(dh_size[0])))
		HIP_ERROR("Unknown/unsupported MODP group %d\n", hip_dh_group_type);
	else
		ret = dh_size[hip_dh_group_type] / 8;

	return ret + 1;
}

int hip_map_virtual_to_pages(struct scatterlist *slist, int *slistcnt, 
			     const u8 *addr, const u8 size)
{
	int err = -1;
	unsigned long offset,pleft;
	unsigned int elt = 0;
	int slcnt = *slistcnt;
#ifdef CONFIG_HIP_DEBUG
	unsigned int i;
#endif

	if (slcnt < 1) {
		HIP_ERROR("Illegal use of function\n");
		return err;
	}

	offset = 0;
	while(offset < size) {
		slist[elt].dma_address = 0;
		slist[elt].page = virt_to_page(addr+offset);
		slist[elt].offset = (unsigned long) (addr+offset) % PAGE_SIZE;
		
		/* page left */
		pleft = PAGE_SIZE - slist[elt].offset;
		HIP_ASSERT(pleft > 0 && pleft <= PAGE_SIZE);

		if (pleft + offset < size) {
			slist[elt].length = size - offset;
			break;
		}
		slist[elt].length = pleft;

		elt++;
		if (elt >= slcnt) {
			HIP_ERROR("Not enough room for scatterlist vector\n");
			err = -ENOMEM;
			return err;
		}
		offset += pleft;
	}

#ifdef CONFIG_HIP_DEBUG
	for(i=0;i<=elt;i++) {
		HIP_DEBUG("Scatterlist: %x, page: %x, offset: %x, length: %x\n",
			  i, (int)slist[i].page, slist[i].offset, slist[i].length);
	}
#endif
	*slistcnt = elt+1;
	return 0;
}
/**
 * hip_build_digest - calculate a digest over given data
 * @type: the type of digest, e.g. "sha1"
 * @in: the beginning of the data to be digested
 * @in_len: the length of data to be digested in octets
 * @out: the digest
 *
 * @out should be long enough to hold the digest. This cannot be
 * checked!
 *
 * Returns: 0 on success, otherwise < 0.
 */
int hip_build_digest(const int type, const void *in, int in_len, void *out)
{
	struct crypto_tfm *impl = NULL;
	struct scatterlist sg[HIP_MAX_SCATTERLISTS];
	unsigned int nsg = HIP_MAX_SCATTERLISTS;

	int err = 0;
	switch(type) {
	case HIP_DIGEST_SHA1:
		impl = impl_sha1;
		break;
	case HIP_DIGEST_MD5:
		HIP_DEBUG("Not implemented\n");
	default:
		HIP_ERROR("Unknown digest: %x\n",type);
		return -EFAULT;
	}

	err = hip_map_virtual_to_pages(sg, &nsg, in, in_len);
	if (err || nsg < 1 ) {
		HIP_ERROR("Error mapping virtual addresses to physical pages\n");
		return -EFAULT;
	}

	crypto_digest_init(impl);
	crypto_digest_digest(impl, sg, nsg, out);

	return 0;
}

/**
 * hip_write_hmac - calculate hmac
 * @type: Type (digest algorithm) of HMAC
 * @key: Pointer to the key used for HMAC
 * @in: Input buffer pointer
 * @in_len: Length of buffer
 * @out: Output buffer pointer. For SHA1-HMAC this is 160bits
 *
 * Returns true, if ok.
 */
int hip_write_hmac(int type, void *key, void *in, int in_len, void *out)
{
	int err = 0;
	int keylen = 20; // anticipating HIP_DIGEST_SHA1_HMAC
	struct crypto_tfm *impl = NULL;
	struct scatterlist sg[HIP_MAX_SCATTERLISTS];
	int nsg = HIP_MAX_SCATTERLISTS;

	switch(type) {
	case HIP_DIGEST_SHA1_HMAC:
		impl = impl_sha1;
		break;
	case HIP_DIGEST_MD5_HMAC:
		HIP_DEBUG("MD5_HMAC not implemented\n");
	default:
		HIP_ERROR("Unknown HMAC type 0x%x\n",type);
		return 0;
	}

	err = hip_map_virtual_to_pages(sg, &nsg, in, in_len);
	if (err || nsg < 1) {
		HIP_ERROR("Mapping failed\n");
		return 0;
	}

	crypto_hmac(impl, key, &keylen, sg, nsg, out);

	return 1;
}

/**
 * hip_get_current_birthday - set the current birthday counter into the cookie
 * @bc: cookie where the birthday field is set to
 *
 * Birthday is stored in network byte order.
 *
 * This function never touches the other fields of the cookie @bc.
 */
uint64_t hip_get_current_birthday(void)
{
	return ((uint64_t)load_time << 32) | jiffies;
}

/**
 * hip_birthday_success - compare two birthday counters
 * @old_bd: birthday counter
 * @new_bd: birthday counter used when comparing against @old_bd
 *
 * Returns: 1 (true) if new_bd is newer than old_bd, 0 (false) otherwise.
 */
int hip_birthday_success(uint64_t old_bd, uint64_t new_bd)
{
	return new_bd > old_bd;
}

/**
 * hip_create_r1 - construct a new R1-payload
 * @src_hit: source HIT used in the packet
 *
 * Returns 0 on success, or negative on error
 */
struct hip_common *hip_create_r1(struct in6_addr *src_hit)
{
 	struct hip_common *msg;
 	struct in6_addr dst_hit;
 	uint64_t random_i;
 	int err = 0;
 	u8 *dh_data = NULL;
 	int dh_size,written;
 	/* Supported HIP and ESP transforms */
 	hip_transform_suite_t transform_hip_suite[] = {HIP_TRANSFORM_3DES,
 						       HIP_TRANSFORM_NULL };
 	hip_transform_suite_t transform_esp_suite[] = {HIP_ESP_3DES_SHA1,
 						       HIP_ESP_NULL_SHA1 };
 	struct hip_host_id  *host_id_private = NULL;
 	struct hip_host_id  *host_id_pub = NULL;
 	u8 signature[HIP_DSA_SIGNATURE_LEN];
 
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

 	dh_data = kmalloc(dh_size, GFP_ATOMIC);
 	if (!dh_data) {
 		HIP_ERROR("Failed to alloc memory for dh_data\n");
  		goto out_err;
  	}
	memset(dh_data, 0, dh_size);

	HIP_DEBUG("dh_size=%d\n", dh_size);
 	/* Get a localhost identity, allocate memory for the public key part
 	   and extract the public key from the private key. The public key is
 	   needed for writing the host id parameter in R1. */
 
	host_id_private = hip_get_any_localhost_host_id();
 	if (!host_id_private) {
 		HIP_ERROR("Could not acquire localhost host id\n");
 		goto out_err;
 	}
 	
	host_id_pub = hip_get_any_localhost_public_key();
	if (!host_id_pub) {
		HIP_ERROR("Could not acquire localhost public key\n");
		goto out_err;
	}

 	/* Ready to begin building of the R1 packet */

         /* The destination HIT is unkown because R1s are prebuilt */
 	memset(&dst_hit, 0, sizeof(struct in6_addr));
 	hip_build_network_hdr(msg, HIP_R1, HIP_CONTROL_NONE, src_hit,
 			      &dst_hit);

 	/********** Birthday and cookie **********/

 	get_random_bytes(&random_i, sizeof(uint64_t));
 	err = hip_build_param_cookie(msg, 0, hip_get_current_birthday(), 
				     random_i, HIP_DEFAULT_COOKIE_K);
 	if (err) {
 		HIP_ERROR("Cookies were burned. Bummer!\n");
 		goto out_err;
 	}
 
 	/********** Diffie-Hellman **********/

	written = hip_insert_dh(dh_data,dh_size,HIP_DEFAULT_DH_GROUP_ID);
	if (written < 0) {
 		HIP_ERROR("Could not extract DH public key\n");
 		goto out_err;
 	}
 

 	err = hip_build_param_dh_fixed_contents(msg,
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

 	err = hip_build_param(msg, host_id_pub);
 	if (err) {
 		HIP_ERROR("Building of host id failed\n");
 		goto out_err;
 	}

 	/********** Signature 2 **********/

 	if (!hip_create_signature(msg,
 				  hip_get_msg_total_len(msg),
 				  host_id_private,
 				  signature)) {
 		HIP_ERROR("Signing of R1 failed.\n");
 		goto out_err;
 	}		
 	err = hip_build_param_signature2_contents(msg,
 						 signature,
 						 HIP_DSA_SIGNATURE_LEN,
 						 HIP_SIG_DSA);
 	if (err) {
 		HIP_ERROR("Building of signature failed (%d) on R1\n", err);
 		goto out_err;
 	}

 	/* Packet ready */

 	if (host_id_pub)
 		kfree(host_id_pub);
 	if (dh_data)
 		kfree(dh_data);
 
 	return msg;

  out_err:
	if (host_id_pub)
		kfree(host_id_pub);
 	if (host_id_private)
 		kfree(host_id_private);
 	if (msg)
 		kfree(msg);
 	if (dh_data)
 		kfree(dh_data);

  	return NULL;
}

/**
 * hip_enc_key_length - get encryption key length of a transform
 * @tid: transform
 *
 * Returns: the encryption key length based on the chosen transform,
 * otherwise < 0 on error.
 */
int hip_enc_key_length(int tid)
{
	int ret = -1;

	switch(tid) {
	case HIP_ESP_3DES_SHA1:
		ret = 24;
		break;
	case HIP_ESP_NULL_NULL:
	case HIP_ESP_NULL_SHA1:
		ret = 0;
		break;
	default:
		HIP_ASSERT(0);
		break;
	}
	
	return ret;
}


int hip_hmac_key_length(int tid)
{
	int ret = -1;
	switch(tid) {
	case HIP_ESP_3DES_SHA1:
		ret = 20;
		break;
	case HIP_ESP_NULL_NULL:
	case HIP_ESP_NULL_SHA1:
		ret = 0;
		break;
	default:
		HIP_ASSERT(0);
		break;
	}
	
	return ret;

}

/**
 * hip_transform_key_length - get transform key length of a transform
 * @tid: transform
 *
 * Returns: the transform key length based on the chosen transform,
 * otherwise < 0 on error.
 */
int hip_transform_key_length(int tid)
{
	int ret = -1;

	switch(tid) {
	case HIP_TRANSFORM_3DES:
		ret = 24;
		break;
	case HIP_TRANSFORM_NULL:
		ret = 0;
		break;
	default:
		HIP_ASSERT(0);
		break;
	}
	
	return ret;
}


/**
 * hip_auth_key_length_esp - get authentication key length of a transform
 * @tid: transform
 *
 * Returns: the authentication key length based on the chosen transform.
 * otherwise < 0 on error.
 */
int hip_auth_key_length_esp(int tid)
{
	int ret = -1;

	switch(tid) {
	case HIP_ESP_NULL_SHA1:
	case HIP_ESP_3DES_SHA1:
		ret = 20;
		break;
	case HIP_ESP_NULL_NULL:
		ret = 0;
		break;
	default:
		HIP_ASSERT(0);
		break;
	}
	
	return ret;
}

/**
 * hip_store_base_exchange_keys - store the keys negotiated in base exchange
 * @ctx:             the context inside which the key data will copied around
 * @is_initiator:    true, if the localhost is the initiator, or false if
 *                   the localhost is the responder
 */
void hip_store_base_exchange_keys(struct hip_hadb_state *entry, 
				  struct hip_context *ctx, int is_initiator)
{

  if (is_initiator) {
	memcpy(&entry->esp_our.key, &ctx->hip_espi.key,
	       hip_enc_key_length(entry->esp_transform));
	memcpy(&entry->esp_peer.key, &ctx->hip_espr.key,
	       hip_enc_key_length(entry->esp_transform));
	memcpy(&entry->auth_our.key, &ctx->hip_authi.key,
	       hip_auth_key_length_esp(entry->esp_transform)); 
	memcpy(&entry->auth_peer.key, &ctx->hip_authr.key,
	       hip_auth_key_length_esp(entry->esp_transform));
	memcpy(&entry->hmac_our, &ctx->hip_hmaci,
	       hip_hmac_key_length(entry->esp_transform));
	memcpy(&entry->hmac_peer, &ctx->hip_hmacr,
	       hip_hmac_key_length(entry->esp_transform));
  } else {
	memcpy(&entry->esp_our.key, &ctx->hip_espr.key,
	       hip_enc_key_length(entry->esp_transform));
	memcpy(&entry->esp_peer.key, &ctx->hip_espi.key,
	       hip_enc_key_length(entry->esp_transform));
	memcpy(&entry->auth_our.key, &ctx->hip_authr.key,
	       hip_auth_key_length_esp(entry->esp_transform));
	memcpy(&entry->auth_peer.key, &ctx->hip_authi.key,
	       hip_auth_key_length_esp(entry->esp_transform));
	memcpy(&entry->hmac_our, &ctx->hip_hmacr,
	       hip_hmac_key_length(entry->esp_transform));
	memcpy(&entry->hmac_peer, &ctx->hip_hmaci,
	       hip_hmac_key_length(entry->esp_transform));
  }
}

/**
 * hip_select_hip_transform - select a HIP transform to use
 * @ht: HIP_TRANSFORM payload where the transform is selected from
 *
 * Returns: the first acceptable Transform-ID, otherwise < 0 if no
 * acceptable transform was found. The return value is in host byte order.
 */
hip_transform_suite_t hip_select_hip_transform(struct hip_hip_transform *ht)
{
	hip_transform_suite_t tid = 0;
	int i;
	int length;
	hip_transform_suite_t *suggestion;

	length = ntohs(ht->length);
	suggestion = (hip_transform_suite_t *) &ht->suite_id[0];

	if ( (length >> 1) > 6) 
	{
		HIP_ERROR("Too many transforms (%d)\n",(length >> 1));
		goto out;
	}

	for (i=0; i<length; i++) {
		switch(ntohs(*suggestion)) {

		case HIP_TRANSFORM_3DES:
		case HIP_TRANSFORM_NULL:
			tid = ntohs(*suggestion);
			goto out;
			break;
			
		default:
			/* Specs don't say what to do when unknown are found. 
			 * We ignore.
			 */
			HIP_ERROR("Unknown HIP suite id suggestion (%u)\n",
				  ntohs(*suggestion));
			break;
		}
		suggestion++;
	}

 out:
	if(tid == 0)
		HIP_ERROR("None HIP transforms accepted\n");
	else
		HIP_DEBUG("Chose HIP transform: %d\n", tid);

	return tid;
}


/**
 * hip_select_esp_transform - select an ESP transform to use
 * @ht: ESP_TRANSFORM payload where the transform is selected from
 *
 * Returns: the first acceptable Suite-ID. otherwise < 0 if no
 * acceptable Suite-ID was found.
 */
hip_transform_suite_t hip_select_esp_transform(struct hip_esp_transform *ht)
{
	hip_transform_suite_t tid = 0;
	int i;
	int length;
	hip_transform_suite_t *suggestion;

	length = ntohs(ht->length);
	suggestion = (uint16_t*) &ht->suite_id[0];

	if ( (length >> 1) > 6) 
		goto out;

	for (i=0; i<length; i++) {
		switch(ntohs(*suggestion)) {

		case HIP_ESP_NULL_NULL:
		case HIP_ESP_3DES_SHA1:
		case HIP_ESP_NULL_SHA1:
			tid = ntohs(*suggestion);
			goto out;
			break;
			
		default:
			/* Specs don't say what to do when unknowns are found. 
			 * We ignore.
			 */
			HIP_ERROR("Unknown ESP suite id suggestion (%u)\n",
				  ntohs(*suggestion));
			break;
		}
		suggestion++;
	}

 out:
	HIP_DEBUG("Took ESP transform %d\n", tid);

	if(tid == 0)
		HIP_ERROR("Faulty ESP transform\n");

#if 0 /* IETF58: this did not work with Andrew */
	return tid;
#else
	return HIP_ESP_3DES_SHA1;
#endif
}

/**
 * hip_crypto_encrypted - encrypt/decrypt data
 * @data: data to be encrypted/decrypted
 * @iv: initialization vector
 * @enc_alg: encryption algorithm to use
 * @enc_len: length of @data
 * @enc_key: encryption/decryption key to use
 * @direction: flag for selecting encryption/decryption
 *
 * @direction is HIP_DIRECTION_ENCRYPT if @data is to be encrypted
 * or HIP_DIRECTION_DECRYPT if @data is to be decrypted.
 *
 * The result of the encryption/decryption of @data is overwritten to @data.
 *
 * Returns: 0 is encryption/decryption was successful, otherwise < 0.
 */
int hip_crypto_encrypted(void *data, void *iv, int enc_alg, int enc_len,
			 void* enc_key, int direction)
{
	int err = 0;
	int key_len;  /* in bytes */
	struct crypto_tfm *impl = NULL;
	struct scatterlist src_sg[HIP_MAX_SCATTERLISTS];
	unsigned int src_nsg = HIP_MAX_SCATTERLISTS;

	switch(enc_alg) {
	case HIP_TRANSFORM_3DES:
		impl = impl_3des_cbc;
		key_len = ESP_3DES_KEY_BITS >> 3;
		break;
	case HIP_TRANSFORM_NULL:
		impl = impl_null;
		key_len = 0;
		break;
	default:
		HIP_ERROR("Attempted to use unknown CI (enc_alg=%d)\n", enc_alg);
		return -EFAULT;
	}

	err = hip_map_virtual_to_pages(src_sg, &src_nsg, data, enc_len);
	if (err || src_nsg < 1) {
		HIP_ERROR("Error mapping source data\n");
		return -EFAULT;
	}

	/* we will write over the source */

	err = crypto_cipher_setkey(impl, enc_key, key_len);
	if (err) {
		HIP_ERROR("Could not set encryption/decryption key\n");
		return -EFAULT;
	}

	switch(direction) {
	case HIP_DIRECTION_ENCRYPT:
		err = crypto_cipher_encrypt_iv(impl, src_sg, src_sg, enc_len, iv);
		if (err) {
			HIP_ERROR("Encryption failed\n");
			return -EFAULT;
		}
		break;
	case HIP_DIRECTION_DECRYPT:
		err = crypto_cipher_decrypt_iv(impl, src_sg, src_sg, enc_len, iv);
		if (err) {
			HIP_ERROR("Decryption failed\n");
			return -EFAULT;
		}
		break;
	default:
		HIP_ERROR("Undefined direction (%d)\n", direction);
		err = -2;
		break;
	}

	return 0;
}

/**
 * hip_unknown_spi - handle an unknown SPI by sending R1
 * @daddr: destination IPv6 address of the R1 to be sent
 *
 * IPsec input code calls this when it does not know about the SPI
 * received. We reply by sending a R1 containing NULL destination HIT
 * to the peer which sent the packet containing the unknown SPI.
 *
 * No we don't anymore :) [if this is in draft, then the impl. is now
 * officially broken].
 */
void hip_unknown_spi(struct sk_buff *skb)
{
	int err = 0; /* not returned */

	/* draft: If the R1 is a response to an ESP packet with an unknown
	   SPI, the Initiator HIT SHOULD be zero. */
	HIP_INFO("Sending R1 with NULL dst HIT\n");

	/* We cannot know the destination HIT */
	err = hip_xmit_r1(skb, NULL);
	if (err) {
		HIP_ERROR("hip_xmit_r1 failed (%d)\n", err);
	}
}

/**
 * hip_init_sock - initialize HIP control socket
 *
 * Returns: 0 if successful, else < 0.
 */
static int hip_init_sock(void)
{
	int err = 0;

	err = sock_create(AF_INET6, SOCK_RAW, IPPROTO_NONE, &hip_socket);
	if (err) {
		HIP_ERROR("Failed to allocate the HIP control socket\n");
		return err;
	}

	return 0;
}

/**
 * hip_uninit_sock - uninitialize HIP control socket
 */
void hip_uninit_sock(void)
{
	sock_release(hip_socket);
	return;
}

/**
 * hip_get_addr - get an IPv6 address of given HIT
 * @hit: HIT of which IPv6 address is to be copied
 * @addr: where the IPv6 address is copied to
 *
 * Returns: 1 if successful (a peer address was copied to @addr),
 * else 0.
 */
int hip_get_addr(struct in6_addr *hit, struct in6_addr *addr)
{
#ifdef CONFIG_HIP_DEBUG
	char str[INET6_ADDRSTRLEN];
#endif
	if (!hip_is_hit(hit))
		return 0;

#ifdef CONFIG_HIP_DEBUG
	hip_in6_ntop(hit,str);
#endif
	if (hip_hadb_get_peer_address(hit,addr,HIP_ARG_HIT) < 0) {
		return 0;
	}

#ifdef CONFIG_HIP_DEBUG
	hip_in6_ntop(addr, str);
	HIP_DEBUG("selected dst addr: %s\n", str);
#endif

	return 1;
}

/**
 * hip_get_hits - get this host's HIT to be used in source HIT
 * @hitd: destination HIT
 * @hits: where the selected source HIT is to be stored
 *
 * This function is called in two different contexts.
 * 1: Outgoing packet. The hitd is then a real destination IPv6.
 *    This function obviously does not do any processing at that time
 * 2: <fill this>
 *
 * Returns: 0 if source HIT was copied successfully, otherwise < 0.
 */
int hip_get_hits(struct in6_addr *hitd, struct in6_addr *hits)
{
	if (!hip_is_hit(hitd))
		goto out;

	if (hip_copy_any_localhost_hit(hits) < 0)
		goto out;

	return 1;
		
 out:
	return 0;
}

/**
 * hip_get_saddr_udp - get source HIT
 * @fl: flow containing the destination HIT
 * @hit_storage: where the source address is to be stored
 *
 * ip6_build_xmit() calls this if we have a source address that is not
 * a HIT and destination address which is a HIT. If that is true, we
 * make he source a HIT too.
 */
int hip_get_saddr(struct flowi *fl, struct in6_addr *hit_storage)
{
	if (!hip_is_hit(&fl->fl6_dst))
		return 0;

	if (!hip_hadb_get_own_hit_by_hit(&fl->fl6_dst, hit_storage)) {
		HIP_ERROR("Could not get own hit, corresponding to the peer hit\n");
		return 0;
	}
	return 1;
}

/**
 * hip_bypass_ipsec
 *
 * This function is used by IPsec function ipsec6_input_check() to
 * skip further packet processing if the packet was a HIP packet.
 *
 * Returns: always 1.
 */
int hip_bypass_ipsec(void)
{
	return 1;
}

/**
 * hip_get_load_time - set time when this module was loaded into the kernel
 */
static void hip_get_load_time(void)
{
	struct timeval tv;

	do_gettimeofday(&tv);
	load_time =  tv.tv_sec;
	HIP_DEBUG("load_time=0x%lx\n", load_time);
	return;
}

/**
 * hip_create_device_addrlist - get interface addresses
 * @idev: inet6 device of which addresses are retrieved
 * @addr_list: where the pointer to address list is stored
 * @idev_addr_count: number of addresses in @addr_list
 *
 * Caller is responsible for kfreeing @addr_list.
 * This function assumes that we have the device lock.
 *
 * Returns: 0 if addresses were retrieved successfully. If there was
 * no error but interface has no IPv6 addresses, @addr_list is NULL
 * and 0 is returned. Else < 0 is returned and @addr_list contains
 * NULL.
 */
static int hip_create_device_addrlist(struct inet6_dev *idev,
				       struct hip_rea_info_addr_item **addr_list,
				       int *idev_addr_count)
{
	struct inet6_ifaddr *ifa = NULL;
	char addrstr[INET6_ADDRSTRLEN];
	int i = 0;
	int err = 0;
	struct hip_rea_info_addr_item *tmp_list = NULL;

	*idev_addr_count = 0;

	HIP_DEBUG("idev=%s ifindex=%d\n", idev->dev->name, idev->dev->ifindex);

	for (ifa = idev->addr_list; ifa; (*idev_addr_count)++, ifa = ifa->if_next) {
		spin_lock_bh(&ifa->lock);
		hip_in6_ntop(&ifa->addr, addrstr);
		HIP_DEBUG("addr %d: %s\n", *idev_addr_count+1, addrstr);
		spin_unlock_bh(&ifa->lock);
	}
	HIP_DEBUG("address list count=%d\n", *idev_addr_count);

	if (*idev_addr_count > 0) {
		/* create address list for building of REA */

		/* todo: convert to struct list_head ? */
		tmp_list = kmalloc(*idev_addr_count * sizeof(struct hip_rea_info_addr_item), GFP_ATOMIC);
		if (!tmp_list) {
			HIP_DEBUG("addr_list creation failed\n");
			err = -ENOMEM;
			goto out_err;
		}

		/* todo: skip addresses which we don't want/need to include into
		 * the REA packet, localhost address, multicast addresses etc
		 *
		 * this list is maybe better to be created for each of
		 * the peers, policy ?
		 */
		for (i = 0, ifa = idev->addr_list;
		     ifa && i < *idev_addr_count; i++, ifa = ifa->if_next) {
			/* todo: continue only if address flag has IFA_F_PERMANENT ? */

			spin_lock_bh(&ifa->lock);
			tmp_list[i].lifetime = htonl(0); /* todo: how to calculate address lifetime */
			tmp_list[i].reserved = 0;
			ipv6_addr_copy(&tmp_list[i].address, &ifa->addr);
			spin_unlock_bh(&ifa->lock);
		}
	}

	*addr_list = tmp_list;

 out_err:
	return err;
}

/**
 * hip_net_event_handle - finish netdev and inet6 event handling
 * @event_src: event source
 * @event_dev: the device which caused the event
 * @event: the event
 *
 * This function does the actual work (sending of REA, that is) after
 * the event type was inspected in hip_inet6addr_event_handler or
 * hip_netdev_event_handler.
 *
 * Events caused by loopback devices are ignored.
 *
 * NOTE: this uses our own REA extension (REA containing no addresses)
 *
 * @event_src is 0 if @event to be handled came from inet6addr_notifier,
 * or 1 if @event came from netdevice_notifier.
 */
static void hip_net_event_handle(int event_src, struct net_device *event_dev,
				 unsigned long event)
{
	/* event_dev -> event_dev->ifindex ? */
        int err = 0;
        struct net_device *dev;
        struct inet6_dev *idev;
        int idev_addr_count = 0;
        struct hip_rea_info_addr_item *addr_list = NULL;

        if (!event_dev) {
                HIP_ERROR("NULL event_dev, shouldn't happen ?\n");
                return;
        }
        if (! (event_src == 0 || event_src == 1) ) {
                HIP_ERROR("unknown event source %d\n", event_src);
                return;
        }

	HIP_DEBUG("event_src=%d event=%lu dev=%s ifindex=%d\n",
		  event_src, event, event_dev->name, event_dev->ifindex);

        /* skip events caused by loopback (as long as we do not have
           loopback support) */
        if (event_dev->flags & IFF_LOOPBACK) {
                HIP_DEBUG("ignoring loopback event\n");
                return;
        }

        read_lock(&dev_base_lock);
        read_lock(&addrconf_lock);

        for (dev = dev_base; dev; dev = dev->next) {
		int rea_netdev;
                HIP_DEBUG("loop: dev=%s ifindex=%d\n", dev->name, dev->ifindex);

                idev_addr_count = 0;
                addr_list = NULL;
                /* skip loopback devices */
                if (dev->flags & IFF_LOOPBACK) {
                        HIP_DEBUG("skip loopback device\n");
                        continue;
                }
                idev = in6_dev_get(dev);
                if (!idev) {
                        HIP_DEBUG("NULL idev on event %ld, skipping\n", event);
                        continue;
                }
                read_lock(&idev->lock);

		/* When a network device gets NETDEV_DOWN, create a 0
		 * address REA if dev is the device which went down,
		 * else (an IPv6 address was added or deleted or
		 * network device came up) send "all addresses REA" */
                if (event_src == 1 && dev->ifindex == event_dev->ifindex) {
                                idev_addr_count = 0;
                                addr_list = NULL;
		} else {
			err = hip_create_device_addrlist(idev, &addr_list,
							 &idev_addr_count);
			if (err) {
				HIP_ERROR("hip_create_device_addrlist failed, err=%d\n", err);
				goto out_err;
			}
		}
		/* Now we have the addresses to be included in the REA, send REAs */

		/* When an IPv6 address was added, try to use the same
		 * interface for sending out the REA as which caused
		 * the event. Else we let the kernel dedice the
		 * interface to use. */
                if (event_src == 0 && event == NETDEV_UP) {
			rea_netdev = REA_OUT_NETDEV_GIVEN;
		} else {
			rea_netdev = REA_OUT_NETDEV_ANY;
		}
		hip_send_rea_all(dev->ifindex, addr_list,
				 idev_addr_count, rea_netdev);

        out_err:
                read_unlock(&idev->lock);
                in6_dev_put(idev);
                if (addr_list)
                        kfree(addr_list);
        }

        read_unlock(&addrconf_lock);
        read_unlock(&dev_base_lock);
        return;
}

/**
 * hip_inet6addr_event_handler - handle IPv6 address events
 * @notifier_block: device notifier chain
 * @event: the event
 * @ptr: pointer to the IPv6 address which caused the event
 *
 * Currently we handle only NETDEV_UP (an address was added) and
 * NETDEV_DOWN (an address was deleted).
 *
 * Returns: always NOTIFY_DONE.
 */
static int hip_inet6addr_event_handler(struct notifier_block *notifier_block,
                                      unsigned long event,
                                      void *ptr)
{
        struct net_device *event_dev;
	struct inet6_ifaddr *ifa;

        if (! (event == NETDEV_UP || event == NETDEV_DOWN) ) {
                HIP_DEBUG("Ignore inet6 event %lu\n", event);
                return NOTIFY_DONE;
        }

	ifa = (struct inet6_ifaddr *) ptr;
	if (!ifa) {
		HIP_ERROR("ifa is NULL\n");
		return NOTIFY_DONE;
	}
	in6_ifa_hold(ifa);
	event_dev = ifa->idev->dev;
	dev_hold(event_dev);
	in6_ifa_put(ifa);

        if (!event_dev) {
                HIP_ERROR("NULL event_dev, shouldn't happen ?\n");
		dev_put(event_dev);
                return NOTIFY_DONE;
        }

	/* event_dev -> event_dev->ifindex ? */
        hip_net_event_handle(0, event_dev, event);
	dev_put(event_dev);
	return NOTIFY_DONE;
}

/**
 * hip_netdev_event_handler - handle network device events
 * @notifier_block: device notifier chain
 * @event: the event
 * @ptr: pointer to the network device which caused the event
 *
 * Currently we handle only NETDEV_DOWN and NETDEV_UNREGISTER.
 *
 * Returns: always %NOTIFY_DONE.
 */
static int hip_netdev_event_handler(struct notifier_block *notifier_block,
                                    unsigned long event,
                                    void *ptr)
{
        struct net_device *event_dev;

        if (! (event == NETDEV_DOWN || event == NETDEV_UNREGISTER)) {
                HIP_DEBUG("Ignoring event\n");
                return NOTIFY_DONE;
        }

        event_dev = (struct net_device *) ptr;
        if (!event_dev) {
                HIP_ERROR("NULL event_dev, shouldn't happen ?\n");
                return NOTIFY_DONE;
        }

	/* event_dev -> event_dev->ifindex ? */
        hip_net_event_handle(1, event_dev, event);
	return NOTIFY_DONE;
}

/**
 * hip_handle_dst_unreachable - ICMPv6 Destination Unreachable message handler
 * @skb: sk_buff containing the received ICMPv6 packet
 *
 * This function does currently nothing useful. Later we should mark
 * peer addresses as unusable if we receive ICMPv6 Destination
 * Unreachable caused by a packet which was sent to some of the peer
 * addresses we know of.
 */
void hip_handle_dst_unreachable(struct sk_buff *skb)
{
	struct icmp6hdr *hdr;
	struct ipv6hdr *invoking_hdr; /* RFC 2463 sec 3.1 */
#ifdef CONFIG_HIP_DEBUG
        struct in6_addr *saddr, *daddr;
	char strs[INET6_ADDRSTRLEN];
	char strd[INET6_ADDRSTRLEN];
#endif

	/* todo: option to allow/disallow icmpv6 handling */

	if (!pskb_may_pull(skb, 4+sizeof(struct ipv6hdr))) {
		/* RFC 2463 sec 3.1 */
		HIP_DEBUG("short icmp\n");
		return;
	}

	hdr = (struct icmp6hdr *) skb->h.raw;
	invoking_hdr = (struct ipv6hdr *) (hdr+1); /* check */
#ifdef CONFIG_HIP_DEBUG
	saddr = &skb->nh.ipv6h->saddr;
        daddr = &skb->nh.ipv6h->daddr;
	hip_in6_ntop(saddr, strs);
	hip_in6_ntop(daddr, strd);
	HIP_DEBUG("icmp6: src=%s dst=%s type=%d code=%d skb->len=%d\n",
		  strs, strd, hdr->icmp6_type, hdr->icmp6_code, skb->len);
	_HIP_HEXDUMP("received icmp6 Dest Unreachable", hdr, skb->len);
	hip_in6_ntop(&invoking_hdr->saddr, strs);
	hip_in6_ntop(&invoking_hdr->daddr, strd);
	HIP_DEBUG("invoking_hdr ip6: src=%s dst=%s\n", strs, strd);
#endif

	switch(hdr->icmp6_code) {
	case ICMPV6_NOROUTE:
	case ICMPV6_ADM_PROHIBITED:
	case ICMPV6_ADDR_UNREACH:
		HIP_DEBUG("TODO: handle ICMP DU code %d\n", hdr->icmp6_code);
		/* todo: deactivate invoking_hdr->daddr from every sdb
		 * entry peer addr list */
		break;
	default:
		HIP_DEBUG("ICMP DU code %d not handled, returning\n", hdr->icmp6_code);
		break;
	}

	return;
}

/**
 * hip_init_cipher - initialize needed cipher algorithms
 * There is no need to delay initialization and locking of these
 * algorithms since we require their use. Some optional algorithms
 * may be initialized later.
 * Currently we use 3DES-CBC, NULL-ECB?, SHA1(+HMAC), DSA, DH
 * Returns: 1 if all algorithms were initialized, otherwise < 0.
 */
static int hip_init_cipher(void)
{
	int err = 0;
	u32 supported_groups;

	/* Get implementations for all the ciphers we support */
	impl_3des_cbc = crypto_alloc_tfm("des3_ede", CRYPTO_TFM_MODE_CBC);
	if (!impl_3des_cbc) {
		HIP_ERROR("Unable to register 3DES cipher\n");
		err = -1;
		goto out_err;
	}

	impl_null = crypto_alloc_tfm("cipher_null", CRYPTO_TFM_MODE_ECB);
	if (!impl_null) {
		HIP_ERROR("Unable to register NULL cipher\n");
		err = -1;
		goto out_err;
	}

	impl_sha1 = crypto_alloc_tfm("sha1", 0);
	if (!impl_sha1) {
		HIP_ERROR("Unable to register SHA1 digest\n");
		err = -1;
		goto out_err;
	}

	supported_groups = (1 << HIP_DH_OAKLEY_1 | 
			    1 << HIP_DH_OAKLEY_5);
//			    1 << HIP_DH_384);

	/* Does not return errors. Should it?
	   the code will try to regenerate the key if it is
	   missing...
	*/
	hip_regen_dh_keys(supported_groups);	
	return 0;

 out_err:
	hip_uninit_cipher();
	return err;
}

/**
 * hip_uninit_cipher - uninitialize needed cipher algorithms
 *
 * Actually this does nothing because it looks like the cipher
 * implementations do not require freeing, although it seems possible
 * to unregister them.
 */
static void hip_uninit_cipher(void)
{
	int i;
        /* 
	 * jlu XXX: If I understand correctly, the implementations do
	 * not require freeing, although it seems possible to unregister them...
	 * Really weird. Something is broken somewhere.
	 */
	for(i=1;i<HIP_MAX_DH_GROUP_ID;i++) {
		if (dh_table[i] != NULL) {
			hip_free_dh_structure(dh_table[i]);
			dh_table[i] = NULL;
		}
	}

	if (impl_sha1)
		crypto_free_tfm(impl_sha1);
	if (impl_null)
		crypto_free_tfm(impl_null);
	if (impl_3des_cbc)
		crypto_free_tfm(impl_3des_cbc);

	return;
}

#ifdef CONFIG_PROC_FS
/**
 * hip_init_procfs - initialize HIP procfs support
 *
 * Returns: 1 if procfs was initialized successfully, otherwise -1.
 */
static int hip_init_procfs(void)
{
	HIP_DEBUG("procfs init\n");
	hip_proc_root = create_proc_entry("net/hip", S_IFDIR, NULL);
	if (!hip_proc_root)
		return -1;

	create_proc_read_entry("net/hip/lhi", 0, 0, hip_proc_read_lhi, NULL);
	create_proc_read_entry("net/hip/sdb_state", 0, 0,
			       hip_proc_read_hadb_state, NULL);
	create_proc_read_entry("net/hip/sdb_peer_addrs", 0, 0,
			       hip_proc_read_hadb_peer_addrs, NULL);
	return 1;
}

/**
 * hip_uninit_procfs - uninitialize HIP procfs support
 */
static void hip_uninit_procfs(void)
{
	HIP_DEBUG("\n");
	remove_proc_entry("sdb_state", hip_proc_root);
	remove_proc_entry("lhi", hip_proc_root);
	remove_proc_entry("sdb_peer_addrs", hip_proc_root);
	remove_proc_entry("net/hip", NULL);
	return;
}
#endif /* CONFIG_PROC_FS */

#ifdef CONFIG_HIP_DEBUG
void hip_test_csum(void *data, int len)
{
	int csum;
	HIP_HEXDUMP("CSUM DATA", data, len);
	csum = csum_partial(data, len, 0);
	HIP_DEBUG("csum=0x%x ntohs=0x%x\n", csum, ntohs(csum));
}
#endif

/**
 * hip_init_register_inet6addr_notifier - initialize IPv6 address event handler
 *
 * This function adds this module to the notifier list which receives
 * event related to changes in IPv6 addresses such as addition or
 * deletion of an IPv6 address.
 *
 * Returns: currently always 0.
 */
int hip_init_register_inet6addr_notifier(void)
{
	HIP_DEBUG("\n");
	hip_notifier_block.notifier_call = hip_inet6addr_event_handler;
	hip_notifier_block.next = NULL;
	hip_notifier_block.priority = 0;
	return register_inet6addr_notifier(&hip_notifier_block);
}

/**
 * hip_uninit_register_inet6addr_notifier - uninitialize IPv6 address event handler
 *
 * Returns: currently always 0.
 */
int hip_uninit_register_inet6addr_notifier(void)
{
	return unregister_inet6addr_notifier(&hip_notifier_block);
}

int hip_init_netdev_notifier(void)
{
	HIP_DEBUG("\n");
	hip_netdev_notifier.notifier_call =  hip_netdev_event_handler;
	hip_netdev_notifier.next = NULL;
        hip_netdev_notifier.priority = 0;
        return register_netdevice_notifier(&hip_netdev_notifier);
}

void hip_uninit_netdev_notifier(void)
{
	HIP_DEBUG("\n");
        unregister_netdevice_notifier(&hip_netdev_notifier);
}

static int hip_do_work(void)
{
	int res = 0;
	struct hip_work_order *job;
	int tlist[4];
	uint32_t tmp32;
	//uint64_t tmp64;

	job = hip_get_work_order();
	if (!job) {
		HIP_ERROR("Unable to fetch from work queue\n");
		res = -2;
		goto out_err;
	}

	switch (job->type) {
	case HIP_WO_TYPE_INCOMING:
		switch(job->subtype) {
		case HIP_WO_SUBTYPE_RECV_I1:
			KRISU_START_TIMER(KMM_PARTIAL);
			res = hip_receive_i1(job->arg1);
			KRISU_STOP_TIMER(KMM_PARTIAL,"I1");
			break;
		case HIP_WO_SUBTYPE_RECV_R1:
			KRISU_START_TIMER(KMM_PARTIAL);
			res = hip_receive_r1(job->arg1);
			KRISU_STOP_TIMER(KMM_PARTIAL,"R1");
			break;
		case HIP_WO_SUBTYPE_RECV_I2:
			KRISU_START_TIMER(KMM_PARTIAL);
			res = hip_receive_i2(job->arg1);
			KRISU_STOP_TIMER(KMM_PARTIAL,"I2");
			break;
		case HIP_WO_SUBTYPE_RECV_R2:
			KRISU_START_TIMER(KMM_PARTIAL);
			res = hip_receive_r2(job->arg1);
			KRISU_STOP_TIMER(KMM_PARTIAL,"R2");
			KRISU_STOP_TIMER(KMM_GLOBAL,"Base Exchange");
			break;
		case HIP_WO_SUBTYPE_RECV_REA:
			KRISU_START_TIMER(KMM_PARTIAL);
			res = hip_receive_rea(job->arg1);
			KRISU_STOP_TIMER(KMM_PARTIAL,"REA");
			break;
		case HIP_WO_SUBTYPE_RECV_AC:
			KRISU_START_TIMER(KMM_PARTIAL);
			res = hip_receive_ac_or_acr(job->arg1,HIP_AC);
			KRISU_STOP_TIMER(KMM_PARTIAL,"AC");
			break;
		case HIP_WO_SUBTYPE_RECV_ACR:
			KRISU_START_TIMER(KMM_PARTIAL);
			res = hip_receive_ac_or_acr(job->arg1,HIP_ACR);
			KRISU_STOP_TIMER(KMM_PARTIAL,"ACR");
			break;
		default:
			HIP_ERROR("Unknown subtype: %d\n",job->subtype);
			break;
		}
		job->arg1 = NULL; /* to skip double kfree() */
		if (res < 0)
			res = KHIPD_ERROR;
		break;
	case HIP_WO_TYPE_OUTGOING:
		switch(job->subtype) {
		case HIP_WO_SUBTYPE_NEW_CONN:
			/* arg1 = d-hit, arg.u32[0] = new state, 
			   arg2 = own hit */
			tmp32 = job->arg.u32[0];
			tlist[0] = HIP_HADB_STATE;
			tlist[1] = HIP_HADB_OWN_HIT;
			
			res = hip_hadb_multiset(job->arg1,tlist,2,&tmp32,job->arg2,
						NULL,NULL,HIP_ARG_HIT);
			if (res < 2) {
				HIP_ERROR("Multiset error\n");
				res = KHIPD_ERROR;
			}
			HIP_DEBUG("moved to state %d\n",tmp32);
			/* print own hit */
			break;
		case HIP_WO_SUBTYPE_DEL_CONN:
			/* arg1 = d-hit */
			res = hip_hadb_reinitialize_state(job->arg1,HIP_ARG_HIT);
			if (res < 0) {
				HIP_ERROR("Unable to reinitialize state\n");
				res = KHIPD_ERROR;
			}
			HIP_DEBUG("State reverted to start\n");
			break;
		}
		break;
	case HIP_WO_TYPE_MSG:
		switch(job->subtype) {
		case HIP_WO_SUBTYPE_STOP:
			res = KHIPD_QUIT;
			break;
		case HIP_WO_SUBTYPE_ADDMAP:
			/* arg1 = d-hit, arg2=ipv6 */
			res = hip_add_peer_info(job->arg1,job->arg2);
			if (res < 0)
				res = KHIPD_ERROR;
			break;
		case HIP_WO_SUBTYPE_DELMAP:
		case HIP_WO_SUBTYPE_FLUSHMAPS:
			/* arg1 = dhit, or :: for all entries */
			res = hip_hadb_flush_states(job->arg1);
			if (res < 0)
				res = KHIPD_ERROR;
			break;
		case HIP_WO_SUBTYPE_ADDHI:
		case HIP_WO_SUBTYPE_DELHI:
		case HIP_WO_SUBTYPE_FLUSHHIS:
		case HIP_WO_SUBTYPE_NEWDH:
			HIP_INFO("Not implemented subtype: %d\n",job->subtype);
			res = KHIPD_ERROR;
			goto out_err;
		default:
			HIP_ERROR("Unknown subtype: %d on type: %d\n",job->subtype,job->type);
			res = KHIPD_ERROR;
			goto out_err;
		}
	}
		
 out_err:
	if (job) {
		if (job->arg1)
			kfree(job->arg1);
		if (job->arg2)
			kfree(job->arg2);
		kfree(job); // implies dynamically allocated structures
	}
	return res;
}

static int hip_worker(void *unused)
{
	int result = 0;

	hip_working = 1;
	daemonize("khipd");

	/* initialize */

	hip_init_workqueue();

	if (hip_init_daemon() < 0)
		goto out_err1;

	if (hip_init_ioctl() < 0)
		goto out_err2;

	if (hip_init_register_inet6addr_notifier() < 0)
		goto out_err3;

	/* comment this to disable network device event handler
	   (crashed sometimes) */
	if (hip_init_netdev_notifier() < 0)
		goto out_err4;

 	HIP_SETCALL(hip_bypass_ipsec, hip_bypass_ipsec);   
	HIP_SETCALL(hip_handle_output, hip_handle_output); 
	HIP_SETCALL(hip_handle_esp, hip_handle_esp);       
	HIP_SETCALL(hip_get_addr, hip_get_addr);           
	HIP_SETCALL(hip_get_hits, hip_get_hits);           
	HIP_SETCALL(hip_inbound, hip_inbound);             
	HIP_SETCALL(hip_get_saddr, hip_get_saddr);       
	HIP_SETCALL(hip_unknown_spi, hip_unknown_spi);   
	HIP_SETCALL(hip_handle_dst_unreachable, hip_handle_dst_unreachable); 

	/* work loop */

	while(1) {
		down(&hip_work);
		HIP_DEBUG("Got work\n");

		result = hip_do_work();
		if (result < 0) {
			if (result == KHIPD_QUIT) {
				HIP_INFO("Stop requested. Cleaning up\n");
				break;
			} 
			else if (result == KHIPD_ERROR)
				HIP_INFO("Recoverable error occured\n");
			else {
				HIP_INFO("Unrecoverable error occured. Cleaning up\n");
				break;
			}
		}
		HIP_DEBUG("Work done\n");
	}


	/* cleanup */

	HIP_INVALIDATE(hip_handle_dst_unreachable);
	HIP_INVALIDATE(hip_unknown_spi);
	HIP_INVALIDATE(hip_get_saddr);
	HIP_INVALIDATE(hip_inbound);
	HIP_INVALIDATE(hip_get_hits);
	HIP_INVALIDATE(hip_get_addr);
	HIP_INVALIDATE(hip_handle_esp);
	HIP_INVALIDATE(hip_handle_output);
	HIP_INVALIDATE(hip_bypass_ipsec);

	hip_uninit_workqueue();
	// out_err5:
	hip_uninit_netdev_notifier(); 	/* comment this if network device event */
 out_err4:
	hip_uninit_register_inet6addr_notifier();
 out_err3:
	hip_uninit_ioctl();
 out_err2:
	hip_uninit_daemon();
 out_err1:
	hip_working = 0;

	return (result+1);
}



static int hip_init(void)
{
	HIP_INFO("Initializing HIP module\n");
	hip_get_load_time();

	
	if(!hip_init_r1())
		goto out_err1;

	if (hip_init_sock() < 0)
		goto out_err2;

	if (hip_init_cipher() < 0)
		goto out_err4;

#ifdef CONFIG_PROC_FS
	if (hip_init_procfs() < 0)
		goto out_err6;
#endif /* CONFIG_PROC_FS */


	kernel_thread(hip_worker, NULL,CLONE_FS | CLONE_FILES | CLONE_SIGHAND | SIGCHLD);

	HIP_INFO("HIP module initialized successfully\n");
	return 0;


#ifdef CONFIG_PROC_FS
	hip_uninit_procfs();
#endif /* CONFIG_PROC_FS */

 out_err6:
	hip_uninit_host_id_dbs();

	//out_err5:
	hip_uninit_cipher();
	
 out_err4:
 	hip_uninit_hadb();

	//out_err3:
	hip_uninit_sock();
	
 out_err2:
	hip_uninit_r1();

 out_err1:
	hip_rea_delete_sent_list();
	hip_ac_delete_sent_list();

	HIP_ERROR("Failed to init module\n");
	return -EINVAL;
}

static void hip_cleanup(void)
{
	HIP_INFO("uninitializing HIP module\n");

	if (hip_working) {
		hip_stop_khipd(); /* tell the hip kernel thread(s) to stop */

		while(hip_working)
			schedule(); /* wait until stopped */
	}

	HIP_DEBUG("Thread finished\n");

#ifdef CONFIG_PROC_FS
	hip_uninit_procfs();
#endif /* CONFIG_PROC_FS */
	hip_uninit_host_id_dbs();
	hip_uninit_hadb();
	hip_uninit_sock();
	hip_uninit_r1();
	hip_rea_delete_sent_list();
	hip_ac_delete_sent_list();
	HIP_INFO("HIP module uninitialized successfully\n");
	return;
}

MODULE_AUTHOR("HIPL <hipl@gaijin.tky.hut.fi>");
MODULE_DESCRIPTION("HIP development module");
MODULE_LICENSE("GPL");
#ifdef KRISUS_THESIS
MODULE_PARM(kmm,"i");
MODULE_PARM_DESC(kmm, "Measuring mode: 1 = Global timing, 2 = {I,R}{1,2} timing, 3 = spinlock timing");
#endif
module_init(hip_init);
module_exit(hip_cleanup);

/*
	void	(*err_handler)(struct sk_buff *skb,
			       struct inet6_skb_parm *opt,
			       int type, int code, int offset,
			       __u32 info);
*/
static struct inet6_protocol hip_protocol = {
	.handler     = hip_inbound,
//	.err_handler = hip_errhand,
	.flags       = INET6_PROTO_NOPOLICY,
};
