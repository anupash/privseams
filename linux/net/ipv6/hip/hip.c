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
#include "hadb.h"
#include "input.h"
#include "builder.h"
#include "db.h"
#include "cookie.h"
#include "keymat.h"
#include "security.h"
#include "misc.h"
#include "output.h"
#include "rea.h"
#include "workqueue.h"
#include "ioctl.h"
#include "daemon.h"
#include "socket.h"
#include "update.h"
#ifdef CONFIG_HIP_RVS
# include "rvs.h"
#endif

#include <linux/proc_fs.h>
#include <linux/notifier.h>
#include <linux/spinlock.h>
#include <linux/xfrm.h>
#include <linux/crypto.h>
#include <net/protocol.h>
#include <net/hip.h>
#include <net/checksum.h>
#include <net/hip_glue.h>
#include <net/addrconf.h>
#include <net/xfrm.h>

static atomic_t hip_working = ATOMIC_INIT(0);

time_t load_time;


static struct notifier_block hip_netdev_notifier;
static void hip_uninit_cipher(void); // forward decl.
static void hip_cleanup(void);

/* All cipher and digest implementations we support. */
static struct crypto_tfm *impl_3des_cbc = NULL;


/* global variables */
struct socket *hip_output_socket;
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

//spinlock_t hip_workqueue_lock = SPIN_LOCK_UNLOCKED;

#ifdef CONFIG_PROC_FS
static struct proc_dir_entry *hip_proc_root = NULL;
#endif /* CONFIG_PROC_FS */

LIST_HEAD(hip_sent_rea_info_pkts);
LIST_HEAD(hip_sent_ac_info_pkts);


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

	_HIP_DEBUG("dh_group_type=%u\n", hip_dh_group_type);
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

/**
 * hip_map_virtual_to_pages - Maps virtual addresses to physical page addresses
 * @slist: Pointer to an array of scatterlists that contain the phycical page information
 * @slistcnt: Number of elements in @slist array
 * @addr: Virtual address
 * @size: Size of the block that is beeing transformed (from @addr in bytes)
 *
 * Cryptoapi requires that all addresses are given in physical pages rather than
 * virtual addresses. Thus, we need to convert the virtual addresses seen by the
 * HIPL code to pages. 
 * We will fill at most @slitcnt scatterlists. If more are required, an error is
 * returned.
 *
 * Returns 0, if ok. <0 if an error occured. As a side effect @slist will be filled
 * with @slistcnt entries. At the exit, the @slistcnt variable will hold the actual
 * number of scatterlist entries that were written.
 */
int hip_map_virtual_to_pages(struct scatterlist *slist, int *slistcnt, 
			     const u8 *addr, const u32 size)
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


	_HIP_DEBUG("Virtual addresses: %p, size: %d\n",addr,size);

	offset = 0;
	while(offset < size) {

		slist[elt].dma_address = 0;
		slist[elt].page = virt_to_page(addr+offset);
		slist[elt].offset = (unsigned long) (addr+offset) % PAGE_SIZE;

		/* page left */
		/* pleft = how many bytes there are for us in current page */
		pleft = PAGE_SIZE - slist[elt].offset;
		HIP_ASSERT(pleft > 0 && pleft <= PAGE_SIZE);

		_HIP_DEBUG("offset: %ld, space on current page: %ld\n",offset,pleft);
		if (pleft + offset >= size) {
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
		_HIP_DEBUG("Scatterlist: %x, page: %x, offset: %x, length: %x\n",
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

	_HIP_DEBUG("Mapping virtual to pages\n");

	err = hip_map_virtual_to_pages(sg, &nsg, in, in_len);
	if (err || nsg < 1 ) {
		HIP_ERROR("Error mapping virtual addresses to physical pages\n");
		return -EFAULT;
	}

	_HIP_DEBUG("Mapping virtual to pages successful\n");

	crypto_digest_init(impl);
	crypto_digest_digest(impl, sg, nsg, out);

	return 0;
}

/**
 * hip_build_digest_repeat - Calculate digest repeatedly
 * @dgst: Digest transform
 * @sg: Valid scatterlist array
 * @nsg: Number of scatterlists in the @sg array.
 * @out: Output buffer. Should contain enough bytes for the digest.
 * 
 * Use this function instead of the one above when you need to do repeated
 * calculations *IN THE SAME MEMORY SPACE (SIZE _AND_ ADDRESS)*
 * This is an optimization for cookie solving. There we do a lots of digests
 * in the same memory block and its size is constant.
 * So instead of calling N times hip_map_virtual_to_pages() the caller maps
 * once and all the digest iterations use the same pages.
 * This improves the speed greatly.
 *
 * Returns 0 always. The digest is written to @out.
*/
int hip_build_digest_repeat(struct crypto_tfm *dgst, struct scatterlist *sg, 
			    int nsg, void *out)
{
	crypto_digest_init(dgst); // is this necessary always?
	crypto_digest_digest(dgst, sg, nsg, out);
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

	_HIP_DEBUG("Mapping virtual to pages\n");

	err = hip_map_virtual_to_pages(sg, &nsg, in, in_len);
	if (err || nsg < 1) {
		HIP_ERROR("Mapping failed\n");
		return 0;
	}

	_HIP_DEBUG("Mapping virtual to pages successful\n");

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
struct hip_common *hip_create_r1(const struct in6_addr *src_hit)
{
 	struct hip_common *msg;
 	struct in6_addr dst_hit;
 	int err = 0;
 	u8 *dh_data = NULL;
 	int dh_size,written, mask;
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

	_HIP_DEBUG("dh_size=%d\n", dh_size);
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
 	memset(&dst_hit, 0, sizeof(struct in6_addr));

	mask = HIP_CONTROL_NONE;
#ifdef CONFIG_HIP_RVS
	mask |= HIP_CONTROL_RVS_CAPABLE;
#endif

 	hip_build_network_hdr(msg, HIP_R1, mask, src_hit,
 			      &dst_hit);

	/********** R1_COUNTER (OPTIONAL) *********/

 	/********** PUZZLE ************/
	{
		err = hip_build_param_puzzle(msg, HIP_DEFAULT_COOKIE_K, 0, 0);
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

	_HIP_DEBUG("This HOST ID belongs to: %s\n", hip_get_param_host_id_hostname(host_id_pub));
	err = hip_build_param(msg, host_id_pub);
 	if (err) {
 		HIP_ERROR("Building of host id failed\n");
 		goto out_err;
 	}

	/********** ECHO_REQUEST_SIGN (OPTIONAL) *********/

	while(0);

 	/********** Signature 2 **********/

 	if (!hip_create_signature(msg,
 				  hip_get_msg_total_len(msg),
 				  host_id_private,
 				  signature)) {
 		HIP_ERROR("Signing of R1 failed.\n");
 		goto out_err;
 	}		

	_HIP_HEXDUMP("R1", msg, hip_get_msg_total_len(msg));

 	err = hip_build_param_signature2_contents(msg,
 						 signature,
 						 HIP_DSA_SIGNATURE_LEN,
 						 HIP_SIG_DSA);
 	if (err) {
 		HIP_ERROR("Building of signature failed (%d) on R1\n", err);
 		goto out_err;
 	}


	/********** ECHO_REQUEST (OPTIONAL) *********/

	while(0);


	/* Fill puzzle parameters */

	{
		struct hip_puzzle *pz;
		uint64_t random_i;

		pz = hip_get_param(msg, HIP_PARAM_PUZZLE);
		if (!pz) {
			HIP_ERROR("Internal error\n");
			goto out_err;
		}

		get_random_bytes(pz->opaque, HIP_PUZZLE_OPAQUE_LEN);

		get_random_bytes(&random_i,sizeof(random_i));
		pz->I = random_i;
	}

 	/************** Packet ready ***************/

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
		HIP_ERROR("unknown tid=%d\n", tid);
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
		HIP_ERROR("unknown tid=%d\n", tid);
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
		HIP_ERROR("unknown tid=%d\n", tid);
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
		HIP_ERROR("unknown tid=%d\n", tid);
		HIP_ASSERT(0);
		break;
	}

	return ret;
}

/**
 * hip_store_base_exchange_keys - store the keys negotiated in base exchange
 * @ctx:             the context inside which the key data will copied around
 * @is_initiator:    true if the localhost is the initiator, or false if
 *                   the localhost is the responder
 *
 * Returns: 0 if everything was stored successfully, otherwise < 0.
 */
int hip_store_base_exchange_keys(struct hip_hadb_state *entry, 
				  struct hip_context *ctx, int is_initiator)
{
	int err = 0;
	int hmac_key_len, enc_key_len, auth_key_len;

	hmac_key_len = hip_hmac_key_length(entry->esp_transform);
	enc_key_len = hip_enc_key_length(entry->esp_transform);
	auth_key_len = hip_auth_key_length_esp(entry->esp_transform);

	memcpy(&entry->hip_hmac_out, &ctx->hip_hmac_out, hmac_key_len);
	memcpy(&entry->hip_hmac_in, &ctx->hip_hmac_in, hmac_key_len);

	memcpy(&entry->esp_in.key, &ctx->esp_in.key, enc_key_len);
	memcpy(&entry->auth_in.key, &ctx->auth_in.key, auth_key_len);

	memcpy(&entry->esp_out.key, &ctx->esp_out.key, enc_key_len);
	memcpy(&entry->auth_out.key, &ctx->auth_out.key, auth_key_len);

	hip_update_entry_keymat(entry, ctx->current_keymat_index,
				ctx->keymat_calc_index, ctx->current_keymat_K);

	if (entry->dh_shared_key) {
		HIP_DEBUG("kfreeing old dh_shared_key\n");
		kfree(entry->dh_shared_key);
	}

	entry->dh_shared_key_len = 0;
	/* todo: reuse pointer, no kmalloc */
	entry->dh_shared_key = kmalloc(ctx->dh_shared_key_len, GFP_ATOMIC);
	if (!entry->dh_shared_key) {
		HIP_ERROR("entry dh_shared kmalloc failed\n");
		err = -ENOMEM;
		goto out_err;
	}

	entry->dh_shared_key_len = ctx->dh_shared_key_len;
	memcpy(entry->dh_shared_key, ctx->dh_shared_key, entry->dh_shared_key_len);
	_HIP_HEXDUMP("Entry DH SHARED", entry->dh_shared_key, entry->dh_shared_key_len);
	_HIP_HEXDUMP("Entry Kn", entry->current_keymat_K, HIP_AH_SHA_LEN);
	return err;

 out_err:
	if (entry->dh_shared_key)
		kfree(entry->dh_shared_key);

	return err;
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

	if ( (length >> 1) > 6) {
		HIP_ERROR("Too many transforms (%d)\n", length >> 1);
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

	if ( (length >> 1) > 6) {
		HIP_ERROR("Too many transforms (%d)\n", length >> 1);
		goto out;
	}

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

#if 1
	return tid;
#else
	/* IETF58: only this worked with Andrew */
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
 * A NULL IV is not guaranteed to be interoperable with 3DES, so it's
 * recommended to use a non-NULL iv (even with just all zeroes).
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

	/* We cannot use the same memory are for en/decryption? */
	void *result = NULL;
	result = kmalloc(enc_len, GFP_KERNEL);
	if (!result) {
		err = -ENOMEM;
		goto out_err;
	}

	memcpy(result, data, enc_len);

	_HIP_HEXDUMP("hip_crypto_encrypted encrypt data", data, enc_len);
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
		err = -EFAULT;
		goto out_err;
	}

	_HIP_DEBUG("Mapping virtual to pages\n");

	err = hip_map_virtual_to_pages(src_sg, &src_nsg, result, enc_len);
	if (err || src_nsg < 1) {
		HIP_ERROR("Error mapping source data\n");
		err = -EFAULT;
		goto out_err;
	}

	_HIP_DEBUG("Mapping virtual to pages successful\n");

	/* we will write over the source */

	err = crypto_cipher_setkey(impl, enc_key, key_len);
	if (err) {
		if (impl->crt_flags & CRYPTO_TFM_RES_BAD_KEY_SCHED) {
			HIP_ERROR("3DES key is weak.\n");
			HIP_HEXDUMP("3DES key", enc_key, key_len);
		}
		HIP_ERROR("Could not set encryption/decryption key\n");
		err = -EFAULT;
		goto out_err;
	}

	HIP_DEBUG("enc_len=%d\n", enc_len);
	switch(direction) {
	case HIP_DIRECTION_ENCRYPT:
		if (iv) {
			err = crypto_cipher_encrypt_iv(impl, src_sg, src_sg,
						       enc_len, iv);
			/* The encrypt function writes crap on iv */
			memset(iv, 0, 8);
		} else {
			err = crypto_cipher_encrypt(impl, src_sg, src_sg,
						    enc_len);
		}
		if (err) {
			HIP_ERROR("Encryption failed\n");
			err = -EFAULT;
			goto out_err;
		}

		break;
	case HIP_DIRECTION_DECRYPT:
		if (iv) {
			err = crypto_cipher_decrypt_iv(impl, src_sg, src_sg, enc_len, iv);
		} else {
			err = crypto_cipher_decrypt(impl, src_sg, src_sg, enc_len);
		}
		if (err) {
			HIP_ERROR("Decryption failed\n");
			err = -EFAULT;
			goto out_err;
		}
		break;
	default:
		HIP_ERROR("Undefined direction (%d)\n", direction);
		err = -EINVAL;
		break;
	}

	if (iv) {
		memcpy(data, result, enc_len);
	} else {
		HIP_ASSERT(iv); /* Not tested/interoperated without iv */
	}


 out_err:
	if (result)
		kfree(result);
	return err;
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
void hip_unknown_spi(struct sk_buff *skb, uint32_t spi)
{
	/* draft: If the R1 is a response to an ESP packet with an unknown
	   SPI, the Initiator HIT SHOULD be zero. */
	HIP_DEBUG("Received Unknown SPI: 0x%x\n", ntohl(spi));
	HIP_INFO("Sending R1 with NULL dst HIT\n");

	HIP_DEBUG("SKIP SENDING OF R1 ON UNKNOWN SPI\n");
	/* TODO: send NOTIFY */
	return;
#if 0
	/* We cannot know the destination HIT */
	err = hip_xmit_r1(skb, NULL);
	if (err) {
		HIP_ERROR("hip_xmit_r1 failed (%d)\n", err);
	}
#endif
}

/**
 * hip_init_sock - initialize HIP control socket
 *
 * Returns: 0 if successful, else < 0.
 */
static int hip_init_output_socket(void)
{
	int err = 0;

	err = sock_create(AF_INET6, SOCK_RAW, IPPROTO_NONE, &hip_output_socket);
	if (err)
		HIP_ERROR("Failed to allocate the HIP control socket (err=%d)\n", err);
	return err;
}

/**
 * hip_uninit_sock - uninitialize HIP control socket
 */
void hip_uninit_output_socket(void)
{
	sock_release(hip_output_socket);
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
int hip_get_addr(hip_hit_t *hit, struct in6_addr *addr)
{
	hip_ha_t *entry;
	char str[INET6_ADDRSTRLEN];

	if (!hip_is_hit(hit))
		return 0;

	hip_in6_ntop(hit,str);

	entry = hip_hadb_find_byhit(hit);
	if (!entry) {
		HIP_ERROR("Unknown HIT: %s\n", str);
		return 0;
	}

	if (hip_hadb_get_peer_addr(entry, addr) < 0) {
		hip_put_ha(entry);
		return 0;
	}
	hip_put_ha(entry);

	hip_in6_ntop(addr, str);
	HIP_DEBUG("selected dst addr: %s\n", str);

	return 1;
}

/**
 * hip_trigger_bex - Trigger HIP base exchange
 * @dsthit: Destination HIT
 *
 * Returns 0
 */
int hip_trigger_bex(struct in6_addr *dsthit)
{
	struct ipv6hdr hdr = {0};

	ipv6_addr_copy(&hdr.daddr, dsthit);
	hip_handle_output(&hdr, NULL);
	return 0;
}


/**
 * hip_get_hits - get this host's HIT to be used in source HIT
 * @hitd: destination HIT
 * @hits: where the selected source HIT is to be stored
 *
 * Returns: 1 if source HIT was copied successfully, otherwise 0.
 */
int hip_get_hits(struct in6_addr *hitd, struct in6_addr *hits)
{
	if (!ipv6_addr_is_hit(hitd))
		goto out;

	if (hip_copy_any_localhost_hit(hits) < 0)
		goto out;

	return 1;

 out:
	return 0;
}

/**
 * hip_get_saddr - get source HIT
 * @fl: flow containing the destination HIT
 * @hit_storage: where the source address is to be stored
 *
 * ip6_build_xmit() calls this if we have a source address that is not
 * a HIT and destination address which is a HIT. If that is true, we
 * make the source a HIT too.
 */
int hip_get_saddr(struct flowi *fl, struct in6_addr *hit_storage)
{
	hip_ha_t *entry;

	if (!ipv6_addr_is_hit(&fl->fl6_dst)) {
		HIP_ERROR("dst not a HIT\n");
		return 0;
	}

	entry = hip_hadb_find_byhit((hip_hit_t *)&fl->fl6_dst);
	if (!entry) {
		HIP_ERROR("Unknown HIT\n");
		return 0;
	}

	ipv6_addr_copy(hit_storage, &entry->hit_our);

	hip_put_ha(entry);

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


/* base exchange IPv6 addresses need to be put into ifindex2spi map,
 * so a function is needed which gets the ifindex of the network
 * device which has the address @addr */
int hip_ipv6_devaddr2ifindex(struct in6_addr *addr)
{
	int ifindex = 0;
	struct inet6_ifaddr *ifp = ipv6_get_ifaddr(addr, NULL, 1);
	if (ifp) {
		ifindex = ifp->idev->dev->ifindex;
		in6_ifa_put(ifp);
	}
	return ifindex;
}

/**
 * hip_create_device_addrlist - get interface addresses
 * @event_dev: network device of which addresses are retrieved from
 * @addr_list: where the pointer to address list is stored
 * @idev_addr_count: number of addresses in @addr_list
 *
 * Caller is responsible for kfreeing @addr_list.
 *
 * Returns: 0 if addresses were retrieved successfully. If there was
 * no error but interface has no IPv6 addresses, @addr_list is NULL
 * and 0 is returned. Else < 0 is returned and @addr_list contains
 * NULL.
 */
static int hip_create_device_addrlist(struct net_device *event_dev,
				       struct hip_rea_info_addr_item **addr_list,
				       int *idev_addr_count)
{
	struct inet6_dev *idev;
	struct inet6_ifaddr *ifa = NULL;
	char addrstr[INET6_ADDRSTRLEN];
	int i = 0;
	int err = 0;
	struct hip_rea_info_addr_item *tmp_list = NULL;
	int n_addrs = 0;

	*idev_addr_count = 0;

        read_lock(&addrconf_lock);
	idev = in6_dev_get(event_dev);
	if (!idev) {
		HIP_DEBUG("event_dev has no IPv6 addrs, returning\n");
		goto out;
	}
	read_lock(&idev->lock);

	for (ifa = idev->addr_list; ifa; ifa = ifa->if_next) {
		spin_lock_bh(&ifa->lock);
		hip_in6_ntop(&ifa->addr, addrstr);
		HIP_DEBUG("addr %d: %s flags=0x%x valid_lft=%u jiffies-ifa_timestamp=%lu\n",
			  n_addrs+1, addrstr, ifa->flags,
			  ifa->valid_lft, (jiffies-ifa->tstamp)/HZ);
		if (ipv6_addr_type(&ifa->addr) & IPV6_ADDR_LINKLOCAL) {
			HIP_DEBUG("not counting link local address\n");
		} else
			n_addrs++;
		spin_unlock_bh(&ifa->lock);
	}
	HIP_DEBUG("address list count=%d\n", n_addrs);

	if (n_addrs > 0) {
		/* create address list for building of REA */
		tmp_list = kmalloc(n_addrs * sizeof(struct hip_rea_info_addr_item), GFP_ATOMIC);
		if (!tmp_list) {
			HIP_DEBUG("addr_list creation failed\n");
			err = -ENOMEM;
			goto out_in6_unlock;
		}

		/* todo: skip addresses which we don't want/need to include into
		 * the REA packet, localhost address, multicast addresses etc
		 *
		 * this list is maybe better to be created for each of
		 * the peers, policy ?
		 */
		for (i = 0, ifa = idev->addr_list;
		     ifa && i < n_addrs; ifa = ifa->if_next, i++) {
			spin_lock_bh(&ifa->lock);
			if (!(ipv6_addr_type(&ifa->addr) & IPV6_ADDR_LINKLOCAL)) {
				ipv6_addr_copy(&tmp_list[i].address, &ifa->addr);
				/* lifetime: select prefered_lft or valid_lft ? */
				tmp_list[i].lifetime = htonl(ifa->valid_lft); /* or: (jiffies-ifp->tstamp)/HZ ? */
				if (i == 0)
					tmp_list[i].reserved = htonl(1 << 31); /* for testing preferred address */
				else
					tmp_list[i].reserved = 0;
			} else {
				HIP_DEBUG("not adding link local address\n");
			}
			spin_unlock_bh(&ifa->lock);
		}
	}

	*addr_list = tmp_list;
	*idev_addr_count = n_addrs;

 out_in6_unlock:
	read_unlock(&idev->lock);
 out:
	read_unlock(&addrconf_lock);
	return err;
}

/* helper function for creating and initializing work order for
 * network events */
struct hip_work_order *hip_net_event_prepare_hwo(int subtype,
						 int ifindex, int event)
{
	struct hip_work_order *hwo;

	hwo = hip_init_job(GFP_ATOMIC);
	if (!hwo)
		return NULL;

	hwo->type = HIP_WO_TYPE_MSG;
	hwo->subtype = subtype;
	hwo->arg1 = (void *)ifindex;
	hwo->arg2 = (void *)event;
	hwo->destructor = NULL;
	return hwo;
}


/**
 * hip_handle_ipv6_dad_completed - handle IPv6 address events
 * @ifa: IPv6 address of an interface which caused the event
 *
 * This function gets notification when DAD procedure has finished
 * successfully for an address @ifa.
 */
void hip_handle_ipv6_dad_completed(struct inet6_ifaddr *ifa) {
	struct net_device *event_dev = NULL;
	struct inet6_dev *idev = NULL;
	struct hip_work_order *hwo;

	HIP_DEBUG("\n");

	if (!ifa) {
		HIP_ERROR("ifa is NULL\n");
		goto out;
	}

	in6_ifa_hold(ifa);
	hip_print_hit("ifa address", &ifa->addr);

	if (ipv6_addr_type(&ifa->addr) & IPV6_ADDR_LINKLOCAL) {
		HIP_DEBUG("skipping event on link local address\n");
		goto out_ifa_put;
	}

	idev = ifa->idev;
        if (!idev) {
                HIP_DEBUG("NULL idev\n");
		goto out_ifa_put;
        }
	in6_dev_hold(idev);
	event_dev = idev->dev;
        if (!event_dev) {
                HIP_ERROR("NULL event_dev, shouldn't happen ?\n");
		goto out_idev_put;
        }
	dev_hold(event_dev);

	hwo = hip_net_event_prepare_hwo(HIP_WO_SUBTYPE_IN6_EVENT,
					event_dev->ifindex, NETDEV_UP);
  	if (!hwo) {
		HIP_ERROR("Unable to handle address event\n");
  	} else
		hip_insert_work_order(hwo);

	dev_put(event_dev);
 out_idev_put:
	in6_dev_put(idev);
 out_ifa_put:
	in6_ifa_put(ifa);
 out:
	return;
}

#define EVENTSRC_INET6 0
#define EVENTSRC_NETDEV 1

/** hip_net_event - start handling the network device event
 * @ifindex: the device which caused the event
 * @event_src: 0 for IPv6 address events and 1 for network device related events
 * @event: event type, NETDEV_UP or NETDEV_DOWN
 *
 * Workqueue runs this function when it is assigned a job related to
 * networking events.
 */
static void hip_net_event(int ifindex, uint32_t event_src, uint32_t event)
{
	int err = 0;
	struct net_device *event_dev;
        int idev_addr_count = 0;
        struct hip_rea_info_addr_item *addr_list = NULL;

	HIP_DEBUG("\n");

        if (! (event_src == EVENTSRC_INET6 || event_src == EVENTSRC_NETDEV) ) {
                HIP_ERROR("unknown event source %d\n", event_src);
                return;
        }

	event_dev = dev_get_by_index(ifindex);
	if (!event_dev) {
		HIP_DEBUG("Network interface (ifindex=%d) does not exist anymore\n",
			  ifindex);
		return;
	}
	/* dev_get_by_index does a dev_hold */

	HIP_DEBUG("event_src=%s dev=%s ifindex=%d event=%u\n",
		  event_src == EVENTSRC_INET6 ? "inet6" : "netdev",
		  event_dev->name, ifindex, event);

        /* Skip events caused by loopback devices (as long as we do
	 * not have loopback support). TODO: skip tunnels etc. */
        if (event_dev->flags & IFF_LOOPBACK) {
                HIP_DEBUG("ignoring event from loopback device\n");
		dev_put(event_dev);
		return;
        }

	err = hip_create_device_addrlist(event_dev, &addr_list, &idev_addr_count);
	dev_put(event_dev);

	if (err) {
		HIP_ERROR("hip_create_device_addrlist failed, err=%d\n", err);
	} else {
		/* send UPDATEs if there are addresses to be informed to the peers */
		if (idev_addr_count > 0 && addr_list)
			hip_send_update_all(addr_list, idev_addr_count, ifindex, 0x0);
		else
			HIP_DEBUG("Netdev has no addresses to be informed, UPDATE not sent\n");
	}

	if (addr_list)
		kfree(addr_list);
}

/**
 * hip_handle_inet6_addr_del - handle IPv6 address deletion events
 * @ifindex: the interface index of the network device which caused the event
 */
void hip_handle_inet6_addr_del(int ifindex) {
	struct hip_work_order *hwo;

	HIP_DEBUG("ifindex=%d\n", ifindex);

	hwo = hip_net_event_prepare_hwo(HIP_WO_SUBTYPE_IN6_EVENT,
					ifindex, NETDEV_DOWN);
  	if (!hwo) {
		HIP_ERROR("Unable to handle address event\n");
		goto out;
  	}
	hip_insert_work_order(hwo);
 out:
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
                                    unsigned long event, void *ptr)
{
        struct net_device *event_dev;
	struct hip_work_order *hwo;

        if (! (event == NETDEV_DOWN || event == NETDEV_UNREGISTER)) {
                _HIP_DEBUG("Ignoring event %lu\n", event);
                return NOTIFY_DONE;
        }

	HIP_DEBUG("got event NETDEV_%s\n", event == NETDEV_DOWN ? "DOWN" : "UNREGISTER");

        event_dev = (struct net_device *) ptr;
        if (!event_dev) {
                HIP_ERROR("NULL event_dev, shouldn't happen ?\n");
                return NOTIFY_DONE;
        }
	dev_hold(event_dev);

	hwo = hip_net_event_prepare_hwo(HIP_WO_SUBTYPE_DEV_EVENT,
					event_dev->ifindex, event);
  	if (!hwo) {
		HIP_ERROR("Unable to handle address event\n");
		goto out;
  	}
	hip_insert_work_order(hwo);

 out:
	dev_put(event_dev);
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
		HIP_DEBUG("Too short an ICMP packet\n");
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

	/* instruct the "IPsec" to check for available algorithms */
	xfrm_probe_algs();

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
			    1 << HIP_DH_OAKLEY_5 |
			    1 << HIP_DH_384);

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
	hip_proc_root = create_proc_entry("hip", S_IFDIR, proc_net);
	if (!hip_proc_root)
		return -1;

	/* todo: set file permission modes */
	if (!create_proc_read_entry("lhi", 0, hip_proc_root, hip_proc_read_lhi, NULL))
		goto out_err_root;
	if (!create_proc_read_entry("sdb_state", 0, hip_proc_root,
			       hip_proc_read_hadb_state, NULL))
		goto out_err_lhi;
	if (!create_proc_read_entry("sdb_peer_addrs", 0, hip_proc_root,
			       hip_proc_read_hadb_peer_addrs, NULL))
		goto out_err_sdb_state;
	if (!create_proc_read_entry("sdb_peer_spi_list", 0, hip_proc_root,
			       hip_proc_read_hadb_peer_spi_list, NULL))
		goto out_err_peer_addrs;
	/* a simple way to trigger sending of UPDATE packet to all peers */
	if (!create_proc_read_entry("send_update", 0, hip_proc_root,
			       hip_proc_send_update, NULL))
		goto out_err_spi_list;
	/* for testing dummy NOTIFY packets */
	if (!create_proc_read_entry("send_notify", 0, hip_proc_root,
			       hip_proc_send_notify, NULL))
		goto out_err_send_update;

	HIP_DEBUG("profcs init successful\n");
	return 1;

 out_err_send_update:
	remove_proc_entry("send_update", hip_proc_root);
 out_err_spi_list:
	remove_proc_entry("sdb_peer_spi_list", hip_proc_root);
 out_err_peer_addrs:
	remove_proc_entry("sdb_peer_addrs", hip_proc_root);
 out_err_sdb_state:
	remove_proc_entry("sdb_state", hip_proc_root);
 out_err_lhi:
	remove_proc_entry("lhi", hip_proc_root);
 out_err_root:
	remove_proc_entry("net/hip", NULL);

	HIP_ERROR("profcs init failed\n");
	return -1;
}

/**
 * hip_uninit_procfs - uninitialize HIP procfs support
 */
static void hip_uninit_procfs(void)
{
	HIP_DEBUG("\n");
	remove_proc_entry("lhi", hip_proc_root);
	remove_proc_entry("sdb_state", hip_proc_root);
	remove_proc_entry("sdb_peer_addrs", hip_proc_root);
	remove_proc_entry("send_update", hip_proc_root);
	remove_proc_entry("send_notify", hip_proc_root);
	remove_proc_entry("sdb_peer_spi_list", hip_proc_root);
	remove_proc_entry("hip", proc_net);
}
#endif /* CONFIG_PROC_FS */

int hip_init_netdev_notifier(void)
{
	HIP_DEBUG("\n");
	hip_netdev_notifier.notifier_call = hip_netdev_event_handler;
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
			hip_hadb_dump_hits();
			break;
		case HIP_WO_SUBTYPE_RECV_R1:
			KRISU_START_TIMER(KMM_PARTIAL);
			res = hip_receive_r1(job->arg1);
			KRISU_STOP_TIMER(KMM_PARTIAL,"R1");
			hip_hadb_dump_hits();
			break;
		case HIP_WO_SUBTYPE_RECV_I2:
			KRISU_START_TIMER(KMM_PARTIAL);
			res = hip_receive_i2(job->arg1);
			KRISU_STOP_TIMER(KMM_PARTIAL,"I2");
			hip_hadb_dump_hits();
			break;
		case HIP_WO_SUBTYPE_RECV_R2:
			KRISU_START_TIMER(KMM_PARTIAL);
			res = hip_receive_r2(job->arg1);
			KRISU_STOP_TIMER(KMM_PARTIAL,"R2");
			KRISU_STOP_TIMER(KMM_GLOBAL,"Base Exchange");
			hip_hadb_dump_hits();
			break;
		case HIP_WO_SUBTYPE_RECV_UPDATE:
			KRISU_START_TIMER(KMM_PARTIAL);
			res = hip_receive_update(job->arg1);
			KRISU_STOP_TIMER(KMM_PARTIAL,"UPDATE");
			break;
		case HIP_WO_SUBTYPE_RECV_NOTIFY:
			KRISU_START_TIMER(KMM_PARTIAL);
			res = hip_receive_notify(job->arg1);
			KRISU_STOP_TIMER(KMM_PARTIAL,"NOTIFY");
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
		if (res < 0)
			res = KHIPD_ERROR;
		break;
	case HIP_WO_TYPE_OUTGOING:
		HIP_INFO("Nothing for outgoing stuff\n");
		break;
	case HIP_WO_TYPE_MSG:
		switch(job->subtype) {
		case HIP_WO_SUBTYPE_STOP:
			res = KHIPD_QUIT;
			break;
		case HIP_WO_SUBTYPE_IN6_EVENT:
			hip_net_event((int)job->arg1, 0, (uint32_t) job->arg2);
			res = KHIPD_OK;
			break;
		case HIP_WO_SUBTYPE_DEV_EVENT:
			hip_net_event((int)job->arg1, 1, (uint32_t) job->arg2);
			res = KHIPD_OK;
			break;
		case HIP_WO_SUBTYPE_ADDMAP:
			/* arg1 = d-hit, arg2=ipv6 */
			res = hip_hadb_add_peer_info(job->arg1, job->arg2);
			if (res < 0)
				res = KHIPD_ERROR;
			hip_hadb_dump_hits();
			break;
		case HIP_WO_SUBTYPE_DELMAP:
			/* arg1 = d-hit arg2=d-ipv6 */
			res = hip_del_peer_info(job->arg1, job->arg2);
			if (res < 0)
				res = KHIPD_ERROR;
			break;
#ifdef CONFIG_HIP_RVS
		case HIP_WO_SUBTYPE_ADDRVS:
			/* arg1 = d-hit, arg2=ipv6 */
			res = hip_hadb_add_peer_info(job->arg1, job->arg2);
			if (res < 0)
				res = KHIPD_ERROR;
			hip_rvs_set_request_flag(job->arg1);
			break;
#endif
		case HIP_WO_SUBTYPE_FLUSHMAPS:
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
	hip_free_work_order(job);
	return res;
}

static int hip_worker(void *cpu_id)
{
	int result = 0;
	int cid = (int) cpu_id;

	/* set up thread */
	daemonize("khipd/%d",cid);
	set_cpus_allowed(current, cpumask_of_cpu(cid));

	//set_user_nice(current, 0); //XXX: Set this as you please

	/* initialize */
	hip_init_workqueue();
	atomic_inc(&hip_working);
	/* work loop */

	while(1) {
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
	hip_uninit_workqueue();
	atomic_dec(&hip_working);

	return 0;
}



static int __init hip_init(void)
{
	int i,pid;

	HIP_INFO("Initializing HIP module\n");
	hip_get_load_time();

	if(!hip_init_r1())
		goto out;

	if (hip_init_output_socket() < 0)
		goto out;

	if (hip_init_cipher() < 0)
		goto out;

	hip_init_hadb();

#ifdef CONFIG_HIP_RVS
	hip_init_rvadb();
#endif

#ifdef CONFIG_PROC_FS
	if (hip_init_procfs() < 0)
		goto out;
#endif /* CONFIG_PROC_FS */

	if (hip_init_user() < 0)
		goto out;

	if (hip_init_ioctl() < 0)
		goto out;

	/* comment this to disable network device event handler
	   (crashed sometimes) */
	if (hip_init_netdev_notifier() < 0)
		goto out;

	if (hip_init_socket_handler() < 0)
		goto out;

	if (hip_setup_sp(XFRM_POLICY_OUT) < 0)
		goto out;

	if (hip_setup_sp(XFRM_POLICY_IN) < 0)
		goto out;

	for(i=0;i<NR_CPUS;i++) {
		pid = kernel_thread(hip_worker, (void *) i, CLONE_FS | CLONE_FILES | CLONE_SIGHAND | SIGCHLD);
		if (IS_ERR(ERR_PTR(pid)))
			goto out;
	}

	HIP_SETCALL(hip_handle_output);
	HIP_SETCALL(hip_handle_esp);
	HIP_SETCALL(hip_get_addr);
	HIP_SETCALL(hip_get_saddr);
	HIP_SETCALL(hip_unknown_spi);
	HIP_SETCALL(hip_handle_dst_unreachable);
	HIP_SETCALL(hip_trigger_bex);
	HIP_SETCALL(hip_handle_ipv6_dad_completed);
	HIP_SETCALL(hip_handle_inet6_addr_del);
	HIP_SETCALL(hip_update_spi_waitlist_ispending);
	HIP_SETCALL(hip_get_default_spi_out);

	if (inet6_add_protocol(&hip_protocol, IPPROTO_HIP) < 0) {
		HIP_ERROR("Could not add HIP protocol\n");
		goto out;
	}

	HIP_INFO("HIP module initialized successfully\n");
	return 0;


 out:
	hip_cleanup();
	HIP_ERROR("Failed to init module\n");
	return -EINVAL;
}

/*
 * We first invalidate the hooks, so that softirqs wouldn't enter them.
 */
static void __exit hip_cleanup(void)
{
	HIP_INFO("uninitializing HIP module\n");

	/* disable callback for HIP packets */
	inet6_del_protocol(&hip_protocol, IPPROTO_HIP);

	/* disable hooks to call our code */
	HIP_INVALIDATE(hip_update_spi_waitlist_ispending);
	HIP_INVALIDATE(hip_handle_ipv6_dad_completed);
	HIP_INVALIDATE(hip_handle_inet6_addr_del);
	HIP_INVALIDATE(hip_trigger_bex);
	HIP_INVALIDATE(hip_handle_dst_unreachable);
	HIP_INVALIDATE(hip_unknown_spi);
	HIP_INVALIDATE(hip_get_saddr);
	HIP_INVALIDATE(hip_get_addr);
	HIP_INVALIDATE(hip_handle_esp);
	HIP_INVALIDATE(hip_handle_output);
	HIP_INVALIDATE(hip_get_default_spi_out);

	/* kill threads */
	if (atomic_read(&hip_working) != 0) {
		hip_stop_khipd(); /* tell the hip kernel thread(s) to stop */

		while(atomic_read(&hip_working)) {
			if (net_ratelimit())
				HIP_DEBUG("%d HIP threads left\n", atomic_read(&hip_working));
			schedule(); /* wait until stopped */
		}
	}

	HIP_DEBUG("Thread(s) finished\n");

	hip_delete_sp(XFRM_POLICY_IN);
	hip_delete_sp(XFRM_POLICY_OUT);

	hip_uninit_netdev_notifier(); 	/* comment this if network device event causes troubles */
	hip_uninit_ioctl();
	hip_uninit_user();

#ifdef CONFIG_PROC_FS
	hip_uninit_procfs();
#endif /* CONFIG_PROC_FS */

	hip_uninit_socket_handler();
	hip_uninit_host_id_dbs();
#ifdef CONFIG_HIP_RVS
	hip_uninit_rvadb();
#endif
	hip_uninit_hadb();
	hip_uninit_all_eid_db();
	hip_uninit_output_socket();
	hip_uninit_r1();

	hip_rea_delete_sent_list();
	hip_ac_delete_sent_list();
	hip_update_spi_waitlist_delete_all();
	hip_hadb_dump_spi_list_all();
	HIP_INFO("HIP module uninitialized successfully\n");
	return;
}

MODULE_AUTHOR("HIPL <hipl-dev@freelists.org>");
MODULE_DESCRIPTION("HIP development module");
MODULE_LICENSE("GPL");
#ifdef KRISUS_THESIS
MODULE_PARM(kmm,"i");
MODULE_PARM_DESC(kmm, "Measuring mode: 1 = Global timing, 2 = {I,R}{1,2} timing, 3 = spinlock timing");
#endif
module_init(hip_init);
module_exit(hip_cleanup);
