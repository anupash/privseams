/*
 * HIP init/uninit and other miscellaneous functions
 *
 * Authors: Janne Lundberg <jlu@tcs.hut.fi>
 *          Miika Komu <miika@iki.fi>
 *          Mika Kousa <mkousa@cc.hut.fi>
 *          Kristian Slavov <kslavov@hiit.fi>
 *          Anthony D. Joseph <adj@hiit.fi>
 *
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
#include "workqueue.h"
#include "socket.h"
#include "update.h"
#ifdef CONFIG_HIP_RVS
#include "rvs.h"
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
#include <linux/suspend.h>
#include <linux/completion.h>
#include <linux/cpumask.h>
#ifdef CONFIG_SYSCTL
#include <linux/sysctl.h>
#endif

static atomic_t hip_working = ATOMIC_INIT(0);

time_t load_time;

static struct notifier_block hip_netdev_notifier;
static void hip_uninit_cipher(void); // forward decl.
static void hip_cleanup(void);

/* All cipher and digest implementations we support. */
static struct crypto_tfm *impl_3des_cbc = NULL;
static struct crypto_tfm *impl_aes_cbc = NULL;

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
struct hip_kthread_data {
	int cpu;
	pid_t pid;
	struct completion kthread_work;
	int killed;
};

struct hip_kthread_data hip_kthreads[NR_CPUS];

#ifdef CONFIG_PROC_FS
static struct proc_dir_entry *hip_proc_root = NULL;
#endif /* CONFIG_PROC_FS */


static void hip_err_handler(struct sk_buff *skb,
			    struct inet6_skb_parm *opt,
			    int type, int code, int offset,
			    __u32 info);

static struct inet6_protocol hip_protocol = {
	.handler     = hip_inbound,
	.err_handler = hip_err_handler,
	.flags       = INET6_PROTO_NOPOLICY,
};

#ifdef CONFIG_SYSCTL
/* /proc/sys/net/hip */
int sysctl_hip_test = 0;
static struct ctl_table_header *hip_sysctl_header = NULL;

static int zero = 0, max_k = 64;  /* sysctl table wants pointers to ranges */

struct hip_sys_config hip_sys_config;

static ctl_table hip_table[] = {
	{
		.ctl_name	= NET_HIP_COOKIE_MAX_K_R1,
		.procname	= "cookie_max_k_r1",
		.data		= &hip_sys_config.hip_cookie_max_k_r1,
		.maxlen		= sizeof (int),
		.mode		= 0600,
		.proc_handler	= &proc_dointvec_minmax,
		.strategy	= &sysctl_intvec,
		.extra1		= &zero,
		.extra2		= &max_k
	},
	{ .ctl_name = 0 }
};

static ctl_table hip_net_table[] = {
	{
		.ctl_name	= NET_HIP,
		.procname	= "hip",
		.mode		= 0555,
		.child		= hip_table
	},
        { .ctl_name = 0 }
};

static ctl_table hip_root_table[] = {
	{
		.ctl_name	= CTL_NET,
		.procname	= "net",
		.mode		= 0555,
		.child		= hip_net_table
	},
        { .ctl_name = 0 }
};

int hip_register_sysctl(void)
{
	HIP_DEBUG("\n");
	hip_sysctl_header = register_sysctl_table(hip_root_table, 0);
	return (hip_sysctl_header ? 1 : 0);
}

void hip_unregister_sysctl(void)
{
	HIP_DEBUG("\n");
	if (hip_sysctl_header)
		unregister_sysctl_table(hip_sysctl_header);
}

/**
 * hip_init_sys_config - Initialize HIP related sysctl variables to default values
 */
void hip_init_sys_config(void)
{
	hip_sys_config.hip_cookie_max_k_r1 = 20;
}
#endif

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
	else if (hip_dh_group_type > ARRAY_SIZE(dh_size))
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

	_HIP_HEXDUMP("HMAC key", key, keylen);
	_HIP_HEXDUMP("write hmac", in, in_len);

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
	struct hip_lhi lhi;
	
	memset(&lhi, 0, sizeof(struct hip_lhi));
	memcpy(&(lhi.hit), src_hit,sizeof(struct in6_addr));
	//ipv6_addr_copy(&lhi.hit, src_hit);

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

	host_id_private = hip_get_localhost_host_id(&lhi);
	//host_id_private = hip_get_any_localhost_host_id(HIP_HI_DEFAULT_ALGO);
 	if (!host_id_private) {
 		HIP_ERROR("Could not acquire localhost host id\n");
 		goto out_err;
 	}
	HIP_DEBUG("GOTID:%d",hip_get_param_total_len(host_id_private));

	host_id_pub = hip_get_localhost_public_key(&lhi);
	//host_id_pub = hip_get_any_localhost_public_key(HIP_HI_DEFAULT_ALGO);
	if (!host_id_pub) {
		HIP_ERROR("Could not acquire localhost public key\n");
		goto out_err;
	}
	
	/* check for the used algorithm */
	if (hip_get_host_id_algo(host_id_pub) == HIP_HI_RSA) {
			use_rsa = 1;
	} else if (hip_get_host_id_algo(host_id_pub) != HIP_HI_DSA) {
			HIP_ERROR("Unsupported algorithm:%d\n", 
					  hip_get_host_id_algo(host_id_pub));
			goto out_err;
	}

	signature = kmalloc(MAX(HIP_DSA_SIGNATURE_LEN,
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
 		kfree(host_id_pub);
 	if (dh_data)
 		kfree(dh_data);

	HIP_HEXDUMP("r1", msg, hip_get_msg_total_len(msg));

	return msg;

  out_err:
	if (signature) 
		kfree(signature);
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
	case HIP_ESP_AES_SHA1:
		ret = 16;
		break;
	case HIP_ESP_3DES_SHA1:
		ret = 24;
		break;
	case HIP_ESP_NULL_SHA1:
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


int hip_hmac_key_length(int tid)
{
	int ret = -1;
	switch(tid) {
       	case HIP_ESP_AES_SHA1:
	  //		ret = 16;
	  //		break;
	case HIP_ESP_3DES_SHA1:
	case HIP_ESP_NULL_SHA1:
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
	case HIP_HIP_AES_SHA1:
		ret = 16;
		break;
	case HIP_HIP_3DES_SHA1:
		ret = 24;
		break;
	case HIP_HIP_NULL_SHA1: // XX FIXME: SHOULD BE NULL_SHA1? 
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
	case HIP_ESP_AES_SHA1:
		//ret = 16;
		//break;
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

		case HIP_HIP_AES_SHA1:
		case HIP_HIP_3DES_SHA1:
		case HIP_HIP_NULL_SHA1:
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

	length = hip_get_param_contents_len(ht);
	suggestion = (uint16_t*) &ht->suite_id[0];

	if (length > sizeof(struct hip_esp_transform) -
	    sizeof(struct hip_common)) {
		HIP_ERROR("Too many transforms\n");
		goto out;
	}

	for (i=0; i<length; i++) {
		switch(ntohs(*suggestion)) {

		case HIP_ESP_AES_SHA1:
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
	_HIP_DEBUG("Took ESP transform %d\n", tid);

	if(tid == 0)
		HIP_ERROR("Faulty ESP transform\n");

	return tid;
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
int hip_crypto_encrypted(void *data, const void *iv, int enc_alg, int enc_len,
			 void* enc_key, int direction)
{
	int err = 0;
	int key_len;  /* in bytes */
	struct crypto_tfm *impl = NULL;
	struct scatterlist src_sg[HIP_MAX_SCATTERLISTS];
	unsigned int src_nsg = HIP_MAX_SCATTERLISTS;
	/* crypto_cipher_encrypt_iv writes a new iv on top of the old when
	   encrypting, so we need to preserve the the original. Also, we
	   encrypt only once in HIP, so we can discard the new iv. */
	char *iv_copy = NULL;

	/* I haven't tested if the function works with 3DES + NULL iv. The
	   NULL transform + NULL iv combination works, though. -miika */

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
	case HIP_HIP_AES_SHA1:
		impl = impl_aes_cbc;
		key_len = ESP_AES_KEY_BITS >> 3;
		iv_copy = kmalloc(16, GFP_KERNEL);
		if (!iv_copy) {
			err = -ENOMEM;
			goto out_err;
		}
		memcpy(iv_copy, iv, 16);
		break;
	case HIP_HIP_3DES_SHA1:
		impl = impl_3des_cbc;
		key_len = ESP_3DES_KEY_BITS >> 3;
		iv_copy = kmalloc(8, GFP_KERNEL);
		if (!iv_copy) {
			err = -ENOMEM;
			goto out_err;
		}
		memcpy(iv_copy, iv, 8);
		break;
	case HIP_HIP_NULL_SHA1:
		impl = impl_null;
		key_len = 0;
		iv_copy = NULL;
		break;
	default:
		HIP_ERROR("Attempted to use unknown CI (enc_alg=%d)\n",
			  enc_alg);
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
			HIP_ERROR("key is weak.\n");
			HIP_HEXDUMP("key", enc_key, key_len);
		}
		HIP_ERROR("Could not set encryption/decryption key\n");
		err = -EFAULT;
		goto out_err;
	}

	HIP_DEBUG("enc_len=%d\n", enc_len);
	switch(direction) {
	case HIP_DIRECTION_ENCRYPT:
		if (iv_copy) {
			err = crypto_cipher_encrypt_iv(impl, src_sg, src_sg,
						       enc_len, iv_copy);
			/* The encrypt function writes crap on iv */
			//memset(iv, 0, 8);
		} else {
			err = crypto_cipher_encrypt(impl, src_sg, src_sg,
						    enc_len);
		}
		if (err) {
			HIP_ERROR("Encryption failed\n");
			//err = -EFAULT;
			goto out_err;
		}

		break;
	case HIP_DIRECTION_DECRYPT:
		if (iv_copy) {
			err = crypto_cipher_decrypt_iv(impl, src_sg, src_sg,
						       enc_len, iv_copy);
		} else {
			err = crypto_cipher_decrypt(impl, src_sg, src_sg,
						    enc_len);
		}
		if (err) {
			HIP_ERROR("Decryption failed\n");
			//err = -EFAULT;
			goto out_err;
		}
		break;
	default:
		HIP_ERROR("Undefined direction (%d)\n", direction);
		err = -EINVAL;
		break;
	}

	memcpy(data, result, enc_len);

 out_err:
	if (iv_copy)
		kfree(iv_copy);
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
	if (!hip_is_hit(&(skb->nh.ipv6h->saddr)))
		return;

	/* draft: If the R1 is a response to an ESP packet with an unknown
	   SPI, the Initiator HIT SHOULD be zero. */
	HIP_DEBUG("Received Unknown SPI: 0x%x\n", ntohl(spi));
	HIP_DEBUG("TODO: rekey old SA ?\n");  /* and/or TODO: send NOTIFY ? */
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
	struct ipv6_pinfo *np;

	err = sock_create(AF_INET6, SOCK_RAW, IPPROTO_NONE, &hip_output_socket);
	if (err) {
		HIP_ERROR("Failed to allocate the HIP control socket (err=%d)\n", err);
		goto out;
	}

	/* prevent multicast packets sent out coming back to us */
	np = inet6_sk(hip_output_socket->sk);
	if (!np) {
		HIP_ERROR("Could not get inet6 sock of HIP control socket\n");
		err = -EFAULT;
		goto out;
	} else {
		np->mc_loop = 0;
	}
	/* TODO: same for IPv4 ? */
 out:
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
	_HIP_DEBUG("selected dst addr: %s\n", str);

	return 1;
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
		HIP_ERROR("Unknown destination HIT\n");
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
	_HIP_DEBUG("load_time=0x%lx\n", load_time);
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

/* Returns 1 if address can be added into REA parameter. Currently all
 * other than link locals are accepted. */
static inline int hip_rea_addr_ok(struct in6_addr *addr)
{
	if (ipv6_addr_type(addr) & IPV6_ADDR_LINKLOCAL)
		return 0;
	return 1;
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
		if (!hip_rea_addr_ok(&ifa->addr)) {
			HIP_DEBUG("address not accepted into REA\n");
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

		for (i = 0, ifa = idev->addr_list;
		     ifa && i < n_addrs; ifa = ifa->if_next, i++) {
			spin_lock_bh(&ifa->lock);
			if (hip_rea_addr_ok(&ifa->addr)) {
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
	in6_dev_put(idev);
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
 * @ifindex: the ifindex of the interface which caused the event
 *
 * This function gets notification when DAD procedure has finished
 * successfully for an address in the network device @ifindex.
 */
void hip_handle_ipv6_dad_completed(int ifindex) {
	struct hip_work_order *hwo;

	HIP_DEBUG("ifindex=%d\n", ifindex);
	if (!ifindex) {
		HIP_ERROR("no ifindex\n");
		return;
	}

	hwo = hip_net_event_prepare_hwo(HIP_WO_SUBTYPE_IN6_EVENT,
					ifindex, NETDEV_UP);
  	if (!hwo) {
		HIP_ERROR("Unable to handle address event\n");
  	} else
		hip_insert_work_order(hwo);
	return;
}

#define EVENTSRC_INET6 0
#define EVENTSRC_NETDEV 1

#define SEND_UPDATE_NES (1 << 0)
#define SEND_UPDATE_REA (1 << 1)
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
		//if (idev_addr_count > 0 && addr_list)
		hip_send_update_all(addr_list, idev_addr_count, ifindex, SEND_UPDATE_REA);
		//else
		//HIP_DEBUG("Netdev has no addresses to be informed, UPDATE not sent\n");
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
	return;
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

        if (event == NETDEV_UNREGISTER) {
		/* avoid sending rapidly consecutive UPDATEs */
                HIP_DEBUG("not handling UNREGISTER event, assuming already handled DOWN\n");
                return NOTIFY_DONE;
        }

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
 * hip_err_handler - ICMPv6 handler
 * @skb: received ICMPv6 packet
 * @opt: todo
 * @type: ICMP type
 * @code: ICMP code
 * @offset: offset from the start of the IPv6 header (?)
 * @info: information related to type and code
 *
 * ICMP errors caused by HIP packets are handled by this function.
 */
static void hip_err_handler(struct sk_buff *skb, struct inet6_skb_parm *opt, 
			    int type, int code, int offset, __u32 info)
{
	struct icmp6hdr *hdr;
	struct ipv6hdr *invoking_hdr; /* RFC 2463 sec 3.1 */
        struct in6_addr *saddr, *daddr;
	char str[INET6_ADDRSTRLEN];

	/* todo: option to allow/disallow icmpv6 handling */
	if (!pskb_may_pull(skb, 4+sizeof(struct ipv6hdr))) {
		/* already checked in icmpv6_rcv/icmpv6_notify ? */
		/* RFC 2463 sec 3.1 */
		HIP_DEBUG("Too short an ICMP packet (skb len=%d)\n", skb->len);
		return;
	}

	hdr = (struct icmp6hdr *) skb->h.raw;
	invoking_hdr = (struct ipv6hdr *) (hdr+1); /* check */

	saddr = &skb->nh.ipv6h->saddr;
        daddr = &skb->nh.ipv6h->daddr;
	hip_in6_ntop(saddr, str);
	HIP_DEBUG("icmp6: outer hdr src=%s\n", str);
	hip_in6_ntop(daddr, str);
	HIP_DEBUG("icmp6: outer hdr dst=%s\n", str);
	HIP_DEBUG("icmp6: type=%d code=%d offset=%d info=%u skb->len=%d\n",
		  type, code,  offset, info, skb->len);
	HIP_DEBUG("dev=%s input_dev=%s real_dev=%s\n",
		  skb->dev ? skb->dev->name : "null",
		  skb->input_dev ? skb->input_dev->name : "null",
		  skb->real_dev ? skb->real_dev->name : "null");
	hip_in6_ntop(&invoking_hdr->saddr, str);
	HIP_DEBUG("invoking ip6 hdr: src=%s\n", str);
	hip_in6_ntop(&invoking_hdr->daddr, str);
	HIP_DEBUG("invoking ip6 hdr: dst=%s\n", str);

	HIP_DEBUG("invoking pkt remaining len=%d\n", skb->len-offset);
	HIP_DEBUG("invoking pkt nexthdr=%d\n", invoking_hdr->nexthdr);

	if (invoking_hdr->nexthdr != IPPROTO_HIP) {
		HIP_ERROR("invoking pkt hext header is not a HIP packet, not handling\n");
		return;
	}

	switch (type) {
	case ICMPV6_DEST_UNREACH:
		HIP_DEBUG("got DEST_UNREACH\n");
		switch(code) {
		case ICMPV6_NOROUTE:
		case ICMPV6_ADM_PROHIBITED:
		case ICMPV6_ADDR_UNREACH:
			HIP_DEBUG("TODO: handle ICMP DU code %d\n", code);
			/* todo: deactivate invoking_hdr->daddr from every sdb
			 * entry peer addr list */
			break;
		default:
			HIP_DEBUG("ICMP DU code %d not handled\n", code);
			break;
		}
		break;
	case ICMPV6_PARAMPROB:
		HIP_DEBUG("got PARAMPROB code=%d\n", code);
		break;
	case ICMPV6_TIME_EXCEED:
		HIP_DEBUG("got TIME_EXCEED code=%d\n", code);
		break;
	default:
		HIP_DEBUG("unhandled type %d code=%d\n", type, code);
	}

	return;
}

/* Handler which is notified when SA state has changed.
   TODO: send UPDATE when SA lifetime has expired or is about to expire. */
static int hip_xfrm_handler_notify(struct xfrm_state *x, int hard)
{
	HIP_DEBUG("SPI=0x%x hard expiration=%d state=%d\n",
		  ntohl(x->id.spi), hard, x->km.state);
	HIP_DEBUG("TODO..send UPDATE ?\n");
#if 0
	if (SA is HIP SA) {
		hip_ha_t *entry;

		/* todo: zero the spi from hadb */
		/* was this event caused by inbound SA ?*/
		entry = hip_hadb_find_byspi(ntohl(x->id.spi));
		if (entry) {
			hip_send_update(entry, NULL, 0, 0, 0); /* non-mm UPDATE */
			hip_ha_put(entry);
		} else {
			/* check if SA was outbound .. */
		}
	}
#endif

	return 0;
}

/* This function is called when XFRM key manager does not know SA for
 * given destination address. If the destination address is a HIT we
 * must trigger base exchange to that HIT.
 *
 * Also it seems that we get here if the IPsec SA has expired and we
 * are trying to send HIP traffic to that SA.
 */
static int hip_xfrm_handler_acquire(struct xfrm_state *xs,
				    struct xfrm_tmpl *xtmpl,
				    struct xfrm_policy *pol, int dir)
{
	int err = -EINVAL;
	char str[INET6_ADDRSTRLEN];
	struct ipv6hdr hdr = {0};

	hip_in6_ntop((struct in6_addr *) &(xs->id.daddr), str);
	HIP_DEBUG("daddr=%s dir=%d\n", str, dir);

	if (! (pol->selector.daddr.a6[0] == htonl(0x40000000) &&
	       pol->selector.prefixlen_d == 2)) {
		hip_in6_ntop((struct in6_addr *) &(pol->selector.daddr), str);
		HIP_ERROR("Policy (pol daddr=%s) is not for HIP, returning\n",
			  str);
		goto out;
	}

	if (!hip_is_hit((struct in6_addr *) &(xs->id.daddr))) {
		HIP_ERROR("%s not a HIT\n", str);
		goto out;
	}

	ipv6_addr_copy(&hdr.daddr, (struct in6_addr *) &(xs->id.daddr));
	err = hip_handle_output(&hdr, NULL);
	if (err)
		HIP_ERROR("TODO: handle err=%d\n", err);
	err = 0; /* tell XFRM that we handle this SA acquiring even
		  * if the previous failed */
	
out:
	HIP_DEBUG("returning, err=%d\n", err);
	return err;
}

/* Called when policy is expired */
static int hip_xfrm_handler_policy_notify(struct xfrm_policy *xp,
					  int dir, int hard)
{
	HIP_DEBUG("xp=0x%p dir=%d hard expiration=%d\n", xp, dir, hard);
	HIP_DEBUG("TODO..\n");
	return 0;
}

/* Callbacks for HIP related IPsec SA management functions */
static struct xfrm_mgr hip_xfrm_km_mgr = {
	.id		= "HIP",
	.notify		= hip_xfrm_handler_notify,
	.acquire	= hip_xfrm_handler_acquire,
	.notify_policy	= hip_xfrm_handler_policy_notify
	/* .compile_policy = hip_xfrm_handler_compile_policy, not needed ? */
};

/* Register handler for XFRM key management calls */
int hip_register_xfrm_km_handler(void)
{
	int err;

	HIP_DEBUG("registering XFRM key management handler\n");
	err = xfrm_register_km(&hip_xfrm_km_mgr);
	if (err)
		HIP_DEBUG("Registration of XFRM km handler failed, err=%d\n", err);
	return err;
}

/**
 * hip_init_cipher - initialize needed cipher algorithms
 * There is no need to delay initialization and locking of these
 * algorithms since we require their use. Some optional algorithms
 * may be initialized later.
 * Currently we use AES, 3DES-CBC, NULL-ECB?, SHA1(+HMAC), DSA, DH
 * Returns: 1 if all algorithms were initialized, otherwise < 0.
 */
static int hip_init_cipher(void)
{
	int err = 0;
	u32 supported_groups;

	/* instruct the "IPsec" to check for available algorithms */
	xfrm_probe_algs();

	/* Get implementations for all the ciphers we support */
	impl_aes_cbc = crypto_alloc_tfm("aes", CRYPTO_TFM_MODE_CBC);
	if (!impl_aes_cbc) {
		HIP_ERROR("Unable to register AES cipher\n");
		err = -1;
		goto out_err;
	}

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

	HIP_DEBUG("Initializing SHA1\n");
	schedule();
	
	impl_sha1 = crypto_alloc_tfm("sha1", 0);
	if (!impl_sha1) {
		HIP_ERROR("Unable to register SHA1 digest\n");
		err = -1;
		goto out_err;
	}

	HIP_DEBUG("SHA1 initialized\n");
	schedule();

	supported_groups = (1 << HIP_DH_OAKLEY_1 | 
			    1 << HIP_DH_OAKLEY_5 |
			    1 << HIP_DH_384);

	/* Does not return errors. Should it?
	   the code will try to regenerate the key if it is
	   missing...
	*/
	HIP_DEBUG("Generating DH keys\n");
	schedule();
	
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
	if (impl_aes_cbc)
		crypto_free_tfm(impl_aes_cbc);

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
	if (!create_proc_read_entry("lhi", 0, hip_proc_root,
				    hip_proc_read_lhi, NULL))
		goto out_err_root;
	if (!create_proc_read_entry("sdb_state", 0, hip_proc_root,
			       hip_proc_read_hadb_state, NULL))
		goto out_err_lhi;
	if (!create_proc_read_entry("sdb_peer_addrs", 0, hip_proc_root,
			       hip_proc_read_hadb_peer_addrs, NULL))
		goto out_err_sdb_state;
#if 0
	/* a simple way to trigger sending of UPDATE packet to all peers */
	if (!create_proc_read_entry("send_update", 0, hip_proc_root,
			       hip_proc_send_update, NULL))
		goto out_err_peer_addrs;
	/* for testing dummy NOTIFY packets */
	if (!create_proc_read_entry("send_notify", 0, hip_proc_root,
			       hip_proc_send_notify, NULL))
		goto out_err_send_update;
#endif

	HIP_DEBUG("profcs init successful\n");
	return 1;

#if 0
 out_err_send_update:
	remove_proc_entry("send_update", hip_proc_root);
 out_err_peer_addrs:
	remove_proc_entry("sdb_peer_addrs", hip_proc_root);
#endif
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
#if 0
	remove_proc_entry("send_update", hip_proc_root);
	remove_proc_entry("send_notify", hip_proc_root);
#endif
	remove_proc_entry("hip", proc_net);
}
#endif /* CONFIG_PROC_FS */

/* Init/uninit network interface event notifier. When a network event
   causes an event (e.g. it goes up or down, or is unregistered from
   the system), hip_netdev_event_handler is called. */
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
		HIP_DEBUG("Did not get anything from the work queue\n");
		res = KHIPD_ERROR;
		goto out_err;
	}

	HIP_DEBUG("New job: type=%d subtype=%d\n", job->type, job->subtype);

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
		case HIP_WO_SUBTYPE_RECV_BOS:
			KRISU_START_TIMER(KMM_PARTIAL);
			res = hip_receive_bos(job->arg1);
			KRISU_STOP_TIMER(KMM_PARTIAL,"BOS");
			break;
		default:
			HIP_ERROR("Unknown subtype: %d (type=%d)\n",
				  job->subtype, job->type);
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
			{
				struct ipv6hdr hdr = {0};
				ipv6_addr_copy(&hdr.daddr, job->arg1);
				hip_handle_output(&hdr, NULL);
			}
			res = 0;
			break;
#endif
		case HIP_WO_SUBTYPE_FLUSHMAPS:
		case HIP_WO_SUBTYPE_ADDHI:
		case HIP_WO_SUBTYPE_DELHI:
		case HIP_WO_SUBTYPE_FLUSHHIS:
		case HIP_WO_SUBTYPE_NEWDH:
			HIP_INFO("Not implemented subtype: %d (type=%d)\n",
				 job->subtype, job->type);
			res = KHIPD_ERROR;
			goto out_err;
		default:
			HIP_ERROR("Unknown subtype: %d on type: %d\n",job->subtype,job->type);
			res = KHIPD_ERROR;
			goto out_err;
		}
	}

 out_err:
	if (job)
		hip_free_work_order(job);
	return res;
}

/* HIP kernel thread, arg t is per-cpu thread data */
static int hip_worker(void *t)
{
	int result = 0;
	struct hip_kthread_data *thr = (struct hip_kthread_data *) t;
	int cpu = thr->cpu;
	pid_t pid;

	/* set up thread */
	thr->pid = pid = current->pid;
	hip_init_workqueue();
	atomic_inc(&hip_working);
	daemonize("khipd/%d", cpu);
	allow_signal(SIGKILL);
	flush_signals(current);
	set_cpus_allowed(current, cpumask_of_cpu(cpu));/* TODO: check return value */
	//set_user_nice(current, 0); //XXX: Set this as you please

	HIP_DEBUG("HIP kernel thread %s pid=%d started\n", current->comm, pid);

	/* work loop */
	while(1) {
		if (signal_pending(current)) {
			HIP_INFO("HIP thread pid %d got SIGKILL, cleaning up\n", pid);
			/* zero thread pid so we do not kill other
			 * process having the same pid later by accident */
			thr->pid = 0;
			thr->killed = 1;
			_HIP_DEBUG("signalled, flushing signals\n");
			flush_signals(current);
			break;
		}

		/* swsuspend,  see eg. drivers/net/irda/sir_kthread.c */
		if (current->flags & PF_FREEZE) {
			HIP_DEBUG("handle swsuspend\n");
			refrigerator(PF_FREEZE);
		}

		result = hip_do_work();
		if (result < 0) {
			if (result == KHIPD_ERROR)
				HIP_INFO("Recoverable error occured (%d)\n", result);
			else {
				/* maybe we should just recover and continue ? */
				HIP_INFO("Unrecoverable error occured (%d). Cleaning up\n",
					 result);
				break;
			}
		}
		HIP_DEBUG("Work done (pid=%d, cpu=%d)\n", pid, cpu);
	}

	/* cleanup and finish thread */
	hip_uninit_workqueue();
	atomic_dec(&hip_working);
	HIP_DEBUG("HIP kernel thread %d exiting on cpu %d\n", pid, cpu);

	/* plain complete and return seemed to cause random oopses */
	complete_and_exit(&thr->kthread_work, 0);
}


static int __init hip_init(void)
{
	int cpu, pid;

	HIP_INFO("Initializing HIP module\n");
	hip_get_load_time();
	hip_init_sys_config();

	memset(&hip_kthreads, 0, sizeof(hip_kthreads));

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

	if (hip_setup_sp(XFRM_POLICY_OUT) < 0)
		goto out;

	if (hip_setup_sp(XFRM_POLICY_IN) < 0)
		goto out;

	for(cpu = 0; cpu < num_possible_cpus(); cpu++) {
		hip_kthreads[cpu].cpu = cpu;
		init_completion(&hip_kthreads[cpu].kthread_work);
		hip_kthreads[cpu].killed = 0;
		pid = kernel_thread(hip_worker, &hip_kthreads[cpu],
				    CLONE_KERNEL | SIGCHLD);
		if (IS_ERR(ERR_PTR(pid))) {
			hip_kthreads[cpu].pid = 0;
			HIP_ERROR("Failed to set up a kernel thread for HIP "
				  "(cpu=%d, ret=%d)\n", cpu, pid);
			goto out;
		}
	}

	HIP_SETCALL(hip_handle_output);
	HIP_SETCALL(hip_handle_esp);
	HIP_SETCALL(hip_get_addr);
	HIP_SETCALL(hip_get_saddr);
	HIP_SETCALL(hip_unknown_spi);
	HIP_SETCALL(hip_handle_ipv6_dad_completed);
	HIP_SETCALL(hip_handle_inet6_addr_del);
	/* HIP_SETCALL(hip_update_spi_waitlist_ispending); */
	HIP_SETCALL(hip_get_default_spi_out);
	HIP_SETCALL(hip_hit_is_our);

	if (inet6_add_protocol(&hip_protocol, IPPROTO_HIP) < 0) {
		HIP_ERROR("Could not add HIP protocol\n");
		goto out;
	}

	if (hip_init_socket_handler() < 0)
		goto out;


	if (hip_init_netdev_notifier() < 0)
		goto out;

	if (hip_register_xfrm_km_handler()) {
		HIP_ERROR("Could not register XFRM key manager for HIP\n");
		goto out;
	}
#ifdef CONFIG_SYSCTL
	if (!hip_register_sysctl()) {
		HIP_ERROR("Could not register sysctl for HIP\n");
		goto out;
	}
#endif
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
	int i, pid, cpu;

	HIP_INFO("Uninitializing HIP module\n");

#ifdef CONFIG_SYSCTL
	hip_unregister_sysctl();
#endif
	/* unregister XFRM km handler */
	xfrm_unregister_km(&hip_xfrm_km_mgr);

	/* disable callbacks for HIP packets and notifier chains */
	inet6_del_protocol(&hip_protocol, IPPROTO_HIP);
	hip_uninit_netdev_notifier();

	/* disable hooks to call our code */
	//HIP_INVALIDATE(hip_update_spi_waitlist_ispending);
	HIP_INVALIDATE(hip_handle_ipv6_dad_completed);
	HIP_INVALIDATE(hip_handle_inet6_addr_del);
	HIP_INVALIDATE(hip_unknown_spi);
	HIP_INVALIDATE(hip_get_saddr);
	HIP_INVALIDATE(hip_get_addr);
	HIP_INVALIDATE(hip_handle_esp);
	HIP_INVALIDATE(hip_handle_output);
	HIP_INVALIDATE(hip_get_default_spi_out);

	/* kill kernel threads and wait for them to complete */
	for(i = 0; i < num_possible_cpus(); i++) {
		pid = hip_kthreads[i].pid;
		cpu = hip_kthreads[i].cpu;
		if (pid > 0) {
			HIP_INFO("Stopping HIP kernel thread pid=%d on cpu=%d\n", pid, cpu);
			kill_proc(pid, SIGKILL, 1);
			schedule();
			wait_for_completion(&hip_kthreads[i].kthread_work);
		} else if (pid == 0) {
			_HIP_DEBUG("Already killed HIP kernel thread on cpu=%d ?\n", cpu);
			if (hip_kthreads[i].killed) {
				HIP_DEBUG("Waiting killed thread to complete on cpu=%d\n", cpu);
				wait_for_completion(&hip_kthreads[i].kthread_work);
			}
		} else
			HIP_DEBUG("Invalid HIP kernel thread pid=%d on cpu=%d\n", pid, cpu);
	}
	HIP_DEBUG("All HIP threads finished\n");

	hip_delete_sp(XFRM_POLICY_IN);
	hip_delete_sp(XFRM_POLICY_OUT);

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

	/* update_spi_waitlist_delete_all(); */
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
