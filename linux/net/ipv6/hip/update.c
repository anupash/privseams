#include <net/hip.h>
#include <net/xfrm.h>

#include "update.h"
#include "hip.h"
#include "security.h"
#include "input.h"
#include "hadb.h"
#include "db.h"
#include "keymat.h"
#include "builder.h"
#include "misc.h"
#include "output.h"


atomic_t hip_update_id = ATOMIC_INIT(0);
spinlock_t hip_update_id_lock = SPIN_LOCK_UNLOCKED;

/* List of SPIs which are waiting for data to come through */
/* See draft's section "Processing an initial UPDATE packet" */
LIST_HEAD(hip_update_spi_waitlist);
spinlock_t hip_update_spi_waitlist_lock = SPIN_LOCK_UNLOCKED;

struct hip_update_spi_waitlist_item {
	struct list_head list;
	uint32_t spi;
	struct in6_addr hit;
};


/**
 * hip_update_spi_waitlist_add - add a SPI to SPI waitlist
 * @spi: the inbound SPI to be added in host byte order
 * @hit: the HIT for which the @spi is related to
 */
void hip_update_spi_waitlist_add(uint32_t spi, struct in6_addr *hit)
{
	struct hip_update_spi_waitlist_item *s;
	unsigned long flags = 0;
	struct list_head *pos, *n;
	int i = 1;

	HIP_DEBUG("spi=0x%x\n", spi);

	s = kmalloc(sizeof(struct hip_update_spi_waitlist_item), GFP_ATOMIC);
	if (!s) {
		HIP_ERROR("kmalloc failed\n");
		return;
	}

	s->spi = spi;
	ipv6_addr_copy(&s->hit, hit);

	spin_lock_irqsave(&hip_update_spi_waitlist_lock, flags);
	list_add(&s->list, &hip_update_spi_waitlist);
	HIP_DEBUG("Current SPI waitlist:\n");
	list_for_each_safe(pos, n, &hip_update_spi_waitlist) {
		s = list_entry(pos, struct hip_update_spi_waitlist_item, list);
		HIP_DEBUG("SPI waitlist %d: SPI=0x%x\n", i, s->spi);
		i++;
	}
	spin_unlock_irqrestore(&hip_update_spi_waitlist_lock, flags);
	return;
}

/**
 * hip_update_spi_waitlist_delete - delete a SPI from SPI waitlist
 * @spi: SPI in host byte order
 */
void hip_update_spi_waitlist_delete(uint32_t spi)
{
	struct list_head *pos, *n;
	struct hip_update_spi_waitlist_item *s = NULL;
	int i = 1;

	HIP_DEBUG("deleting spi=0x%x\n", spi);
	/* hip_update_spi_waitlist_ispending holds the
	 * hip_update_spi_waitlist_lock */
	list_for_each_safe(pos, n, &hip_update_spi_waitlist) {
		s = list_entry(pos, struct hip_update_spi_waitlist_item, list);
		if (s->spi == spi) {
			HIP_DEBUG("found, delete item %d\n", i);
			list_del(&s->list);
			kfree(s);
			break;
		}
		i++;
	}
	return;
}

/**
 * hip_update_spi_waitlist_delete_all - delete all SPIs from the SPI waitlist
 */
void hip_update_spi_waitlist_delete_all(void)
{
	struct list_head *pos, *n;
	struct hip_update_spi_waitlist_item *s = NULL;
	unsigned long flags = 0;

	HIP_DEBUG("\n");
	spin_lock_irqsave(&hip_update_spi_waitlist_lock, flags);
	list_for_each_safe(pos, n, &hip_update_spi_waitlist) {
		s = list_entry(pos, struct hip_update_spi_waitlist_item, list);
		list_del(&s->list);
		kfree(s);
	}
	spin_unlock_irqrestore(&hip_update_spi_waitlist_lock, flags);
	return;
}

/**
 * hip_update_spi_waitlist_ispending - test if SPI is on the SPI waitlist
 * @spi: SPI in host byte order
 *
 * Called from xfrm6_rcv.
 *
 * When data is received on the new incoming SA the new outgoing SA is
 * activated and old SA is deleted.
 *
 * Returns 1 if @spi is in the SPI waitlist, otherwise 0.
 */
int hip_update_spi_waitlist_ispending(uint32_t spi)
{
	int err = 0, found = 0;
	struct hip_update_spi_waitlist_item *s = NULL;
	unsigned long flags = 0;
	struct list_head *pos, *n;
	int i = 1;

	/* todo: change list_for_each to atomic_t ispending, return is_pending */

	spin_lock_irqsave(&hip_update_spi_waitlist_lock, flags);

	list_for_each_safe(pos, n, &hip_update_spi_waitlist) {
		s = list_entry(pos, struct hip_update_spi_waitlist_item, list);
		HIP_DEBUG("SPI waitlist %d: SPI=0x%x\n", i, s->spi);
		if (s->spi == spi) {
			found = 1;
			break;
		}
		i++;
	}

	/* If the SPI was in pending list, switch the NEW_SPI to be
	 * the current active SPI. Delete also the old SA and remove
	 * the SPI from the pending list.*/
	if (found) {
		uint32_t old_spi_out;
		hip_ha_t *entry;
		HIP_DEBUG("spi=0x%x : pending=yes\n", spi);

		entry = hip_hadb_find_byhit(&s->hit);
		if (!entry) {
			HIP_ERROR("Entry not found\n");
			goto out;
		}
		HIP_LOCK_HA(entry);

		HIP_DEBUG("Switching from SPI_OUT=0x%x to NEW_SPI_OUT=0x%x\n",
			  entry->spi_out, entry->new_spi_out);
		old_spi_out = entry->spi_out;
		hip_hadb_remove_state_spi(entry);
		entry->spi_out = entry->new_spi_out;

		entry->default_spi_out = entry->spi_out;
		HIP_DEBUG("set default SPI out=0x%x\n", entry->default_spi_out);

		{
			struct in6_addr a;
			ipv6_addr_set(&a, htonl(0x3ffe), 0 , 0, 2);
hip_hadb_add_addr_to_spi(entry, entry->spi_out, &a, 0, PEER_ADDR_STATE_ACTIVE, 0, 0);
		}

		hip_hadb_insert_state(entry);
		hip_print_hit("finalizing", &s->hit);
		hip_finalize_sa(&s->hit, entry->new_spi_out);
#if 0
		HIP_DEBUG("Removing old inbound IPsec SA, SPI=0x%x\n", old_spi_out);
		err = hip_delete_sa(old_spi_out, &s->hit);
		if (err)
			HIP_DEBUG("delete_sa ret err=%d\n", err);
		entry->new_spi_out = 0;
#endif

		HIP_UNLOCK_HA(entry);
		hip_put_ha(entry);
		hip_update_spi_waitlist_delete(spi);
	}

 out:
	spin_unlock_irqrestore(&hip_update_spi_waitlist_lock, flags);
	return found;
}


/**
 * hip_get_new_update_id - Get a new UPDATE ID number
 *
 * Returns: the next UPDATE ID value to use in host byte order
 */
static uint16_t hip_get_new_update_id(void) {
	uint16_t id = hip_get_next_atomic_val_16(&hip_update_id, &hip_update_id_lock);
	_HIP_DEBUG("got UPDATE ID %u\n", id);
	return id;
}

/* Get keys needed by UPDATE */
int hip_update_get_sa_keys(hip_ha_t *entry, uint16_t *keymat_offset_new,
			   uint8_t *calc_index_new, uint8_t *Kn_out,
			   struct hip_crypto_key *espkey_gl, struct hip_crypto_key *authkey_gl,
			   struct hip_crypto_key *espkey_lg, struct hip_crypto_key *authkey_lg)
{
	int err = 0;
       	unsigned char Kn[HIP_AH_SHA_LEN];
	uint16_t k = *keymat_offset_new;
	int esp_transform;
	int esp_transf_length = 0;
	int auth_transf_length = 0;
	uint8_t c = *calc_index_new;

	HIP_DEBUG("k=%u c=%u\n", k, c);

	esp_transform = entry->esp_transform;
	esp_transf_length = hip_enc_key_length(esp_transform);
	auth_transf_length = hip_auth_key_length_esp(esp_transform);
	HIP_DEBUG("enckeylen=%d authkeylen=%d\n", esp_transf_length, auth_transf_length);

	memcpy(Kn, Kn_out, HIP_AH_SHA_LEN);

	/* SA-gl */
	err = hip_keymat_get_new(espkey_gl->key, esp_transf_length, entry->dh_shared_key,
				 entry->dh_shared_key_len, &k, &c, Kn);
	HIP_DEBUG("enckey_gl hip_keymat_get_new ret err=%d k=%u c=%u\n", err, k, c);
	if (err)
		goto out_err;
	HIP_HEXDUMP("ENC KEY gl", espkey_gl->key, esp_transf_length);
	k += esp_transf_length;
	err = hip_keymat_get_new(authkey_gl->key, auth_transf_length, entry->dh_shared_key,
				 entry->dh_shared_key_len, &k, &c, Kn);
	HIP_DEBUG("authkey_gl hip_keymat_get_new ret err=%d k=%u c=%u\n", err, k, c);
	if (err)
		goto out_err;
	HIP_HEXDUMP("AUTH KEY gl", authkey_gl->key, auth_transf_length);
	k += auth_transf_length;

	/* SA-lg */
	err = hip_keymat_get_new(espkey_lg->key, esp_transf_length, entry->dh_shared_key,
				 entry->dh_shared_key_len, &k, &c, Kn);
	HIP_DEBUG("enckey_lg hip_keymat_get_new ret err=%d k=%u c=%u\n", err, k, c);
	if (err)
		goto out_err;
	HIP_HEXDUMP("ENC KEY lg", espkey_lg->key, esp_transf_length);
	k += esp_transf_length;
	err = hip_keymat_get_new(authkey_lg->key, auth_transf_length, entry->dh_shared_key,
				 entry->dh_shared_key_len, &k, &c, Kn);
	HIP_DEBUG("authkey_lg hip_keymat_get_new ret err=%d k=%u c=%u\n", err, k, c);
	if (err)
		goto out_err;
	HIP_HEXDUMP("AUTH KEY lg", authkey_lg->key, auth_transf_length);
	k += auth_transf_length;

	HIP_DEBUG("at end: k=%u c=%u\n", k, c);
	*keymat_offset_new = k;
	*calc_index_new = c;
	memcpy(Kn_out, Kn, HIP_AH_SHA_LEN);
 out_err:
	return err;
}

/**
 * hip_handle_update_initial - handle incoming initial UPDATE packet
 * @msg: the HIP packet
 * @state: the state in which we are with the peer
 *
 * This function handles cases 8 and 10 in draft-09 section "8.10
 * Processing UPDATE packets".
 *
 * Returns: 0 if successful, otherwise < 0.
 */
int hip_handle_update_initial(struct hip_common *msg, struct in6_addr *src_ip, int state /*, int is_reply*/)
{
	int err = 0;
	struct in6_addr *hits = &msg->hits, *hitr = &msg->hitr;
	struct hip_nes *nes;
	int esp_transform = -1;
	struct hip_crypto_key espkey_gl, authkey_gl;
	struct hip_crypto_key espkey_lg, authkey_lg;
	uint32_t prev_spi_in = 0;
	uint32_t new_spi_in = 0;  /* inbound IPsec SA SPI */
	uint32_t new_spi_out = 0; /* outbound IPsec SA SPI */
	struct hip_common *update_packet = NULL;
	uint16_t our_current_keymat_index; /* current or prev ? */
	struct in6_addr daddr;
	struct hip_dh_fixed *dh;
	struct hip_host_id *host_id_private;
 	u8 signature[HIP_DSA_SIGNATURE_LEN];
	int need_to_generate_key = 0, dh_key_generated = 0, new_keymat_generated;
	int we_are_HITg = 0;
	hip_ha_t *entry = NULL;

	HIP_DEBUG("state=%s\n", hip_state_str(state));
	nes = hip_get_param(msg, HIP_PARAM_NES);

	/* draft-09 8.10.1 Processing an initial UPDATE packet */

	/* 1. If the system is in state ESTABLISHED, it consults its
	 * policy to see if it needs to generate a new Diffie-Hellman
	 * key, and generates a new key if needed. If the system is in
	 * state REKEYING, it may already have generated a new
	 * Diffie-Hellman key, and SHOULD use it. */
	if (state == HIP_STATE_ESTABLISHED) {
		_HIP_DEBUG("8.10.1 case 1 TODO: need to rekey here ?\n");
		if (need_to_generate_key) {
			_HIP_DEBUG("would generate new D-H keys\n");
			/* generate_dh_key(); */
			dh_key_generated = 1;
		} else {
			dh_key_generated = 0;
		}
	}

#if 0
	if (state == HIP_STATE_REKEYING) {
			dh_key_generated = 1; ?
	}
#endif
	_HIP_DEBUG("dh_key_generated=%d\n", dh_key_generated);

	/* 2. If either the received UPDATE contains a new
	 * Diffie-Hellman key, the system has a new Diffie-Hellman key
	 * from the previous step, or both, the system generates new
	 * KEYMAT. If there is only one new Diffie-Hellman key, the
	 * other old key is used. */
	dh = hip_get_param(msg, HIP_PARAM_DIFFIE_HELLMAN);
	if (dh || dh_key_generated) {
		_HIP_DEBUG("would generate new keymat\n");
		/* generate_new_keymat(); */
		new_keymat_generated = 1;
	} else {
		new_keymat_generated = 0;
	}

	_HIP_DEBUG("new_keymat_generated=%d\n", new_keymat_generated);

	entry = hip_hadb_find_byhit(hits);
	if (!entry) {
		HIP_ERROR("Entry not found\n");
		goto out_err;
	}

	HIP_LOCK_HA(entry);
	our_current_keymat_index = entry->current_keymat_index;

	/* 3. If the system generated new KEYMAT in the previous step,
	 * it sets Keymat Index to zero, independent on whether the
	 * received UPDATE included a Diffie-Hellman key or not. */
	if (new_keymat_generated) {
		our_current_keymat_index = 0;
	}

	HIP_DEBUG("our_current_keymat_index=%d\n", our_current_keymat_index);

	/* 4. The system draws keys for new incoming and outgoing ESP
	 * SAs, starting from the Keymat Index, and prepares new
	 * incoming and outgoing ESP SAs.  The SPI for the outgoing SA
	 * is the new SPI value from the received UPDATE. The SPI for
	 * the incoming SA is locally generated, and SHOULD be random.
	 * The system MUST NOT start using the new outgoing SA before
	 * it receives traffic on the new incoming SA. */
	{
		uint8_t calc_index_new;
		uint16_t keymat_offset_new;
		unsigned char Kn[HIP_AH_SHA_LEN];

		we_are_HITg = hip_hit_is_bigger(hitr, hits);
		HIP_DEBUG("we are: HIT%c\n", we_are_HITg ? 'g' : 'l');

		esp_transform = entry->esp_transform; /* needed below */
		calc_index_new = entry->keymat_calc_index;
		keymat_offset_new = 0x7fff & ntohs(nes->keymat_index);

		/* check */
		if (our_current_keymat_index != 0 &&
		    keymat_offset_new > our_current_keymat_index)
			our_current_keymat_index = keymat_offset_new;

		/* todo: if testing keymat_offset_new += random */
		memcpy(Kn, entry->current_keymat_K, HIP_AH_SHA_LEN);

		err = hip_update_get_sa_keys(entry, &keymat_offset_new, &calc_index_new, Kn,
					     &espkey_gl, &authkey_gl, &espkey_lg, &authkey_lg);
		HIP_DEBUG("get_sa_keys ret err=%d\n", err);

		/* todo: update entry keymat later */
		hip_update_entry_keymat(entry, keymat_offset_new, calc_index_new, Kn);
		if (err)
			goto out_err;
	}

	/* set up new outgoing IPsec SA */

	/* draft: The system MUST NOT start using the new outgoing SA
	   before it receives traffic on the new incoming SA. */
	HIP_DEBUG("Trying to set up new outgoing SA\n");
	new_spi_out = ntohl(nes->new_spi);
	err = hip_setup_sa(hitr, hits,
			   &new_spi_out, esp_transform,
			   we_are_HITg ? &espkey_gl.key : &espkey_lg.key,
			   we_are_HITg ? &authkey_gl.key : &authkey_lg.key,
			   0);
	if (err) {
		HIP_ERROR("Error while setting up new SPI for SA-%s (err=%d)\n",
			  we_are_HITg ? "gl" : "lg", err);
		goto out_err;
	}
	HIP_DEBUG("Set up new outgoing SA, new_spi_out=0x%x\n", new_spi_out);

	/* store new_spi_out in hadb */
	entry->new_spi_out = new_spi_out;
	HIP_DEBUG("Stored SPI 0x%x to new_spi_out for future use\n", new_spi_out);

	_HIP_DEBUG("after new_spi_out: out=0x%08x in=0x%08x new_in=0x%08x new_out=0x%08x\n",
		  entry->spi_in, entry->spi_out, entry->new_spi_in, entry->new_spi_out);

	/* Set up new incoming IPsec SA */

	/* Old SPI value to put in NES tlv */
	prev_spi_in = entry->spi_in;

	new_spi_in = 0;
	err = hip_setup_sa(hits, hitr,
			   &new_spi_in, esp_transform,
			   we_are_HITg ? &espkey_lg.key : &espkey_gl.key,
			   we_are_HITg ? &authkey_lg.key : &authkey_gl.key,
			   1);
	if (err) {
		HIP_ERROR("Setting up new incoming IPsec SA failed (%d)\n", err);
		goto out_err;
	}
	HIP_DEBUG("Set up new incoming SA, new_spi_in=0x%x\n", new_spi_in);

	hip_hadb_remove_state_spi(entry);
	entry->spi_in = new_spi_in;
	hip_hadb_insert_state(entry);

	HIP_DEBUG("Stored SPI 0x%x to spi_in\n", new_spi_in);
	hip_finalize_sa(hitr, new_spi_in); /* move below */


	hip_update_spi_waitlist_add(new_spi_in, hits);

#if 0
	/* delete old incoming SA */
	/* todo: set to dying/drop old IPsec SA ? */
	HIP_DEBUG("Removing old inbound IPsec SA, SPI=0x%x\n", prev_spi_in);
	err = hip_delete_sa(prev_spi_in, hitr);
	HIP_DEBUG("delete_sa retval=%d\n", err ); /* ignore error ? */
	err = 0;
#endif

	_HIP_DEBUG("after new_spi_out: out=0x%08x in=0x%08x new_in=0x%08x new_out=0x%08x\n",
		  entry->spi_in, entry->spi_out, entry->new_spi_in, entry->new_spi_out);

	/* 5. The system prepares a reply UPDATE packet, with the R-bit one in
	 * the NES TLV, Keymat Index being the one used above, UPDATE ID
	 * being equal to the one in the received UPDATE, old SPI being the
	 * current incoming SPI, and new SPI being the newly generated
	 * incoming SPI.  If the system generated a new Diffie-Hellman key
	 * above, the new key is included in the packet in the
	 * Diffie-Hellman payload.  Note that if the system is in state
	 * REKEYING, the new Diffie-Hellman key was probably generated and
	 * sent already earlier, in which case it MUST NOT be included into
	 * the reply packet. */

	/* create and send reply UPDATE packet */
	update_packet = hip_msg_alloc();
	if (!update_packet) {
		HIP_DEBUG("update_packet alloc failed\n");
		err = -ENOMEM;
		goto out_err;
	}

	hip_build_network_hdr(update_packet, HIP_UPDATE, 0, hitr, hits);
	err = hip_build_param_nes(update_packet, 1,
				  our_current_keymat_index, ntohs(nes->update_id),
				  prev_spi_in, new_spi_in);
	if (err) {
		HIP_ERROR("Building of NES failed\n");
		goto out_err;
	}

	/* TODO: hmac/signature to common functions */
	/* Add HMAC */
	err = hip_build_param_hmac_contents(update_packet, &entry->hmac_our);
	if (err) {
		HIP_ERROR("Building of HMAC failed (%d)\n", err);
		goto out_err;
	}
	HIP_DEBUG("HMAC added\n");

	/* Add SIGNATURE */
	host_id_private = hip_get_any_localhost_host_id();
	if (!host_id_private) {
		HIP_ERROR("Could not get our host identity. Can not sign data\n");
		goto out_err;
	}

	if (!hip_create_signature(update_packet, hip_get_msg_total_len(update_packet),
				  host_id_private, signature)) {
		HIP_ERROR("Could not sign UPDATE. Failing\n");
		err = -EINVAL;
		goto out_err;
	}

	err = hip_build_param_signature_contents(update_packet, signature,
						 HIP_DSA_SIGNATURE_LEN,
 						 HIP_SIG_DSA);
 	if (err) {
 		HIP_ERROR("Building of SIGNATURE failed (%d)\n", err);
 		goto out_err;
 	}
	HIP_DEBUG("SIGNATURE added\n");

	/* send reply UPDATE */

        err = hip_hadb_get_peer_addr(entry, &daddr);
        if (err) {
                HIP_DEBUG("hip_sdb_get_peer_address err = %d\n", err);
                goto out_err;
        }

        HIP_DEBUG("Sending reply UPDATE packet\n");
	err = hip_csum_send(NULL, &daddr, update_packet);
	if (err) {
		HIP_DEBUG("hip_csum_send err=%d\n", err);
		HIP_DEBUG("NOT ignored, or should we..\n");
                /* goto out_err; ? */
	}

 out_err:
	HIP_UNLOCK_HA(entry);
	if (entry)
		hip_put_ha(entry);
	if (update_packet)
		kfree(update_packet);
	if (err) {
		/* SA remove not tested yet */
		if (new_spi_in)
			hip_delete_sa(new_spi_in, hitr);
		if (new_spi_out)
			hip_delete_sa(new_spi_out, hits);
	}
	return err;
}


/**
 * hip_handle_update_reply - handle incoming reply UPDATE packet
 * @msg: the HIP packet
 * @state: the state in which we are with the peer
 *
 * This function handles case 9 in draft-09 section "8.10
 * Processing UPDATE packets".
 *
 * Returns: 0 if successful, otherwise < 0.
 */
int hip_handle_update_reply(struct hip_common *msg, struct in6_addr *src_ip, int state /*, int is_reply*/)
{
	int err = 0;
	struct in6_addr *hits = &msg->hits, *hitr = &msg->hitr;
	struct hip_nes *nes;
	struct hip_common *update_packet = NULL;
	struct hip_dh_fixed *dh;
	int esp_transform = -1;
	struct hip_crypto_key espkey_gl, authkey_gl;
	struct hip_crypto_key espkey_lg, authkey_lg;
//	int need_to_generate_key;
	int dh_key_generated = 0, new_keymat_generated;
	uint16_t current_keymat_index;
	uint32_t new_spi_in = 0;  /* inbound IPsec SA SPI */
	uint32_t new_spi_out = 0; /* outbound IPsec SA SPI */
	uint32_t prev_spi_in = 0, prev_spi_out = 0;
	int we_are_HITg = 0;
	int esp_transf_length = 0;
	int auth_transf_length = 0;
	struct xfrm_state *xs;
	hip_ha_t *entry = NULL;

	/* draft-09 8.10.2 Processing a reply UPDATE packet */

	HIP_DEBUG("state=%s\n", hip_state_str(state));

	nes = hip_get_param(msg, HIP_PARAM_NES);

	/* 1. If either the received UPDATE contains a new
	 * Diffie-Hellman key, the system has a new Diffie-Hellman key
	 * from initiating rekey, or both, the system generates new
	 * KEYMAT. If there is only one new Diffie-Hellman key, the
	 * old key is used as the other key. */
	dh = hip_get_param(msg, HIP_PARAM_DIFFIE_HELLMAN);
	if (dh || dh_key_generated) {
		HIP_DEBUG("would generate new keymat\n");
		/* generate_new_keymat(); */
		new_keymat_generated = 1;
	} else {
		new_keymat_generated = 0;
	}

	HIP_DEBUG("new_keymat_generated=%d\n", new_keymat_generated);

	entry = hip_hadb_find_byhit(hits);
	if (!entry) {
		HIP_ERROR("Entry not found\n");
		goto out_err;
	}
	HIP_LOCK_HA(entry);

	/* 2. If the system generated new KEYMAT in the previous step,
	 * it sets Keymat Index to zero, independent on whether the
	 * received UPDATE included a Diffie-Hellman key or not. */
	if (new_keymat_generated) {
		current_keymat_index = 0;
	} else {
		current_keymat_index = entry->current_keymat_index;
	}

	HIP_DEBUG("current_keymat_index=%u\n", current_keymat_index);

	/* 3. The system draws keys for new incoming and outgoing ESP
	 * SAs, starting from the Keymat Index, and prepares new
	 * incoming and outgoing ESP SAs. The SPI for the outgoing SA
	 * is the new SPI value from the UPDATE.  The SPI for the
	 * incoming SA was generated when rekey was initiated. */

	{
		uint8_t calc_index_new;
		uint16_t keymat_offset_new;
		unsigned char Kn[HIP_AH_SHA_LEN];

		we_are_HITg = hip_hit_is_bigger(hitr, hits);
		HIP_DEBUG("we are: HIT%c\n", we_are_HITg ? 'g' : 'l');

		esp_transform = entry->esp_transform;
		esp_transf_length = hip_enc_key_length(esp_transform); /* needed below */
		auth_transf_length = hip_auth_key_length_esp(esp_transform);
		HIP_DEBUG("enckeylen=%d authkeylen=%d\n", esp_transf_length, auth_transf_length);

		calc_index_new = entry->keymat_calc_index;
		keymat_offset_new = 0x7fff & ntohs(nes->keymat_index);
		if (keymat_offset_new > current_keymat_index) {
			HIP_DEBUG("using keymat index from reply update packet\n");
			current_keymat_index = keymat_offset_new;
		}

		memcpy(Kn, entry->current_keymat_K, HIP_AH_SHA_LEN);
		err = hip_update_get_sa_keys(entry, &keymat_offset_new, &calc_index_new, Kn,
					     &espkey_gl, &authkey_gl, &espkey_lg, &authkey_lg);
		HIP_DEBUG("get_sa_keys ret err=%d\n", err);

		/* todo: update entry keymat later */
		hip_update_entry_keymat(entry, keymat_offset_new, calc_index_new, Kn);
		if (err)
			goto out_err;
	}

	/* set up new outbound IPsec SA */
	new_spi_out = ntohl(nes->new_spi);
	err = hip_setup_sa(hitr, hits,
			   &new_spi_out, esp_transform,
			   we_are_HITg ? &espkey_gl.key : &espkey_lg.key,
			   we_are_HITg ? &authkey_gl.key : &authkey_lg.key,
			   1);
	if (err) {
		HIP_ERROR("Setting up new outbound IPsec failed (%d)\n", err);
		goto out_err;
	}
	HIP_DEBUG("Set up new outbound IPsec SA, SPI=0x%x\n", new_spi_out);

	_HIP_DEBUG("after new_spi_out: out=0x%08x in=0x%08x new_in=0x%08x new_out=0x%08x\n",
		   entry->spi_in, entry->spi_out, entry->new_spi_in, entry->new_spi_out);

	/* remember the current outbound SPI so we can delete it after
	   we have changed to use the new outbound SPI */
	prev_spi_out = entry->spi_out;

	/* draft: 4. The system starts to send to the new outgoing SA. */
	entry->spi_out = new_spi_out;

	HIP_DEBUG("updated outbound SPI (SPI_OUT), new_spi_out=0x%x\n", new_spi_out);

	entry->default_spi_out = entry->spi_out;
	HIP_DEBUG("set default SPI out=0x%x\n", entry->default_spi_out);
	hip_hadb_add_addr_to_spi(entry, entry->spi_out, src_ip, 0, PEER_ADDR_STATE_ACTIVE, 0, 1);

#if 0
	/* todo: set SA state to dying */
	HIP_DEBUG("REMOVING OLD OUTBOUND IPsec SA, SPI=0x%x\n", prev_spi_out);
	err = hip_delete_sa(prev_spi_out, hits);
	HIP_DEBUG("delete_sa retval=%d\n", err);
#endif
	err = 0;

	/* clear out spi value from hadb */
	entry->new_spi_out = 0;

	/* use the new inbound IPsec SA created when rekeying started */
	new_spi_in = entry->new_spi_in;

	HIP_DEBUG("copying keys to new updated inbound SA\n");

	/* todo: move this to security.c */
	HIP_DEBUG("Searching for spi: 0x%x (0x%x)\n", new_spi_in, htonl(new_spi_in));
	xs = xfrm_state_lookup((xfrm_address_t *)hitr, htonl(new_spi_in),
			       IPPROTO_ESP, AF_INET6);
	if (!xs) {
		HIP_ERROR("Did not find SA\n");
		goto out_err;
	}

	spin_lock_bh(&xs->lock);
	if (xs->ealg->alg_key_len / 8 != esp_transf_length ||
	    xs->aalg->alg_key_len / 8 != auth_transf_length) {
		/* weird .. shouldn't happen, but check anyway */
		HIP_ERROR("Sizes for enc/auth keys differ, current xs a/e=%d/%d vs. %d/%d\n",
			  xs->aalg->alg_key_len / 8, xs->ealg->alg_key_len / 8,
			  auth_transf_length, esp_transf_length);
		err = -EINVAL;
	} else {
		memcpy(xs->ealg->alg_key, we_are_HITg ? &espkey_lg  : &espkey_gl,  esp_transf_length);
		memcpy(xs->aalg->alg_key, we_are_HITg ? &authkey_lg : &authkey_gl, auth_transf_length);
		HIP_DEBUG("Copied new keys to SA\n");

		/* THIS WILL PROBABLY LEAK MEMORY (xs->type->init_state in esp6.c) */
		if (xs->type && xs->type->init_state(xs, NULL)) {
			HIP_ERROR("Could not reinitialize XFRM state\n");
			//goto out;
		} else
			HIP_DEBUG("xs ESP reinit ok\n");
	}

	spin_unlock_bh(&xs->lock);
	xfrm_state_put(xs);

	prev_spi_in = entry->spi_in;

#if 0
	/* delete old inbound SA */
	/* todo: set SA state to dying */
	HIP_DEBUG("REMOVING OLD INBOUND IPsec SA, SPI=0x%x\n", prev_spi_in);
	err = hip_delete_sa(prev_spi_in, hitr);
	HIP_DEBUG("delete_sa retval=%d\n", err);
	err = 0;
#endif

	HIP_DEBUG("switching to new updated inbound SPI=0x%x, new_spi_in\n", new_spi_in);

	hip_hadb_remove_state_spi(entry);
	entry->spi_in = new_spi_in;
	hip_hadb_insert_state(entry);

	HIP_DEBUG("switch ok\n");

	/* clear out spi value from hadb */
	entry->new_spi_in = 0;

	/* activate the new inbound and outbound SAs */
	HIP_DEBUG("finalizing the new inbound SA, SPI=0x%x\n", new_spi_in);
	hip_finalize_sa(hitr, new_spi_in);
	HIP_DEBUG("finalizing the new outbound SA, SPI=0x%x\n", new_spi_out);
	hip_finalize_sa(hits, new_spi_out);


	/* Go back to ESTABLISHED state */
	entry->state = HIP_STATE_ESTABLISHED;
	HIP_DEBUG("Went back to ESTABLISHED state\n");

 out_err:
	HIP_UNLOCK_HA(entry);
	if (entry)
		hip_put_ha(entry); /* try to do this earlier */
	/* if (err) move to state = ? */
	if (update_packet)
		kfree(update_packet);
	/* TODO: REMOVE IPSEC SAs */
	return err;
}

/**
 * hip_receive_update - receive UPDATE packet
 * @skb: sk_buff where the HIP packet is in
 * @hip_common: pointer to HIP header
 *
 * This is the initial function which is called when an UPDATE packet
 * is received. The validity of the packet is checked and then this
 * function acts according to whether this packet is a reply or not.
 *
 * Returns: 0 if successful (HMAC and signature (if needed) are
 * validated, and the rest of the packet is handled if current state
 * allows it), otherwise < 0.
 */
int hip_receive_update(struct sk_buff *skb)
{
	int err = 0;
	struct hip_common *msg;
	struct in6_addr *hits;
	struct hip_nes *nes;
	int state = 0;
	uint16_t pkt_update_id; /* UPDATE ID in packet */
	uint16_t update_id_in;  /* stored incoming UPDATE ID */
	int is_reply;           /* the R bit in NES */
	uint16_t keymat_index;
	struct hip_dh_fixed *dh;
	struct in6_addr *src_ip;
	hip_ha_t *entry = NULL;

	HIP_DEBUG("\n");
	msg = (struct hip_common *) skb->h.raw;
	_HIP_HEXDUMP("msg", msg, hip_get_msg_total_len(msg));

	src_ip = &(skb->nh.ipv6h->saddr);
	hits = &msg->hits;

	entry = hip_hadb_find_byhit(hits);
	if (!entry) {
		HIP_ERROR("Entry not found\n");
		goto out_err;
	}
	HIP_LOCK_HA(entry);

	state = entry->state; /* todo: remove variable state */

	HIP_DEBUG("Received UPDATE in state %s\n", hip_state_str(state));

	nes = hip_get_param(msg, HIP_PARAM_NES);
	if (!nes) {
		HIP_ERROR("UPDATE contained no NES parameter\n");
		err = -ENOMSG;
		goto out_err;
	}
	HIP_DEBUG("NES found\n");

	is_reply = ntohs(nes->keymat_index) & 0x8000 ? 1 : 0;
	keymat_index = 0x7fff & ntohs(nes->keymat_index);
	pkt_update_id = ntohs(nes->update_id);

	HIP_DEBUG("NES: is reply packet: %s\n", is_reply ? "yes" : "no");
	HIP_DEBUG("NES: Keymaterial Index: %u\n", keymat_index);
	HIP_DEBUG("NES: UPDATE ID: %u\n", pkt_update_id);
	HIP_DEBUG("NES: Old SPI: 0x%x\n", ntohl(nes->old_spi));
	HIP_DEBUG("NES: New SPI: 0x%x\n", ntohl(nes->new_spi));

	/* draft-09: 8.10 Processing UPDATE packets checks */

	/* 1. If the system is in state ESTABLISHED and the UPDATE has
	 * the R-bit set in the NES TLV, the packet is silently
	 * dropped. */
	if (is_reply && state == HIP_STATE_ESTABLISHED) {
		HIP_DEBUG("Received UPDATE packet is a reply and state is ESTABLISHED. Dropping\n");
		err = 0; /* ok case */
		goto out_err;
	}

 	/* 2. If the UPDATE ID in the received UPDATE is smaller than
	 * the stored incoming UPDATE ID, the packet MUST BE
	 * dropped. */
	update_id_in = entry->update_id_in;

	HIP_DEBUG("previous incoming update id=%u\n", update_id_in);
	if (!is_reply && pkt_update_id < update_id_in) {

		HIP_DEBUG("Not a reply and received UPDATE ID (%u) < stored incoming UPDATE ID (%u). Dropping\n",
			  pkt_update_id, update_id_in);
		err = -EINVAL;
		goto out_err;
	} else if (pkt_update_id == update_id_in) {
		HIP_DEBUG("Retransmitted UPDATE packet (?), continuing\n");
		/* todo: ignore this packet or process anyway ? */
	}

	/* 3. The system MUST verify the HMAC in the UPDATE packet.
	 * If the verification fails, the packet MUST be dropped. */

        /* verify HMAC */
	err = hip_verify_packet_hmac(msg, entry);
	if (err) {
		HIP_ERROR("HMAC validation on UPDATE failed\n");
		goto out_err;
	}
        HIP_DEBUG("UPDATE HMAC ok\n");

	/* 4. If the received UPDATE contains a Diffie-Hellman
	 * parameter, the received Keymat Index MUST be zero. If this
	 * test fails, the packet SHOULD be dropped and the system
	 * SHOULD log an error message.*/
	HIP_DEBUG("packet keymat_index=%u\n", keymat_index);
	dh = hip_get_param(msg, HIP_PARAM_DIFFIE_HELLMAN);
	if (dh) {
		HIP_DEBUG("packet contains DH\n");
		if (keymat_index != 0) {
			/* SHOULD -> we currently drop */
			HIP_ERROR("UPDATE contains Diffie-Hellman parameter with non-zero"
				  "keymat value %u in NES. Dropping\n",
				  keymat_index);
			err = -EINVAL;
			goto out_err;
		}
	} else 	{
		uint16_t current_keymat_index;

		HIP_DEBUG("packet does not contain DH\n");

		/* 5. If the received UPDATE does not contain a
		   Diffie-Hellman parameter, the received Keymat Index
		   MUST be larger or equal to the index of the next
		   byte to be drawn from the current KEYMAT. If this
		   test fails, the packet SHOULD be dropped and the
		   system SHOULD log an error message.*/
		current_keymat_index = entry->current_keymat_index;

		HIP_DEBUG("current_keymat_index=%d\n", current_keymat_index);

		/* test only incoming keymat index instead of this ? */
		if (current_keymat_index == 0x7fff) { /* max value of keymat index */
			HIP_ERROR("current keymat index would overflow from 0x7fff to 0, bug ? Dropping\n");
			err = -EINVAL;
			goto out_err;
		}

		if (keymat_index < current_keymat_index+1) {
			HIP_DEBUG("Received UPDATE KEYMAT Index (%u) < stored KEYMAT Index +1 (%u). Dropping\n",
				  keymat_index, current_keymat_index+1);
			err = -EINVAL;
			goto out_err;
		}
	}

	/* 6. The system MAY verify the SIGNATURE in the UPDATE
	 * packet. If the verification fails, the packet SHOULD be
	 * dropped and an error message logged. */

	/* MAY -> we currently do */

        /* Verify SIGNATURE */
	{
		struct hip_lhi peer_lhi;
		struct hip_host_id *peer_id;

                peer_lhi.anonymous = 0;
                memcpy(&peer_lhi.hit, &msg->hits, sizeof(struct in6_addr));
                peer_id = hip_get_host_id(HIP_DB_PEER_HID, &peer_lhi);
                if (!peer_id) {
                        HIP_ERROR("Unknown peer (no identity found)\n");
                        err = -EINVAL;
                        goto out_err;
                }

		err = hip_verify_packet_signature(msg, peer_id);
		if (err) {
			HIP_ERROR("Verification of UPDATE signature failed\n");
			err = -EINVAL;
			goto out_err;
		}
	}

        HIP_DEBUG("SIGNATURE ok\n");

	/* 7. The system MUST record the UPDATE ID in the received
	 * packet, for replay protection. */

	if (!is_reply) {
		entry->update_id_in = pkt_update_id;
		HIP_DEBUG("Stored peer's incoming UPDATE ID %u\n", pkt_update_id);
	}

	/* todo: check that Old SPI value exists ? */
	/* cases 8-10: */

	switch(state) {
	case HIP_STATE_ESTABLISHED:
		if (!is_reply) {
			HIP_DEBUG("case 8: established and is not reply\n");
			err = hip_handle_update_initial(msg, src_ip, state);
		}
		break;
	case HIP_STATE_REKEYING:
		if (is_reply) {
			HIP_DEBUG("case 9: rekeying and is reply\n");
			err = hip_handle_update_reply(msg, src_ip, state);
		} else {
			HIP_DEBUG("case 10: rekeying and is not reply\n");
			err = hip_handle_update_initial(msg, src_ip, state);
		}
		break;
	default:
		HIP_ERROR("Received UPDATE in illegal state %s. Dropping\n", hip_state_str(state));
		err = -EINVAL;
		goto out_err;
		break;
	}

	if (err) {
		HIP_ERROR("UPDATE handler failed, err=%d\n", err);
		goto out_err;
	}

 out_err:
	HIP_UNLOCK_HA(entry);
	if (entry)
		hip_put_ha(entry);

	return err;
}


int hip_send_update(struct hip_hadb_state *entry)
{
	int err = 0;
	uint16_t update_id_out;
	uint32_t new_spi_in = 0;
	struct hip_common *update_packet = NULL;
	struct in6_addr daddr;
	struct hip_host_id *host_id_private;
 	u8 signature[HIP_DSA_SIGNATURE_LEN];
	struct hip_crypto_key null_key;

	HIP_DEBUG("\n");
	if (!entry) {
		HIP_ERROR("null entry\n");
		err = -EINVAL;
		goto out_err;
	}

	hip_print_hit("sending UPDATE to", &entry->hit_peer);

	/* we can not know yet from where we should start to draw keys
	   from the keymat, so we just zero a key and fill in
	   the keys later */
	memset(&null_key.key, 0, HIP_MAX_KEY_LEN);

	/* The specifications does not say that new incoming SA should be done
	 * here, but it is needed because of the New SPI value */

	/* get a New SPI to use in the UPDATE packet and prepare a new
	 * incoming IPsec SA */
	new_spi_in = 0;
	err = hip_setup_sa(&entry->hit_peer, &entry->hit_our,
			   &new_spi_in, entry->esp_transform,
			   &null_key.key, &null_key.key, 0);
	/* todo: if failed try again a couple of times ? */
	if (err) {
		HIP_ERROR("Error while setting up new IPsec SA (err=%d)\n", err);
		goto out_err;
	}
	HIP_DEBUG("New SA created with New SPI (in)=0x%x\n", new_spi_in);

	entry->new_spi_in = new_spi_in;
	HIP_DEBUG("stored New SPI (NEW_SPI_IN=0x%x)\n", new_spi_in);

	/* start building UPDATE packet */
	update_packet = hip_msg_alloc();
	if (!update_packet) {
		HIP_ERROR("update_packet alloc failed\n");
		err = -ENOMEM;
		goto out_err;
	}

	hip_build_network_hdr(update_packet, HIP_UPDATE, 0, &entry->hit_our, &entry->hit_peer);

	update_id_out = hip_get_new_update_id();
	HIP_DEBUG("outgoing UPDATE ID=%u\n", update_id_out);
	if (!update_id_out) {
		/* todo: handle this case */
		HIP_ERROR("outgoing UPDATE ID overflowed back to 0, bug ?\n");
		err = -EINVAL;
		goto out_err;
	}

	HIP_DEBUG("entry->current_keymat_index=%u\n", entry->current_keymat_index);
	err = hip_build_param_nes(update_packet, 0, entry->current_keymat_index+1,
				  update_id_out, entry->spi_in, new_spi_in); 
	if (err) {
		HIP_ERROR("Building of NES param failed\n");
		goto out_err;
	}

	/* TODO: hmac/signature to common functions */
	/* Add HMAC */
	err = hip_build_param_hmac_contents(update_packet, &entry->hmac_our);
	if (err) {
		HIP_ERROR("Building of HMAC failed (%d)\n", err);
		goto out_err;
	}
	HIP_DEBUG("HMAC added\n");

	/* Add SIGNATURE */
	host_id_private = hip_get_any_localhost_host_id();
	if (!host_id_private) {
		HIP_ERROR("Could not get own host identity. Can not sign data\n");
		goto out_err;
	}

	if (!hip_create_signature(update_packet, hip_get_msg_total_len(update_packet),
				  host_id_private, signature)) {
		HIP_ERROR("Could not sign UPDATE. Failing\n");
		err = -EINVAL;
		goto out_err;
	}

	err = hip_build_param_signature_contents(update_packet, signature,
						 HIP_DSA_SIGNATURE_LEN,
 						 HIP_SIG_DSA);
 	if (err) {
 		HIP_ERROR("Building of SIGNATURE failed (%d)\n", err);
 		goto out_err;
 	}
	HIP_DEBUG("SIGNATURE added\n");


	HIP_DEBUG("spi values when sending update: 0x%08x 0x%08x 0x%08x 0x%08x\n",
		  entry->spi_in, entry->spi_out, entry->new_spi_in, entry->new_spi_out);

	/* send UPDATE */
        HIP_DEBUG("Sending UPDATE packet\n");
        err = hip_hadb_get_peer_addr(entry, &daddr);
        if (err) {
                HIP_DEBUG("hip_sdb_get_peer_addr err=%d\n", err);
                goto out_err;
        }

	/* Store the last UPDATE ID value sent from us */
	entry->update_id_out = update_id_out;

        HIP_DEBUG("Stored peer's outgoing UPDATE ID %u\n", update_id_out);

	entry->state = HIP_STATE_REKEYING;
	HIP_DEBUG("moved to state REKEYING\n");

	err = hip_csum_send(NULL, &daddr, update_packet);
	if (err) {
		HIP_DEBUG("hip_csum_send err=%d\n", err);
		_HIP_DEBUG("NOT ignored, or should we..\n");

		entry->state = HIP_STATE_ESTABLISHED;
		HIP_DEBUG("fallbacked to state ESTABLISHED due to error (ok ?)\n");
		goto out_err;
	}

	/* todo: add UPDATE to sent list */
	/* todo: start retransmission timer */
	goto out;

 out_err:
	/* delete IPsec SA on failure */
	if (new_spi_in)
		hip_delete_sa(new_spi_in, &entry->hit_our);
	entry->new_spi_in = 0;
 out:

	if (update_packet)
		kfree(update_packet);

	return err;
}

/* really ugly hack ripped from rea.c, must convert to list_head asap */
struct hip_update_kludge {
	hip_ha_t **array;
	int count;
	int length;
};

/* from rea.c */
static int hip_update_get_all_valid(hip_ha_t *entry, void *op)
{
	struct hip_update_kludge *rk = op;

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

/**
 * hip_send_update_all - send UPDATE packet to every peer
 *
 * UPDATE is sent to the peer only if the peer is in established
 * state. Note that we can not guarantee that the UPDATE actually reaches
 * the peer (unless the UPDATE is retransmitted some times, which we
 * currently don't do), due to the unreliable nature of IP we just
 * hope the UPDATE reaches the peer.
 *
 * TODO: retransmission timers
 */
void hip_send_update_all(void)
{
	int err = 0, i;

	/* code ripped from rea.c */
	hip_ha_t *entries[HIP_MAX_HAS] = {0};
	struct hip_update_kludge rk;

	HIP_DEBUG("\n");

	rk.array = entries;
	rk.count = 0;
	rk.length = HIP_MAX_HAS;

	err = hip_for_each_ha(hip_update_get_all_valid, &rk);
	if (err) {
		HIP_ERROR("for_each_ha err=%d\n", err);
		return;
	}

	for (i = 0; i < rk.count; i++) {
		if (rk.array[i] != NULL) {
			hip_send_update(rk.array[i]);
			hip_put_ha(rk.array[i]);
		}
	}

	return;
}
