#include <net/hip.h>
#include <linux/xfrm.h>
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
	struct in6_addr v6addr_test;
	/* REA stuff ? address list */
};


/**
 * hip_update_spi_waitlist_add - add a SPI to SPI waitlist
 * @spi: the inbound SPI to be added in host byte order
 * @hit: the HIT for which the @spi is related to
 */
void hip_update_spi_waitlist_add(uint32_t spi, struct in6_addr *hit, struct hip_rea_info_mm02 *rea)
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
	HIP_DEBUG("End of SPI waitlist\n");
	return;
}

/**
 * hip_update_spi_waitlist_delete - delete a SPI from SPI waitlist
 * @spi: SPI in host byte order to be deleted
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

	HIP_DEBUG("skipping test, not needed anymore ?\n");
	return 0;

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
		hip_hadb_insert_state(entry);

		entry->default_spi_out = entry->spi_out;
		HIP_DEBUG("set default SPI out=0x%x\n", entry->default_spi_out);

		/* test, todo: addr from rea */
//		hip_print_hit("v6addr_test", &s->v6addr_test);
//		hip_hadb_add_addr_to_spi(entry, entry->default_spi_out, &s->v6addr_test, PEER_ADDR_STATE_ACTIVE, 0, 0);

//		hip_hadb_insert_state(entry);
		hip_print_hit("finalizing", &s->hit);
		hip_finalize_sa(&s->hit, entry->new_spi_out);
#if 1
		HIP_DEBUG("Removing old inbound IPsec SA, SPI=0x%x\n", old_spi_out);
		hip_ifindex2spi_map_del(entry, old_spi_out);
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

/* Get keys needed by UPDATE */
int hip_update_get_sa_keys(hip_ha_t *entry, uint16_t *keymat_offset_new,
			   uint8_t *calc_index_new, uint8_t *Kn_out,
			   struct hip_crypto_key *espkey_gl, struct hip_crypto_key *authkey_gl,
			   struct hip_crypto_key *espkey_lg, struct hip_crypto_key *authkey_lg)
{
	int err = 0;
       	unsigned char Kn[HIP_AH_SHA_LEN];
	uint16_t k = *keymat_offset_new;
	uint8_t c = *calc_index_new;
	int esp_transform;
	int esp_transf_length = 0;
	int auth_transf_length = 0;
	uint16_t Kn_pos;

	HIP_DEBUG("k=%u c=%u\n", k, c);

	esp_transform = entry->esp_transform;
	esp_transf_length = hip_enc_key_length(esp_transform);
	auth_transf_length = hip_auth_key_length_esp(esp_transform);
	_HIP_DEBUG("enckeylen=%d authkeylen=%d\n", esp_transf_length, auth_transf_length);

	if (*keymat_offset_new + 2*(esp_transf_length+auth_transf_length) > 0xffff) {
		HIP_ERROR("Can not draw requested amount of new KEYMAT, keymat index=%u, requested amount=%d\n",
			  *keymat_offset_new, 2*(esp_transf_length+auth_transf_length));
		err = -EINVAL;
		goto out_err;
	}

	memcpy(Kn, Kn_out, HIP_AH_SHA_LEN);

	/* SA-gl */
	Kn_pos = entry->current_keymat_index - (entry->current_keymat_index % HIP_AH_SHA_LEN);
	err = hip_keymat_get_new(espkey_gl->key, esp_transf_length, entry->dh_shared_key,
				 entry->dh_shared_key_len, &k, &c, Kn, &Kn_pos);
	_HIP_DEBUG("enckey_gl hip_keymat_get_new ret err=%d k=%u c=%u\n", err, k, c);
	if (err)
		goto out_err;
	_HIP_HEXDUMP("ENC KEY gl", espkey_gl->key, esp_transf_length);
	k += esp_transf_length;
	err = hip_keymat_get_new(authkey_gl->key, auth_transf_length, entry->dh_shared_key,
				 entry->dh_shared_key_len, &k, &c, Kn, &Kn_pos);
	_HIP_DEBUG("authkey_gl hip_keymat_get_new ret err=%d k=%u c=%u\n", err, k, c);
	if (err)
		goto out_err;
	_HIP_HEXDUMP("AUTH KEY gl", authkey_gl->key, auth_transf_length);
	k += auth_transf_length;

	/* SA-lg */
	err = hip_keymat_get_new(espkey_lg->key, esp_transf_length, entry->dh_shared_key,
				 entry->dh_shared_key_len, &k, &c, Kn, &Kn_pos);
	_HIP_DEBUG("enckey_lg hip_keymat_get_new ret err=%d k=%u c=%u\n", err, k, c);
	if (err)
		goto out_err;
	_HIP_HEXDUMP("ENC KEY lg", espkey_lg->key, esp_transf_length);
	k += esp_transf_length;
	err = hip_keymat_get_new(authkey_lg->key, auth_transf_length, entry->dh_shared_key,
				 entry->dh_shared_key_len, &k, &c, Kn, &Kn_pos);
	_HIP_DEBUG("authkey_lg hip_keymat_get_new ret err=%d k=%u c=%u\n", err, k, c);
	if (err)
		goto out_err;
	_HIP_HEXDUMP("AUTH KEY lg", authkey_lg->key, auth_transf_length);
	k += auth_transf_length;

	HIP_DEBUG("at end: k=%u c=%u\n", k, c);
	*keymat_offset_new = k;
	*calc_index_new = c;
	memcpy(Kn_out, Kn, HIP_AH_SHA_LEN);
 out_err:
	return err;
}

int hip_update_handle_rea_parameter(hip_ha_t *entry, struct hip_rea_info_mm02 *rea)
{
	/* assume that caller has the entry lock */
	int err = 0;
	uint32_t spi;
	struct hip_rea_info_addr_item *rea_address_item;
	int i, n_addrs;
	struct hip_peer_spi_list_item *spi_list;
	struct hip_peer_addr_list_item *a, *tmp;
	/* mm-02-pre1 8.2 Handling received REAs */

	spi = ntohl(rea->spi);
	HIP_DEBUG("SPI=0x%x\n", spi);

	if ((hip_get_param_total_len(rea) - sizeof(struct hip_rea_info_mm02)) %
	    sizeof(struct hip_rea_info_addr_item))
		HIP_ERROR("addr item list len modulo not zero, (len=%d)\n", rea->length);

	n_addrs = (hip_get_param_total_len(rea) - sizeof(struct hip_rea_info_mm02)) /
		sizeof(struct hip_rea_info_addr_item);
	HIP_DEBUG(" REA has %d addresses, rea param len=%d\n", n_addrs, hip_get_param_total_len(rea));
	if (n_addrs < 0) {
		HIP_DEBUG("BUG: n_addrs=%d < 0\n", n_addrs);
		goto out_err;
	}
	if (n_addrs == 0) {
		HIP_DEBUG("REA (SPI=0x%x) contains no addresses\n", spi);
		_HIP_DEBUG("TODO: DEPRECATE all addresses ?\n");
		/* err is 0, no error */

		/* comment out goto if deprecate all current addresses */
		goto out_err;
	}

	/* 1.  The host checks if the SPI listed is a new one.  If it
	   is a new one, it creates a new SPI that contains no addresses. */
	spi_list = hip_hadb_get_spi_list(entry, spi);
	if (!spi_list) {
		err = hip_hadb_add_peer_spi(entry, spi);
		if (err) {
			HIP_DEBUG("failed to create a new SPI list\n");
			goto out_err;
		}
		spi_list = hip_hadb_get_spi_list(entry, spi);
		if (!spi_list) {
			HIP_ERROR("Couldn't get newly created SPI list\n"); /* weird */
			goto out_err;
		}
		HIP_DEBUG("created a new SPI list\n");
	}

	rea_address_item = (void *)rea+sizeof(struct hip_rea_info_mm02);
	for(i = 0; i < n_addrs; i++, rea_address_item++) {
		struct in6_addr *rea_address = &rea_address_item->address;
		uint32_t lifetime = ntohl(rea_address_item->lifetime);
		int is_preferred = ntohl(rea_address_item->reserved) == 1 << 31;
		hip_print_hit("REA address", rea_address);
		HIP_DEBUG(" addr %d: is_pref=%s reserved=0x%x lifetime=0x%x\n", i+1,
			   is_preferred ? "yes" : "no", ntohl(rea_address_item->reserved),
			  lifetime);
		/* 2. check that the address is a legal unicast or anycast address */
		/* todo: test anycast */
		if (! (ipv6_addr_type(rea_address) & IPV6_ADDR_UNICAST) ) {
			HIP_DEBUG("skipping non-unicast address\n");
			continue;
		}
		/* 3. check if the address is already bound to the SPI + add/update address */
		err = hip_hadb_add_addr_to_spi(entry, spi, rea_address, PEER_ADDR_STATE_UNVERIFIED,
					       lifetime, is_preferred);
		if (err) {
			HIP_DEBUG("failed to add/update address to the SPI list\n");
			goto out_err;
		}
	}

	/* 4. Mark all addresses on the SPI that were NOT listed in the REA
	   parameter as DEPRECATED. */

	HIP_DEBUG("deprecating not listed address from the SPI list\n");
	list_for_each_entry_safe(a, tmp, &spi_list->peer_addr_list, list) {
		int spi_addr_is_in_rea = 0;
		
		hip_print_hit("testing SPI address", &a->address);
		rea_address_item = (void *)rea+sizeof(struct hip_rea_info_mm02);
		for(i = 0; i < n_addrs; i++, rea_address_item++) {
			struct in6_addr *rea_address = &rea_address_item->address;
			hip_print_hit(" against REA address", rea_address);
			if (!ipv6_addr_cmp(&a->address, rea_address)) {
				spi_addr_is_in_rea = 1;
				break;
			}

		}
		if (spi_addr_is_in_rea) {
			HIP_DEBUG("SPI address was in REA\n");
			continue;
		}
		HIP_DEBUG("SPI address was not in REA\n");
		/* deprecate the address */
		a->address_state = PEER_ADDR_STATE_DEPRECATED;
	}

 out_err:
	return err;
}


/**
 * hip_handle_update_established - handle incoming UPDATE packet received in ESTABLISHED state
 * @msg: the HIP packet
 * @src_ip: source IPv6 address from where the UPDATE was sent
 *
 * This function handles case 7 in section 8.11 Processing UPDATE
 * packets of the base draft.
 *
 * Returns: 0 if successful, otherwise < 0.
 */
int hip_handle_update_established(struct hip_common *msg, struct in6_addr *src_ip)
{
	int err = 0;
	struct in6_addr *hits = &msg->hits, *hitr = &msg->hitr;
	struct hip_nes *nes;
	struct hip_seq *seq;
	//struct hip_rea_info_mm02 *rea;
	int esp_transform = -1;
	struct hip_crypto_key espkey_gl, authkey_gl;
	struct hip_crypto_key espkey_lg, authkey_lg;
	uint32_t update_id_out = 0;
	uint32_t prev_spi_in = 0;
	uint32_t new_spi_in = 0;  /* inbound IPsec SA SPI */
	uint32_t new_spi_out = 0; /* outbound IPsec SA SPI */
	struct hip_common *update_packet = NULL;
	uint16_t keymat_index;
	struct in6_addr daddr;
	struct hip_dh_fixed *dh;
	struct hip_host_id *host_id_private;
 	u8 signature[HIP_DSA_SIGNATURE_LEN];
	int need_to_generate_key = 0, dh_key_generated = 0; //, new_keymat_generated;
	int we_are_HITg = 0;
	hip_ha_t *entry = NULL;

	HIP_DEBUG("\n");

	/* 8.11.1  Processing an UPDATE packet in state ESTABLISHED */

	/* 1.  The system consults its policy to see if it needs to generate a
	   new Diffie-Hellman key, and generates a new key if needed. */
	_HIP_DEBUG("8.11.1 case 1 TODO: need to rekey here ?\n");
	if (need_to_generate_key) {
		_HIP_DEBUG("would generate new D-H keys\n");
		/* generate_dh_key(); */
		dh_key_generated = 1;
		/* todo: The system records any newly generated or
		   received Diffie-Hellman keys, for use in KEYMAT generation upon
		   leaving the REKEYING state. */
	} else {
		dh_key_generated = 0;
	}

	_HIP_DEBUG("dh_key_generated=%d\n", dh_key_generated);

	entry = hip_hadb_find_byhit(hits);
	if (!entry) {
		HIP_ERROR("Entry not found\n");
		goto out_err;
	}

	HIP_LOCK_HA(entry);
#if 0
	/* testing REA parameters in UPDATE */
	while (	(rea = hip_get_nth_param(msg, HIP_PARAM_REA_INFO, rea_i)) != NULL) {
		HIP_DEBUG("Found REA parameter [%d]\n", rea_i);
		/* error, need to get corresponding nes tlv for the rea */
		err = hip_update_handle_rea_parameter(entry, rea);
		HIP_DEBUG("rea param handling ret %d\n", err);
		err = 0;
		rea_i++;
	}
#endif

	nes = hip_get_param(msg, HIP_PARAM_NES);

	/* 2. If the system generated new Diffie-Hellman key in the previous
	   step, or it received a DIFFIE_HELLMAN parameter, it sets NES
	   Keymat Index to zero. */
	dh = hip_get_param(msg, HIP_PARAM_DIFFIE_HELLMAN);
	if (dh || dh_key_generated) {
		HIP_DEBUG("would generate new keymat\n");
		/* todo: generate_new_keymat(); */
		keymat_index = 0;
	} else {
		/* Otherwise, the NES Keymat Index MUST be larger or
		   equal to the index of the next byte to be drawn from the
		   current KEYMAT. */
		if (ntohs(nes->keymat_index) < entry->current_keymat_index) {
			HIP_ERROR("NES Keymat Index (%u) < current KEYMAT %u\n",
				  ntohs(nes->keymat_index), entry->current_keymat_index);
			goto out_err;
		}
		/* In this case, it is RECOMMENDED that the host use the
		   Keymat Index requested by the peer in the received NES. */

		/* here we could set the keymat index to use, but we
		 * follow the recommendation */
		HIP_DEBUG("Using Keymat Index from NES\n");
		keymat_index = ntohs(nes->keymat_index);
	}

	HIP_DEBUG("keymat_index=%d\n", keymat_index);
	{
		uint8_t calc_index_new;
		uint16_t keymat_offset_new;
		unsigned char Kn[HIP_AH_SHA_LEN];

		/* TODO: Just call xfrm_alloc_spi instead */

		we_are_HITg = hip_hit_is_bigger(hitr, hits);
		HIP_DEBUG("we are: HIT%c\n", we_are_HITg ? 'g' : 'l');
		esp_transform = entry->esp_transform; /* needed below */
		calc_index_new = entry->keymat_calc_index;
		keymat_offset_new = keymat_index;
		if (keymat_index != 0 &&
		    keymat_offset_new > keymat_index)
			keymat_index = keymat_offset_new;

		/* todo: if testing keymat_offset_new += random */
		memcpy(Kn, entry->current_keymat_K, HIP_AH_SHA_LEN);
		err = hip_update_get_sa_keys(entry, &keymat_offset_new, &calc_index_new, Kn,
					     &espkey_gl, &authkey_gl, &espkey_lg, &authkey_lg);
		if (err)
			goto out_err;

		/* Set up new incoming IPsec SA */
		/* Old SPI value to put in NES tlv */
		prev_spi_in = entry->spi_in;
		new_spi_in = 0;
		err = hip_setup_sa(hits, hitr, &new_spi_in, esp_transform,
				   we_are_HITg ? &espkey_lg.key : &espkey_gl.key,
				   we_are_HITg ? &authkey_lg.key : &authkey_gl.key,
				   1);
		if (err) {
			HIP_ERROR("Setting up new incoming IPsec SA failed (%d)\n", err);
			goto out_err;
		}
		HIP_DEBUG("Set up new incoming SA, new_spi_in=0x%x\n", new_spi_in);

		//hip_hadb_remove_state_spi(entry);
		entry->new_spi_in = new_spi_in;
		//hip_hadb_insert_state(entry);

		HIP_DEBUG("Stored SPI 0x%x to new_spi_in\n", new_spi_in);
//		hip_finalize_sa(hitr, new_spi_in); /* move below */
//		hip_update_spi_waitlist_add(new_spi_in, hits, NULL /*rea*/); /* move away ? */
	}

	/*  3. The system increments its outgoing Update ID by one. */
	entry->update_id_out++;
	update_id_out = entry->update_id_out;
	HIP_DEBUG("outgoing UPDATE ID=%u\n", update_id_out);
	if (!update_id_out) { /* todo: handle this case */
		HIP_ERROR("outgoing UPDATE ID overflowed back to 0, bug ?\n");
		err = -EINVAL;
		goto out_err;
	}
	entry->stored_sent_update_id = update_id_out;

	/* 4. The system creates a UPDATE packet, which contains an SEQ
	   parameter (with the current value of Update ID), NES parameter
	   and the optional DIFFIE_HELLMAN parameter. The UPDATE packet also
	   includes the ACK of the Update ID found in the received UPDATE
	   SEQ parameter. */
	update_packet = hip_msg_alloc();
	if (!update_packet) {
		HIP_ERROR("update_packet alloc failed\n");
		err = -ENOMEM;
		goto out_err;
	}
	hip_build_network_hdr(update_packet, HIP_UPDATE, 0, hitr, hits);


//	if (nes->old_spi != nes->new_spi)
	err = hip_build_param_nes(update_packet, keymat_index,
				  prev_spi_in, new_spi_in);
//	else /* ack to rea update */
//		err = hip_build_param_nes(update_packet, keymat_index, 
//					  entry->spi_in, entry->spi_in);
	if (err) {
		HIP_ERROR("Building of NES failed\n");
		goto out_err;
	}

	err = hip_build_param_seq(update_packet, update_id_out);
	if (err) {
		HIP_ERROR("Building of SEQ failed\n");
		goto out_err;
	}

	/* ACK received UPDATE */
	seq = hip_get_param(msg, HIP_PARAM_SEQ);
	err = hip_build_param_ack(update_packet, ntohl(seq->update_id));
	if (err) {
		HIP_ERROR("Building of ACK failed\n");
		goto out_err;
	}

	/* TODO: hmac/signature to common functions */
	/* Add HMAC */
	err = hip_build_param_hmac_contents(update_packet, &entry->hip_hmac_out);
	if (err) {
		HIP_ERROR("Building of HMAC failed (%d)\n", err);
		goto out_err;
	}

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

        err = hip_hadb_get_peer_addr(entry, &daddr);
        if (err) {
                HIP_DEBUG("hip_sdb_get_peer_address err = %d\n", err);
                goto out_err;
        }

	/* 5.  The system sends the UPDATE packet and transitions to state
	   REKEYING.  The system stores any received NES and DIFFIE_HELLMAN
	   parameters. */
	entry->stored_received_nes.keymat_index =  ntohs(nes->keymat_index);
	entry->stored_received_nes.old_spi = ntohl(nes->old_spi);
	entry->stored_received_nes.new_spi = ntohl(nes->new_spi);
	entry->update_state_flags |= 0x2;
	HIP_DEBUG("saved NES\n");

	entry->state = HIP_STATE_REKEYING;
	HIP_DEBUG("moved to state REKEYING\n");

        HIP_DEBUG("Sending reply UPDATE packet\n");
	err = hip_csum_send(NULL, &daddr, update_packet);
	if (err) {
		HIP_DEBUG("hip_csum_send err=%d\n", err);
		HIP_DEBUG("NOT ignored, or should we..\n");
		/* fallback to established ? */
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

/* 8.11.3 Leaving REKEYING state */
int hip_update_finish_rekeying(struct hip_common *msg, hip_ha_t *entry)
{
	int err = 0;
	struct in6_addr *hits = &msg->hits, *hitr = &msg->hitr;
	uint8_t calc_index_new;
	unsigned char Kn[HIP_AH_SHA_LEN];
	uint16_t keymat_index;
	struct hip_crypto_key espkey_gl, authkey_gl;
	struct hip_crypto_key espkey_lg, authkey_lg;
	uint32_t new_spi_in = 0;  /* inbound IPsec SA SPI */
	uint32_t new_spi_out = 0; /* outbound IPsec SA SPI */
	uint32_t prev_spi_in = 0, prev_spi_out = 0;
	int we_are_HITg = 0;
	int esp_transform = -1;
	int esp_transf_length = 0;
	int auth_transf_length = 0;
	struct xfrm_state *xs;

	HIP_DEBUG("\n");
	HIP_DEBUG("stored NES: Keymat Index: %u\n", entry->stored_received_nes.keymat_index);
	HIP_DEBUG("stored NES: Old SPI: 0x%x\n", entry->stored_received_nes.old_spi);
	HIP_DEBUG("stored NES: New SPI: 0x%x\n", entry->stored_received_nes.new_spi);

	/* 2. .. If the system did not generate new KEYMAT, it uses
	   the lowest Keymat Index of the two NES parameters. */
	HIP_DEBUG("entry keymat index=%u\n", entry->current_keymat_index);
	if (entry->current_keymat_index < entry->stored_received_nes.keymat_index)
		keymat_index = entry->current_keymat_index;
	else
		keymat_index = entry->stored_received_nes.keymat_index;
	HIP_DEBUG("lowest keymat_index=%u\n", keymat_index);

	/* 3. The system draws keys for new incoming and outgoing ESP
	   SAs, starting from the Keymat Index, and prepares new incoming
	   and outgoing ESP SAs. The SPI for the outgoing SA is the new
	   SPI value from the UPDATE. The SPI for the incoming SA was
	   generated when NES was sent. */
	we_are_HITg = hip_hit_is_bigger(hitr, hits);
	HIP_DEBUG("we are: HIT%c\n", we_are_HITg ? 'g' : 'l');

	esp_transform = entry->esp_transform;
	esp_transf_length = hip_enc_key_length(esp_transform); /* needed below */
	auth_transf_length = hip_auth_key_length_esp(esp_transform);
	HIP_DEBUG("enckeylen=%d authkeylen=%d\n", esp_transf_length, auth_transf_length);
	calc_index_new = entry->keymat_calc_index;
	memcpy(Kn, entry->current_keymat_K, HIP_AH_SHA_LEN);
	err = hip_update_get_sa_keys(entry, &keymat_index, &calc_index_new, Kn,
					     &espkey_gl, &authkey_gl, &espkey_lg, &authkey_lg);
	if (err)
		goto out_err;
	/* todo: update entry keymat later */
	hip_update_entry_keymat(entry, keymat_index, calc_index_new, Kn);

	/* set up new outbound IPsec SA */
	new_spi_out = entry->stored_received_nes.new_spi;
	if (new_spi_out == 0) {
		HIP_ERROR("bug: stored New SPI in HA is 0\n");
		goto out_err;
	}
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

	prev_spi_out = entry->spi_out;
	prev_spi_in = entry->spi_in;

	entry->spi_out = new_spi_out;
	HIP_DEBUG("updated outbound SPI (SPI_OUT), new_spi_out=0x%x\n", new_spi_out);
	entry->default_spi_out = entry->spi_out;
	HIP_DEBUG("set default SPI out=0x%x\n", entry->default_spi_out);
#if 0
	hip_hadb_add_addr_to_spi(entry, entry->spi_out, src_ip, PEER_ADDR_STATE_ACTIVE, 0, 1);
#endif
	entry->new_spi_out = 0;
/* use the new inbound IPsec SA created when rekeying started */
	new_spi_in = entry->new_spi_in;

	HIP_DEBUG("copying keys to new updated inbound SA\n");

	/* todo: move this to security.c */
	_HIP_DEBUG("Searching for spi: 0x%x (0x%x)\n", new_spi_in, htonl(new_spi_in));
	xs = xfrm_state_lookup((xfrm_address_t *)hitr, htonl(new_spi_in),
			       IPPROTO_ESP, AF_INET6);
	if (!xs) {
		HIP_ERROR("Did not find SA for SPI 0x%x\n", new_spi_in);
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
		_HIP_DEBUG("Copied new keys to SA\n");

		/* THIS WILL MOST PROBABLY LEAK MEMORY (xs->type->init_state in esp6.c) */
		if (xs->type && xs->type->init_state(xs, NULL)) {
			HIP_ERROR("Could not reinitialize XFRM state\n");
		} else
			HIP_DEBUG("xs ESP reinit ok\n");
	}

	spin_unlock_bh(&xs->lock);
	xfrm_state_put(xs);

	HIP_DEBUG("switching to new updated inbound SPI=0x%x, new_spi_in\n", new_spi_in);

	hip_hadb_remove_state_spi(entry);
	entry->spi_in = new_spi_in;
	hip_hadb_insert_state(entry);

	_HIP_DEBUG("switch ok\n");

	/* clear out spi value from hadb */
	entry->new_spi_in = 0;

	/* activate the new inbound and outbound SAs */
	HIP_DEBUG("finalizing the new inbound SA, SPI=0x%x\n", new_spi_in);
	hip_finalize_sa(hitr, new_spi_in);
	HIP_DEBUG("finalizing the new outbound SA, SPI=0x%x\n", new_spi_out);
	hip_finalize_sa(hits, new_spi_out);

	/* 4.  The system cancels any timers protecting the UPDATE and
	   transitions to ESTABLISHED. */
	entry->state = HIP_STATE_ESTABLISHED;
	HIP_DEBUG("Went back to ESTABLISHED state\n");

	/* delete old SAs */
	/* todo: set SA state to dying */
	HIP_DEBUG("REMOVING OLD OUTBOUND IPsec SA, SPI=0x%x\n", prev_spi_out);
	err = hip_delete_sa(prev_spi_out, hits);
	HIP_DEBUG("delete_sa out retval=%d\n", err);

	HIP_DEBUG("REMOVING OLD INBOUND IPsec SA, SPI=0x%x\n", prev_spi_in);
	err = hip_delete_sa(prev_spi_in, hitr);

	hip_print_hit("map_del", hits);
	hip_ifindex2spi_map_del(entry, prev_spi_in);

	HIP_DEBUG("delete_sa in retval=%d\n", err);

 out_err:
	entry->update_state_flags = 0;
	return err;
}

/**
 * hip_handle_update_rekeying - handle incoming UPDATE packet received in REKEYING state
 * @msg: the HIP packet
 * @src_ip: source IPv6 address from where the UPDATE was sent
 *
 * This function handles case 8 in section 8.11 Processing UPDATE
 * packets of the base draft.
 *
 * Returns: 0 if successful, otherwise < 0.
 */
int hip_handle_update_rekeying(struct hip_common *msg, struct in6_addr *src_ip)
{
	int err = 0;
	struct in6_addr *hits = &msg->hits, *hitr = &msg->hitr;
	struct hip_common *update_packet = NULL;
	struct hip_nes *nes;
	struct hip_seq *seq;
	struct hip_ack *ack = NULL;
	hip_ha_t *entry = NULL;
	struct in6_addr daddr;
	struct hip_host_id *host_id_private;
	u8 signature[HIP_DSA_SIGNATURE_LEN];

	/* 8.11.2  Processing an UPDATE packet in state REKEYING */

	HIP_DEBUG("\n");

	entry = hip_hadb_find_byhit(hits);
	if (!entry) {
		HIP_ERROR("Entry not found\n");
		goto out_err;
	}
	HIP_LOCK_HA(entry);

	seq = hip_get_param(msg, HIP_PARAM_SEQ);
	nes = hip_get_param(msg, HIP_PARAM_NES);

	if (seq && nes) {
		/* 1. If the packet contains a SEQ and NES parameters, then the system
		   generates a new UPDATE packet with an ACK of the peer's Update ID
		   as received in the SEQ parameter. .. */

		update_packet = hip_msg_alloc();
		if (!update_packet) {
			HIP_DEBUG("update_packet alloc failed\n");
			err = -ENOMEM;
			goto out_err;
		}
		_HIP_DEBUG("update_packet=%p\n\n", update_packet);
		hip_build_network_hdr(update_packet, HIP_UPDATE, 0, hitr, hits);

		err = hip_build_param_ack(update_packet, ntohl(seq->update_id));
		if (err) {
			HIP_ERROR("Building of ACK param failed\n");
			goto out_err;
		}
		_HIP_DEBUG("ack+\n");
		_HIP_DUMP_MSG(update_packet);
	}

	/* .. Additionally, if the UPDATE packet contained an ACK of the
	   outstanding Update ID, or if the ACK of the UPDATE packet that
	   contained the NES has already been received, the system stores
	   the received NES and (optional) DIFFIE_HELLMAN parameters and
	   finishes the rekeying procedure as described in Section
	   8.11.3. If the ACK of the outstanding Update ID has not been
	   received, stay in state REKEYING after storing the recived NES
	   and (optional) DIFFIE_HELLMAN. */
	ack = hip_get_param(msg, HIP_PARAM_ACK);
	if (ack) {
		size_t n, i;
		uint32_t *peer_update_id;

		HIP_DEBUG("UPDATE contains ACK\n");
		if (hip_get_param_contents_len(ack) % sizeof(uint32_t)) {
			HIP_ERROR("ACK param length not divisible by 4 (%u)\n",
				  hip_get_param_contents_len(ack));
			goto out_err;
		}

		HIP_DEBUG("stored Update ID=%u\n", entry->stored_sent_update_id);
		n = hip_get_param_contents_len(ack) / sizeof(uint32_t);
		peer_update_id = (uint32_t *) ((void *)ack+sizeof(struct hip_tlv_common));
		for (i = 0; i < n; i++, peer_update_id++) {
			uint32_t puid = ntohl(*peer_update_id);

			HIP_DEBUG("ACK: peer Update ID=%u\n", puid);
			if (puid == entry->stored_sent_update_id) {
				HIP_DEBUG("this UPDATE is ACK to sent UPDATE\n");
				entry->update_state_flags |= 0x1;
				break;
			}
		}
	}

	if (nes && (entry->update_state_flags & 0x1)) {
		HIP_DEBUG("store NES and DH\n");
		/* todo: store DH here */
		entry->stored_received_nes.keymat_index = ntohs(nes->keymat_index);
		entry->stored_received_nes.old_spi = ntohl(nes->old_spi);
		entry->stored_received_nes.new_spi = ntohl(nes->new_spi);
		entry->update_state_flags |= 0x2;
	}

	HIP_DEBUG("update_state_flags=%d\n", entry->update_state_flags);
	if (entry->update_state_flags == 0x3) {
		/* our SEQ is now ACKed and peer's NES is stored */
		err = hip_update_finish_rekeying(msg, entry);
	}

	if (!update_packet) {
		HIP_DEBUG("not sending ACK\n");
		goto out;
	}

	/* send ACK */

	/* TODO: hmac/signature to common functions */
	/* Add HMAC */
	err = hip_build_param_hmac_contents(update_packet, &entry->hip_hmac_out);
	if (err) {
		HIP_ERROR("Building of HMAC failed (%d)\n", err);
		goto out_err;
	}

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
	_HIP_DEBUG("up=%p s=%p\n", update_packet, signature);
	_HIP_DUMP_MSG(update_packet);

	err = hip_build_param_signature_contents(update_packet, signature,
						 HIP_DSA_SIGNATURE_LEN,
 						 HIP_SIG_DSA);
 	if (err) {
 		HIP_ERROR("Building of SIGNATURE failed (%d)\n", err);
 		goto out_err;
 	}
	_HIP_DEBUG("SIGNATURE added\n");
	_HIP_DEBUG("sig+\n");
	_HIP_DUMP_MSG(update_packet);

        err = hip_hadb_get_peer_addr(entry, &daddr);
        if (err) {
                HIP_DEBUG("hip_sdb_get_peer_address err = %d\n", err);
                goto out_err;
        }

	HIP_DEBUG("Sending reply UPDATE packet (only ACK)\n");
	err = hip_csum_send(NULL, &daddr, update_packet);
	if (err) {
		HIP_DEBUG("hip_csum_send err=%d\n", err);
		HIP_DEBUG("NOT ignored, or should we..\n");
		/* fallback to established ? */
                /* goto out_err; ? */
	}

	out:

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
	struct hip_nes *nes = NULL;
	struct hip_seq *seq = NULL;
	struct hip_ack *ack = NULL;
	int state = 0;
	uint32_t pkt_update_id = 0; /* UPDATE ID in packet */
	uint32_t update_id_in = 0;  /* stored incoming UPDATE ID */
	int is_retransmission = 0;
	uint16_t keymat_index = 0;
	struct hip_dh_fixed *dh;
	struct in6_addr *src_ip;
	struct hip_lhi peer_lhi;
	struct hip_host_id *peer_id;
	hip_ha_t *entry = NULL;

	HIP_DEBUG("\n");
	msg = (struct hip_common *) skb->h.raw;
	_HIP_HEXDUMP("msg", msg, hip_get_msg_total_len(msg));

	src_ip = &(skb->nh.ipv6h->saddr);
	hits = &msg->hits;

#if 0
	{
		struct xfrm_state *xs;
		xs = xfrm_find_acq(XFRM_MODE_TRANSPORT, 0, IPPROTO_ESP,
				   (xfrm_address_t *)&msg->hitr, (xfrm_address_t *)hits,
				   1, AF_INET6);
		if (!xs) {
			HIP_ERROR("Error while acquiring an SA\n");
		} else {
			xfrm_alloc_spi(xs, htonl(256), htonl(0xFFFFFFFF));
			if (xs->id.spi == 0) {
				HIP_ERROR("Could not get SPI value for the SA\n");
			} else {
				HIP_DEBUG("Got SPI value for the SA 0x%x\n", ntohl(xs->id.spi));
			}
			xfrm_state_put(xs);
		}
	}
#endif

	entry = hip_hadb_find_byhit(hits);
	if (!entry) {
		HIP_ERROR("Entry not found\n");
		goto out_err;
	}
	HIP_LOCK_HA(entry);

	state = entry->state; /* todo: remove variable state */

	HIP_DEBUG("Received UPDATE in state %s\n", hip_state_str(state));

	/* in state R2-SENT: Receive UPDATE, go to ESTABLISHED and
	 * process from ESTABLISHED state */
	if (state == HIP_STATE_R2_SENT) {
		state = entry->state = HIP_STATE_ESTABLISHED;
		HIP_DEBUG("Moved from R2-SENT to ESTABLISHED\n");
	}

	if (! (state == HIP_STATE_ESTABLISHED || state == HIP_STATE_REKEYING) ) {
		HIP_DEBUG("Received UPDATE in illegal state %s. Dropping\n",
			  hip_state_str(state));
		err = -EINVAL;
		goto out_err;
	}

	nes = hip_get_param(msg, HIP_PARAM_NES);
	seq = hip_get_param(msg, HIP_PARAM_SEQ);
	ack = hip_get_param(msg, HIP_PARAM_ACK);

	if (nes) {
		HIP_DEBUG("UPDATE contains (at least one) NES parameter\n");
		keymat_index = ntohs(nes->keymat_index);
		HIP_DEBUG("NES: Keymaterial Index: %u\n", keymat_index);
		HIP_DEBUG("NES: Old SPI: 0x%x\n", ntohl(nes->old_spi));
		HIP_DEBUG("NES: New SPI: 0x%x\n", ntohl(nes->new_spi));
	}
	if (seq) {
		pkt_update_id = ntohl(seq->update_id);
		HIP_DEBUG("SEQ: UPDATE ID: %u\n", pkt_update_id);
	}
	if (ack) {
		size_t n, i;
		uint32_t *peer_update_id;
		if (hip_get_param_contents_len(ack) % sizeof(uint32_t)) {
			HIP_ERROR("ACK param length not divisible by 4 (%u)\n",
				  hip_get_param_contents_len(ack));
			goto out_err;
		}
		n = hip_get_param_contents_len(ack) / sizeof(uint32_t);
		peer_update_id = (uint32_t *) ((void *)ack+sizeof(struct hip_tlv_common));
		for (i = 0; i < n; i++, peer_update_id++) {
			uint32_t puid = ntohl(*peer_update_id);
			
			HIP_DEBUG("ACK: peer Update ID=%u\n", puid);
#if 1
			if (puid == entry->stored_sent_update_id) {
				HIP_DEBUG("is ack to sent seq\n");
				entry->update_state_flags |= 0x1;
			}
#endif
		}
	}

	/* 8.11 Processing UPDATE packets checks */
	if (seq && nes) {
		HIP_DEBUG("UPDATE has both SEQ and NES, peer host is rekeying, MUST process this UPDATE\n");
	}

	if (state == HIP_STATE_REKEYING && ack) {
		HIP_DEBUG("in REKEYING state and ACK, MUST process this UPDATE\n");
	}

	if ( !( (seq && nes) || (state == HIP_STATE_REKEYING && ack) ) ) {
		HIP_ERROR("NOT processing UPDATE packet\n");
		goto out_err;
	}

	update_id_in = entry->update_id_in;
	HIP_DEBUG("previous incoming update id=%u\n", update_id_in);
	if (seq) {
		/* 1. If the SEQ parameter is present, and the Update ID in the
		   received SEQ is smaller than the stored Update ID for the host,
		   the packet MUST BE dropped. */
		if (pkt_update_id < update_id_in) {
			HIP_DEBUG("SEQ param present and received UPDATE ID (%u) < stored incoming UPDATE ID (%u). Dropping\n",
				  pkt_update_id, update_id_in);
			err = -EINVAL;
			goto out_err;
		} else if (pkt_update_id == update_id_in) {
			/* 2. If the SEQ parameter is present, and the Update ID in the
			   received SEQ is equal to the stored Update ID for the host, the
			   packet is treated as a retransmission. */
			is_retransmission = 1;
			HIP_DEBUG("Retransmitted UPDATE packet (?), continuing\n");
			/* todo: ignore this packet or process anyway ? */
		}
	}

	/* 3. The system MUST verify the HMAC in the UPDATE packet.
	   If the verification fails, the packet MUST be dropped. */
	err = hip_verify_packet_hmac(msg, entry);
	if (err) {
		HIP_ERROR("HMAC validation on UPDATE failed\n");
		goto out_err;
	}
        _HIP_DEBUG("UPDATE HMAC ok\n");

	/* 4. If the received UPDATE contains a Diffie-Hellman
	   parameter, the received Keymat Index MUST be zero. If this
	   test fails, the packet SHOULD be dropped and the system
	   SHOULD log an error message. */
	// if (nes) HIP_DEBUG("packet keymat_index=%u\n", keymat_index);
	dh = hip_get_param(msg, HIP_PARAM_DIFFIE_HELLMAN);
	if (dh) {
		HIP_DEBUG("packet contains DH\n");
		if (!nes) {
			HIP_ERROR("packet contains DH but not NES\n");
			goto out_err;
		}
		if (keymat_index != 0) {
			HIP_ERROR("UPDATE contains Diffie-Hellman parameter with non-zero"
				  "keymat value %u in NES. Dropping\n",
				  keymat_index);
			err = -EINVAL;
			goto out_err;
		}
	}

	/* 5. The system MAY verify the SIGNATURE in the UPDATE
	   packet. If the verification fails, the packet SHOULD be
	   dropped and an error message logged. */
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
		_HIP_DEBUG("ignoring SIGNATURE fail\n");
		goto out_err;
	}
        _HIP_DEBUG("SIGNATURE ok\n");

	/* 6.  If a new SEQ parameter is being processed, the system MUST record
	   the Update ID in the received SEQ parameter, for replay
	   protection. */
	if (seq && !is_retransmission) {
		entry->update_id_in = pkt_update_id;
		HIP_DEBUG("Stored peer's incoming UPDATE ID %u\n", pkt_update_id);
	}

	/* check that Old SPI value exists */
	if (nes && (ntohl(nes->old_spi) != entry->spi_out)) {
		HIP_ERROR("Old SPI value 0x%x in NES parameter does not belong to the currentSPI 0x%x in HA\n",
			  ntohl(nes->old_spi), entry->spi_out);
		goto out_err;
	}

	/* cases 7-8: */
	if (state == HIP_STATE_ESTABLISHED) {
		if (nes && seq) {
			HIP_DEBUG("case 7: in ESTABLISHED and has NES and SEQ\n");
			err = hip_handle_update_established(msg, src_ip);
		} else {
			HIP_ERROR("in ESTABLISHED but no both NES and SEQ\n");
			err = -EINVAL;
		}
	} else {
		HIP_DEBUG("case 8: in REKEYING\n");
		err = hip_handle_update_rekeying(msg, src_ip);
	}

	if (err) {
		HIP_ERROR("UPDATE handler failed, err=%d\n", err);
		goto out_err;
	}

 out_err:
	if (entry) {
		HIP_UNLOCK_HA(entry);
		hip_put_ha(entry);
	}

	return err;
}

/* hip_send_update - send initial UPDATE packet to the peer */

/* if addr_list is non-NULL (netdev initiated sending of UPDATE), perform
   readdress without rekeying as in mm02-pre3 */
/* REA: addrlist items belong to the spi */
int hip_send_update(struct hip_hadb_state *entry, struct hip_rea_info_addr_item *addr_list,
		    int addr_count, int ifindex)
{
	int err = 0;
	uint32_t update_id_out = 0;
	uint32_t spi = 0;
	uint32_t new_spi_in = 0;
	struct hip_common *update_packet = NULL;
	struct in6_addr daddr;
	struct hip_host_id *host_id_private;
 	u8 signature[HIP_DSA_SIGNATURE_LEN];
	struct hip_crypto_key null_key;

	HIP_DEBUG("addr_list=0x%p addr_count=%d ifindex=%d\n",
		  addr_list, addr_count, ifindex);

	if (!entry) {
		HIP_ERROR("null entry\n");
		err = -EINVAL;
		goto out_err;
	}

	if (!addr_list)
		HIP_DEBUG("Plain UPDATE\n");
	else
		HIP_DEBUG("mm UPDATE\n");

	/* start building UPDATE packet */
	update_packet = hip_msg_alloc();
	if (!update_packet) {
		HIP_ERROR("update_packet alloc failed\n");
		err = -ENOMEM;
		goto out_err;
	}

	hip_print_hit("sending UPDATE to", &entry->hit_peer);
	hip_build_network_hdr(update_packet, HIP_UPDATE, 0, &entry->hit_our, &entry->hit_peer);

	/* mm stuff */
	if (addr_list && addr_count > 0) {
		spi = hip_ifindex2spi_get_spi(entry, ifindex);
		HIP_DEBUG("mapped spi=0x%x\n", spi);
		if (spi) {
			/* NES not needed */
			HIP_DEBUG("5.1 Mobility with single SA pair, readdress with no rekeying\n");
			/* 5.1 Mobility with single SA pair */
			err = hip_build_param_rea_info_mm02(update_packet, spi, addr_list, addr_count);
			if (err) {
				HIP_ERROR("Building of REA param failed\n");
				goto out_err;
			}
			goto plain_rea_out;
		}
	}

	/* we can not know yet from where we should start to draw keys
	   from the keymat, so we just zero a key and fill in the keys later */
	memset(&null_key.key, 0, HIP_MAX_KEY_LEN);
	/* get a New SPI, prepare a new incoming IPsec SA */

	/* TODO: Just call xfrm_alloc_spi instead */
	new_spi_in = 0;
	err = hip_setup_sa(&entry->hit_peer, &entry->hit_our,
			   &new_spi_in, entry->esp_transform,
			   &null_key.key, &null_key.key, 0);
	if (err) {
		HIP_ERROR("Error while setting up new IPsec SA (err=%d)\n", err);
		goto out_err;
	}
	HIP_DEBUG("New inbound SA created with New SPI (in)=0x%x\n", new_spi_in);
	entry->new_spi_in = new_spi_in;
	HIP_DEBUG("stored New SPI (NEW_SPI_IN=0x%x)\n", new_spi_in);

	if (ifindex) /* todo: move to rekeying_finish */
		hip_ifindex2spi_map_add(entry, new_spi_in, ifindex);

	if (addr_list && addr_count > 0) {
		/* tell the peer about additional interface */
		/* mm02-pre3 5.2 Host multihoming */
		err = hip_build_param_rea_info_mm02(update_packet, new_spi_in, addr_list, addr_count);
		if (err) {
			HIP_ERROR("Building of REA param failed\n");
			goto out_err;
		}
	}

	_HIP_ERROR("remove hip_get_new_update_id, Update ID is per HA\n");
	entry->update_id_out++;
	update_id_out = entry->update_id_out;
	HIP_DEBUG("outgoing UPDATE ID=%u\n", update_id_out);
	if (!update_id_out) { /* todo: handle this case */
		HIP_ERROR("outgoing UPDATE ID overflowed back to 0, bug ?\n");
		err = -EINVAL;
		goto out_err;
	}
	entry->stored_sent_update_id = update_id_out;
	memset(&entry->stored_received_nes, 0, sizeof(struct hip_nes));
	entry->update_state_flags = 0;

	HIP_DEBUG("entry->current_keymat_index=%u\n", entry->current_keymat_index);
	if (addr_list && addr_count > 0) /* mm02-pre3 5.2 Host multihoming */
		err = hip_build_param_nes(update_packet, entry->current_keymat_index,
					  new_spi_in, new_spi_in); 
	else /* plain UPDATE */
		err = hip_build_param_nes(update_packet, entry->current_keymat_index,
					  entry->spi_in, new_spi_in); 
	if (err) {
		HIP_ERROR("Building of NES param failed\n");
		goto out_err;
	}

	err = hip_build_param_seq(update_packet, update_id_out);
	if (err) {
		HIP_ERROR("Building of SEQ param failed\n");
		goto out_err;
	}

	/* TODO: hmac/signature to common functions */
	/* Add HMAC */
	err = hip_build_param_hmac_contents(update_packet, &entry->hip_hmac_out);
	if (err) {
		HIP_ERROR("Building of HMAC failed (%d)\n", err);
		goto out_err;
	}
	_HIP_DEBUG("HMAC added\n");

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
	_HIP_DEBUG("SIGNATURE added\n");

	entry->state = HIP_STATE_REKEYING;
	HIP_DEBUG("moved to state REKEYING\n");

 plain_rea_out:

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

	err = hip_csum_send(NULL, &daddr, update_packet);
	if (err) {
		HIP_DEBUG("hip_csum_send err=%d\n", err);
		_HIP_DEBUG("NOT ignored, or should we..\n");

		entry->state = HIP_STATE_ESTABLISHED;
		HIP_DEBUG("fallbacked to state ESTABLISHED due to error (ok ?)\n");
		goto out_err;
	}

	/* todo: 5. The system SHOULD start a timer whose timeout value should be ..*/
	goto out;

 out_err:
	entry->state = HIP_STATE_ESTABLISHED;
	HIP_DEBUG("fallbacked to state REKEYING (ok ?)\n");
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
 * state.
 *
 * Add REA parameter if @addr_list is non-null. @ifindex tells which
 * device caused the network device event.
 *
 * TODO: retransmission timers
 */
void hip_send_update_all(struct hip_rea_info_addr_item *addr_list, int addr_count, int ifindex)
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
			hip_send_update(rk.array[i], addr_list, addr_count, ifindex);
			hip_put_ha(rk.array[i]);
		}
	}

	return;
}
