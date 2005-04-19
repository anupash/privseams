/*
 * Licence: GNU/GPL
 * Authors:
 * - Mika Kousa <mkousa@cc.hut.fi>
 */

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


/* SPI waitlist stuff is not currently used */


#if 0
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
#endif


#if 0
/**
 * hip_update_spi_waitlist_add - add a SPI to SPI waitlist
 * @spi: the inbound SPI to be added in host byte order
 * @hit: the HIT for which the @spi is related to
 */
void hip_update_spi_waitlist_add(uint32_t spi, struct in6_addr *hit, struct hip_rea *rea)
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
#endif

#if 0
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
#endif

#if 0
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
#endif

#if 0
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
#if 0
	int err = 0, found = 0;
	struct hip_update_spi_waitlist_item *s = NULL;
	unsigned long flags = 0;
	struct list_head *pos, *n;
	int i = 1;
#endif

	HIP_DEBUG("skipping test, not needed anymore ?\n");
	return 0;
#if 0
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
//		hip_hadb_remove_state_spi(entry);
		entry->spi_out = entry->new_spi_out;
		hip_hadb_insert_state(entry);

		/* SETTING OF DEFAULT SPI THIS WAY IS BROKEN */
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
//		err = hip_delete_sa(old_spi_out, &s->hit);
		hip_hadb_delete_outbound_spi(entry, old_spi_out);
//		if (err)
//			HIP_DEBUG("delete_sa ret err=%d\n", err);
		entry->new_spi_out = 0;
#endif

		HIP_UNLOCK_HA(entry);
		hip_put_ha(entry);
		hip_update_spi_waitlist_delete(spi);
	}

 out:
	spin_unlock_irqrestore(&hip_update_spi_waitlist_lock, flags);
	return found;
#endif
}
#endif



/** hip_update_get_sa_keys - Get keys needed by UPDATE
 * @entry: corresponding hadb entry of the peer
 * @keymat_offset_new: value-result parameter for keymat index used
 * @calc_index_new: value-result parameter for the one byte index used
 * @Kn_out: value-result parameter for keymat 
 * @espkey_gl: HIP-gl encryption key
 * @authkey_gl: HIP-gl integrity (HMAC)
 * @espkey_lg: HIP-lg encryption key
 * @authkey_lg: HIP-lg integrity (HMAC)
 *
 * Returns: 0 on success (all encryption and integrity keys are
 * successfully stored and @keymat_offset_new, @calc_index_new, and
 * @Kn_out contain updated values). On error < 0 is returned.
 */
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

	_HIP_DEBUG("k=%u c=%u\n", k, c);

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

	_HIP_DEBUG("at end: k=%u c=%u\n", k, c);
	*keymat_offset_new = k;
	*calc_index_new = c;
	memcpy(Kn_out, Kn, HIP_AH_SHA_LEN);
 out_err:
	return err;
}

/** hip_update_test_rea_addr - test if IPv6 address is to be added into REA.
 * @addr: the IPv6 address to be tested
 *
 * Currently the following address types are ignored: unspecified
 * (any), loopback, link local, site local, and other not unicast
 * addresses.
 *
 * Returns 1 if address is ok to be used as a peer address, otherwise 0.
*/
int hip_update_test_rea_addr(struct in6_addr *addr)
{
	int addr_type = ipv6_addr_type(addr);

	if (addr_type == IPV6_ADDR_ANY) {
		HIP_DEBUG("skipping IPV6_ADDR_ANY address\n");
		return 0;
	}
	if (addr_type & IPV6_ADDR_LOOPBACK) {
		HIP_DEBUG("skipping loopback address, not supported\n");
		return 0;
	}
	if (addr_type & IPV6_ADDR_LINKLOCAL) {
		HIP_DEBUG("skipping link local address, not supported\n");
		return 0;
	}
	if (addr_type & IPV6_ADDR_SITELOCAL) {
		HIP_DEBUG("skipping site local address, not supported\n");
		return 0;
	}
	if (! (addr_type & IPV6_ADDR_UNICAST) ) {
		HIP_DEBUG("skipping non-unicast address\n");
		return 0;
	}

	return 1;
}

/** hip_update_handle_rea_parameter - Process REA parameters in the UPDATE
 * @entry: corresponding hadb entry of the peer
 * @rea: the REA parameter in the packet
 *
 * ietf-mm-02 7.2 Handling received REAs
 *
 * @entry must be is locked when this function is called.
 *
 * Returns: 0 if the REA parameter was processed successfully,
 * otherwise < 0.
 */
int hip_update_handle_rea_parameter(hip_ha_t *entry, struct hip_rea *rea)
{
	int err = 0; /* set to -Esomething ?*/
	uint32_t spi;
	struct hip_rea_info_addr_item *rea_address_item;
	int i, n_addrs;
	struct hip_spi_out_item *spi_out;
	struct hip_peer_addr_list_item *a, *tmp;

	spi = ntohl(rea->spi);
	HIP_DEBUG("REA SPI=0x%x\n", spi);

	if ((hip_get_param_total_len(rea) - sizeof(struct hip_rea)) %
	    sizeof(struct hip_rea_info_addr_item))
		HIP_ERROR("addr item list len modulo not zero, (len=%d)\n",
			  ntohs(rea->length));

	n_addrs = (hip_get_param_total_len(rea) - sizeof(struct hip_rea)) /
		sizeof(struct hip_rea_info_addr_item);
	HIP_DEBUG("REA has %d address(es), rea param len=%d\n",
		  n_addrs, hip_get_param_total_len(rea));
	if (n_addrs < 0) {
		HIP_DEBUG("BUG: n_addrs=%d < 0\n", n_addrs);
		goto out_err;
	}

	/* 1. The host checks if the SPI listed is a new one. If it
	   is a new one, it creates a new SPI that contains no addresses. */
	spi_out = hip_hadb_get_spi_list(entry, spi);
	if (!spi_out) {
		/* bug: outbound SPI must have been already created by the
		   corresponding NES in the same UPDATE packet */
		HIP_ERROR("bug: outbound SPI 0x%x does not exist\n", spi);
		goto out_err;
	}

	_HIP_DEBUG("Clearing old preferred flags of the SPI\n");
	list_for_each_entry_safe(a, tmp, &spi_out->peer_addr_list, list) {
		a->is_preferred = 0;
	}

	rea_address_item = (void *)rea+sizeof(struct hip_rea);
	for(i = 0; i < n_addrs; i++, rea_address_item++) {
		struct in6_addr *rea_address = &rea_address_item->address;
		uint32_t lifetime = ntohl(rea_address_item->lifetime);
		int is_preferred = ntohl(rea_address_item->reserved) == 1 << 31;

		hip_print_hit("REA address", rea_address);
		HIP_DEBUG(" addr %d: is_pref=%s reserved=0x%x lifetime=0x%x\n", i+1,
			   is_preferred ? "yes" : "no", ntohl(rea_address_item->reserved),
			  lifetime);
		/* 2. check that the address is a legal unicast or anycast address */
		if (!hip_update_test_rea_addr(rea_address))
			continue;

		if (i > 0) {
			/* preferred address allowed only for the first address */
			if (is_preferred)
				HIP_ERROR("bug, preferred flag set to other than the first address\n");
			is_preferred = 0;
		}
		/* 3. check if the address is already bound to the SPI + add/update address */
		err = hip_hadb_add_addr_to_spi(entry, spi, rea_address, 0,
					       lifetime, is_preferred);
		if (err) {
			HIP_DEBUG("failed to add/update address to the SPI list\n");
			goto out_err;
		}
	}

	/* 4. Mark all addresses on the SPI that were NOT listed in the REA
	   parameter as DEPRECATED. */
	_HIP_DEBUG("deprecating not listed address from the SPI list\n");

	list_for_each_entry_safe(a, tmp, &spi_out->peer_addr_list, list) {
		int spi_addr_is_in_rea = 0;

		rea_address_item = (void *)rea+sizeof(struct hip_rea);
		for(i = 0; i < n_addrs; i++, rea_address_item++) {
			struct in6_addr *rea_address = &rea_address_item->address;

			if (!ipv6_addr_cmp(&a->address, rea_address)) {
				spi_addr_is_in_rea = 1;
				break;
			}

		}
		if (!spi_addr_is_in_rea) {
			/* deprecate the address */
			hip_print_hit("deprecating address", &a->address);
			a->address_state = PEER_ADDR_STATE_DEPRECATED;
		}
	}

	if (n_addrs == 0) /* our own extension, use some other SPI */
		(void)hip_hadb_relookup_default_out(entry);
	/* relookup always ? */

	_HIP_DEBUG("done\n");
 out_err:
	return err;
}


/**
 * hip_handle_update_established - handle incoming UPDATE packet received in ESTABLISHED state
 * @entry: hadb entry corresponding to the peer
 * @msg: the HIP packet
 * @src_ip: source IPv6 address from where the UPDATE was sent
 * @dst_ip: destination IPv6 address where the UPDATE was received
 *
 * This function handles case 7 in section 8.11 Processing UPDATE
 * packets of the base draft.
 *
 * @entry must be is locked when this function is called.
 *
 * Returns: 0 if successful, otherwise < 0.
 */
int hip_handle_update_established(hip_ha_t *entry, struct hip_common *msg,
				  struct in6_addr *src_ip, struct in6_addr *dst_ip)
{
	int err = 0;
	struct in6_addr *hits = &msg->hits, *hitr = &msg->hitr;
	struct hip_nes *nes;
	struct hip_seq *seq;
	struct hip_rea *rea;
	struct hip_dh_fixed *dh;
	struct hip_host_id *host_id_private;
	uint32_t update_id_out = 0;
	uint32_t prev_spi_in = 0, new_spi_in = 0;
	uint16_t keymat_index = 0;
	struct hip_common *update_packet = NULL;
	//struct in6_addr daddr;
 	u8 signature[HIP_RSA_SIGNATURE_LEN]; /* RSA sig > DSA sig */
	int need_to_generate_key = 0, dh_key_generated = 0; //, new_keymat_generated;
	int nes_i = 1;
	uint16_t mask;

	HIP_DEBUG("\n");

	seq = hip_get_param(msg, HIP_PARAM_SEQ);
	if (!seq) {
		HIP_ERROR("No SEQ parameter in packet\n");
		goto out_err;
	}

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
	mask = hip_create_control_flags(0, 0, HIP_CONTROL_SHT_TYPE1,
					HIP_CONTROL_DHT_TYPE1);
	hip_build_network_hdr(update_packet, HIP_UPDATE, mask, hitr, hits);

	/*  3. The system increments its outgoing Update ID by one. */
	entry->update_id_out++;
	update_id_out = entry->update_id_out;
	_HIP_DEBUG("outgoing UPDATE ID=%u\n", update_id_out);
	if (!update_id_out) { /* todo: handle this case */
		HIP_ERROR("outgoing UPDATE ID overflowed back to 0, bug ?\n");
		err = -EINVAL;
		goto out_err;
	}

	/* test: handle multiple NES, not tested well yet */
 handle_nes:
	nes = hip_get_nth_param(msg, HIP_PARAM_NES, nes_i);
	if (!nes) {
		HIP_DEBUG("no more NES params found\n");
		goto nes_params_handled;
	}
	HIP_DEBUG("Found NES parameter [%d]\n", nes_i);

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
		_HIP_DEBUG("Using Keymat Index from NES\n");
		keymat_index = ntohs(nes->keymat_index);
	}

	/* Set up new incoming IPsec SA, (Old SPI value to put in NES tlv) */
	prev_spi_in = hip_get_spi_to_update_in_established(entry, dst_ip);
	HIP_DEBUG("Old incoming SA selected for update, prev_spi_in=0x%x\n", prev_spi_in);
	if (!prev_spi_in)
		goto out_err;

	new_spi_in = hip_acquire_spi(hits, hitr);
	if (!new_spi_in) {
		HIP_ERROR("Error while acquiring a SPI\n");
		goto out_err;
	}
	HIP_DEBUG("acquired inbound SPI 0x%x\n", new_spi_in);
	hip_update_set_new_spi_in(entry, prev_spi_in, new_spi_in, ntohl(nes->old_spi));

	/* draft-hip-mm test */
	if (nes->old_spi == nes->new_spi) {
		struct hip_spi_out_item spi_out_data;

		_HIP_DEBUG("peer has a new SA, create a new outbound SA\n");
		memset(&spi_out_data, 0, sizeof(struct hip_spi_out_item));
		spi_out_data.spi = ntohl(nes->new_spi);
		spi_out_data.seq_update_id = ntohl(seq->update_id);
		err = hip_hadb_add_spi(entry, HIP_SPI_DIRECTION_OUT, &spi_out_data);
		if (err) {
			goto out_err;
		}
		HIP_DEBUG("added SPI=0x%x to list of outbound SAs (SA not created yet)\n",
			  ntohl(nes->new_spi));
	}

	/* testing REA parameters in UPDATE */
	rea = hip_get_nth_param(msg, HIP_PARAM_REA, nes_i);
	if (rea) {
		HIP_DEBUG("Found REA parameter [%d]\n", nes_i);
		if (rea->spi != nes->new_spi) {
			HIP_ERROR("SPI 0x%x in REA is not equal to the New SPI 0x%x in NES\n",
				  ntohl(rea->spi), ntohl(nes->new_spi));
		} else {
			err = hip_update_handle_rea_parameter(entry, rea);
			_HIP_DEBUG("rea param handling ret %d\n", err);
			err = 0;
		}
	}

	/* associate Old SPI with Update ID, NES received, store
	 * received NES and proposed keymat index value used in the reply NES */
	hip_update_set_status(entry, prev_spi_in,
			      0x1 | 0x2 | 0x4 | 0x8, update_id_out, 0x2,
			      nes, keymat_index);

	nes_i++;
	goto handle_nes;

 nes_params_handled:

	/* 5.  The system sends the UPDATE packet and transitions to state
	   REKEYING.  The system stores any received NES and DIFFIE_HELLMAN
	   parameters. */

	err = hip_build_param_nes(update_packet, keymat_index,
				  prev_spi_in, new_spi_in);
	if (err) {
		HIP_ERROR("Building of NES failed\n");
		goto out_err;
	}

	err = hip_build_param_seq(update_packet, update_id_out);
	if (err) {
		HIP_ERROR("Building of SEQ failed\n");
		goto out_err;
	}

	/* ACK the received UPDATE SEQ */
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
	host_id_private = hip_get_any_localhost_host_id(HIP_HI_DEFAULT_ALGO);
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

	if (HIP_HI_DEFAULT_ALGO == HIP_HI_RSA) {
		err = hip_build_param_signature_contents(update_packet,
							 signature,
							 HIP_RSA_SIGNATURE_LEN,
							 HIP_SIG_RSA);
	} else {
		err = hip_build_param_signature_contents(update_packet,
							 signature,
							 HIP_DSA_SIGNATURE_LEN,
							 HIP_SIG_DSA);
	}

 	if (err) {
 		HIP_ERROR("Building of SIGNATURE failed (%d)\n", err);
 		goto out_err;
 	}
	_HIP_DEBUG("SIGNATURE added\n");

#if 0
        err = hip_hadb_get_peer_addr(entry, &daddr);
        if (err) {
                HIP_DEBUG("hip_sdb_get_peer_address err = %d\n", err);
                goto out_err;
        }
#endif
	/* 5.  The system sends the UPDATE packet and transitions to state
	   REKEYING. */
	entry->state = HIP_STATE_REKEYING;
	HIP_DEBUG("moved to state REKEYING\n");

        HIP_DEBUG("Sending reply UPDATE packet\n");
	//err = hip_csum_send(NULL, &daddr, update_packet);
	err = hip_csum_send(NULL, src_ip, update_packet);
	if (err) {
		HIP_DEBUG("hip_csum_send err=%d\n", err);
		HIP_DEBUG("NOT ignored, or should we..\n");
		/* fallback to established ? */
                /* goto out_err; ? */
	}

 out_err:
	if (update_packet)
		kfree(update_packet);
	if (err) {
		hip_set_spi_update_status(entry, prev_spi_in, 0);
		/* SA remove not tested yet */
		if (new_spi_in) {
			//hip_delete_sa(new_spi_in, hitr);
			hip_hadb_delete_inbound_spi(entry, new_spi_in);
		}
	}

	return err;
}

int hip_update_send_addr_verify(hip_ha_t *entry, struct hip_common *msg,
				struct in6_addr *src_ip, uint32_t spi);


/** hip_update_finish_rekeying - finish handling of REKEYING state
 * @msg: the HIP packet
 * @entry: hadb entry corresponding to the peer
 * @nes: the NES param to be handled in the received UPDATE
 * 
 * Performs items described in 8.11.3 Leaving REKEYING state of he
 * base draft-01.
 *
 * Parameters in @nes are host byte order.
 * @entry must be is locked when this function is called.
 *
 * On success new IPsec SAs are created. Old SAs are deleted if the
 * UPDATE was not the multihoming case.
 *
 * Returns: 0 if successful, otherwise < 0.
 */
int hip_update_finish_rekeying(struct hip_common *msg, hip_ha_t *entry,
			       struct hip_nes *nes)
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
	struct hip_spi_in_item spi_in_data;
	struct hip_ack *ack;
	uint16_t kmindex_saved;

	HIP_DEBUG("\n");
	ack = hip_get_param(msg, HIP_PARAM_ACK);

	HIP_DEBUG("handled NES: Old SPI: 0x%x\n", nes->old_spi);
	HIP_DEBUG("handled NES: New SPI: 0x%x\n", nes->new_spi);
	HIP_DEBUG("handled NES: Keymat Index: %u\n", nes->keymat_index);

	prev_spi_out = nes->old_spi;
	if (!prev_spi_out) {
		HIP_ERROR("bug: stored NES Old SPI is 0\n");
		goto out_err;
	}

	new_spi_out = nes->new_spi;
	if (!new_spi_out) {
		HIP_ERROR("bug: stored NES New SPI is 0\n");
		goto out_err;
	}

	prev_spi_in = hip_update_get_prev_spi_in(entry, ntohl(ack->peer_update_id));

	/* use the new inbound IPsec SA created when rekeying started */
	new_spi_in = hip_update_get_new_spi_in(entry, ntohl(ack->peer_update_id));
	if (!new_spi_in) {
		HIP_ERROR("Did not find related New SPI for peer Update ID %u\n",
			  ntohl(ack->peer_update_id));
		goto out_err;
	}
	HIP_DEBUG("prev_spi_in=0x%x new_spi_in=0x%x prev_spi_out=0x%x new_spi_out=0x%x\n",
		  prev_spi_in, new_spi_in, prev_spi_out, new_spi_out);

	kmindex_saved = hip_update_get_spi_keymat_index(entry, ntohl(ack->peer_update_id));
	if (!kmindex_saved) {
		HIP_ERROR("saved kmindex is 0\n");
		goto out_err;
	}
	_HIP_DEBUG("saved kmindex for NES is %u\n", kmindex_saved);

	/* 2. .. If the system did not generate new KEYMAT, it uses
	   the lowest Keymat Index of the two NES parameters. */
	_HIP_DEBUG("entry keymat index=%u\n", entry->current_keymat_index);
	if (kmindex_saved < nes->keymat_index)
		keymat_index = kmindex_saved;
	else
		keymat_index = nes->keymat_index;
	_HIP_DEBUG("lowest keymat_index=%u\n", keymat_index);

	/* 3. The system draws keys for new incoming and outgoing ESP
	   SAs, starting from the Keymat Index, and prepares new incoming
	   and outgoing ESP SAs. */
	we_are_HITg = hip_hit_is_bigger(hitr, hits);
	HIP_DEBUG("we are: HIT%c\n", we_are_HITg ? 'g' : 'l');

	esp_transform = entry->esp_transform;
	esp_transf_length = hip_enc_key_length(esp_transform);
	auth_transf_length = hip_auth_key_length_esp(esp_transform);
	_HIP_DEBUG("enckeylen=%d authkeylen=%d\n", esp_transf_length, auth_transf_length);
	calc_index_new = entry->keymat_calc_index;
	memcpy(Kn, entry->current_keymat_K, HIP_AH_SHA_LEN);
	err = hip_update_get_sa_keys(entry, &keymat_index, &calc_index_new, Kn,
					     &espkey_gl, &authkey_gl, &espkey_lg, &authkey_lg);
	if (err)
		goto out_err;
	/* todo: update entry keymat later */
	hip_update_entry_keymat(entry, keymat_index, calc_index_new, Kn);

	/* set up new outbound IPsec SA */
	HIP_DEBUG("Setting new outbound SA, SPI=0x%x\n", new_spi_out);
	err = hip_setup_sa(hitr, hits, &new_spi_out, esp_transform,
			   we_are_HITg ? &espkey_gl.key : &espkey_lg.key,
			   we_are_HITg ? &authkey_gl.key : &authkey_lg.key,
			   0, HIP_SPI_DIRECTION_OUT);
	if (err) {
		HIP_ERROR("Setting up new outbound IPsec failed (%d)\n", err);
		goto out_err;
	}
	HIP_DEBUG("Set up new outbound IPsec SA, SPI=0x%x\n", new_spi_out);

	HIP_DEBUG("Setting new inbound SA, SPI=0x%x\n", new_spi_in);
	err = hip_setup_sa(hits, hitr, &new_spi_in, entry->esp_transform,
			   we_are_HITg ? &espkey_lg  : &espkey_gl,
			   we_are_HITg ? &authkey_lg : &authkey_gl,
			   1, HIP_SPI_DIRECTION_IN);
	if (err) {
		HIP_ERROR("Error while setting up new IPsec SA (err=%d)\n", err);
		goto out_err;
	}
	HIP_DEBUG("New inbound SA created with SPI=0x%x\n", new_spi_in);

	if (prev_spi_in == new_spi_in) {
		memset(&spi_in_data, 0, sizeof(struct hip_spi_in_item));
		spi_in_data.spi = new_spi_in;
		spi_in_data.ifindex = hip_hadb_get_spi_ifindex(entry, prev_spi_in);/* already set ? */
		err = hip_hadb_add_spi(entry, HIP_SPI_DIRECTION_IN, &spi_in_data);
		if (err)
			goto out_err;
	} else
		_HIP_DEBUG("Old SPI <> New SPI, not adding a new inbound SA\n");

	/* activate the new inbound and outbound SAs */
	_HIP_DEBUG("finalizing the new inbound SA, SPI=0x%x\n", new_spi_in);
	hip_finalize_sa(hitr, new_spi_in);
	_HIP_DEBUG("finalizing the new outbound SA, SPI=0x%x\n", new_spi_out);
	hip_finalize_sa(hits, new_spi_out);

	HIP_DEBUG("switching inbound SPIs: 0x%x -> 0x%x\n", prev_spi_in, new_spi_in);
	hip_update_switch_spi_in(entry, prev_spi_in);

	hip_update_set_new_spi_out(entry, prev_spi_out, new_spi_out); /* temporary fix */
	HIP_DEBUG("switching outbound SPIs: 0x%x -> 0x%x\n", prev_spi_out, new_spi_out);
	hip_update_switch_spi_out(entry, prev_spi_out);

	hip_set_spi_update_status(entry, new_spi_in, 0);
	hip_update_clear_status(entry, new_spi_in);

	// if (is not mm update) ?
	hip_hadb_set_default_out_addr(entry, hip_hadb_get_spi_list(entry, new_spi_out), NULL);

	/* 4.  The system cancels any timers protecting the UPDATE and
	   transitions to ESTABLISHED. */
	entry->state = HIP_STATE_ESTABLISHED;
	HIP_DEBUG("Went back to ESTABLISHED state\n");

	/* delete old SAs */
	if (prev_spi_out != new_spi_out) {
		HIP_DEBUG("REMOVING OLD OUTBOUND IPsec SA, SPI=0x%x\n", prev_spi_out);
		err = hip_delete_sa(prev_spi_out, hits);
		HIP_DEBUG("TODO: set new spi to 0\n");
		_HIP_DEBUG("delete_sa out retval=%d\n", err);
		err = 0;
	} else
		HIP_DEBUG("prev SPI_out = new SPI_out, not deleting the outbound SA\n");

	if (prev_spi_in != new_spi_in) {
		HIP_DEBUG("REMOVING OLD INBOUND IPsec SA, SPI=0x%x\n", prev_spi_in);
		err = hip_delete_sa(prev_spi_in, hitr);
		/* remove old HIT-SPI mapping and add a new mapping */

		/* actually should change hip_hadb_delete_inbound_spi
		 * somehow, but we do this or else delete_inbound_spi
		 * would delete both old and new SPIs */
		hip_hadb_remove_hs(prev_spi_in);
		err = hip_hadb_insert_state_spi_list(entry, new_spi_in);
		if (err == -EEXIST) {
			HIP_DEBUG("HIT-SPI mapping already exists, hmm ..\n");
			err = 0;
		} else if (err) {
			HIP_ERROR("Could not add a HIT-SPI mapping for SPI 0x%x (err=%d)\n",
				  new_spi_in, err);
		}
	} else
		_HIP_DEBUG("prev SPI_in = new SPI_in, not deleting the inbound SA\n");

	/* start verifying addresses */
	_HIP_DEBUG("start verifing addresses for new spi 0x%x\n", new_spi_out);
	err = hip_update_send_addr_verify(entry, msg, NULL /* ok ? */, new_spi_out);

	/* hip_update_spi_waitlist_add(new_spi_in, hits, NULL); */

 out_err:
	return err;
}

/**
 * hip_handle_update_rekeying - handle incoming UPDATE packet received in REKEYING state
 * @entry: hadb entry corresponding to the peer
 * @msg: the HIP packet
 * @src_ip: source IPv6 address from where the UPDATE was sent
 *
 * This function handles case 8 in section 8.11 Processing UPDATE
 * packets of the base draft.
 *
 * @entry must be is locked when this function is called.
 *
 * Returns: 0 if successful, otherwise < 0.
 */
int hip_handle_update_rekeying(hip_ha_t *entry, struct hip_common *msg,
			       struct in6_addr *src_ip)
{
	int err = 0;
	struct in6_addr *hits = &msg->hits, *hitr = &msg->hitr;
	struct hip_common *update_packet = NULL;
	struct hip_nes *nes = NULL;
	struct hip_seq *seq = NULL;
	struct hip_ack *ack = NULL;
	struct in6_addr daddr;
	struct hip_host_id *host_id_private;
	u8 signature[HIP_RSA_SIGNATURE_LEN]; /* RSA sig > DSA sig */
	uint16_t mask;

	/* 8.11.2  Processing an UPDATE packet in state REKEYING */

	HIP_DEBUG("\n");

	seq = hip_get_param(msg, HIP_PARAM_SEQ);
	nes = hip_get_param(msg, HIP_PARAM_NES);
	ack = hip_get_param(msg, HIP_PARAM_ACK);

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
		mask = hip_create_control_flags(0, 0, HIP_CONTROL_SHT_TYPE1,
						HIP_CONTROL_DHT_TYPE1);
		hip_build_network_hdr(update_packet, HIP_UPDATE, mask, hitr, hits);

		err = hip_build_param_ack(update_packet, ntohl(seq->update_id));
		if (err) {
			HIP_ERROR("Building of ACK param failed\n");
			goto out_err;
		}
	}


	if (nes && ack) { /* kludge */
		uint32_t s = hip_update_get_prev_spi_in(entry, ntohl(ack->peer_update_id));
		_HIP_DEBUG("s=0x%x\n", s);
		hip_update_set_status(entry, s, 0x4, 0, 0, nes, 0);
	}
	/* .. Additionally, if the UPDATE packet contained an ACK of the
	   outstanding Update ID, or if the ACK of the UPDATE packet that
	   contained the NES has already been received, the system stores
	   the received NES and (optional) DIFFIE_HELLMAN parameters and
	   finishes the rekeying procedure as described in Section
	   8.11.3. If the ACK of the outstanding Update ID has not been
	   received, stay in state REKEYING after storing the recived NES
	   and (optional) DIFFIE_HELLMAN. */

	if (ack) /* breaks if packet has no ack but nes exists ? */
		hip_update_handle_ack(entry, ack, nes ? 1 : 0, NULL);
//	if (nes)
//		hip_update_handle_nes(entry, puid); /* kludge */

	/* finish SAs if we have received ACK and NES */
	{
		struct hip_spi_in_item *item, *tmp;

		list_for_each_entry_safe(item, tmp, &entry->spis_in, list) {
			_HIP_DEBUG("test item: spi_in=0x%x seq=%u updflags=0x%x\n",
				  item->spi, item->seq_update_id, item->update_state_flags);
			if (item->update_state_flags == 0x3) {
				err = hip_update_finish_rekeying(msg, entry, &item->stored_received_nes);
				_HIP_DEBUG("update_finish handling ret err=%d\n", err);
			}
		}
		err = 0;
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
	host_id_private = hip_get_any_localhost_host_id(HIP_HI_DEFAULT_ALGO);
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

	if (HIP_HI_DEFAULT_ALGO == HIP_HI_RSA) {
		err = hip_build_param_signature_contents(update_packet,
							 signature,
							 HIP_RSA_SIGNATURE_LEN,
							 HIP_SIG_RSA);
	} else {
		err = hip_build_param_signature_contents(update_packet,
							 signature,
							 HIP_DSA_SIGNATURE_LEN,
							 HIP_SIG_DSA);
	}

 	if (err) {
 		HIP_ERROR("Building of SIGNATURE failed (%d)\n", err);
 		goto out_err;
 	}
	_HIP_DEBUG("SIGNATURE added\n");


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
	/* if (err)
	   TODO: REMOVE IPSEC SAs
	   move to state = ?
	*/
	if (update_packet)
		kfree(update_packet);
	
	return err;
}


/**
 * hip_update_send_addr_verify - send address verification UPDATE
 * @entry: hadb entry corresponding to the peer
 * @msg: the HIP packet
 * @src_ip: source IPv6 address to use in the UPDATE to be sent out
 * @spi: outbound SPI in host byte order
 *
 * @entry must be is locked when this function is called.
 *
 * Returns: 0 if successful, otherwise < 0.
 */
int hip_update_send_addr_verify(hip_ha_t *entry, struct hip_common *msg,
				struct in6_addr *src_ip, uint32_t spi)
{
	int err = 0;
	struct in6_addr *hits = &msg->hits, *hitr = &msg->hitr;
	struct hip_spi_out_item *spi_out;
	struct hip_peer_addr_list_item *addr, *tmp;
	struct hip_common *update_packet = NULL;
	uint16_t mask;

	HIP_DEBUG("SPI=0x%x\n", spi);

	spi_out = hip_hadb_get_spi_list(entry, spi);
	if (!spi_out) {
		HIP_DEBUG("bug: outbound SPI 0x%x does not exist\n", spi);
		goto out_err;
	}

	/* start checking the addresses */

	update_packet = hip_msg_alloc();
	if (!update_packet) {
		HIP_ERROR("update_packet alloc failed\n");
		err = -ENOMEM;
		goto out_err;
	}

	mask = hip_create_control_flags(0, 0, HIP_CONTROL_SHT_TYPE1,
					HIP_CONTROL_DHT_TYPE1);
	hip_build_network_hdr(update_packet, HIP_UPDATE, mask, hitr, hits);

	list_for_each_entry_safe(addr, tmp, &spi_out->peer_addr_list, list) {
		u8 signature[HIP_RSA_SIGNATURE_LEN]; /* RSA > DSA */
		struct hip_host_id *host_id_private;

		hip_print_hit("new addr to check", &addr->address);

		if (addr->address_state == PEER_ADDR_STATE_DEPRECATED) {
			_HIP_DEBUG("addr state is DEPRECATED, not verifying\n");
			continue;
		}

		if (addr->address_state == PEER_ADDR_STATE_ACTIVE) {
			_HIP_DEBUG("not verifying already active address\n"); 
			if (addr->is_preferred) {
				HIP_DEBUG("TEST (maybe should not do this yet?): setting already active address and set as preferred to default addr\n");
				hip_hadb_set_default_out_addr(entry, spi_out, &addr->address);
			}
			continue;
		}

		hip_msg_init(update_packet);
		mask = hip_create_control_flags(0, 0, HIP_CONTROL_SHT_TYPE1,
						HIP_CONTROL_DHT_TYPE1);
		hip_build_network_hdr(update_packet, HIP_UPDATE, mask, hitr, hits);

		err = hip_build_param_spi(update_packet, 0x11223344); /* test */
		if (err) {
			HIP_ERROR("Building of SPI failed\n");
			goto out_err;
		}

		entry->update_id_out++;
		addr->seq_update_id = entry->update_id_out;
		_HIP_DEBUG("outgoing UPDATE ID for REA addr check=%u\n", addr->seq_update_id);
		/* todo: handle overflow if (!update_id_out) */
		err = hip_build_param_seq(update_packet, addr->seq_update_id);
		if (err) {
			HIP_ERROR("Building of SEQ failed\n");
			continue;
		}

		/* Add HMAC */
		err = hip_build_param_hmac_contents(update_packet, &entry->hip_hmac_out);
		if (err) {
			HIP_ERROR("Building of HMAC failed (%d)\n", err);
			continue;
		}

		/* Add SIGNATURE */
		host_id_private = hip_get_any_localhost_host_id(HIP_HI_DEFAULT_ALGO);
		if (!host_id_private) {
			HIP_ERROR("Could not get own host identity. Can not sign data\n");
			continue;
		}

		if (!hip_create_signature(update_packet, hip_get_msg_total_len(update_packet),
					  host_id_private, signature)) {
			HIP_ERROR("Could not sign UPDATE. Failing\n");
			continue;
		}

		if (HIP_HI_DEFAULT_ALGO == HIP_HI_RSA) {
			err = hip_build_param_signature_contents(update_packet,
								 signature,
							 HIP_RSA_SIGNATURE_LEN,
							 HIP_SIG_RSA);
		} else {
			err = hip_build_param_signature_contents(update_packet,
								 signature,
							 HIP_DSA_SIGNATURE_LEN,
								 HIP_SIG_DSA);
		}

		if (err) {
			HIP_ERROR("Building of SIGNATURE failed (%d)\n", err);
			continue;
		}

		get_random_bytes(addr->echo_data, sizeof(addr->echo_data));
		_HIP_HEXDUMP("ECHO_REQUEST in REA addr check",
			     addr->echo_data, sizeof(addr->echo_data));
		err = hip_build_param_echo(update_packet, addr->echo_data ,
					   sizeof(addr->echo_data), 0, 1);
		if (err) {
			HIP_ERROR("Building of ECHO_REQUEST failed\n");
			continue;
		}


		HIP_DEBUG("Sending reply UPDATE packet (for REA)\n");
		/* test: send all addr check from same address */
		err = hip_csum_send(src_ip, &addr->address, update_packet);
		if (err) {
			HIP_DEBUG("hip_csum_send err=%d\n", err);
			HIP_DEBUG("NOT ignored, or should we..\n");
		}
	}

 out_err:
	if (update_packet)
		kfree(update_packet);

	_HIP_DEBUG("done, err=%d\n", err);
	return err;
}


/** hip_handle_update_plain_rea - handle UPDATE(REA, SEQ)
 * @entry: hadb entry corresponding to the peer
 * @msg: the HIP packet
 * @src_ip: source IPv6 address to use in the UPDATE to be sent out
 * @dst_ip: destination IPv6 address to use in the UPDATE to be sent out
 *
 * @entry must be is locked when this function is called.
 *
 * For each address in the REA, we reply with ACK and
 * UPDATE(SPI, SEQ, ACK, ECHO_REQUEST)
 *
 * Returns: 0 if successful, otherwise < 0.
 */
int hip_handle_update_plain_rea(hip_ha_t *entry, struct hip_common *msg,
				struct in6_addr *src_ip, struct in6_addr *dst_ip)
{
	int err = 0;
	struct in6_addr *hits = &msg->hits, *hitr = &msg->hitr;
	struct hip_common *update_packet = NULL;
	struct hip_seq *seq;
	struct hip_rea *rea;
	uint16_t mask;

	HIP_DEBUG("\n");

	update_packet = hip_msg_alloc();
	if (!update_packet) {
		HIP_ERROR("update_packet alloc failed\n");
		err = -ENOMEM;
		goto out_err_nolock;
	}

	mask = hip_create_control_flags(0, 0, HIP_CONTROL_SHT_TYPE1,
					HIP_CONTROL_DHT_TYPE1);
	hip_build_network_hdr(update_packet, HIP_UPDATE, mask, hitr, hits);

	/* ACK the received UPDATE SEQ */
	seq = hip_get_param(msg, HIP_PARAM_SEQ);
	err = hip_build_param_ack(update_packet, ntohl(seq->update_id));
	if (err) {
		HIP_ERROR("Building of ACK failed\n");
		goto out_err_nolock;
	}

	HIP_DEBUG("Sending reply UPDATE packet (for REA)\n");
	err = hip_csum_send(dst_ip, src_ip, update_packet);
	if (err) {
		HIP_DEBUG("hip_csum_send err=%d\n", err);
		HIP_DEBUG("NOT ignored, or should we..\n");
	}


	rea = hip_get_param(msg, HIP_PARAM_REA);
	hip_update_handle_rea_parameter(entry, rea);
	err = hip_update_send_addr_verify(entry, msg, dst_ip, ntohl(rea->spi));

 out_err_nolock:
	if (update_packet)
		kfree(update_packet);
	return err;
}


/** hip_handle_update_addr_verify - handle address verification UPDATE
 * @entry: hadb entry corresponding to the peer
 * @msg: the HIP packet
 * @src_ip: source IPv6 address to use in the UPDATE to be sent out
 * @dst_ip: destination IPv6 address to use in the UPDATE to be sent out
 *
 * @entry must be is locked when this function is called.
 *
 * handle UPDATE(SPI, SEQ, ACK, ECHO_REQUEST) or handle UPDATE(SPI,
 * SEQ, ECHO_REQUEST)
 *
 * Returns: 0 if successful, otherwise < 0.
 */
int hip_handle_update_addr_verify(hip_ha_t *entry, struct hip_common *msg,
				  struct in6_addr *src_ip, struct in6_addr *dst_ip)
{
	int err = 0;
	struct in6_addr *hits = &msg->hits, *hitr = &msg->hitr;
	struct hip_common *update_packet = NULL;
	struct hip_seq *seq = NULL;
	struct hip_echo_request *echo = NULL;
 	u8 signature[HIP_RSA_SIGNATURE_LEN]; /* RSA > DSA */
	struct hip_host_id *host_id_private;
	uint16_t mask;

	/* assume already locked entry */

	HIP_DEBUG("\n");

	echo = hip_get_param(msg, HIP_PARAM_ECHO_REQUEST);
	if (!echo) {
		HIP_ERROR("ECHO not found\n");
		goto out_err;
	}

	seq = hip_get_param(msg, HIP_PARAM_SEQ);
	if (!seq) {
		HIP_ERROR("SEQ not found\n");
		goto out_err;
	}

	update_packet = hip_msg_alloc();
	if (!update_packet) {
		HIP_ERROR("update_packet alloc failed\n");
		err = -ENOMEM;
		goto out_err;
	}

	mask = hip_create_control_flags(0, 0, HIP_CONTROL_SHT_TYPE1,
					HIP_CONTROL_DHT_TYPE1);
	hip_build_network_hdr(update_packet, HIP_UPDATE, mask, hitr, hits);

	/* reply with UPDATE(ACK, ECHO_RESPONSE) */
	err = hip_build_param_ack(update_packet, ntohl(seq->update_id));
	if (err) {
		HIP_ERROR("Building of ACK failed\n");
		goto out_err;
	}

	/* Add HMAC */
	err = hip_build_param_hmac_contents(update_packet, &entry->hip_hmac_out);
	if (err) {
		HIP_ERROR("Building of HMAC failed (%d)\n", err);
		goto out_err;
	}

	/* Add SIGNATURE */
	host_id_private = hip_get_any_localhost_host_id(HIP_HI_DEFAULT_ALGO);
	if (!host_id_private) {
		HIP_ERROR("Could not get own host identity. Can not sign data\n");
		goto out_err;
	}

	if (!hip_create_signature(update_packet,
				  hip_get_msg_total_len(update_packet),
				  host_id_private, signature)) {
		HIP_ERROR("Could not sign UPDATE. Failing\n");
		err = -EINVAL;
		goto out_err;
	}

	if (HIP_HI_DEFAULT_ALGO == HIP_HI_RSA) {
		err = hip_build_param_signature_contents(update_packet,
							 signature,
							 HIP_RSA_SIGNATURE_LEN,
							 HIP_SIG_RSA);
	} else {	
		err = hip_build_param_signature_contents(update_packet,
							 signature,
							 HIP_DSA_SIGNATURE_LEN,
							 HIP_SIG_DSA);
	}

 	if (err) {
 		HIP_ERROR("Building of SIGNATURE failed (%d)\n", err);
 		goto out_err;
 	}

	/* ECHO_RESPONSE (no sign) */
	HIP_DEBUG("echo opaque data len=%d\n",
		   hip_get_param_contents_len(echo));
	err = hip_build_param_echo(update_packet,
				   (void *)echo+sizeof(struct hip_tlv_common),
				   hip_get_param_contents_len(echo), 0, 0);
	if (err) {
		HIP_ERROR("Building of ECHO_RESPONSE failed\n");
		goto out_err;
	}

	HIP_DEBUG("Sending reply UPDATE packet (address check)\n");
	err = hip_csum_send(dst_ip, src_ip, update_packet);
	if (err) {
		HIP_DEBUG("hip_csum_send err=%d\n", err);
		HIP_DEBUG("NOT ignored, or should we..\n");
	}

 out_err:
	if (update_packet)
		kfree(update_packet);
	return err;
}


/**
 * hip_receive_update - receive UPDATE packet
 * @skb: sk_buff where the HIP packet is in
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
	struct hip_rea *rea = NULL;
	struct hip_echo_request *echo = NULL;
	struct hip_echo_response *echo_response = NULL;
	struct hip_hmac *hmac = NULL;
	struct hip_signature *signature = NULL;
	int state = 0;
	uint32_t pkt_update_id = 0; /* UPDATE ID in packet */
	uint32_t update_id_in = 0;  /* stored incoming UPDATE ID */
	int is_retransmission = 0;
	uint16_t keymat_index = 0;
	struct hip_dh_fixed *dh;
	struct in6_addr *src_ip, *dst_ip;
	struct hip_lhi peer_lhi;
	struct hip_host_id *peer_id;
	int handle_upd = 0;
	hip_ha_t *entry = NULL;

	HIP_DEBUG("\n");
	msg = (struct hip_common *) skb->h.raw;
	_HIP_HEXDUMP("msg", msg, hip_get_msg_total_len(msg));

	src_ip = &(skb->nh.ipv6h->saddr);
	dst_ip = &(skb->nh.ipv6h->daddr);
	hits = &msg->hits;

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

	if (! (state == HIP_STATE_ESTABLISHED ||
	       state == HIP_STATE_REKEYING) ) {
		HIP_DEBUG("Received UPDATE in illegal state %s. Dropping\n",
			  hip_state_str(state));
		err = -EINVAL;
		goto out_err;
	}

	nes = hip_get_param(msg, HIP_PARAM_NES);
	seq = hip_get_param(msg, HIP_PARAM_SEQ);
	ack = hip_get_param(msg, HIP_PARAM_ACK);
	rea = hip_get_param(msg, HIP_PARAM_REA);
	echo = hip_get_param(msg, HIP_PARAM_ECHO_REQUEST);
	echo_response = hip_get_param(msg, HIP_PARAM_ECHO_RESPONSE);

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
	if (ack)
		HIP_DEBUG("ACK found\n");
	if (rea)
		HIP_DEBUG("REA: SPI 0x%x\n", ntohl(rea->spi));
	if (echo)
		HIP_DEBUG("ECHO_REQUEST found\n");
	if (echo_response)
		HIP_DEBUG("ECHO_RESPONSE found\n");

	/* 8.11 Processing UPDATE packets checks */
	if (seq && nes) {
		HIP_DEBUG("UPDATE has both SEQ and NES, peer host is rekeying, MUST process this UPDATE\n");
		handle_upd = 1;
	}

	if (!handle_upd && state == HIP_STATE_REKEYING && ack && !echo) {
		HIP_DEBUG("in REKEYING state and ACK and not ECHO_REQUEST, MUST process this UPDATE\n");
		handle_upd = 1;
	}

	/* mm-02 UPDATE tests */
	if (!handle_upd && rea && seq && !nes) {
		HIP_DEBUG("have REA and SEQ but no NES, process this UPDATE\n");
		handle_upd = 2;
	}

	//if (!handle_upd && /* SPI && */ seq && ack && !nes && echo) {
	if (!handle_upd && /* SPI && */ seq && !nes && echo) {
		/* ACK might have been in a separate packet */
		HIP_DEBUG("have SEQ,ECHO_REQUEST but no NES, process this UPDATE\n");
		handle_upd = 3;
	}
	if (!handle_upd && ack && echo) {
		HIP_DEBUG("have ACK and ECHO_REQUEST, process this UPDATE\n");
		handle_upd = 4;
	}

	if (!handle_upd && ack) {
		HIP_DEBUG("have only ACK, process this UPDATE\n");
		handle_upd = 5;
	}

	if (!handle_upd) {
		HIP_ERROR("NOT processing UPDATE packet\n");
		goto out_err;
	}

	update_id_in = entry->update_id_in;
	_HIP_DEBUG("previous incoming update id=%u\n", update_id_in);
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

	HIP_DEBUG("handle_upd=%d\n", handle_upd);
	if (handle_upd > 1) {
		_HIP_DEBUG("MM-02 UPDATE\n");
	}

	hmac = hip_get_param(msg, HIP_PARAM_HMAC);
	if (hmac) {
		/* 3. The system MUST verify the HMAC in the UPDATE packet.
		   If the verification fails, the packet MUST be dropped. */
		err = hip_verify_packet_hmac(msg, &entry->hip_hmac_in);
		if (err) {
			HIP_ERROR("HMAC validation on UPDATE failed\n");
			goto out_err;
		}
		_HIP_DEBUG("UPDATE HMAC ok\n");
	} else {
		HIP_DEBUG("HMAC not found, error ?\n");
	}

	/* 4. If the received UPDATE contains a Diffie-Hellman
	   parameter, the received Keymat Index MUST be zero. If this
	   test fails, the packet SHOULD be dropped and the system
	   SHOULD log an error message. */
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
	signature = hip_get_param(msg, HIP_PARAM_HIP_SIGNATURE);
	if (signature) {
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
	} else
		HIP_DEBUG("SIGNATURE not found, error ?\n");

	/* 6.  If a new SEQ parameter is being processed, the system MUST record
	   the Update ID in the received SEQ parameter, for replay
	   protection. */
	if (seq && !is_retransmission) {
		entry->update_id_in = pkt_update_id;
		_HIP_DEBUG("Stored peer's incoming UPDATE ID %u\n", pkt_update_id);
	}

	/* check that Old SPI value exists */
	if (nes &&
	    (nes->old_spi != nes->new_spi) && /* mm check */
	    !hip_update_exists_spi(entry, ntohl(nes->old_spi), HIP_SPI_DIRECTION_OUT, 0)) {
		HIP_ERROR("Old SPI value 0x%x in NES parameter does not belong to the current list of outbound SPIs in HA\n",
			  ntohl(nes->old_spi));
		goto out_err;
	}

	if (handle_upd == 2) {
		/* REA, SEQ */
		err = hip_handle_update_plain_rea(entry, msg, src_ip, dst_ip);
	} else if (handle_upd == 3) {
		/* SPI, SEQ, ACK, ECHO_REQUEST */
		err = hip_handle_update_addr_verify(entry, msg, src_ip, dst_ip);
	} else if (handle_upd == 5) {
		/* ACK, ECHO_RESPONSE */
		hip_update_handle_ack(entry, ack, 0, echo_response);
	} else {
		/* base draft cases 7-8: */
		if (state == HIP_STATE_ESTABLISHED) {
			if (nes && seq) {
				HIP_DEBUG("case 7: in ESTABLISHED and has NES and SEQ\n");
				err = hip_handle_update_established(entry, msg, src_ip, dst_ip);
			} else {
				HIP_ERROR("in ESTABLISHED but no both NES and SEQ\n");
				err = -EINVAL;
			}
		} else {
			HIP_DEBUG("case 8: in REKEYING\n");
			err = hip_handle_update_rekeying(entry, msg, src_ip);
		}
	}

 out_err:
	if (err)
		HIP_ERROR("UPDATE handler failed, err=%d\n", err);

	if (entry) {
		HIP_UNLOCK_HA(entry);
		hip_put_ha(entry);
	}
	return err;
}

/** hip_copy_spi_in_addresses - copy addresses to the inbound SPI
 * @src: address list
 * @spi_in: the inbound SPI the addresses are copied to
 * @count: number of addresses in @src
 *
 * A simple helper function to copy interface addresses to the inbound
 * SPI of. Caller must kfree the allocated memory.
 *
 * Returns: 0 on success, < 0 otherwise.
 */
int hip_copy_spi_in_addresses(struct hip_rea_info_addr_item *src,
			      struct hip_spi_in_item *spi_in,
			      int count) {
	HIP_DEBUG("src=0x%p count=%d\n", src, count);
	size_t s = count * sizeof(struct hip_rea_info_addr_item);
	void *p = NULL;

	if (!spi_in || (src && count <= 0)) {
 		HIP_ERROR("!spi_in or src & illegal count (%d)\n", count);
		return -EINVAL;
	}

	if (src) {
		p = kmalloc(s, GFP_ATOMIC);
		if (!p) {
			HIP_ERROR("kmalloc failed\n");
			return -ENOMEM;
		}
		memcpy(p, src, s);
	} else
		count = 0;

	_HIP_DEBUG("prev addresses_n=%d\n", spi_in->addresses_n);
	if (spi_in->addresses) {
		HIP_DEBUG("kfreeing old address list at 0x%p\n",
			  spi_in->addresses);
		kfree(spi_in->addresses);
	}

	spi_in->addresses_n = count;
	spi_in->addresses = p;
	return 0;
}

#define SEND_UPDATE_NES (1 << 0)
#define SEND_UPDATE_REA (1 << 1)

/** hip_send_update - send initial UPDATE packet to the peer
 * @entry: hadb entry corresponding to the peer
 * @addr_list: if non-NULL, REA parameter is added to the UPDATE
 * @addr_count: number of addresses in @addr_list
 * @ifindex: if non-zero, the ifindex value of the interface which caused the event
 * @flags: TODO comment
 *
 * Returns: 0 if UPDATE was sent, otherwise < 0.
 */
int hip_send_update(struct hip_hadb_state *entry,
		    struct hip_rea_info_addr_item *addr_list,
		    int addr_count, int ifindex, int flags)
{
	int err = 0;
	uint32_t update_id_out = 0;
	uint32_t mapped_spi = 0; /* SPI of the SA mapped to the ifindex */
	uint32_t new_spi_in = 0;
	struct hip_common *update_packet = NULL;
	struct in6_addr daddr;
	struct hip_host_id *host_id_private;
 	u8 signature[HIP_RSA_SIGNATURE_LEN]; /* RSA > DSA */
	int make_new_sa = 0;
	int add_nes = 0, add_rea;
	uint32_t nes_old_spi = 0, nes_new_spi = 0;
	uint16_t mask;
	struct hip_spi_in_item *spi_in = NULL;

	add_rea = flags & SEND_UPDATE_REA;
	HIP_DEBUG("addr_list=0x%p addr_count=%d ifindex=%d flags=0x%x\n",
		  addr_list, addr_count, ifindex, flags);
	if (!ifindex)
		_HIP_DEBUG("base draft UPDATE\n");

	if (add_rea)
		_HIP_DEBUG("mm UPDATE, %d addresses in REA\n", addr_count);
	else
		_HIP_DEBUG("Plain UPDATE\n");

	HIP_LOCK_HA(entry);

	/* start building UPDATE packet */
	update_packet = hip_msg_alloc();
	if (!update_packet) {
		HIP_ERROR("update_packet alloc failed\n");
		err = -ENOMEM;
		goto out_err;
	}

	hip_print_hit("sending UPDATE to", &entry->hit_peer);
	mask = hip_create_control_flags(0, 0, HIP_CONTROL_SHT_TYPE1,
					HIP_CONTROL_DHT_TYPE1);
	hip_build_network_hdr(update_packet, HIP_UPDATE, mask,
			      &entry->hit_our, &entry->hit_peer);
	if (add_rea) {
		/* mm stuff, per-ifindex SA */
		/* reuse old SA if we have one, else create a new SA */
		mapped_spi = hip_hadb_get_spi(entry, ifindex);
		HIP_DEBUG("mapped_spi=0x%x\n", mapped_spi);
		if (mapped_spi) {
			/* NES not needed */
			add_nes = 0;
			make_new_sa = 0;
			_HIP_DEBUG("5.1 Mobility with single SA pair, readdress with no rekeying\n");
			HIP_DEBUG("Reusing old SA\n");
			/* 5.1 Mobility with single SA pair */
		} else {
			_HIP_DEBUG("5.2 Host multihoming\n");
			make_new_sa = 1;
			_HIP_DEBUG("TODO\n");
		}
	} else {
		/* base draft UPDATE, create a new SA anyway */
		_HIP_DEBUG("base draft UPDATE, create a new SA\n");
		make_new_sa = 1;
	}

	/* If this is mm-UPDATE (ifindex should be then != 0) avoid
	 * sending empty REAs to the peer if we have not sent previous
	 * information on this ifindex/SPI yet */
	if (ifindex != 0 && mapped_spi == 0 && addr_count == 0) {
		HIP_DEBUG("NETDEV_DOWN and ifindex not advertised yet, returning\n");
		goto out;
	}

	if (make_new_sa) {
		HIP_DEBUG("make_new_sa=1 -> add_nes=1\n");
		add_nes = 1;
	}

	HIP_DEBUG("add_nes=%d make_new_sa=%d\n", add_nes, make_new_sa);

	if (make_new_sa) {
		new_spi_in = hip_acquire_spi(&entry->hit_peer, &entry->hit_our);
		if (!new_spi_in) {
			HIP_ERROR("Error while acquiring a SPI\n");
			goto out_err;
		}
		HIP_DEBUG("Got SPI value for the SA 0x%x\n", new_spi_in);

		/* TODO: move to rekeying_finish */
		if (!mapped_spi) {
			struct hip_spi_in_item spi_in_data;

			_HIP_DEBUG("previously unknown ifindex, creating a new item to inbound spis_in\n");
			memset(&spi_in_data, 0, sizeof(struct hip_spi_in_item));
			spi_in_data.spi = new_spi_in;
			spi_in_data.ifindex = ifindex;
			spi_in_data.updating = 1;
			err = hip_hadb_add_spi(entry, HIP_SPI_DIRECTION_IN, &spi_in_data);
			if (err) {
				HIP_ERROR("add_spi failed\n");
				goto out_err;
			}
		}
		else {
			_HIP_DEBUG("is previously mapped ifindex\n");
		}
	} else
		_HIP_DEBUG("not creating a new SA\n");

	_HIP_DEBUG("entry->current_keymat_index=%u\n", entry->current_keymat_index);

	if (add_rea) {
		/* REA is the first parameter of the UPDATE */
		if (mapped_spi)
			err = hip_build_param_rea(update_packet, mapped_spi,
							    addr_list, addr_count);
		else
			err = hip_build_param_rea(update_packet, new_spi_in,
							    addr_list, addr_count);
		if (err) {
			HIP_ERROR("Building of REA param failed\n");
			goto out_err;
		}
	} else
		HIP_DEBUG("not adding REA\n");

	if (add_nes) {
		if (addr_list) {
			if (make_new_sa) {
				/* mm02 5.2 Host multihoming */
				HIP_DEBUG("mm-02, adding NES, Old SPI == New SPI\n");
				/* notify the peer about new interface */
				nes_old_spi = new_spi_in;
				nes_new_spi = new_spi_in;

			} else {
				HIP_DEBUG("mm-02, !makenewsa\n");
				nes_old_spi = mapped_spi;
				nes_new_spi = new_spi_in;
			}
		} else {
			HIP_DEBUG("adding NES, Old SPI <> New SPI\n");
			/* plain UPDATE or readdress with rekeying */
			/* update the SA of the interface which caused the event */
			nes_old_spi = hip_hadb_get_spi(entry, ifindex);
			if (!nes_old_spi) {
				HIP_ERROR("Could not find SPI to use in Old SPI\n");
				goto out_err;
			}
			hip_set_spi_update_status(entry, nes_old_spi, 1); /* here or later ? */
			nes_new_spi = new_spi_in;
		}

		HIP_DEBUG("nes_old_spi=0x%x nes_new_spi=0x%x\n", nes_old_spi, nes_new_spi);
		err = hip_build_param_nes(update_packet, entry->current_keymat_index,
					  nes_old_spi, nes_new_spi);  
		if (err) {
			HIP_ERROR("Building of NES param failed\n");
			goto out_err;
		}
	} else {
		HIP_DEBUG("not adding NES\n");
		nes_old_spi = nes_new_spi = mapped_spi;
	}


	/* avoid advertising the same address set */
	/* (currently assumes that lifetime or reserved field do not
	 * change, later store only addresses) */
	spi_in = hip_hadb_get_spi_in_list(entry, nes_old_spi);
	if (!spi_in) {
		HIP_ERROR("SPI listaddr list copy failed\n");
		goto out_err;
	}
	if (addr_count == spi_in->addresses_n &&
	    addr_list && spi_in->addresses &&
	    memcmp(addr_list, spi_in->addresses,
		   addr_count*sizeof(struct hip_rea_info_addr_item)) == 0) {
		HIP_DEBUG("Same address set as before, return\n");
		goto out;
	} else
		HIP_DEBUG("Address set has changed, continue\n");

	hip_update_set_new_spi_in(entry, nes_old_spi, nes_new_spi, 0);

	entry->update_id_out++;
	update_id_out = entry->update_id_out;
	_HIP_DEBUG("outgoing UPDATE ID=%u\n", update_id_out);
	if (!update_id_out) { /* todo: handle this case */
		HIP_ERROR("outgoing UPDATE ID overflowed back to 0, bug ?\n");
		err = -EINVAL;
		goto out_err;
	}

	err = hip_build_param_seq(update_packet, update_id_out);
	if (err) {
		HIP_ERROR("Building of SEQ param failed\n");
		goto out_err;
	}

	if (add_nes) {
		/* remember the update id of this update */
		hip_update_set_status(entry, nes_old_spi,
				      0x1 | 0x2 | 0x8, update_id_out, 0, NULL,
				      entry->current_keymat_index);
	}

	/* Add HMAC */
	err = hip_build_param_hmac_contents(update_packet, &entry->hip_hmac_out);
	if (err) {
		HIP_ERROR("Building of HMAC failed (%d)\n", err);
		goto out_err;
	}

	/* Add SIGNATURE */
	host_id_private = hip_get_any_localhost_host_id(HIP_HI_DEFAULT_ALGO);
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

	if (HIP_HI_DEFAULT_ALGO == HIP_HI_RSA) {
		err = hip_build_param_signature_contents(update_packet,
							 signature,
							 HIP_RSA_SIGNATURE_LEN,
							 HIP_SIG_RSA);
	} else {
		err = hip_build_param_signature_contents(update_packet,
							 signature,
							 HIP_DSA_SIGNATURE_LEN,
							 HIP_SIG_DSA);
	}

 	if (err) {
 		HIP_ERROR("Building of SIGNATURE failed (%d)\n", err);
 		goto out_err;
 	}

	/* send UPDATE */
        err = hip_hadb_get_peer_addr(entry, &daddr);
        if (err) {
                HIP_DEBUG("hip_sdb_get_peer_addr err=%d\n", err);
                goto out_err;
        }

#if 0
	/* Store the last UPDATE ID value sent from us */
	entry->update_id_out = update_id_out;
        _HIP_DEBUG("Stored peer's outgoing UPDATE ID %u\n", update_id_out);
#endif

	hip_set_spi_update_status(entry, nes_old_spi, 1);

	/* if UPDATE contains only REA, then do not move state ? */
	if (add_nes) {
		entry->state = HIP_STATE_REKEYING;
		HIP_DEBUG("moved to state REKEYING\n");
	} else
		HIP_DEBUG("experimental: staying in ESTABLISHED (NES not added)\n");


        HIP_DEBUG("Sending initial UPDATE packet\n");
	err = hip_csum_send(NULL, &daddr, update_packet);
	if (err) {
		HIP_DEBUG("hip_csum_send err=%d\n", err);
		_HIP_DEBUG("NOT ignored, or should we..\n");

		entry->state = HIP_STATE_ESTABLISHED;
		HIP_DEBUG("fallbacked to state ESTABLISHED due to error (ok ?)\n");
		goto out_err;
	}

	/* remember the address set we have advertised to the peer */
	err = hip_copy_spi_in_addresses(addr_list, spi_in, addr_count);
	if (err) {
		HIP_ERROR("addr list copy failed\n");
		goto out_err;
	}

	/* todo: 5. The system SHOULD start a timer whose timeout value should be ..*/
	goto out;

 out_err:
	entry->state = HIP_STATE_ESTABLISHED;
	HIP_DEBUG("fallbacked to state ESTABLISHED (ok ?)\n");
	hip_set_spi_update_status(entry, nes_old_spi, 0);
	/* delete IPsec SA on failure */
	HIP_ERROR("TODO: delete SA\n");
 out:
	HIP_UNLOCK_HA(entry);
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

/* Internal function copied originally from rea.c */
static int hip_update_get_all_valid(hip_ha_t *entry, void *op)
{
	struct hip_update_kludge *rk = op;

	if (rk->count >= rk->length)
		return -1;

	if (entry->hastate == HIP_HASTATE_HITOK && entry->state == HIP_STATE_ESTABLISHED) {
		rk->array[rk->count] = entry;
		hip_hold_ha(entry);
		rk->count++;
	} else
		HIP_DEBUG("skipping HA entry 0x%p\n", entry);

	return 0;
}

/**
 * hip_send_update_all - send UPDATE packet to every peer
 * @addr_list: if non-NULL, REA parameter is added to the UPDATE
 * @addr_count: number of addresses in @addr_list
 * @ifindex: if non-zero, the ifindex value of the interface which caused the event
 * @flags: flags passed to @hip_send_update
 *
 * UPDATE is sent to the peer only if the peer is in established
 * state.
 *
 * Add REA parameter if @addr_list is non-null. @ifindex tells which
 * device caused the network device event.
 */
void hip_send_update_all(struct hip_rea_info_addr_item *addr_list, int addr_count,
			 int ifindex, int flags)
{
	int err = 0, i;
	hip_ha_t *entries[HIP_MAX_HAS] = {0};
	struct hip_update_kludge rk;

	HIP_DEBUG("ifindex=%d\n", ifindex);
	if (!ifindex) {
		HIP_DEBUG("test: returning, ifindex=0 (fix this for non-mm UPDATE)\n");
		return;
	}

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
			hip_send_update(rk.array[i], addr_list, addr_count, ifindex, flags);
			hip_put_ha(rk.array[i]);
		}
	}

	return;
}
