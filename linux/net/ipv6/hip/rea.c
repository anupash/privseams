#include "rea.h"
#include "debug.h"
#include "output.h"
#include "builder.h"
#include "input.h"
#include "misc.h"
#include "rvs.h"

#include <asm/atomic.h>
#include <linux/spinlock.h>
#include <linux/ipv6.h>
#include <linux/list.h>
#include <linux/timer.h>
#include <linux/skbuff.h>
#include <net/ipv6.h>
#include <net/hip.h>
#include <net/addrconf.h>


spinlock_t hip_sent_rea_info_lock = SPIN_LOCK_UNLOCKED;
spinlock_t hip_sent_ac_info_lock = SPIN_LOCK_UNLOCKED;

atomic_t hip_rea_ac_id = ATOMIC_INIT(0);
spinlock_t hip_rea_ac_id_lock = SPIN_LOCK_UNLOCKED;
atomic_t hip_rea_id = ATOMIC_INIT(0);
spinlock_t hip_rea_id_lock = SPIN_LOCK_UNLOCKED;


/**
 * hip_get_next_atomic_val_16 - get the next number of given atomic variable
 * @a: the atomic variable
 * @lock: atomic operations are protected 
 *
 * @a is truncated to 16 bits, so this function retuns values from the
 * range of 0-65535.
 *
 * Returns the new value of @a.
 */
uint16_t hip_get_next_atomic_val_16(atomic_t *a, spinlock_t *lock)
{
	uint16_t val;

	_HIP_DEBUG("entering\n");
	spin_lock_bh(lock);
	atomic_inc(a);
	atomic_clear_mask(~0xffff, a);
	val = atomic_read(a);
	spin_unlock_bh(lock);

	return val;
}

/**
 * hip_get_new_ac_id - get a new AC ID number
 *
 * Returns the next value of AC ID to use.
 */
uint16_t hip_get_new_ac_id(void) {
	uint16_t id;

	id = hip_get_next_atomic_val_16(&hip_rea_ac_id, &hip_rea_ac_id_lock);
	_HIP_DEBUG("got AC ID %u\n", id);
	return id;
}

/**
 * hip_rea_check_received_rea_id - check if REA was sent to the HIT
 * @rea_id: REA ID in host byte order
 * @hit: HIT where REA was sent
 *
 * Returns 1: if we have sent a REA packet containing REA ID @rea_id to
 * HIT @hit, 0 otherwise.
 */
int hip_rea_check_received_rea_id(uint16_t rea_id, struct in6_addr *hit) {
	int err = 0;
	struct hip_sent_rea_info *sent_rea, *tmp;
	int i = 1;

	spin_lock_bh(&hip_sent_rea_info_lock);
	HIP_DEBUG("rea_id=%u\n", rea_id);

	list_for_each_entry_safe(sent_rea, tmp, &hip_sent_rea_info_pkts, list) {
		_HIP_DEBUG("check %d: rea_id=%u (net=%u)\n",
			  i, sent_rea->rea_id, htohn(sent_rea->rea_id));
		if (sent_rea->rea_id == rea_id &&
		    !ipv6_addr_cmp(&sent_rea->hit, hit)) {
			err = 1;
			goto out;
		}
		i++;
	}
	HIP_ERROR("REA ID %u not found\n", rea_id);
 out:
	spin_unlock_bh(&hip_sent_rea_info_lock);
	return err;
}

/**
 * hip_rea_check_received_ac_id - check if AC was sent to IPv6 address
 * @rea_id: REA ID in host byte order
 * @ac_id: AC ID in host byte order
 * @src_ip: IPv6 address where AC was sent to
 * @ip: where @src_ip is copied to
 * @lifetime: where lifetime of address @src_ip is copied to
 * @interface: where Interface ID of address @src_ip is copied to
 * @rtt_sent: where the time when AC was sent is copied to
 *
 * Returns: 1 if we have sent an AC packet containing @rea_id as its
 * REA ID and @ac_id as its AC ID to @src_ip, @src_ip is copied to
 * @ip, address lifetime, Interface ID associated with @src_ip and the
 * time when AC was sent are assigned to @lifetime, @interface_id and
 * @rtt_sent (if they are non-NULL). Otherwise 0 is returned.
 */
int hip_rea_check_received_ac_id(uint16_t rea_id, uint16_t ac_id,
				 struct in6_addr *src_ip, struct in6_addr *ip,
				 uint32_t *lifetime, uint32_t *interface_id,
				 unsigned long *rtt_sent) {
	int err = 0;
	struct hip_sent_ac_info *sent_ac, *tmp;
	char addrstr[INET6_ADDRSTRLEN];

	spin_lock_bh(&hip_sent_ac_info_lock);
	HIP_DEBUG("rea_id=%u ac_id=%u\n", rea_id, ac_id);

	list_for_each_entry_safe(sent_ac, tmp, &hip_sent_ac_info_pkts, list) {
		hip_in6_ntop(&sent_ac->ip, addrstr);
		if (sent_ac->rea_id == rea_id && sent_ac->ac_id == ac_id &&
		    !ipv6_addr_cmp(&sent_ac->ip, src_ip)) {
			ipv6_addr_copy(ip, &sent_ac->ip);
			if (lifetime)
				*lifetime = sent_ac->lifetime;
			if (interface_id)
				*interface_id = sent_ac->interface_id;
			if (rtt_sent)
				*rtt_sent = sent_ac->rtt_sent;
			err = 1;
			goto out;
		}
	}

	HIP_ERROR("Not found (AC ID=%u, REA ID=%u)\n", ac_id, rea_id);
 out:
	spin_unlock_bh(&hip_sent_ac_info_lock);
	return err;
}


/**
 * hip_receive_ac_or_acr - handle incoming AC or ACR packet
 * @skb: sk_buff where the HIP packet is in
 * @hip_common: pointer to HIP header
 * @pkt_type: %HIP_AC for AC packets and %HIP_ACR for ACR packets
 *
 * Returns: 0 if the packet was processed successfully, otherwise
 * nonzero.
 */
int hip_receive_ac_or_acr(struct sk_buff *skb, int pkt_type)
{
	int err = 0;
	struct hip_common *msg = NULL;
	struct hip_ac_info *ac_info;
	struct hip_common *hip_common;
	hip_ha_t *entry = NULL;

	unsigned long recv_time = jiffies;
	char *pkt_descr;

	HIP_DEBUG("\n");

	hip_common = (struct hip_common *)(skb)->h.raw;

	if (!(pkt_type == HIP_AC || pkt_type == HIP_ACR)) {
	  HIP_ERROR("Illegal pkt_type %d\n", pkt_type);
	  err = -EINVAL;
	  goto out_err;
	}
	pkt_descr = pkt_type == HIP_AC ? "AC" : "ACR";

	_HIP_HEXDUMP(pkt_descr, hip_common, hip_get_msg_total_len(hip_common));
	_HIP_HEXDUMP("pkt v6 saddr", &skb->nh.ipv6h->saddr, sizeof(struct in6_addr));
	_HIP_HEXDUMP("pkt v6 daddr", &skb->nh.ipv6h->daddr, sizeof(struct in6_addr));

	entry = hip_hadb_find_byhit(&hip_common->hits);
	if (!entry) {
		err = -ENOMSG;
		HIP_ERROR("Received %s but no state with peer. Dropping\n", pkt_descr);
		goto out_err;
	}

	/* todo: use hip_tlv_sane */
	msg = (struct hip_common *) skb->h.raw;

	ac_info = hip_get_param(msg, HIP_PARAM_AC_INFO);
	if (!ac_info) {
		HIP_ERROR("%s contained no AC_INFO parameter\n", pkt_descr);
		err = -ENOMSG;
		goto out_err;
	}
	HIP_DEBUG("AC_INFO found\n");


        /* verify HMAC */
	err = hip_verify_packet_hmac(msg, entry);
	if (err) {
		HIP_ERROR("HMAC validation on %s failed\n", pkt_descr);
		goto out_err;
	}
        HIP_DEBUG("HMAC ok\n");

	if (pkt_type == HIP_AC) {
		/* AC handling specific functions */

		/* check if we have sent the corresponding REA
		 * (draft-nikander-hip-mm-00.txt sec 5.3) */
		if (!hip_rea_check_received_rea_id(ntohs(ac_info->rea_id), &msg->hits)) {
			HIP_ERROR("Found no corresponding REA ID for received AC (%u)\n",
				  ntohs(ac_info->rea_id));
			err = -ENOMSG;
			goto out_err;
		}
		HIP_DEBUG("Received REA ID matches with sent REA ID\n");
		/* todo: delete the sent REA from the sent REA list if
		   we have received AC for every address listed in the sent REA */

		HIP_DEBUG("send ACR\n");
		/* todo: should we use AC's dst address as src address
		   or let the kernel choose it ? */
		err = hip_send_ac_or_acr(HIP_ACR, entry,
					 &skb->nh.ipv6h->daddr, &skb->nh.ipv6h->saddr,
					 ntohs(ac_info->ac_id), ntohs(ac_info->rea_id),
					 ac_info->rtt, 0, 0);
	} else {
		/* ACR handling specific functions */
		struct in6_addr addr;
		uint32_t interface_id, lifetime;
		unsigned long rtt_sent;
		/* check if we have sent the corresponding REA and AC */

		/* check: do we have to care about the source IPv6 address
		 * from where the packet came ? */
		if (!hip_rea_check_received_ac_id(ntohs(ac_info->rea_id),
						  ntohs(ac_info->ac_id),
						  &skb->nh.ipv6h->saddr,
						  &addr, &lifetime,
						  &interface_id, &rtt_sent)) {
			HIP_ERROR("Found no corresponding REA ID (%u) and AC ID (%u) for received ACR\n",
				  ntohs(ac_info->rea_id),
				  ntohs(ac_info->ac_id));
			err = -ENOMSG;
			goto out_err;
		}
		HIP_DEBUG("Received REA ID and AC ID matches, received ACR is valid\n");
		HIP_DEBUG("calculated RTT: %lu jiffies\n", recv_time-rtt_sent);
		/* kludge */
		if (rtt_sent != ac_info->rtt) {
			_HIP_DEBUG("paranoia, sender has changed RTT of AC: original=0x%lx received=0x%lx\n",
				  rtt_sent, ac_info->rtt);
			/* anyway, we couldn't care less because we
			   don't use the RTT field of the incoming AC
			   packet */
		} else {
			HIP_DEBUG("test: received RTT was same as sent RTT\n");
		}
		_HIP_HEXDUMP("remembered saddr", &addr, sizeof(struct in6_addr));

		err = hip_hadb_add_peer_addr(entry, &addr, interface_id,  lifetime);
		if (err) {
			HIP_ERROR("error while adding a new peer address item\n");
			goto out_err;
		}

#ifdef CONFIG_HIP_RVS
		/* If we are the RVS, we need to update the RVA also. */
		{
			HIP_RVA *rva;

			rva = hip_rva_find_valid(&entry->hit_peer);
			if (rva) {
				hip_rva_insert_ip(rva, &addr);
				hip_put_rva(rva);
			}
		}
#endif
		/* ***** todo: CANCEL SENT REA TIMER ***** */
		hip_ac_delete_sent_list_one(0, ntohs(ac_info->rea_id), ntohs(ac_info->ac_id));
	}

	HIP_ASSERT(!err);
	hip_put_ha(entry);
	return err;

 out_err:
	if (entry)
		hip_put_ha(entry);
	return err;
}

/**
 * hip_handle_rea_finish - finish handling of REA
 * @rea_info: pointer to REA_INFO in the packet 
 * @entry: Corresponding HA entry
 * @src_addr: Our source address (this is needed in linklocal case).
 *
 * This functions finishes the handling of the incoming REA packet
 * after the HMAC and signature verification. AC packets are sent to all
 * addresses listed in the REA_INFO payload except to the addresses we
 * already know of (we assume that the address is still valid).
 *
 * TODO:Currently this function handles only one REA_INFO payload. We
 * should resend an AC packet if some address is moved to a different
 * Interface ID.
 *
 * Returns 0 if the packet was processed successfully, otherwise
 * nonzero.
 */
int hip_handle_rea_finish(struct hip_rea_info *rea_info, hip_ha_t *entry,
			  struct in6_addr *src_addr)
{
	int err = 0;
	int i;
	unsigned int addrlist_len, n_addrs;
	void *p;

	HIP_DEBUG("\n");

	/* todo: convert to struct list_head */
	addrlist_len = hip_get_param_total_len(rea_info) -
		sizeof(struct hip_rea_info_addr_item);
	n_addrs = addrlist_len / sizeof(struct hip_rea_info_addr_item);
	_HIP_DEBUG("addlistlen=%d naddrs=%d\n", addrlist_len, n_addrs);
	HIP_DEBUG("REA-in contains %d addresses\n", n_addrs);
	if (addrlist_len > 0 &&
	    (addrlist_len % sizeof(struct hip_rea_info_addr_item)))
		HIP_DEBUG("bug: addlistlen=%d not divisible exactly by %d\n",
			  addrlist_len, sizeof(struct hip_rea_info_addr_item));

	/* delete all occurrences of peer's interface if REA does not
	   contain any addresses (experimental, not in spec) */
	if (n_addrs == 0) {
		HIP_DEBUG("delete all peer addresses belonging to interface %u\n",
			  rea_info->interface_id);
		hip_hadb_delete_peer_addr_if(entry, rea_info->interface_id);
		goto out;
	}

	p = (void*)rea_info+sizeof(struct hip_rea_info);
	hip_hadb_delete_peer_addr_not_in_list(entry, p, n_addrs, rea_info->interface_id);

	HIP_DEBUG("start sending all ACs\n");

	/* send AC to listed addresses */
	p = (void*)rea_info+sizeof(struct hip_rea_info);
	for (i = 0; i < n_addrs; i++, p += sizeof(struct hip_rea_info_addr_item)) {
		struct hip_rea_info_addr_item *addr = (struct hip_rea_info_addr_item *) p;
		char addrstr[INET6_ADDRSTRLEN];
		uint32_t current_time, prev_if;

		hip_in6_ntop(&addr->address, addrstr);
		HIP_DEBUG("item %d: lifetime=0x%x address=%s\n",
			  i+1, ntohl(addr->lifetime), addrstr);

		if (hip_hadb_get_peer_addr_info(entry, &addr->address, &prev_if, 
						NULL, NULL)) 
		{
			/* Hmm..I think we still have to send AC if interface changes, check */
			_HIP_DEBUG("do not resend AC to already know address\n");
			if (prev_if != rea_info->interface_id) {
				HIP_DEBUG("address' iface changed -> update info\n");
				/* todo: update lifetime too ? */
				err = hip_hadb_set_peer_addr_info(entry, &addr->address,
								  &rea_info->interface_id, NULL);
				if (!err) {
					HIP_DEBUG("hip_sdb_set_peer_address_info failed\n");
					err = 0;
				}
			}

			/* move the known address to the top of the list so we use the
			   latest address received, ** kludge ** */

			/* todo: write some address update function and remove these two lines */

			/* remove soon */
 			hip_hadb_delete_peer_addrlist_one(entry, &addr->address);
			err = hip_hadb_add_peer_addr(entry, &addr->address,
						     rea_info->interface_id, addr->lifetime);
			_HIP_DEBUG("known address moved to the end of the peer address list\n");
			/* (testing) continue; */
		} else 
			HIP_DEBUG("is not known address\n");

		if (ntohl(addr->reserved) != 0)
			HIP_DEBUG("reserved in REA_INFO not zero (0x%x), ignored\n", ntohl(addr->reserved));

		current_time = jiffies; /* for testing, see todo */
		_HIP_DEBUG("current_time=0x%x/%u\n", current_time, current_time);

		HIP_DEBUG("send AC\n");

		//err = hip_send_ac_or_acr(HIP_AC, our_hit, NULL, &addr->address, hip_get_new_ac_id(),
		err = hip_send_ac_or_acr(HIP_AC, entry, src_addr, &addr->address,
					 hip_get_new_ac_id(), ntohs(rea_info->rea_id),
					 current_time, rea_info->interface_id,
					 addr->lifetime /* conversion ? */);
		if (err)
			HIP_DEBUG("hip_send_ac_or_acr ret err=%d\n", err);
	}

 out:
	return err;
}

/**
 * hip_handle_rea - handle incoming REA packet
 * @skb: sk_buff where the HIP packet is in
 *
 * This function is the actual point from where the processing of REA
 * is started.
 *
 * On success (HMAC and signature are validated, and
 * hip_handle_rea_finish is called successfully) 0 is returned,
 * otherwise < 0.
 */
int hip_handle_rea(struct sk_buff *skb, hip_ha_t *entry)
{
	int err = 0;
	struct hip_common *msg = NULL;
	struct hip_rea_info *rea_info;
	struct hip_sig *sig;

	HIP_DEBUG("\n");
	msg = (struct hip_common *) skb->h.raw;

	_HIP_HEXDUMP("msg", msg, hip_get_msg_total_len(msg));
	_HIP_DUMP_MSG(msg);

	/* todo: validate tlvs */
	/* todo: handle multiple REA_INFOs, currently only the first
	   is handled  */

	rea_info = hip_get_param(msg, HIP_PARAM_REA_INFO);
	if (!rea_info) {
		HIP_ERROR("REA contained no REA_INFO parameter\n");
		err = -ENOMSG;
		goto out_err;
	}
	HIP_DEBUG("REA_INFO found\n");

	sig = (struct hip_sig *) hip_get_param(msg, HIP_PARAM_HIP_SIGNATURE);
        if (!sig) {
                HIP_ERROR("no HIP_SIGNATURE found\n");
                err = -ENOMSG;
                goto out_err;
        }

	HIP_DEBUG("SIGNATURE found\n");

	HIP_DEBUG("REA_INFO: REA ID: %u\n", ntohs(rea_info->rea_id));
	HIP_DEBUG("REA_INFO: Interface ID (as is): 0x%x/(dec %u)\n",
		  rea_info->interface_id, rea_info->interface_id);
	HIP_DEBUG("REA_INFO: Current SPI reverse: 0x%x\n",
		  ntohl(rea_info->current_spi_rev));
	HIP_DEBUG("REA_INFO: Current SPI: 0x%x\n",
		  ntohl(rea_info->current_spi));
	HIP_DEBUG("REA_INFO: New SPI: 0x%x\n", ntohl(rea_info->new_spi));
	HIP_DEBUG("REA_INFO: Keymaterial index: %u\n",
		  ntohs(rea_info->keymat_index));

        /* verify HMAC */
	err = hip_verify_packet_hmac(msg,entry);
	if (err) {
		HIP_ERROR("HMAC validation on REA failed\n");
		goto out_err;
	}
        HIP_DEBUG("HMAC ok\n");

        /* verify signature */
        /* copypaste from hip_handle_r2 */
        {
                int len;
                struct hip_host_id *peer_id;
                struct hip_lhi peer_lhi;

                len = (u8 *)sig - (u8*)msg;
                hip_zero_msg_checksum(msg);
                hip_set_msg_total_len(msg, len);

                peer_lhi.anonymous = 0;
                memcpy(&peer_lhi.hit, &msg->hits, sizeof(struct in6_addr));

                peer_id = hip_get_host_id(HIP_DB_PEER_HID, &peer_lhi);
                if (!peer_id) {
                        HIP_ERROR("Unknown peer (no identity found)\n");
                        err = -EINVAL;
                        goto out_err;
                }

                if (!hip_verify_signature(msg, len, peer_id,
					  (u8 *)(sig + 1))) {
                        HIP_ERROR("Verification of REA signature failed\n");
                        err = -EINVAL;
                        goto out_err;
                }
        }
        HIP_DEBUG("Signature ok\n");

	/* spi check is implicit since the entry is checked in receive function */
	err = hip_handle_rea_finish(rea_info, entry, &skb->nh.ipv6h->daddr);
	if (err)
		HIP_DEBUG("hip_handle_rea_finish ret err=%d\n", err);

 out_err:
	/* skb is freed by hip_receive_rea */
	return err;
}

/**
 * hip_receive_rea - receive REA packet
 * @skb: sk_buff where the HIP packet is in
 * @hip_common: pointer to HIP header
 *
 * This is the initial function which is called when a REA packet is
 * received. REA is handled in hip_handle_rea() only if we are in
 * established state with the peer.
 *
 * Returns 0 is successful, otherwise < 0.
 */
int hip_receive_rea(struct sk_buff *skb) 
{
	struct hip_common *hip_common;
	int state = 0;
	int err = 0;
	hip_ha_t *entry = NULL;

	HIP_DEBUG("\n");

	hip_common = (struct hip_common *)skb->h.raw;

	if (ipv6_addr_any(&hip_common->hitr)) {
		HIP_ERROR("Received NULL receiver HIT in REA. Dropping\n");
		err = -EINVAL;
		goto out_err;
	}

	entry = hip_hadb_find_byhit(&hip_common->hits);
	if (!entry) {
		HIP_ERROR("Unknown host sent us REA. Dropping\n");
		err = -ENOENT;
		goto out_err;
	}

	HIP_LOCK_HA(entry);
	state = entry->state;
	if (entry->hastate != HIP_HASTATE_VALID) {
		HIP_UNLOCK_HA(entry);
		HIP_ERROR("HA not valid\n");
		err = -EINVAL;
		goto out_err;
	}
	HIP_UNLOCK_HA(entry);

	HIP_DEBUG("Received REA in state %s.\n", hip_state_str(state));

	switch(state) {
	case HIP_STATE_ESTABLISHED:
		err = hip_handle_rea(skb, entry);
		if (err) {
			HIP_ERROR("REA handler failed\n");
			goto out_err;
		}
		break;
	default:
		HIP_ERROR("Received REA without established state. Dropping\n");
		err = -EINVAL;
		break;
	}

 out_err:
	if (entry)
		hip_put_ha(entry);
	return err;
}


/**
 * hip_get_new_rea_id - Get a new REA ID number
 *
 * Returns: the next REA ID value to use in host byte order
 */
static uint16_t hip_get_new_rea_id(void) {
	uint16_t id = hip_get_next_atomic_val_16(&hip_rea_id, &hip_rea_id_lock);
	_HIP_DEBUG("got REA ID %u\n", id);
	return id;
}


#if 0
/* currently not used */
#ifdef CONFIG_HIP_DEBUG
/**
 * hip_list_sent_rea_packets - list all sent and not yet deleted REA packets
 * @str: text to print before the data line
 *
 * This function is only used while debugging.
 */
static void hip_list_sent_rea_packets(char *str)
{
	struct hip_sent_rea_info *s, *tmp;
	char peer_hit[INET6_ADDRSTRLEN];
	int i = 1;

	HIP_DEBUG("\n");
	list_for_each_entry_safe(s, tmp, &hip_sent_rea_info_pkts, list) {
		hip_in6_ntop(&s->hit, peer_hit);
		HIP_DEBUG("sent REA %d (%s): hit=%s REA ID=%u (net=%u)\n",
			  i, str, peer_hit, s->rea_id, htons(s->rea_id));
		i++;
	}
	return;
}
#endif
#endif

/**
 * hip_rea_delete_sent_list_one - delete sent REA(s)
 * @delete_all: flag
 * @rea_id: REA ID in host byte order
 *
 * If @delete_all is non-zero all sent REAs are deleted, else
 * only the REA packet identified by @rea_id is deleted.
 */
static void hip_rea_delete_sent_list_one(int delete_all, uint16_t rea_id) 
{
	struct hip_sent_rea_info *sent_rea, *tmp;
	int i = 1;
	
	spin_lock_bh(&hip_sent_rea_info_lock);
	_HIP_DEBUG("delete_all=%d rea_id=%u (net=%u)\n",
		   delete_all, rea_id, htons(rea_id));
	
	list_for_each_entry_safe(sent_rea, tmp, &hip_sent_rea_info_pkts, list) {
		if (delete_all || (sent_rea->rea_id == rea_id)) {
			_HIP_DEBUG("%d: pos=0x%p, sent_rea=0x%p rea_id=%u\n",
				   i, pos, sent_rea, sent_rea->rea_id);
			del_timer_sync(&sent_rea->timer);
			list_del(&sent_rea->list);
			kfree(sent_rea);
			break;
		}
		i++;
	}
	spin_unlock_bh(&hip_sent_rea_info_lock);
	return;
}

/**
 * hip_rea_delete_sent_list - delete all sent REA packets
 */
void hip_rea_delete_sent_list(void) {
	hip_rea_delete_sent_list_one(1, 0);
	HIP_DEBUG("deleted all sent REAs\n");
	return;
}

/**
 * hip_rea_sent_id_expired - timeout handler for the sent REA packets
 * @val: data value of the timer which is to be cast into appropriate type
 *
 * This function is called when timeout happens for a sent REA packet.
 */
static void hip_rea_sent_id_expired(unsigned long val)
{
	uint16_t rea_id = (uint16_t) val;

	HIP_DEBUG("REA ID %u\n", rea_id);
	hip_rea_delete_sent_list_one(0, rea_id);
	return;
}

/**
 * hip_rea_add_to_sent_list - add given REA ID to the list of sent REA ID packets
 * @rea_id: REA ID in host byte order
 * @dst_hit: HIT where REA was sent
 *
 * Returns: 0 if add was successful, else < 0
 */
static int hip_rea_add_to_sent_list(uint16_t rea_id,
				    struct in6_addr *dst_hit)
{
	int err = 0;
	struct hip_sent_rea_info *sent_rea;

	spin_lock_bh(&hip_sent_rea_info_lock);
	HIP_DEBUG("rea_id=%u (net=%u)\n", rea_id, htons(rea_id));

	sent_rea = kmalloc(sizeof(struct hip_sent_rea_info), GFP_ATOMIC);
	if (!sent_rea) {
		HIP_ERROR("sent_rea kmalloc failed\n");
		err = -ENOMEM;
		goto out_err;
	}
	_HIP_DEBUG("kmalloced sent_rea=0x%p\n", sent_rea);

	sent_rea->rea_id = rea_id;
	//ipv6_addr_copy(&sent_rea->hit, &entry->hit_peer);
	ipv6_addr_copy(&sent_rea->hit, dst_hit);
	list_add(&sent_rea->list, &hip_sent_rea_info_pkts);

	/* start timer here to delete the sent REA after timeout (else some
	 * might be hanging if no AC received) */

	/* TODO: put usage count (=number of addresses in this REA
	 * packet) to sent REA packet (having no usage count means that we
	 * must wait until timeout before we can delete the sent REA
	 * packet) */

	init_timer(&sent_rea->timer);
	sent_rea->timer.data = (unsigned long) rea_id;
	sent_rea->timer.function = hip_rea_sent_id_expired;
        /* for testing: 15 sec timeout */
	sent_rea->timer.expires = jiffies + 15*HZ;
	add_timer(&sent_rea->timer);
 out_err:
	spin_unlock_bh(&hip_sent_rea_info_lock);
	return err;
}



#if 0
/* currently not used */
#ifdef CONFIG_HIP_DEBUG
/* for debugging: list all sent and not yet deleted AC packets */
void hip_list_sent_ac_packets(char *str)
{
	struct hip_sent_ac_info *s, *tmp;
	char addr[INET6_ADDRSTRLEN];
	int i = 1;
//	unsigned long flags = 0;

	HIP_DEBUG("\n");

//	spin_lock_irqsave(&hip_sent_ac_info_lock, flags);
	list_for_each_entry_safe(s, tmp, &hip_sent_ac_info_pkts, list) {
		hip_in6_ntop(&s->ip, addr);
		HIP_DEBUG("sent AC %d (%s): addr=%s REA=%u (net=%u) AC=%u (net=%u) interface_id=0x%x lifetime=0x%x/dec %u rtt_sent=0x%x\n",
			  i, str, addr, s->rea_id, htons(s->rea_id), s->ac_id,
			  htons(s->ac_id), s->interface_id, s->lifetime, s->lifetime, s->rtt_sent);
		i++;
	}
//	spin_unlock_irqrestore(&hip_sent_ac_info_lock, flags);
	return;
}
#endif
#endif


/**
 * hip_ac_sent_id_expired - timeout handler for the sent AC packets
 * @val: data value of the timer which is to be cast into appropriate type
 *
 * This function is called when timeout happens for a sent AC packet.
 */
static void hip_ac_sent_id_expired(unsigned long val)
{
	/* struct hip_sent_ac_info *sent_ac =
	   (struct hip_sent_ac_info *) val; */

	/* (if above declaration is used) DANGEROUS: sent_ac might be
	 * kfree'd at any time if ACR is received at the same time
	 * when this functions is called, fix */
	
	/* A simple way to fix the problem is that if we trust that we
	 * don't have two sent ACs with same AC IDs -> use val as the
	 * ac id (that is, we don't have > 65535 sent AC packet within
	 * the AC timeout period) */
	
	/* kludge workaround test */
	uint16_t ac_id = (uint16_t) ((val & 0xffff0000) >> 16);
	uint16_t rea_id = (uint16_t) (val & 0xffff);
	
	HIP_DEBUG("ac_id=%u rea_id=%u\n", ac_id, rea_id);
	hip_ac_delete_sent_list_one(0, rea_id, ac_id);
	return;
}

/**
 * hip_ac_add_to_sent_list - add AC ID and REA ID to the list of sent AC ID packets
 * @rea_id: REA ID
 * @ac_id: AC ID
 * @address: the IPv6 address where the AC packet was sent to
 * @interface_id: Interface ID value of the corresponding REA packet
 * @lifetime: address lifetime value of the corresponding REA packet
 * @rtt_sent: RTT value when this packet was sent
 *
 * @rea_id and @ac_id are in host byte order, @rtt_sent
 * is in host-specific format.
 *
 * TODO: check: @interface_id and @lifetime are given in the same
 * order as in REA (?)
 *
 * Returns: 0 if addition was successful, else < 0
 */
static int hip_ac_add_to_sent_list(uint16_t rea_id, uint16_t ac_id,
				   struct in6_addr *address,
				   uint32_t interface_id, uint32_t lifetime,
				   uint32_t rtt_sent)
{
	int err = 0;
	struct hip_sent_ac_info *sent_ac;
 
	spin_lock_bh(&hip_sent_ac_info_lock);
	_HIP_DEBUG("\n");

	sent_ac = kmalloc(sizeof(struct hip_sent_ac_info), GFP_ATOMIC);
	if (!sent_ac) {
		HIP_ERROR("sent_ac kmalloc failed\n");
		err = -ENOMEM;
		goto out_err;
	}
	HIP_DEBUG("kmalloced sent_ac=0x%p\n", sent_ac);

	sent_ac->ac_id = ac_id;
	sent_ac->rea_id = rea_id;
	sent_ac->interface_id = interface_id;
	sent_ac->lifetime = lifetime;
	sent_ac->rtt_sent = rtt_sent;
	ipv6_addr_copy(&sent_ac->ip, address);

	//hip_list_sent_ac_packets("PRE");
	list_add(&sent_ac->list, &hip_sent_ac_info_pkts);
	//hip_list_sent_ac_packets("POST");

	/* start timer here to delete this AC so unanswered ACs do not
	 * remaing hanging */

	init_timer(&sent_ac->timer);
	/* kludge for now .. might crash if hip_ac_sent_id_expired and
	 * hip_ac_delete_sent_list_one are called almost
	 * simultaneously: hip_ac_delete_sent_list_one deletes sent_ac
	 * and hip_ac_sent_id_expired points to the memory just freed
	 * sent_ac */
	//sent_ac->timer.data = (unsigned long) sent_ac;
	sent_ac->timer.data = (unsigned long) (ac_id << 16 | rea_id); /* kludge until fixed */
	sent_ac->timer.function = hip_ac_sent_id_expired;
	sent_ac->timer.expires = jiffies + 15*HZ; /* for testing: 15 sec timeout */
	/* this timer caused crashing, so AC packets do not currently timeout (memory leak)
	 * add_timer(&sent_ac->timer); */

 out_err:
	spin_unlock_bh(&hip_sent_ac_info_lock);
	return err;
}


/**
 * hip_ac_delete_sent_list_one - delete given AC ID from the list of sent AC packets
 *
 * @delete_all: if non-zero deletes all sent ACs, else only the AC packet
 *              identified by @rea_id and @ac_id
 * @rea_id:     REA ID
 * @ac_id:      AC ID
 *
 * @rea_id and @ac_id are given in host byte order.
 */
void hip_ac_delete_sent_list_one(int delete_all, uint16_t rea_id,
				 uint16_t ac_id)
{
	struct hip_sent_ac_info *sent_ac = NULL, *tmp;
	int i = 1;

	spin_lock_bh(&hip_sent_ac_info_lock);
	_HIP_DEBUG("delete_all=%d (host) rea_id=%u ac_id=%u\n",
		  delete_all, rea_id, ac_id);

	list_for_each_entry_safe(sent_ac, tmp, &hip_sent_ac_info_pkts, list) {
		if (delete_all ||
		    (sent_ac->rea_id == rea_id && sent_ac->ac_id == ac_id)) {
			_HIP_DEBUG("found, delete item %d: rea_id=%u ac_id=%u pos=0x%p, sent_ac=0x%p\n",
				  i, rea_id, ac_id, pos, sent_ac);
			/* see hip_ac_add_to_sent_list above
			   del_timer_sync(&sent_ac->timer); */
			list_del(&sent_ac->list);
			kfree(sent_ac);
			break;
		}
		i++;
	}
	spin_unlock_bh(&hip_sent_ac_info_lock);
	return;
}


/**
 * hip_ac_delete_sent_list - delete all sent AC packets
 */
void hip_ac_delete_sent_list(void) {
	hip_ac_delete_sent_list_one(1, 0, 0);
}

/**
 * hip_send_rea - build a REA packet to be sent to the peer
 * @dst_hit: peer's HIT
 * @interface_id: the ifindex of the network device which caused the event
 * @addresses: addresses of interface related to @interface_id
 * @address_count: number of addresses in @addresses
 * @netdev_flags: controls the selection of source address used in the REA
 *
 * @interface_id is interpreted as in hip_send_rea_all().
 *
 * TODO: SETUP IPSEC
 *
 * TODO: should return value be void ? (because we can not
 * do anything more if REA can not be sent)
 *
 * Returns: 0 if the REA was built successfully and passed to IP layer
 * to be sent onwards, otherwise < 0.
 */
static int hip_send_rea(hip_ha_t *entry, int interface_id,
			struct hip_rea_info_addr_item *addresses,
			int address_count, int netdev_flags)
{
	int err = 0;
	struct hip_common *rea_packet = NULL;
	uint32_t spi_in, spi_out;
	uint16_t rea_id;
	struct in6_addr daddr;
	struct in6_addr hit_our;
	struct in6_addr dst_hit;
	struct hip_crypto_key hmac_our;

	HIP_DEBUG("\n");

	rea_packet = hip_msg_alloc();
	if (!rea_packet) {
		HIP_DEBUG("rea_packet alloc failed\n");
		err = -ENOMEM;
		goto out_err;
	}

	HIP_LOCK_HA(entry);
	ipv6_addr_copy(&hit_our, &entry->hit_our);
	ipv6_addr_copy(&dst_hit, &entry->hit_peer);
	// memcpy(&hmac_our, &entry->hmac_our, sizeof(hmac_our));
	memcpy(&hmac_our, &entry->hip_hmac_out, sizeof(hmac_our));
	spi_in = entry->spi_in;
	spi_out = entry->spi_out;
	HIP_UNLOCK_HA(entry);


	hip_build_network_hdr(rea_packet, HIP_REA, 0,
			      &hit_our, &dst_hit);
	rea_id = hip_get_new_rea_id();

	err = hip_build_param_rea_info(rea_packet, interface_id,
				       spi_in, spi_out, 
				       0x11223344, /* todo: new spi */
				       0x5566, /* todo: keymat index */
				       rea_id,
				       addresses, address_count);
	if (err) {
		HIP_ERROR("Building of REA_INFO failed\n");
		goto out_err;
	}

	_HIP_DUMP_MSG(rea_packet);
	_HIP_HEXDUMP("REA, plain REA_INFO", rea_packet, hip_get_msg_total_len(rea_packet));

        /* add HMAC to REA */
        {
                struct hip_hmac *hmac;
                unsigned int pkt_len;

                hmac = (struct hip_hmac *) (((void *) rea_packet) + hip_get_msg_total_len(rea_packet));

                hip_set_param_type(hmac, HIP_PARAM_HMAC);
                hip_set_param_contents_len(hmac, HIP_AH_SHA_LEN);
                pkt_len = hip_get_msg_total_len(rea_packet);

                _HIP_HEXDUMP("HMAC key", hmac_our.key, HIP_AH_SHA_LEN);

                if (!hip_write_hmac(HIP_DIGEST_SHA1_HMAC, hmac_our.key,
                                    rea_packet, pkt_len, hmac->hmac_data)) {
                        HIP_ERROR("Error while building HMAC\n");
                        goto out_err;
                }
                _HIP_HEXDUMP("HMAC data", hmac->hmac_data, HIP_AH_SHA_LEN);
                pkt_len += hip_get_param_total_len(hmac);
                hip_set_msg_total_len(rea_packet, pkt_len);
                _HIP_HEXDUMP("HMACced data", rea_packet, pkt_len);
        }

        /* add signature to REA */
        {
                struct hip_host_id *hid;
                int pkt_len;
                struct hip_sig *sig;

		sig = (struct hip_sig *) (((void *) rea_packet) + hip_get_msg_total_len(rea_packet));
                pkt_len = hip_get_msg_total_len(rea_packet);

		/* todo: this code is mostly copied from I2/R2 code, fix */
                hid = hip_get_any_localhost_host_id();
		if (!hid) {
			HIP_ERROR("Got no HID\n");
			goto out_err;
		}
		//if (hid->algorithm != 3) { /* only DSA is supported */
		if (hip_get_host_id_algo(hid) != HIP_HI_DSA) {
			HIP_ERROR("Don't know the length of the signature for algorithm: %d",
				  hip_get_host_id_algo(hid));
	    //				  hid->algorithm);
			goto out_err;
		}

                /* Build a digest of the packet built so far. Signature will
                   be calculated over the digest. */
                if (!hip_create_signature(rea_packet, pkt_len,
                                          hid, (u8 *)(sig + 1))) {
			HIP_ERROR("building of signature failed\n");
                        goto out_err;
		}
		err = hip_build_param_signature_contents(rea_packet, sig+1,
							 41, hip_get_host_id_algo(hid));
		//		 41, hid->algorithm);
                pkt_len += hip_get_param_total_len(sig);
                hip_set_msg_total_len(rea_packet, pkt_len);
        }
	_HIP_HEXDUMP("REA+SIG", rea_packet, hip_get_msg_total_len(rea_packet));

        /* remember the sent REA packet's REA ID */
        err = hip_rea_add_to_sent_list(rea_id, &dst_hit);
        if (err) {
                HIP_ERROR("hip_rea_add_to_sent_list failed\n"); 
                goto out_err;
        }

        HIP_DEBUG("Sending REA packet\n");
        err = hip_hadb_get_peer_addr(entry, &daddr);
        if (err) {
                HIP_DEBUG("hip_sdb_get_peer_address err = %d\n", err);
                goto out_err;
        }

	/* decide whether we try to use the same interface for sending
	 * out the REA */
        if (netdev_flags == REA_OUT_NETDEV_GIVEN) {
                /* net dev to use for sending the REA */
                struct net_device *daddr_dev;
                struct inet6_dev *idev;
                struct dst_entry de;
                struct in6_addr saddr;
                char addrstr[INET6_ADDRSTRLEN];

                /*
                 * Get the network device which caused the event and
                 * select an address from this device to use for the
                 * outgoing REA packet. Note that the device might
                 * have went down between hip_send_rea and
                 * hip_send_rea_finish.
                 */
                daddr_dev = dev_get_by_index(interface_id);
                if (!daddr_dev) {
                        HIP_DEBUG("dev_get_by_index failed\n");
                        goto out_err;
                }

                HIP_DEBUG("interface_id=%d (%s)\n",
                          interface_id, daddr_dev->name);
                idev = in6_dev_get(daddr_dev);
                if (!idev) {
                        HIP_DEBUG("dev %s: NULL idev, skipping\n", daddr_dev->name);
                        goto out_dev_put;
                }


                memset(&de, 0, sizeof(struct dst_entry));

                /* test, debug crashing when all IPv6 addresses of interface were deleted */
                if (idev->dead) {
                        HIP_DEBUG("dead device\n");
                        goto out_idev_unlock;
                }

                /* TODO: this initialization of de does not look
                 * right, see how we can get the correct dst_entry
		 */

                /* do we need to set some other fields, too ? */
                de.dev = daddr_dev;
                hip_in6_ntop(&daddr, addrstr);
                HIP_DEBUG("dest address=%s\n", addrstr);
                err = ipv6_get_saddr(&de, &daddr, &saddr);
                _HIP_DEBUG("ipv6_get_saddr err=%d\n", err);
                if (!err) {
                        /* got a source address, send REA */
                        hip_in6_ntop(&saddr, addrstr);
                        _HIP_DEBUG("selected source address: %s\n", addrstr);
                        err = hip_csum_send(&saddr, &daddr, rea_packet);
			if (err)
				HIP_DEBUG("hip_csum_send err=%d\n", err);
                }

	out_idev_unlock:
                in6_dev_put(idev);
        out_dev_put:
                dev_put(daddr_dev);
        } else if (netdev_flags == REA_OUT_NETDEV_ANY) {
                /* on e.g. NETDEV_DOWN we get here */
                err = hip_csum_send(NULL, &daddr, rea_packet);
        } else {
                HIP_ERROR("invalid netdev_flags %d\n", netdev_flags);
                /* shouldn't happen, but fallback to ANY ? */
        }

 out_err:
	if (rea_packet)
		kfree(rea_packet);

	return err;
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

/**
 * hip_send_rea_all - send REA packet to every peer
 * @interface_id: the ifindex the network device which caused the event
 * @addresses: addresses of interface related to @interface_id
 * @rea_info_address_count: number of addresses in @addresses
 * @netdev_flags: controls the selection of source address used in the REA
 *
 * Because the representation of Interface ID field is locally
 * selected (draft mm-00), Interface ID of REA to be created is set to
 * the value in @interface_id.
 *
 * REA is sent to the peer only if the peer is in established
 * state. Note that we can not guarantee that the REA actually reaches
 * the peer (unless the REA is retransmitted some times, which we
 * currently don't do), due to the unreliable nature of IP we just
 * hope the REA reaches the peer.
 *
 * TODO: retransmission timers
 */
void hip_send_rea_all(int interface_id, struct hip_rea_info_addr_item *addresses,
		      int rea_info_address_count, int netdev_flags)
{
	int err = 0, i;
	hip_ha_t *entries[HIP_MAX_HAS] = {0};
	struct hip_rea_kludge rk;


	HIP_DEBUG("interface_id=%d address_count=%d netdev_flags=0x%x\n",
		  interface_id, rea_info_address_count, netdev_flags);

	rk.array = entries;
	rk.count = 0;
	rk.length = HIP_MAX_HAS;
	
	err = hip_for_each_ha(hip_get_all_valid, &rk);

	for (i=0; i<rk.count; i++) {
		if (rk.array[i] != NULL) {
			hip_send_rea(rk.array[i], interface_id, addresses,
				     rea_info_address_count, netdev_flags);
			hip_put_ha(rk.array[i]);
		}
	}
		
	return;
}


/**
 * hip_send_ac_or_acr - create and send an outgoing AC or ACR packet
 * @pkt_type: HIP_AC for AC packets and HIP_ACR for ACR packets
 * @src_hit: AC/ACR packet's source HIT
 * @dst_hit: AC/ACR packet's destination HIT
 * @src_addr: packet's source IPv6 address
 * @dst_addr: packet's destination IPv6 address
 * @ac_id: AC ID of the packet in host byte order
 * @rea_id: REA ID of the packet in host byte order
 * @rtt: RTT value of the packet
 * @interface_id: Interface ID of the packet
 * @lifetime: lifetime of the address associated with @ac_id
 *
 * If @src_addr is NULL kernel selectes the source address to use.
 * (todo: should source address be NULL when sending ACR ?)
 *
 * @ac_id and @rea_id are given in host byte order.
 *
 * @rtt, @interface_id, and @lifetime are in the same format as they
 * were in the received REA packet. Parameters @interface_id and
 * @lifetime are ignored when @pkt_type is %HIP_ACR.
 *
 * todo: move @interface_id and @lifetime handling to some other function.
 *
 * Returns: 0 if successful, else non-zero.
 */
int hip_send_ac_or_acr(int pkt_type, hip_ha_t *entry, 
		       struct in6_addr *src_addr, struct in6_addr *dst_addr,
		       uint16_t ac_id, uint16_t rea_id, uint32_t rtt,
		       uint32_t interface_id, uint32_t lifetime) {
	int err = 0;
	struct hip_common *msg = NULL;
	char addrstr[INET6_ADDRSTRLEN];

	hip_in6_ntop(dst_addr, addrstr);
	HIP_DEBUG("dst_addr=%s pkt_type=%d ac_id=%u rea_id=%u rtt=0x%x interface_id=0x%x lifetime=0x%x\n",
		  addrstr, pkt_type, ac_id, rea_id, rtt, interface_id, lifetime);

	if (!(pkt_type == HIP_AC || pkt_type == HIP_ACR)) {
		HIP_ERROR("Illegal pkt_type %d\n", pkt_type);
		err = -EINVAL;
		goto out_err;
        }

	msg = hip_msg_alloc();
	if (!msg) {
		HIP_ERROR("msg alloc failed\n");
		err = -ENOMEM;
		goto out_err;
	}

        /* no HA locking since those fields (hit_[peer|our] are non-mutable */
	hip_build_network_hdr(msg, pkt_type, HIP_CONTROL_NONE,
			      &entry->hit_our, &entry->hit_peer);

        msg->checksum = htons(0);

	err = hip_build_param_ac_info(msg, ac_id, rea_id, rtt);
	if (err) {
		HIP_ERROR("Building of AC_INFO failed\n");
		goto out_err;
	}

	_HIP_HEXDUMP("packet pre HMAC", msg, hip_get_msg_total_len(msg));

	/* add HMAC */
        {
                struct hip_hmac *hmac;
                unsigned int pkt_len;
		struct hip_crypto_key hmac_our;

		HIP_LOCK_HA(entry);
		// memcpy(&hmac_our, &entry->hmac_our, sizeof(hmac_our));
		memcpy(&hmac_our, &entry->hip_hmac_out, sizeof(hmac_our));
		HIP_UNLOCK_HA(entry);

		hmac = (struct hip_hmac *) (((void *) msg) + hip_get_msg_total_len(msg));

                hip_set_param_type(hmac, HIP_PARAM_HMAC);
                hip_set_param_contents_len(hmac, HIP_AH_SHA_LEN);
                pkt_len = hip_get_msg_total_len(msg);

                _HIP_HEXDUMP("HMAC key", &hmac_our.key, HIP_AH_SHA_LEN);

                if (!hip_write_hmac(HIP_DIGEST_SHA1_HMAC, &hmac_our.key,
                                    msg, pkt_len, hmac->hmac_data))
                {
                        HIP_ERROR("Error while building HMAC\n");
                        goto out_err;
                }
                _HIP_HEXDUMP("HMAC data", hmac->hmac_data, HIP_AH_SHA_LEN);
                pkt_len += hip_get_param_total_len(hmac);
                hip_set_msg_total_len(msg, pkt_len);
                _HIP_HEXDUMP("HMACced data", rea_packet, pkt_len);
        }

	if (pkt_type == HIP_AC) {
                /* AC handling specific functions */

		/* remember the sent AC packet */
		err = hip_ac_add_to_sent_list(rea_id, ac_id,
					      dst_addr, interface_id,
					      lifetime, rtt);
		if (err) {
			HIP_ERROR("hip_rea_add_to_sent_list failed\n"); 
			goto out_err;
		}

		_HIP_DEBUG("send AC packet to hip_csum_send\n");
		/* *** TODO: src addr = dst addr of REA ? *** */
		/* If destination address is link local, then we must use the address from
		 * the IPv6 packet as a source address */
		if (ipv6_addr_type(dst_addr) & IPV6_ADDR_LINKLOCAL) {
			err = hip_csum_send(src_addr, dst_addr, msg);
		} else {
			err = hip_csum_send(NULL, dst_addr, msg);
		}

		if (err) {
			HIP_DEBUG("sending of AC failed\n");
			hip_ac_delete_sent_list_one(0, rea_id, ac_id);
		}

	} else {
                /* ACR handling specific functions */

		HIP_DEBUG("send ACR packet to hip_csum_send\n");
		/* send ACR using source address of the received AC
		 * packet as the destination address */

		/* check: select NULL src_addr anyway ?*/
		err = hip_csum_send(src_addr, dst_addr, msg);
		/* ignore errors from hip_csum_send ? */
	}

 out_err:
	if (msg)
		kfree(msg);
	return err;
}
