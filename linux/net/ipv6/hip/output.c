/*
 * HIP output
 *
 * Authors: Janne Lundberg <jlu@tcs.hut.fi>
 *          Miika Komu <miika@iki.fi>
 *          Mika Kousa <mkousa@cc.hut.fi>
 *          Kristian Slavov <kslavov@hiit.fi>
 *
 * TODO:
 * - If a function returns a value, we MUST NOT ignore it
 * - make null-cipher optional, so that the module can be loaded without it
 * - timeouts to cookies
 * - LOCKING TO REA/AC sent lists
 * - AC/ACR: more accurate RTT timing than jiffies ?
 * - hip_send_rea_all: test with multiple REA_INFO payloads (mm-00 sec 6.1.1)
 * - document hip_getfrag using docbook
 * - rename hip_rea_delete_sent_list_one -> hip_rea_delete_sent_list
 * - remove duplicate code, REA/AC list
 * - adding of HMAC/signature to the packet: own functions
 *
 * BUGS:
 * - It should be signalled somehow when building of R1 is 100 % 
 *   complete. Otherwise an incomplete packet could be sent for
 *   the initiator?
 *
 */

#include "output.h"

extern spinlock_t hip_sent_rea_info_lock;
extern spinlock_t hip_sent_ac_info_lock;
atomic_t hip_rea_id = ATOMIC_INIT(0);
atomic_t hip_nes_id = ATOMIC_INIT(0);
spinlock_t hip_rea_id_lock = SPIN_LOCK_UNLOCKED;
spinlock_t hip_nes_id_lock = SPIN_LOCK_UNLOCKED;

/**
 * hip_handle_output - handle outgoing IPv6 packets
 * @hdr: a pointer to the beginning of IPv6 header in the @skb
 * @skb: the socket buffer that is going to be output
 *
 * Handle outgoing packets sent by the transport layer. Depending on the
 * current state of the HIP association, the packet may be dropped (if it
 * has a HIT as the destination address) until base exchange or other HIP
 * related packet exchange is completed. If the packet is not destined
 * for a HIT, nothing is done for it.
 *
 * The @skb will be freed if the return value is not zero.
 *
 * Returns: an nagative error value on failure. This will be interpreted as
 *          "drop the packet".
 *          Zero if the destination address
 *          was an ordinary IPv6 address or the state was already established.
 *
 */
int hip_handle_output(struct ipv6hdr *hdr, struct sk_buff *skb)
{
	/* XX TODO:
	   - remove retransmission of I1 from here and use timers instead
	   - output buffer to temporarily store outgoing packets during
             base exchange
	 */
	int err = 0;
	struct hip_work_order *hwo = NULL;
	struct hip_work_order *reverse = NULL;
	int state = 0; 
	

	if (!ipv6_addr_is_hit(&hdr->daddr)) {
		/* The address was an IPv6 address, ignore. */
		err = 0;
		goto out;
	}


	/* The source address is not yet a HIT, just the dst address. */

	hip_hadb_get_state_by_hit(&hdr->daddr,&state);
	
	HIP_DEBUG("sdb entry state is %d\n", state);
	switch(state) {
	case HIP_STATE_START:
		HIP_DEBUG("Initiating connection\n");

#ifdef KRISUS_THESIS
		if (!gtv_inuse) {
			KRISU_START_TIMER(KMM_GLOBAL);
			gtv_inuse = 1;
			do_gettimeofday(&gtv_start);
		}
#endif
		hwo = hip_create_job_with_hit(GFP_ATOMIC,&hdr->daddr);
		if (!hwo) {
			HIP_ERROR("No memory, dropping packet\n");
			err = -ENOMEM;
			goto memout;
		}
		
		if (hip_copy_any_localhost_hit(&hdr->saddr) < 0) {
			HIP_ERROR("No localhost hit available\n");
			err = -ENOMEM;
			goto memout;
		}

		hwo->arg2 = kmalloc(sizeof(struct in6_addr),GFP_ATOMIC);
		if (!hwo->arg2) {
			HIP_ERROR("No memory\n");
			err = -ENOMEM;
			goto memout;
		}
		
		ipv6_addr_copy(hwo->arg2,&hdr->saddr);
		hwo->type = HIP_WO_TYPE_OUTGOING;
		hwo->arg.u32[0] = HIP_STATE_INITIATING;
		hwo->subtype = HIP_WO_SUBTYPE_NEW_CONN;

		hip_insert_work_order(hwo);

		err = hip_send_i1(&hdr->daddr);
		if (err < 0) {
			HIP_ERROR("Sending of I1 failed (%d)\n", err);
			err = -ENOMEM;

			/* try to create a reverse job, that will clear the
			 * effects of the previous job
			 */
			reverse = hip_create_job_with_hit(GFP_ATOMIC,&hdr->daddr);
			if (!reverse) {
				HIP_ERROR("Could not undo state change\n");
				goto out;
			}

			reverse->type = HIP_WO_TYPE_OUTGOING;
			reverse->subtype = HIP_WO_SUBTYPE_DEL_CONN;

			hip_insert_work_order(reverse);
			goto out;
		}

		err = -1; // drop the TCP/UDP packet
		break;
	case HIP_STATE_INITIATING:
		HIP_DEBUG("I1 retransmission\n");
		/* XX TODO: we should have timers on HIP layer and
		   not depend on transport layer timeouts? In that case
		   we should not send I1 here. For the time being, this
		   will act as a poor man's timeout... */
		err = hip_send_i1(&hdr->daddr);
		if (err) {
			HIP_ERROR("I1 retransmission failed");
			goto out;
		}
		err = -1; // just something to drop the TCP packet;
		break;
	case HIP_STATE_WAIT_FINISH:
		/* XX TODO: Should the packet be buffered instead? */
		HIP_INFO("Not established yet. Dropping the packet.\n");
		err = -1;
		break;
	case HIP_STATE_ESTABLISHED:
		/* State is already established; just rewrite HITs to IPv6
		   addresses and continue normal IPv6 packet processing. */
		/* first get peer IPv6 addr */
		err = hip_hadb_get_peer_address(&hdr->daddr,&hdr->daddr,
						HIP_ARG_HIT);
		if (err) {
			HIP_ERROR("Could not find peer address\n");
			err = -EADDRNOTAVAIL;
			goto out;
		}

		HIP_DEBUG_IN6ADDR("dst addr", &hdr->daddr);

		err = ipv6_get_saddr(NULL, &hdr->daddr, &hdr->saddr);
		if (err) {
			HIP_ERROR("Could get a source address\n");
			err = -EADDRNOTAVAIL;
			goto out;
		}

		break;
	case HIP_STATE_ESTABLISHED_REKEY:
		/* XX TODO: Should the packet be buffered instead? */
		HIP_INFO("Rekey pending. Dropping the packet.\n");
		err = -1;
		break;
	default:
		HIP_ERROR("Unknown HIP state %d\n", state);
		err = -EFAULT;
		break;
	}

	
	return err; 
/* either this or 'goto out'. Must not free hwo, if things are ok */
 memout:
	if (hwo) {
		if (hwo->arg1)
			kfree(hwo->arg1);
		if (hwo->arg2)
			kfree(hwo->arg2);
		kfree(hwo);
	}
 out:
	return err;
}

/**
 * hip_getfrag - handle IPv6 fragmentation
 * @data: start of the data to be copied from
 * @saddr: source IPv6 address, ignored
 * @buff: destination buffer where to data is copied to
 * @offset: offset from the beginning of @data
 * @len: length of the data to be copied from @data+@offset
 *
 * Returns: always 0.
 */
static int hip_getfrag(void *from, char *to, int offset, int len, int odd, struct sk_buff *skb)
{

	memcpy(to, ((u8 *)from)+offset, len);	

	if (skb->ip_summed != CHECKSUM_HW) {
		unsigned int csum;

		csum = csum_partial((u8 *)from+offset, len, 0);
		skb->csum = csum_block_add(skb->csum, csum, odd);
	}

	return 0;
}

/**
 * hip_csum_verify - verify HIP header checksum
 * @skb: the socket buffer which contains the HIP header
 *
 * Returns: the checksum of the HIP header.
 */
int hip_csum_verify(struct sk_buff *skb)
{
	struct hip_common *hip_common;
	int len;
	int csum;

	hip_common = (struct hip_common*) skb->h.raw;
	len = hip_common->payload_len;

	_HIP_HEXDUMP("hip_csum_verify data", skb->h.raw, (len + 1) << 3);
	_HIP_DEBUG("len=%d\n", len);
	_HIP_HEXDUMP("saddr", &(skb->nh.ipv6h->saddr),
		     sizeof(struct in6_addr));
	_HIP_HEXDUMP("daddr", &(skb->nh.ipv6h->daddr),
		     sizeof(struct in6_addr));

	csum = csum_partial(skb->h.raw, (len + 1) << 3, 0);

	return csum_ipv6_magic(&(skb->nh.ipv6h->saddr),
			       &(skb->nh.ipv6h->daddr),
			       (len + 1) << 3,
			       IPPROTO_HIP,
			       csum);
}

/**
 * hip_csum_send - send a HIP packet
 * @src_addr: packet's source IPv6 address
 * @peer_addr: packet's destination IPv6 address
 * @buf: start of the HIP packet
 *
 * If @src_addr is NULL, kernel selects which source IPv6 address to
 * use is the packet.
 *
 * Returns: 0 if packet was delivered to lower layer, < 0 otherwise.
 */
int hip_csum_send(struct in6_addr *src_addr, struct in6_addr *peer_addr,
		  struct hip_common* buf)
{
	int err = 0;
	struct in6_addr saddr;
	struct dst_entry *dst;

	struct flowi fl;
	unsigned int csum;
	unsigned int len;
	char addrstr[INET6_ADDRSTRLEN];

	fl.proto = IPPROTO_HIP;
	fl.fl6_dst = *peer_addr;
	fl.oif = 0;
	fl.fl6_flowlabel = 0;

	if (!src_addr) {
		HIP_DEBUG("null src_addr, get src addr\n");
		err = ipv6_get_saddr(NULL, &fl.fl6_dst, &saddr);
		if (err) {
			hip_in6_ntop(peer_addr, addrstr);
			HIP_ERROR("Couldn't get source IPv6 address for dst address %s\n", addrstr);
			goto out_err;
		}
		fl.fl6_src = saddr;
	} else {
		HIP_DEBUG("use given src addr\n");
		fl.fl6_src = *src_addr;
	}

	buf->checksum = htons(0);
	len = (buf->payload_len + 1) << 3;

	/* 
	 * jlu XXX: UNCLEAR: 
	 *
	 * Should we use the length from the HIP-header to compute "length" in
	 * the pseudoheader:
	 * Currently: YES
	 *
	 * Should we use the encoded length or convert it to bytes first?
	 * Currently: encoded
	 *
	 * Should we include the piggybacked ESP in the checksum?
	 * Currently: NO
	 *
	 * [RFC2460, RFC????]
	 */
	//#ifdef CONFIG_HIP_DEBUG
	_HIP_HEXDUMP("***CHECKSUM DATA", buf, len);
	HIP_DEBUG("pkt out: len=%d proto=%d\n", len, fl.proto);
	hip_in6_ntop(&fl.fl6_src, addrstr);
	HIP_DEBUG("pkt out: src IPv6 addr: %s\n", addrstr);
	hip_in6_ntop(&fl.fl6_dst, addrstr);
	HIP_DEBUG("pkt out: dst IPv6 addr: %s\n", addrstr);
	//#endif

	/* Interop with Julien: no htons here */
	csum = csum_partial((char*) buf, len, 0);
	buf->checksum = csum_ipv6_magic(&fl.fl6_src, &fl.fl6_dst, len,
					fl.proto, csum);
	HIP_DEBUG("pkt out: checksum value (host order): 0x%x\n",
		  ntohs(buf->checksum));

	if (buf->checksum == 0)
		buf->checksum = -1;

	err = ip6_dst_lookup(hip_output_socket->sk, &dst, &fl);
	if (err) {
		HIP_ERROR("Unable to route HIP packet\n");
		goto out_err;
	}

	
	lock_sock(hip_output_socket->sk);
 	err = ip6_append_data(hip_output_socket->sk, hip_getfrag, buf, len, 0,
			      0xFF, NULL, &fl, (struct rt6_info *)dst, MSG_DONTWAIT);
	if (err)
		HIP_ERROR("ip6_build_xmit failed (err=%d)\n", err);
	else
		err = ip6_push_pending_frames(hip_output_socket->sk);

	release_sock(hip_output_socket->sk);
 out_err:
	return err;
}

/**
 * hip_send_i1 - send an I1 packet to the responder
 * @entry: the HIP database entry reserved for the peer
 *
 * Send an I1 packet to the responder if an IPv6 address for the peer
 * is known.
 *
 * Returns: 0 on success, otherwise < 0 on error.
 */
int hip_send_i1(struct in6_addr *dsthit)
{
	struct hip_i1 i1;
	struct in6_addr daddr;
	struct in6_addr hit_our;
	int err = 0;

	HIP_DEBUG("\n");

	if (hip_copy_any_localhost_hit(&hit_our) < 0) {
		HIP_ERROR("Out HIT not found\n");
		err = -EINVAL;
		goto out_err;
	}


	hip_build_network_hdr((struct hip_common* ) &i1, HIP_I1,
			      HIP_CONTROL_NONE, &hit_our,
			      dsthit);
	/* Eight octet units, not including first */
	i1.payload_len = (sizeof(struct hip_i1) >> 3) - 1;

	HIP_HEXDUMP("HIT SOURCE in send_i1", &i1.hits,
		    sizeof(struct in6_addr));
	HIP_HEXDUMP("HIT DEST in send_i1", &i1.hitr,
		    sizeof(struct in6_addr));

	err = hip_hadb_get_peer_address(dsthit, &daddr, HIP_ARG_HIT);
	if (err) {
		HIP_ERROR("hip_sdb_get_peer_address returned error = %d\n",
			  err);
		goto out_err;
	}

	_HIP_DEBUG("hip: send I1 packet\n");	

	err = hip_csum_send(NULL, &daddr, (struct hip_common*) &i1);

 out_err:

	return err;
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
int hip_xmit_r1(struct sk_buff *skb, struct in6_addr *dst_hit)
{
	struct hip_common *r1pkt;
	struct in6_addr *src_addr;
	struct in6_addr *dst_addr;
	int err = 0;

	HIP_DEBUG("\n");

	src_addr = &skb->nh.ipv6h->saddr;
	dst_addr = &skb->nh.ipv6h->daddr;

	r1pkt = hip_get_r1(src_addr, dst_addr);
	if (!r1pkt)
	{
		HIP_ERROR("No precreated R1\n");
		err = -ENOENT;
		goto out_err;
	}

	if (dst_hit) 
		ipv6_addr_copy(&r1pkt->hitr, dst_hit);
	else
		memset(&r1pkt->hitr, 0, sizeof(struct in6_addr));

	/* set cookie state to used (more or less temporary solution ?) */

	HIP_HEXDUMP("R1 pkt", r1pkt, hip_get_msg_total_len(r1pkt));

	err = hip_csum_send(NULL, src_addr, r1pkt);	
	if (err) {
		HIP_ERROR("hip_csum_send failed, err=%d\n", err);
		goto out_err;
	}

	HIP_ASSERT(!err);
	return 0;

 out_err:
	HIP_ERROR("hip_xmit_r1 failed, err=%d\n", err);
	return err;
}

/**
 * hip_send_r1 - send an R1 to the peer
 * @skb: the socket buffer for the received I1
 *
 * Send an I1 to the peer. The addresses and HITs will be digged
 * out from the @skb.
 *
 * Returns: zero on success, or a negative error value on failure.
 */
int hip_send_r1(struct sk_buff *skb) 
{
	int err = 0;
	struct in6_addr *dst;
	dst = &(((struct hip_common *)skb->h.raw)->hits);

	err = hip_xmit_r1(skb, dst);

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

/**
 * hip_get_new_nes_id - Get a new NES ID number
 *
 * Returns: the next NES ID value to use in host byte order
 */
static uint16_t hip_get_new_nes_id(void) {
	uint16_t id = hip_get_next_atomic_val_16(&hip_nes_id, &hip_nes_id_lock);
	HIP_DEBUG("got NES ID %u\n", id);
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
	struct list_head *pos, *n;
	struct hip_sent_rea_info *s;
	char peer_hit[INET6_ADDRSTRLEN];
	int i = 1;

	HIP_DEBUG("\n");
	list_for_each_safe(pos, n, &hip_sent_rea_info_pkts) {
		s = list_entry(pos, struct hip_sent_rea_info, list);
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
#if 1
static void hip_rea_delete_sent_list_one(int delete_all, uint16_t rea_id) {
		struct list_head *pos, *n;
		struct hip_sent_rea_info *sent_rea;
		int i = 1;
		unsigned long flags = 0;

		spin_lock_irqsave(&hip_sent_rea_info_lock, flags);
		_HIP_DEBUG("delete_all=%d rea_id=%u (net=%u)\n",
			  delete_all, rea_id, htons(rea_id));

		list_for_each_safe(pos, n, &hip_sent_rea_info_pkts) {
			sent_rea = list_entry(pos, struct hip_sent_rea_info,
					      list);
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
		spin_unlock_irqrestore(&hip_sent_rea_info_lock, flags);
		return;
}
#else
static void hip_rea_delete_sent_list_one(int delete_all, uint16_t rea_id)
{
	return;
}
#endif

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
 * @entry: XXXXXXXXX pointer to the sdb entry of the peer
 * @dst_hit: HIT where REA was sent
 *
 * Returns: 0 if add was successful, else < 0
 */
#if 1
static int hip_rea_add_to_sent_list(uint16_t rea_id,
//				    struct hip_sdb_state *entry)
				    struct in6_addr *dst_hit)
{
	int err = 0;
	struct hip_sent_rea_info *sent_rea;
	unsigned long flags = 0;

	spin_lock_irqsave(&hip_sent_rea_info_lock, flags);
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
	spin_unlock_irqrestore(&hip_sent_rea_info_lock, flags);
	return err;
}
#else
static int hip_rea_add_to_sent_list(uint16_t rea_id,
				    struct in6_addr *hit)
{
	return 0;
}
#endif


#if 0
/* currently not used */
#ifdef CONFIG_HIP_DEBUG
/* for debugging: list all sent and not yet deleted AC packets */
void hip_list_sent_ac_packets(char *str)
{
	struct list_head *pos, *n;
	struct hip_sent_ac_info *s;
	char addr[INET6_ADDRSTRLEN];
	int i = 1;
//	unsigned long flags = 0;

	HIP_DEBUG("\n");

//	spin_lock_irqsave(&hip_sent_ac_info_lock, flags);
	list_for_each_safe(pos, n, &hip_sent_ac_info_pkts) {
		s = list_entry(pos, struct hip_sent_ac_info, list);
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
#if 1
static int hip_ac_add_to_sent_list(uint16_t rea_id, uint16_t ac_id,
				   struct in6_addr *address,
				   uint32_t interface_id, uint32_t lifetime,
				   uint32_t rtt_sent)
{
	int err = 0;
	struct hip_sent_ac_info *sent_ac;
	unsigned long flags = 0;
 
	spin_lock_irqsave(&hip_sent_ac_info_lock, flags);
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
	spin_unlock_irqrestore(&hip_sent_ac_info_lock, flags);
	return err;
}
#else
static int hip_ac_add_to_sent_list(uint16_t rea_id, uint16_t ac_id,
				   struct in6_addr *address,
				   uint32_t interface_id, uint32_t lifetime,
				   uint32_t rtt_sent)
{
	return 0;
}
#endif

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
#if 1
void hip_ac_delete_sent_list_one(int delete_all, uint16_t rea_id,
				 uint16_t ac_id)
{
	struct list_head *pos, *n;
	struct hip_sent_ac_info *sent_ac = NULL;
	int i = 1;
	unsigned long flags = 0;

	spin_lock_irqsave(&hip_sent_ac_info_lock, flags);
	_HIP_DEBUG("delete_all=%d (host) rea_id=%u ac_id=%u\n",
		  delete_all, rea_id, ac_id);

	list_for_each_safe(pos, n, &hip_sent_ac_info_pkts) {
		sent_ac = list_entry(pos, struct hip_sent_ac_info, list);
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
	spin_unlock_irqrestore(&hip_sent_ac_info_lock, flags);
	return;
}
#else
void hip_ac_delete_sent_list_one(int delete_all, uint16_t rea_id,
				 uint16_t ac_id)
{
	return;
}
#endif
/**
 * hip_ac_delete_sent_list - delete all sent AC packets
 */
void hip_ac_delete_sent_list(void) {
	hip_ac_delete_sent_list_one(1, 0, 0);
}

/**
 * hip_send_rea - build a REA packet to be sent to the peer
 * XXXXXXXXXX @entry: pointer to the sdb entry of the peer
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
static int hip_send_rea(struct in6_addr *dst_hit,int interface_id,
			struct hip_rea_info_addr_item *addresses,
			int address_count, int netdev_flags)
{
	int err = 0;
	struct hip_common *rea_packet = NULL;
	uint32_t spi_our, spi_peer;
	int tmplist[4];
	void *setlist[4];
	uint16_t rea_id;
	struct in6_addr daddr;
	struct in6_addr hit_our;
	struct hip_crypto_key hmac_our;

	HIP_DEBUG("\n");

	rea_packet = hip_msg_alloc();
	if (!rea_packet) {
		HIP_DEBUG("rea_packet alloc failed\n");
		err = -ENOMEM;
		goto out_err;
	}

	tmplist[0] = HIP_HADB_OWN_HIT;
	tmplist[1] = HIP_HADB_OWN_SPI;
	tmplist[2] = HIP_HADB_PEER_SPI;
	tmplist[3] = HIP_HADB_OWN_HMAC;
	setlist[0] = &hit_our;
	setlist[1] = &spi_our;
	setlist[2] = &spi_peer;
	setlist[3] = &hmac_our;
	err = hip_hadb_multiget(dst_hit, 4, tmplist, setlist, HIP_ARG_HIT);
	if (err != 4) {
		HIP_ERROR("DB error\n");
		goto out_err;
	}

	hip_build_network_hdr(rea_packet, HIP_REA, 0,
			      &hit_our, dst_hit);
	rea_id = hip_get_new_rea_id();
	err = hip_build_param_rea_info(rea_packet, interface_id,
				       spi_our, spi_peer, 
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
        err = hip_rea_add_to_sent_list(rea_id, dst_hit);
        if (err) {
                HIP_ERROR("hip_rea_add_to_sent_list failed\n"); 
                goto out_err;
        }

        HIP_DEBUG("Sending REA packet\n");
        err = hip_hadb_get_peer_address(dst_hit, &daddr, HIP_ARG_HIT);
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
                read_lock(&idev->lock);
                /* test, debug crashing when all IPv6 addresses of interface were deleted */
                if (idev->dead) {
                        HIP_DEBUG("dead device\n");
                        goto out_idev_unlock;
                }

                /* TODO: this initialization of de does not look
                 * right, see how we can get the correct dst_entry
		 */

                memset(&de, 0, sizeof(struct dst_entry));
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
                read_unlock(&idev->lock);
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

/* Simple filter function 
 */
static inline int hip_filter_all_established(struct hip_hadb_state *entry)
{
	if (entry->state == HIP_STATE_ESTABLISHED)
		return 1;
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
 */
void hip_send_rea_all(int interface_id, struct hip_rea_info_addr_item *addresses,
		      int rea_info_address_count, int netdev_flags)
{
	struct hip_entry_list *entry, *iter;
	int err = 0;
	struct list_head head;


	HIP_DEBUG("interface_id=%d address_count=%d netdev_flags=0x%x\n",
		  interface_id, rea_info_address_count, netdev_flags);

	INIT_LIST_HEAD(&head);

	err = hip_hadb_for_each_entry(hip_filter_all_established, NULL,
				      &head);

	if (err < 0) {
		HIP_ERROR("Error while fetching established connections: %d\n",err);
		return;
	}
	/* some of entries might have disappeared */
	list_for_each_entry_safe(entry, iter, &head, list) {
		(void) hip_send_rea(&entry->peer_hit, interface_id, addresses,
				    rea_info_address_count, netdev_flags);
		list_del(&entry->list);
		kfree(entry);
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
#if 1
int hip_send_ac_or_acr(int pkt_type, struct in6_addr *src_hit, struct in6_addr *dst_hit,
		       struct in6_addr *src_addr, struct in6_addr *dst_addr,
		       uint16_t ac_id, uint16_t rea_id, uint32_t rtt,
		       uint32_t interface_id, uint32_t lifetime) {
	int err = 0;
	struct hip_common *msg = NULL;
	char addrstr[INET6_ADDRSTRLEN];
//	struct hip_hadb_state *entry;

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


	hip_build_network_hdr(msg, pkt_type, HIP_CONTROL_NONE,
			      src_hit, dst_hit);
//			      &entry->hit_our, &entry->hit_peer);
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

                if (!hip_hadb_get_own_hmac_by_hit(dst_hit, &hmac_our)) {
			HIP_ERROR("Own HMAC not found\n");
                        err = -ENOENT;
                        goto out_err;
                }

		hmac = (struct hip_hmac *) (((void *) msg) + hip_get_msg_total_len(msg));

                hip_set_param_type(hmac, HIP_PARAM_HMAC);
                hip_set_param_contents_len(hmac, HIP_AH_SHA_LEN);
                pkt_len = hip_get_msg_total_len(msg);

                //_HIP_HEXDUMP("HMAC key", entry->hmac_our.key, HIP_AH_SHA_LEN);
                _HIP_HEXDUMP("HMAC key", &hmac_our.key, HIP_AH_SHA_LEN);

                //if (!hip_write_hmac(HIP_DIGEST_SHA1_HMAC, entry->hmac_our.key,
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
		err = hip_csum_send(NULL, dst_addr, msg);
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
#else
int hip_send_ac_or_acr(int pkt_type,
		       struct in6_addr *src_addr, struct in6_addr *dst_addr,
		       uint16_t ac_id, uint16_t rea_id, uint32_t rtt,
		       uint32_t interface_id, uint32_t lifetime) 
{
	return 0;
}
#endif
