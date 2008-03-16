#include "proxydb.h"

/** A callback wrapper of the prototype required by @c lh_new(). */
//static IMPLEMENT_LHASH_HASH_FN(hip_hash_proxy_db, const hip_proxy_t *)
/** A callback wrapper of the prototype required by @c lh_new(). */
//static IMPLEMENT_LHASH_COMP_FN(hip_compare_proxy_db, const hip_proxy_t *)

/**
 * Maps function @c func to every HA in HIT hash table. The hash table is
 * LOCKED while we process all the entries. This means that the mapper function
 * MUST be very short and _NOT_ do any operations that might sleep!
 *
 * @param func a mapper function.
 * @param opaque opaque data for the mapper function.
 * @return       negative if an error occurs. If an error occurs during
 *               traversal of a the HIT hash table, then the traversal is
 *               stopped and function returns. Returns the last return value of
 *               applying the mapper function to the last element in the hash
 *               table.
 */
int hip_for_each_proxy_db(int (*func)(hip_proxy_t *entry, void *opaq), void *opaque)
{
	int i = 0, fail = 0;
	hip_proxy_t *this;
	hip_list_t *item, *tmp;

	if (!func)
		return -EINVAL;

	HIP_LOCK_HT(&hip_proxy_db);
	list_for_each_safe(item, tmp, hip_proxy_db, i)
	{
		this = list_entry(item);
		_HIP_DEBUG("list_for_each_safe\n");
		hip_hold_ha(this);
		fail = func(this, opaque);
		hip_db_put_ha(this, hip_hadb_delete_state);
		if (fail)
			goto out_err;
	}

 out_err:	
	HIP_UNLOCK_HT(&hip_proxy_db);
	return fail;
}

unsigned long hip_hash_proxy_db(const hip_proxy_t *p)
{
     hip_hit_t hitpair[2];
     uint8_t hash[HIP_AH_SHA_LEN];

     if(p == NULL || &(p->addr_our) == NULL || &(p->addr_peer) == NULL)
     {
	  return 0;
     }
     
     /* The HIT fields of an host association struct cannot be assumed to be
	alligned consecutively. Therefore, we must copy them to a temporary
	array. */
     memcpy(&hitpair[0], &(p->addr_our), sizeof(p->addr_our));
     memcpy(&hitpair[1], &(p->addr_peer), sizeof(p->addr_peer));
     
     hip_build_digest(HIP_DIGEST_SHA1, (void *)hitpair, sizeof(hitpair), hash);
     
     return *((unsigned long *)hash);
}

int hip_compare_proxy_db(const hip_proxy_t *ha1, const hip_proxy_t *ha2)
{
     if(ha1 == NULL || &(ha1->addr_our) == NULL || &(ha1->addr_peer) == NULL ||
	ha2 == NULL || &(ha2->addr_our) == NULL || &(ha2->addr_peer) == NULL)
     {
	  return 1;
     }

     return (hip_hash_proxy_db(ha1) != hip_hash_proxy_db(ha2));
}

void hip_init_proxy_db(void)
{
     /** @todo Check for errors. */
     
     /* The next line initializes the hash table for host associations. Note
	that we are using callback wrappers IMPLEMENT_LHASH_HASH_FN and
	IMPLEMENT_LHASH_COMP_FN defined in the beginning of this file. These
	provide automagic variable casts, so that all elements stored in the
	hash table are cast to hip_ha_t. Lauri 09.10.2007 16:58. */
	//hip_proxy_db = hip_ht_init(LHASH_HASH_FN(hip_hash_proxy_db),
	//			   LHASH_COMP_FN(hip_compare_proxy_db));
	
	hip_proxy_db = hip_ht_init(hip_hash_proxy_db, hip_compare_proxy_db);
	hip_init_proxy_raw_sock_v6(&hip_proxy_raw_sock);
}



void hip_uninit_proxy_db()
{
	int i = 0;
	hip_list_t *item, *tmp;
	hip_proxy_t *entry;
	
	list_for_each_safe(item, tmp, hip_proxy_db, i)
	{
		entry = list_entry(item);
		hip_ht_delete(hip_proxy_db, entry);
	}  

}

int hip_proxy_add_entry(struct in6_addr *addr_our, struct in6_addr *addr_peer)
{
	hip_proxy_t *tmp = NULL, *new_item = NULL;
	int err = 0;
	
	new_item = (hip_proxy_t *)malloc(sizeof(hip_proxy_t));
	if (!new_item)
	{
		HIP_ERROR("new_item malloc failed\n");
		err = -ENOMEM;
		return err;
	}
	
	memset(new_item, 0, sizeof(hip_proxy_t));
	ipv6_addr_copy(&new_item->addr_our, addr_our);
	ipv6_addr_copy(&new_item->addr_peer, addr_peer);
//	new_item->state = 1;
	err = hip_ht_add(hip_proxy_db, new_item);
	HIP_DEBUG("Proxy adds connection state successfully!\n");
	HIP_DEBUG_IN6ADDR("source ip addr",&new_item->addr_our );
	HIP_DEBUG_IN6ADDR("destination ip addr",&new_item->addr_peer);

	return err;
}


hip_proxy_t *hip_proxy_find_by_addr(struct in6_addr *addr, struct in6_addr *addr2)
{
	hip_proxy_t p, *ret;
	memcpy(&p.addr_our, addr, sizeof(struct in6_addr));
	memcpy(&p.addr_peer, addr2, sizeof(struct in6_addr));

	return hip_ht_find(hip_proxy_db, &p);
}

hip_proxy_t *hip_proxy_find_by_hit(hip_hit_t *hit_proxy, hip_hit_t *hit_peer)
{
	int i = 0, fail = 0;
	hip_proxy_t *this;
	hip_list_t *item, *tmp;

	list_for_each_safe(item, tmp, hip_proxy_db, i)
	{
		this = list_entry(item);
		if (!ipv6_addr_cmp(&this->hit_proxy, hit_proxy) &&
		    !ipv6_addr_cmp(&this->hit_peer, hit_peer))
			return this;
	}
	return NULL;
}

int hip_proxy_update_state(struct in6_addr *src_addr,
								struct in6_addr *dst_addr,
								struct in6_addr *proxy_addr,
								hip_hit_t *src_hit,  
								hip_hit_t *dst_hit,
								hip_hit_t *proxy_hit,
								int state)
{
	hip_proxy_t *p;
	
	_HIP_DEBUG_IN6ADDR("src_addr", src_addr);
	_HIP_DEBUG_IN6ADDR("dst_addr", dst_addr);
	_HIP_DEBUG_HIT("src_hit", src_hit);
	_HIP_DEBUG_HIT("dst_hit", dst_hit);
	p = hip_proxy_find_by_addr(src_addr, dst_addr);
	if(p)
	{
		if(src_hit)
			p->hit_our = *src_hit;
		if(dst_hit)
			p->hit_peer = *dst_hit;
		if(proxy_hit)
			p->hit_proxy = *proxy_hit;
		if(proxy_addr)
			p->addr_proxy = *proxy_addr;
		
		p->state = state;
		
/*		
		HIP_DEBUG_IN6ADDR("src_addr",&p-> src_addr);
		HIP_DEBUG_IN6ADDR("dst_addr", &p->dst_addr);
		HIP_DEBUG_IN6ADDR("proxy_addr",&p-> proxy_addr);		
		HIP_DEBUG_HIT("src_hit", &p->src_hit);
		HIP_DEBUG_HIT("dst_hit", &p->dst_hit);
		HIP_DEBUG_HIT("proxy_hit", &p->proxy_hit);
		HIP_DEBUG("state: %d", p->state);
*/		
		HIP_DEBUG("Update connection state successfully!\n");
//		memcpy(&p->hit_our, src_hit, sizeof(struct in6_addr));
//		memcpy(&p->hit_peer, dst_hit, sizeof(struct in6_aadr));
//		ipv6_addr_copy(&p->hit_our, addr_our);
//		ipv6_addr_copy(&p->hit_peer, addr_peer);				
		return 1;
	}
	else
	{
		HIP_DEBUG("Can not update connection state!\n");
		return 0;
	}
}

int hip_proxy_request_peer_hit_from_hipd(const struct in6_addr *peer_ip,
				   struct in6_addr *peer_hit,
				   const struct in6_addr *local_hit,
				   int *fallback,
				   int *reject)
{
	struct hip_common *msg = NULL;
	struct in6_addr *hit_recv = NULL;
	hip_hit_t *ptr = NULL;
	int err = 0;
	int ret = 0;

	*fallback = 1;
	*reject = 0;
	
	HIP_IFE(!(msg = hip_msg_alloc()), -1);
	
	HIP_IFEL(hip_build_param_contents(msg, (void *)(local_hit),
					  HIP_PARAM_HIT,
					  sizeof(struct in6_addr)), -1,
		 "build param HIP_PARAM_HIT  failed\n");
	HIP_IFEL(hip_build_param_contents(msg, (void *)(peer_ip),
					  HIP_PARAM_IPV6_ADDR,
					  sizeof(struct in6_addr)), -1,
		 "build param HIP_PARAM_IPV6_ADDR failed\n");

	
	/* build the message header */
	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_GET_PEER_HIT, 0), -1,
		 "build hdr failed\n");
	
	/* send and receive msg to/from hipd */
	HIP_IFEL(hip_send_recv_daemon_info(msg), -1, "send_recv msg failed\n");
	_HIP_DEBUG("send_recv msg succeed\n");
	
	/* check error value */
	HIP_IFEL(hip_get_msg_err(msg), -1, "Got erroneous message!\n");
	
	ptr = (hip_hit_t *) hip_get_param_contents(msg, HIP_PARAM_HIT);
	if (ptr) {
		memcpy(peer_hit, ptr, sizeof(hip_hit_t));
		HIP_DEBUG_HIT("peer_hit", peer_hit);
		*fallback = 0;
	}

	ptr = hip_get_param(msg, HIP_PARAM_AGENT_REJECT);
	if (ptr)
	{
		HIP_DEBUG("Connection is to be rejected\n");
		*reject = 1;
	}
	
 out_err:
	
	if(msg)
		free(msg);
	
	return err;
}

int hip_get_local_hit_wrapper(hip_hit_t *hit)
{
	int err = 0;
	char *param;
	struct hip_common *msg = NULL;
	//struct gaih_addrtuple *at = NULL;

	HIP_IFEL(!(msg = hip_msg_alloc()), -1, "malloc failed\n");
	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_DEFAULT_HIT, 0),
		 -1, "Fail to get hits");
	HIP_IFEL(hip_send_recv_daemon_info(msg), -1, "send/recv\n");
	HIP_IFEL(!(param = hip_get_param(msg, HIP_PARAM_HIT)), -1,
		 "No HIT received\n");
	ipv6_addr_copy(hit, hip_get_param_contents_direct(param));
	_HIP_DEBUG_HIT("hit", hit);
	
 out_err:
	if (msg)
		free(msg);
	return err;
}

int hip_proxy_send_raw(struct in6_addr *local_addr, struct in6_addr *peer_addr,	struct hip_common *msg)
{
	int err = 0, sa_size, sent, len, dupl, try_again;
	struct sockaddr_storage src, dst;
	int src_is_ipv4, dst_is_ipv4;
	struct sockaddr_in6 *src6, *dst6;
	struct sockaddr_in *src4, *dst4;
	struct in6_addr my_addr;
	/* Points either to v4 or v6 raw sock */
	int hip_raw_sock = 0;
	
	_HIP_DEBUG("hip_send_raw() invoked.\n");
	
	/* Verify the existence of obligatory parameters. */
	HIP_ASSERT(peer_addr != NULL && msg != NULL);
	
	HIP_DEBUG("Sending %s packet on raw HIP.\n",
		  hip_message_type_name(hip_get_msg_type(msg)));
	HIP_DEBUG_IN6ADDR("hip_send_raw(): local_addr", local_addr);
	HIP_DEBUG_IN6ADDR("hip_send_raw(): peer_addr", peer_addr);
//	HIP_DEBUG("Source port=%d, destination port=%d\n", src_port, dst_port);
	HIP_DUMP_MSG(msg);

	dst_is_ipv4 = IN6_IS_ADDR_V4MAPPED(peer_addr);
	len = hip_get_msg_total_len(msg);

	/* Some convinient short-hands to avoid too much casting (could be
	   an union as well) */
	src6 = (struct sockaddr_in6 *) &src;
	dst6 = (struct sockaddr_in6 *) &dst;
	src4 = (struct sockaddr_in *)  &src;
	dst4 = (struct sockaddr_in *)  &dst;

	memset(&src, 0, sizeof(src));
	memset(&dst, 0, sizeof(dst));
	
	if (dst_is_ipv4) {
		hip_raw_sock = hip_proxy_raw_sock;
		sa_size = sizeof(struct sockaddr_in);
	} else {
		HIP_DEBUG("Using IPv6 raw socket\n");
		hip_raw_sock = hip_proxy_raw_sock;
		sa_size = sizeof(struct sockaddr_in6);
	}

	if (local_addr) {
		HIP_DEBUG("local address given\n");
		memcpy(&my_addr, local_addr, sizeof(struct in6_addr));
	} else {
		HIP_DEBUG("no local address, selecting one\n");
//		HIP_IFEL(hip_select_source_address(&hip_nl_route,
//						   &my_addr,
//						   peer_addr), -1,
//			 "Cannot find source address\n");
	}

	src_is_ipv4 = IN6_IS_ADDR_V4MAPPED(&my_addr);

	if (src_is_ipv4) {
		IPV6_TO_IPV4_MAP(&my_addr, &src4->sin_addr);
		src4->sin_family = AF_INET;
		HIP_DEBUG_INADDR("src4", &src4->sin_addr);
	} else {
		memcpy(&src6->sin6_addr, &my_addr,  sizeof(struct in6_addr));
		src6->sin6_family = AF_INET6;
		HIP_DEBUG_IN6ADDR("src6", &src6->sin6_addr);
	}

	if (dst_is_ipv4) {
		IPV6_TO_IPV4_MAP(peer_addr, &dst4->sin_addr);
		dst4->sin_family = AF_INET;

		HIP_DEBUG_INADDR("dst4", &dst4->sin_addr);
	} else {
		memcpy(&dst6->sin6_addr, peer_addr, sizeof(struct in6_addr));
		dst6->sin6_family = AF_INET6;
		HIP_DEBUG_IN6ADDR("dst6", &dst6->sin6_addr);
	}

	if (src6->sin6_family != dst6->sin6_family) {
	  /* @todo: Check if this may cause any trouble.
	     It happens every time we send update packet that contains few locators in msg, one is 
	     the IPv4 address of the source, another is IPv6 address of the source. But even if one of 
	     them is ok to send raw IPvX to IPvX raw packet, another one cause the trouble, and all 
	     updates are dropped.  by Andrey "laser".

	   */
		err = -1;
		HIP_ERROR("Source and destination address families differ\n");
		goto out_err;
	}

	hip_zero_msg_checksum(msg);
	msg->checksum = hip_checksum_packet((char*)msg,
					    (struct sockaddr *) &src,
					    (struct sockaddr *) &dst);

	/* Note that we need the original (possibly mapped addresses here.
	   Also, we need to do queuing before the bind because the bind
	   can fail the first time during mobility events (duplicate address
	   detection). */
	/*	
	 * if (retransmit)
		HIP_IFEL(hip_queue_packet(&my_addr, peer_addr, msg, entry), -1,
			 "Queueing failed.\n"); 
	 */
	
	/* Handover may cause e.g. on-link duplicate address detection
	   which may cause bind to fail. */

	HIP_IFEL(bind(hip_raw_sock, (struct sockaddr *) &src, sa_size),
		 -1, "Binding to raw sock failed\n");

	/*
	if (HIP_SIMULATE_PACKET_LOSS && HIP_SIMULATE_PACKET_IS_LOST()) {
		HIP_DEBUG("Packet loss probability: %f\n", ((uint64_t) HIP_SIMULATE_PACKET_LOSS_PROBABILITY * RAND_MAX) / 100.f);
		HIP_DEBUG("Packet was lost (simulation)\n");
		goto out_err;
	}
	*/

	/* For some reason, neither sendmsg or send (with bind+connect)
	   do not seem to work properly. Thus, we use just sendto() */
	
	len = hip_get_msg_total_len(msg);
	_HIP_HEXDUMP("Dumping packet ", msg, len);

	for (dupl = 0; dupl < HIP_PACKET_DUPLICATES; dupl++) {
		for (try_again = 0; try_again < 2; try_again++) {
			sent = sendto(hip_raw_sock, msg, len, 0,
				      (struct sockaddr *) &dst, sa_size);
			if (sent != len) {
				HIP_ERROR("Could not send the all requested"\
					  " data (%d/%d)\n", sent, len);
				sleep(2);
			} else {
				HIP_DEBUG("sent=%d/%d ipv4=%d\n",
					  sent, len, dst_is_ipv4);
				HIP_DEBUG("Packet sent ok\n");
				break;
			}
		}
	}
	
 out_err:

	/* Reset the interface to wildcard or otherwise receiving
	   broadcast messages fails from the raw sockets */ 
	if (dst_is_ipv4) {
		src4->sin_addr.s_addr = INADDR_ANY;
		src4->sin_family = AF_INET;
		sa_size = sizeof(struct sockaddr_in);
	} else {
		struct in6_addr any = IN6ADDR_ANY_INIT;
		src6->sin6_family = AF_INET6;
		ipv6_addr_copy(&src6->sin6_addr, &any);
		sa_size = sizeof(struct sockaddr_in6);
	}
	bind(hip_raw_sock, (struct sockaddr *) &src, sa_size);

	if (err)
		HIP_ERROR("strerror: %s\n", strerror(errno));

	return err;
}

int hip_init_proxy_raw_sock_v6(int *hip_raw_sock_v6)
{
	int on = 1, off = 0, err = 0;

	*hip_raw_sock_v6 = socket(AF_INET6, SOCK_RAW, IPPROTO_TCP);
	HIP_IFEL(*hip_raw_sock_v6 <= 0, 1, "Raw socket creation failed. Not root?\n");

	/* see bug id 212 why RECV_ERR is off */
	err = setsockopt(*hip_raw_sock_v6, IPPROTO_IPV6, IPV6_RECVERR, &off, sizeof(on));
	HIP_IFEL(err, -1, "setsockopt recverr failed\n");
	err = setsockopt(*hip_raw_sock_v6, IPPROTO_IPV6, IPV6_2292PKTINFO, &on, sizeof(on));
	HIP_IFEL(err, -1, "setsockopt pktinfo failed\n");
	err = setsockopt(*hip_raw_sock_v6, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	HIP_IFEL(err, -1, "setsockopt v6 reuseaddr failed\n");

 out_err:
	return err;
}

int hip_init_proxy_raw_sock_v4(int *hip_raw_sock_v4)
{
	int on = 1, err = 0;
	int off = 0;

	*hip_raw_sock_v4 = socket(AF_INET, SOCK_RAW, IPPROTO_HIP);
	HIP_IFEL(*hip_raw_sock_v4 <= 0, 1, "Raw socket v4 creation failed. Not root?\n");

	/* see bug id 212 why RECV_ERR is off */
	err = setsockopt(*hip_raw_sock_v4, IPPROTO_IP, IP_RECVERR, &off, sizeof(on));
	HIP_IFEL(err, -1, "setsockopt v4 recverr failed\n");
	err = setsockopt(*hip_raw_sock_v4, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on));
	HIP_IFEL(err, -1, "setsockopt v4 failed to set broadcast \n");
	err = setsockopt(*hip_raw_sock_v4, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on));
	HIP_IFEL(err, -1, "setsockopt v4 pktinfo failed\n");
	err = setsockopt(*hip_raw_sock_v4, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	HIP_IFEL(err, -1, "setsockopt v4 reuseaddr failed\n");

 out_err:
	return err;
}

int hip_proxy_request_local_address_from_hipd(struct in6_addr *local_hit,
				   struct in6_addr *peer_hit,
				   struct in6_addr *local_addr,
				   int *fallback,
				   int *reject)
{
	struct hip_common *msg = NULL;
	struct in6_addr *ptr = NULL;
	int err = 0;
	int ret = 0;
	
	*fallback = 1;
	*reject = 0;
	
	HIP_IFE(!(msg = hip_msg_alloc()), -1);
	
	HIP_IFEL(hip_build_param_contents(msg, (void *)(local_hit),
					  HIP_PARAM_HIT,
					  sizeof(struct in6_addr)), -1,
		 "build param HIP_PARAM_HIT  failed\n");
	
	HIP_IFEL(hip_build_param_contents(msg, (void *)(peer_hit),
					  HIP_PARAM_IPV6_ADDR,
					  sizeof(struct in6_addr)), -1,
		 "build param HIP_PARAM_IPV6_ADDR failed\n");;
	
	/* build the message header */
	HIP_IFEL(hip_build_user_hdr(msg, SO_HIP_GET_PROXY_LOCAL_ADDRESS, 0), -1,
		 "build hdr failed\n");

	/* send and receive msg to/from hipd */
	HIP_IFEL(hip_send_recv_daemon_info(msg), -1, "send_recv msg failed\n");
	_HIP_DEBUG("send_recv msg succeed\n");

	/* check error value */
	HIP_IFEL(hip_get_msg_err(msg), -1, "Got erroneous message!\n");
	
	ptr = (struct in6_addr *) hip_get_param_contents(msg, HIP_PARAM_IPV6_ADDR);
	if (ptr) {
		memcpy(local_addr, ptr, sizeof(struct in6_addr));
		HIP_DEBUG_IN6ADDR("local_addr", local_addr);
		*fallback = 0;
	}

	ptr = hip_get_param(msg, HIP_PARAM_AGENT_REJECT);
	if (ptr)
	{
		HIP_DEBUG("Connection is to be rejected\n");
		*reject = 1;
	}
	
 out_err:
	
	if(msg)
		free(msg);
	
	return err;
}

int hip_proxy_send_pkg(struct in6_addr *local_addr, struct in6_addr *peer_addr,	void *msg, int len)
{
	int err = 0, sa_size, sent, dupl, try_again;
	struct sockaddr_storage src, dst;
	int src_is_ipv4, dst_is_ipv4;
	struct sockaddr_in6 *src6, *dst6;
	struct sockaddr_in *src4, *dst4;
	struct in6_addr my_addr;
	/* Points either to v4 or v6 raw sock */
	int hip_raw_sock = 0;
	
	_HIP_DEBUG("hip_send_raw() invoked.\n");
	
	/* Verify the existence of obligatory parameters. */
	HIP_ASSERT(peer_addr != NULL && msg != NULL);
	
	HIP_DEBUG_IN6ADDR("hip_send_raw(): local_addr", local_addr);
	HIP_DEBUG_IN6ADDR("hip_send_raw(): peer_addr", peer_addr);

	dst_is_ipv4 = IN6_IS_ADDR_V4MAPPED(peer_addr);

	/* Some convinient short-hands to avoid too much casting (could be
	   an union as well) */
	src6 = (struct sockaddr_in6 *) &src;
	dst6 = (struct sockaddr_in6 *) &dst;
	src4 = (struct sockaddr_in *)  &src;
	dst4 = (struct sockaddr_in *)  &dst;

	memset(&src, 0, sizeof(src));
	memset(&dst, 0, sizeof(dst));
	
	if (dst_is_ipv4) {
		hip_raw_sock = hip_proxy_raw_sock;
		sa_size = sizeof(struct sockaddr_in);
	} else {
		HIP_DEBUG("Using IPv6 raw socket\n");
		hip_raw_sock = hip_proxy_raw_sock;
		sa_size = sizeof(struct sockaddr_in6);
	}

	if (local_addr) {
		HIP_DEBUG("local address given\n");
		memcpy(&my_addr, local_addr, sizeof(struct in6_addr));
	} else {
		HIP_DEBUG("no local address, selecting one\n");
//		HIP_IFEL(hip_select_source_address(&hip_nl_route,
//						   &my_addr,
//						   peer_addr), -1,
//			 "Cannot find source address\n");
	}

	src_is_ipv4 = IN6_IS_ADDR_V4MAPPED(&my_addr);

	if (src_is_ipv4) {
		IPV6_TO_IPV4_MAP(&my_addr, &src4->sin_addr);
		src4->sin_family = AF_INET;
		HIP_DEBUG_INADDR("src4", &src4->sin_addr);
	} else {
		memcpy(&src6->sin6_addr, &my_addr,  sizeof(struct in6_addr));
		src6->sin6_family = AF_INET6;
		HIP_DEBUG_IN6ADDR("src6", &src6->sin6_addr);
	}

	if (dst_is_ipv4) {
		IPV6_TO_IPV4_MAP(peer_addr, &dst4->sin_addr);
		dst4->sin_family = AF_INET;

		HIP_DEBUG_INADDR("dst4", &dst4->sin_addr);
	} else {
		memcpy(&dst6->sin6_addr, peer_addr, sizeof(struct in6_addr));
		dst6->sin6_family = AF_INET6;
		HIP_DEBUG_IN6ADDR("dst6", &dst6->sin6_addr);
	}

	if (src6->sin6_family != dst6->sin6_family) {
	  /* @todo: Check if this may cause any trouble.
	     It happens every time we send update packet that contains few locators in msg, one is 
	     the IPv4 address of the source, another is IPv6 address of the source. But even if one of 
	     them is ok to send raw IPvX to IPvX raw packet, another one cause the trouble, and all 
	     updates are dropped.  by Andrey "laser".

	   */
		err = -1;
		HIP_ERROR("Source and destination address families differ\n");
		goto out_err;
	}

	hip_zero_msg_checksum(msg);
	((struct ip*)msg)->ip_sum = hip_checksum_packet((char*)msg,
					    (struct sockaddr *) &src,
					    (struct sockaddr *) &dst);

	/* Handover may cause e.g. on-link duplicate address detection
	   which may cause bind to fail. */

	HIP_IFEL(bind(hip_raw_sock, (struct sockaddr *) &src, sa_size),
		 -1, "Binding to raw sock failed\n");

	/* For some reason, neither sendmsg or send (with bind+connect)
	   do not seem to work properly. Thus, we use just sendto() */

	for (dupl = 0; dupl < HIP_PACKET_DUPLICATES; dupl++) {
		for (try_again = 0; try_again < 2; try_again++) {
			sent = sendto(hip_raw_sock, msg, len, 0,
				      (struct sockaddr *) &dst, sa_size);
			if (sent != len) {
				HIP_ERROR("Could not send the all requested"\
					  " data (%d/%d)\n", sent, len);
				sleep(2);
			} else {
				HIP_DEBUG("sent=%d/%d ipv4=%d\n",
					  sent, len, dst_is_ipv4);
				HIP_DEBUG("Packet sent ok\n");
				break;
			}
		}
	}
	
 out_err:

	/* Reset the interface to wildcard or otherwise receiving
	   broadcast messages fails from the raw sockets */ 
	if (dst_is_ipv4) {
		src4->sin_addr.s_addr = INADDR_ANY;
		src4->sin_family = AF_INET;
		sa_size = sizeof(struct sockaddr_in);
	} else {
		struct in6_addr any = IN6ADDR_ANY_INIT;
		src6->sin6_family = AF_INET6;
		ipv6_addr_copy(&src6->sin6_addr, &any);
		sa_size = sizeof(struct sockaddr_in6);
	}
	bind(hip_raw_sock, (struct sockaddr *) &src, sa_size);

	if (err)
		HIP_ERROR("strerror: %s\n", strerror(errno));

	return err;
	
}