/**
 * This code is heavily based on Boeing HIPD hip_netlink.c
 *
 */

#include "netdev.h"
#include "opendht/libhipopendht.h"
#include "debug.h"
#include "libinet6/util.h"
#include "libinet6/include/netdb.h"
#include "libinet6/hipconf.h"

unsigned long hip_netdev_hash(const void *ptr) {
	struct netdev_address *na = (struct netdev_address *) ptr;
	uint8_t hash[HIP_AH_SHA_LEN];

	hip_build_digest(HIP_DIGEST_SHA1, &na->addr,
			 sizeof(struct sockaddr_storage), hash);

	return *((unsigned long *) hash);
}

int hip_netdev_match(const void *ptr1, const void *ptr2) {
	return hip_netdev_hash(ptr1) != hip_netdev_hash(ptr2);
}

static int count_if_addresses(int ifindex)
{
	struct netdev_address *na;
	hip_list_t *n, *t;
	int i = 0, c;

	list_for_each_safe(n, t, addresses, c) {
		na = list_entry(n);
		if (na->if_index == ifindex)
			i++;
	}
	return i;
}


#define FA_IGNORE 0
#define FA_ADD 1
/*
 * Returns FA_ADD if the given address @addr is allowed to be one of the
 * addresses of this host, FA_IGNORE otherwise
 */
int filter_address(struct sockaddr *addr, int ifindex)
{
	HIP_DEBUG("ifindex=%d, address family=%d\n",
		  ifindex, addr->sa_family);
	HIP_HEXDUMP("testing address=", hip_cast_sa_addr(addr), hip_sa_addr_len(addr));

	/* used as a buffer for inet_ntop */
#define sLEN 40
	char s[sLEN];

	switch (addr->sa_family) {
		case AF_INET6:
			inet_ntop(AF_INET6, &((struct sockaddr_in6*)addr)->sin6_addr, s, sLEN);
			HIP_DEBUG("IPv6 addr: %s\n", s);

			struct in6_addr *a_in6 = hip_cast_sa_addr(addr);

			if (IN6_IS_ADDR_UNSPECIFIED(a_in6)) {
				HIP_DEBUG("Ignore: UNSPECIFIED\n");
				return FA_IGNORE;
			} else if (IN6_IS_ADDR_LOOPBACK(a_in6)) {
				HIP_DEBUG("Ignore: IPV6_LOOPBACK\n");
				return FA_IGNORE;
			} else if (IN6_IS_ADDR_MULTICAST(a_in6)) {
				HIP_DEBUG("Ignore: MULTICAST\n");
				return FA_IGNORE;
			} else if (IN6_IS_ADDR_LINKLOCAL(a_in6)) {
				HIP_DEBUG("Ignore: LINKLOCAL\n");
				return FA_IGNORE;
#if 0 /* For Juha-Matti's experiments  */
			} else if (IN6_IS_ADDR_SITELOCAL(a_in6)) {
				HIP_DEBUG("Ignore: SITELOCAL\n");
				return FA_IGNORE;
#endif
			} else if (IN6_IS_ADDR_V4MAPPED(a_in6)) {
				HIP_DEBUG("Ignore: V4MAPPED\n");
				return FA_IGNORE;
			} else if (IN6_IS_ADDR_V4COMPAT(a_in6)) {
				HIP_DEBUG("Ignore: V4COMPAT\n");
				return FA_IGNORE;
			} else if (ipv6_addr_is_hit(a_in6)) {
				HIP_DEBUG("Ignore: hit\n");
				return FA_IGNORE;
			} else
				return FA_ADD;
			break;
			/* XX FIXME: DISCARD LSIs with IN6_IS_ADDR_V4MAPPED AND IS_LSI32 */

		case AF_INET:
			/* AG FIXME more IPv4 address checking
			 * DO we need any more checks here ? -- Abi
			 */
			inet_ntop(AF_INET, &((struct sockaddr_in*)addr)->sin_addr, s, sLEN);
			HIP_DEBUG("IPv4 addr: %s \n", s);

			in_addr_t a_in = ((struct sockaddr_in *)addr)->sin_addr.s_addr;

			if (a_in == INADDR_ANY) {
				HIP_DEBUG("Ignore: INADDR_ANY\n");
				return FA_IGNORE;
			} else if (a_in == INADDR_BROADCAST) {
				HIP_DEBUG("Ignore: INADDR_BROADCAST\n");
				return FA_IGNORE;
			} else if (IN_MULTICAST(ntohs(a_in))) {
				HIP_DEBUG("Ignore: MULTICAST\n");
				return FA_IGNORE;
			} else if (IS_LSI32(a_in)) {
				HIP_DEBUG("Ignore: LSI32\n");
				return FA_IGNORE;
			} else if (IS_IPV4_LOOPBACK(a_in)) {
				HIP_DEBUG("Ignore: IPV4_LOOPBACK\n");
				return FA_IGNORE;
			} else 
				return FA_ADD;
			break;

		default:
			
			return FA_IGNORE;
	}
}

int exists_address_in_list(struct sockaddr *addr, int ifindex)
{
	struct netdev_address *n;
	hip_list_t *tmp, *t;
	int c;

	list_for_each_safe(tmp, t, addresses, c) {
		int mapped = 0;
		int addr_match = 0;
		int family_match = 0;
		n = list_entry(tmp);
		
		mapped = IN6_IS_ADDR_V4MAPPED(hip_cast_sa_addr(&n->addr));
		HIP_DEBUG("mapped=%d\n", mapped);
		
		if (mapped) //|| addr->sa_family == AF_INET) 
		{
			struct in6_addr *in6 = (struct in6_addr * ) hip_cast_sa_addr(&n->addr);
			struct in_addr *in = (struct in_addr *) hip_cast_sa_addr(addr);
			addr_match = IPV6_EQ_IPV4(in6, in);
			family_match = 1;
		} else if (!mapped && addr->sa_family == AF_INET6) {
			addr_match = !memcmp(hip_cast_sa_addr(&n->addr), hip_cast_sa_addr(addr),
					     hip_sa_addr_len(&n->addr));
			family_match = (n->addr.ss_family == addr->sa_family);
		}
		else { // addr->sa_family == AF_INET
			// Hope never happen...If happens we need to add Mapping
		}
		
		HIP_DEBUG("n->addr.ss_family=%d, addr->sa_family=%d, n->if_index=%d, ifindex=%d\n",
			  n->addr.ss_family, addr->sa_family, n->if_index, ifindex);
		if (n->addr.ss_family == AF_INET6) {
			HIP_DEBUG_IN6ADDR("addr6", hip_cast_sa_addr(&n->addr));
		} else if (n->addr.ss_family == AF_INET) {
			HIP_DEBUG_INADDR("addr4", hip_cast_sa_addr(&n->addr));
		}
		if (n->if_index == ifindex && family_match && addr_match)
			return 1;
	}
	
	return 0;
}

void add_address_to_list(struct sockaddr *addr, int ifindex)
{
	struct netdev_address *n;
        unsigned char tmp_secret[40];
        int err_rand = 0;

	if (!filter_address(addr, ifindex))
	{
		HIP_DEBUG("filtering this address\n");
		return;
	}

	n = (struct netdev_address *) malloc(sizeof(struct netdev_address));
	if (!n)
	{
		// FIXME; memory error
		HIP_ERROR("Could not allocate memory\n");
		return;
	}
	memset(n, 0, sizeof(struct netdev_address));

	/* Convert IPv4 address to IPv6 */
	if (addr->sa_family == AF_INET)
	{
		struct sockaddr_in6 temp;
		memset(&temp, 0, sizeof(temp));
		temp.sin6_family = AF_INET6;
		IPV4_TO_IPV6_MAP(&(((struct sockaddr_in *)addr)->sin_addr),
				 &temp.sin6_addr);
	        memcpy(&n->addr, &temp, hip_sockaddr_len(&temp));
	}
	else
		memcpy(&n->addr, addr, hip_sockaddr_len(addr));

        /*
          Add secret to address. Used with openDHT removable puts.
        */        
        memset(tmp_secret,0,sizeof(tmp_secret));
        err_rand = RAND_bytes(tmp_secret,40);
        memcpy(&n->secret, &tmp_secret,sizeof(tmp_secret));

        /*
          Clear the timestamp, initially 0 so everything will be sent
        */
        memset(&n->timestamp, '0', sizeof(time_t));

        n->if_index = ifindex;
	//INIT_LIST_HEAD(&n->next);
	list_add(n, addresses);
	address_count++;
	HIP_DEBUG("added address, address_count at exit=%d\n", address_count);
}

static void delete_address_from_list(struct sockaddr *addr, int ifindex)
{
	struct netdev_address *n;
	hip_list_t *item, *tmp;
	int i;

	HIP_HEXDUMP("deleting address=", hip_cast_sa_addr(addr), hip_sa_addr_len(addr));
	HIP_DEBUG("address_count at entry=%d\n", address_count);

	list_for_each_safe(item, tmp, addresses, i)
	{
		int deleted = 0;
		n = list_entry(item);

		/* remove from list if if_index matches */
		if (!addr)
		{
			if (n->if_index == ifindex)
			{
				list_del(n, addresses);
				deleted = 1;
			}
		}
		else
		{
			/* remove from list if address matches */
			HIP_HEXDUMP("a1:", hip_cast_sa_addr(&n->addr), hip_sa_addr_len(&n->addr));
			HIP_HEXDUMP("a2:", hip_cast_sa_addr(addr), hip_sa_addr_len(addr));
			if ((n->addr.ss_family == addr->sa_family) &&
				((memcmp(hip_cast_sa_addr(&n->addr), hip_cast_sa_addr(addr),
				hip_sa_addr_len(addr))==0)) ||
				IPV6_EQ_IPV4( &(((struct sockaddr_in6 *) &(n->addr))->sin6_addr), &((struct sockaddr_in *) addr)->sin_addr) )
			{
				/* address match */
				list_del(n, addresses);
				deleted = 1;
			}
		}
		if (deleted)
		{
			address_count--;
			HIP_DEBUG("dec address_count to %d\n", address_count);
		}
	}

	HIP_DEBUG("address_count at exit=%d\n", address_count);
	if (address_count < 0) HIP_ERROR("BUG: address_count < 0\n", address_count);
}

void delete_all_addresses(void)
{
	struct netdev_address *n;
	hip_list_t *item, *tmp;
	int i;

	HIP_DEBUG("address_count at entry=%d\n", address_count);
	if (address_count)
	{
		list_for_each_safe(item, tmp, addresses, i)
		{
			n = list_entry(item);
			list_del(n, addresses);
			HIP_FREE(n);
			address_count--;
		}
		if (address_count != 0) HIP_ERROR("BUG: address_count != 0\n", address_count);
	}
}

int hip_netdev_find_if(struct sockaddr *addr)
{
	struct netdev_address *n;
	hip_list_t *item, *tmp;
	int i;

	HIP_DEBUG_IN6ADDR("Trying to find addr", &(((struct sockaddr_in6 *)addr)->sin6_addr));

	list_for_each_safe(item, tmp, addresses, i)
	{
		n = list_entry(item);
		HIP_DEBUG("n family %d, addr family %d\n", n->addr.ss_family ,addr->sa_family);
		HIP_DEBUG_IN6ADDR("n addr ", &(((struct sockaddr_in6 *) &(n->addr))->sin6_addr));
		HIP_DEBUG("index %d\n", n->if_index);
		if ((n->addr.ss_family == addr->sa_family) &&
		    ((memcmp(hip_cast_sa_addr(&n->addr), hip_cast_sa_addr(addr),
			     hip_sa_addr_len(addr))==0)) ||
			  IPV6_EQ_IPV4( &(((struct sockaddr_in6 *) &(n->addr))->sin6_addr), &((struct sockaddr_in *) addr)->sin_addr))
		{
			HIP_DEBUG("index %d\n", n->if_index);
			return n->if_index;
		}

	}

	/* No matching address found */
	return 0;
}

/* base exchange IPv6 addresses need to be put into ifindex2spi map,
 * so a function is needed which gets the ifindex of the network
 * device which has the address @addr
 */
/* FIXME: The caller of this shoul be generalized to both IPv4 and
   IPv6 so that this function can be removed (tkoponen) */
int hip_devaddr2ifindex(struct in6_addr *addr)
{
	struct sockaddr_in6 a;
	a.sin6_family = AF_INET6;
	ipv6_addr_copy(&a.sin6_addr, addr);
	return hip_netdev_find_if((struct sockaddr *)&a);
}
int static add_address(const struct nlmsghdr *h, int len, void *arg)
{
        struct sockaddr_storage ss_addr;
        struct sockaddr *addr = (struct sockaddr*) &ss_addr;

	while (NLMSG_OK(h, len)) {
		struct ifaddrmsg *ifa;
		struct rtattr *rta, *tb[IFA_MAX+1];

		memset(tb, 0, sizeof(tb));
		/* exit this loop on end or error */
		if (h->nlmsg_type == NLMSG_DONE)
		{
			int *done = (int *)arg;
			*done = 1;
			break;
		}

		if (h->nlmsg_type == NLMSG_ERROR)
		{
			HIP_ERROR("Error in Netlink response.\n");
			return -1;
		}

		ifa = NLMSG_DATA(h);
		rta = IFA_RTA(ifa);
		len = h->nlmsg_len - NLMSG_LENGTH(sizeof(*ifa));

		if ((ifa->ifa_family != AF_INET) &&
		    (ifa->ifa_family != AF_INET6))
			continue;

		/* parse list of attributes into table
		 * (same as parse_rtattr()) */
		while (RTA_OK(rta, len))
		{
			if (rta->rta_type <= IFA_MAX)
				tb[rta->rta_type] = rta;
			rta = RTA_NEXT(rta,len);
		}

		/* fix tb entry for inet6 */
		if (!tb[IFA_LOCAL])
			tb[IFA_LOCAL] = tb[IFA_ADDRESS];
		if (!tb[IFA_ADDRESS])
			tb[IFA_ADDRESS] = tb[IFA_LOCAL];

		/* save the addresses we care about */
		if (tb[IFA_LOCAL])
		{
			addr->sa_family = ifa->ifa_family;
			memcpy(hip_cast_sa_addr(addr), RTA_DATA(tb[IFA_LOCAL]),
			       RTA_PAYLOAD(tb[IFA_LOCAL]));
                                add_address_to_list(addr, ifa->ifa_index);
                                _HIP_DEBUG("ifindex=%d\n", ifa->ifa_index);
		}
		h = NLMSG_NEXT(h, len);
	}

	return 0;
}

/*
 * Note: this creates a new NETLINK socket (via getifaddrs), so this has to be
 * run before the global NETLINK socket is opened. I did not have the time
 * and energy to import all of the necessary functionality from iproute2.
 * -miika
 */
int hip_netdev_init_addresses(struct rtnl_handle *nl)
{
	struct ifaddrs *g_ifaces = NULL, *g_iface;
	int err = 0, if_index;

	/* Initialize address list */
	HIP_DEBUG("Initializing addresses...\n");
	//INIT_LIST_HEAD(addresses);
	addresses = hip_ht_init(hip_netdev_hash, hip_netdev_match);

	HIP_IFEL(getifaddrs(&g_ifaces), -1,
		 "getifaddrs failed\n");

	for (g_iface = g_ifaces; g_iface; g_iface = g_iface->ifa_next)
	{
		if (!g_iface->ifa_addr)
			continue;
		HIP_IFEL(!(if_index = if_nametoindex(g_iface->ifa_name)),
			 -1, "if_nametoindex failed\n");

		add_address_to_list(g_iface->ifa_addr, if_index);
	}

 out_err:
	if (g_ifaces)
		freeifaddrs(g_ifaces);
	return err;
}

int hip_netdev_handle_acquire(const struct nlmsghdr *msg) {
	int err = 0, if_index = 0, is_ipv4_locator,
		reuse_hadb_local_address = 0, ha_nat_mode = hip_nat_status,
		old_global_nat_mode = hip_nat_status;
	in_port_t ha_peer_port;
	hip_ha_t *entry;
	hip_hit_t *src_hit, *dst_hit;
	struct xfrm_user_acquire *acq;
	struct in6_addr dst_addr, ha_match;
	struct sockaddr_storage ss_addr;
	struct sockaddr *addr;
	addr = (struct sockaddr*) &ss_addr;

	HIP_DEBUG("Acquire: sending I1 (pid: %d) \n", msg->nlmsg_pid);

	acq = (struct xfrm_user_acquire *)NLMSG_DATA(msg);
	src_hit = (struct in6_addr *) &acq->sel.saddr;
	dst_hit = (struct in6_addr *) &acq->sel.daddr;

	HIP_DEBUG_HIT("src HIT", src_hit);
	HIP_DEBUG_HIT("dst HIT", dst_hit);

	entry = hip_hadb_find_byhits(src_hit, dst_hit);
	if (entry)
		goto skip_entry_creation;

	/* No entry found; find first IP matching to the HIT and then
	   create the entry */

	err = hip_map_hit_to_addr(dst_hit, &dst_addr);
	if (err) {
		/* Search HADB for existing entries */
		entry = hip_hadb_try_to_find_by_peer_hit(dst_hit);
		if (entry) {
			HIP_DEBUG_IN6ADDR("reusing HA",
					  &entry->preferred_address);
			ipv6_addr_copy(&dst_addr, &entry->preferred_address);
			ha_peer_port = entry->peer_udp_port;
			ha_nat_mode = entry->nat_mode;
			err = 0;
		}
	}

	/* broadcast I1 as a last resource */
	if (err) {
		struct in_addr bcast = { INADDR_BROADCAST };
		/* IPv6 multicast (see bos.c) failed to bind() to link local,
		   so using IPv4 here -mk */
		HIP_DEBUG("No information of peer found, trying broadcast\n");
		IPV4_TO_IPV6_MAP(&bcast, &dst_addr);
		/* Broadcast did not work with UDP packets -mk */
		ha_nat_mode = 0;
		err = 0;
	}

	/* @fixme: changing global state won't work with threads */
	hip_nat_status = ha_nat_mode;

	HIP_IFEL(hip_hadb_add_peer_info(dst_hit, &dst_addr), -1,
		 "map failed\n");

	hip_nat_status = old_global_nat_mode; /* restore nat status */
	
	HIP_IFEL(!(entry = hip_hadb_find_byhits(src_hit, dst_hit)), -1,
		 "Internal lookup error\n");

	/* Preserve NAT status with peer */
	entry->peer_udp_port = ha_peer_port;
	entry->nat_mode = ha_nat_mode;

	reuse_hadb_local_address = 1;

skip_entry_creation:

	if (entry->state == HIP_STATE_NONE ||
	    entry->state == HIP_STATE_UNASSOCIATED) {
		HIP_DEBUG("State is %d, sending i1\n", entry->state);
	} else {
		HIP_DEBUG("I1 was already sent, ignoring\n");
		goto out_err;
	}

	is_ipv4_locator = IN6_IS_ADDR_V4MAPPED(&entry->preferred_address);

	memset(addr, 0, sizeof(struct sockaddr_storage));
	addr->sa_family = (is_ipv4_locator ? AF_INET : AF_INET6);

	if (!reuse_hadb_local_address)
		if (is_ipv4_locator) {
			IPV4_TO_IPV6_MAP(((struct in_addr *)&acq->id.daddr),
					 &entry->local_address);
		} else {
			ipv6_addr_copy(&entry->local_address,
				       ((struct in6_addr*)&acq->id.daddr));
		}

	memcpy(hip_cast_sa_addr(addr), &entry->local_address,
	       hip_sa_addr_len(addr));

	HIP_DEBUG_HIT("our hit", &entry->hit_our);
        HIP_DEBUG_HIT("peer hit", &entry->hit_peer);
	HIP_DEBUG_IN6ADDR("peer locator", &entry->preferred_address);
	HIP_DEBUG_IN6ADDR("our locator", &entry->local_address);

	HIP_IFEL(!(if_index = hip_devaddr2ifindex(&entry->local_address)), -1,
			 "if_index NOT determined\n");
        /* we could try also hip_select_source_address() here on failure,
	   but it seems to fail too */

	HIP_DEBUG("acq->sel.ifindex=%d\n", acq->sel.ifindex);

	add_address_to_list(addr, if_index /*acq->sel.ifindex*/);

	HIP_IFEL(hip_send_i1(&entry->hit_our, &entry->hit_peer, entry), -1,
		 "Sending of I1 failed\n");

out_err:
	return err;
}


int hip_netdev_event(const struct nlmsghdr *msg, int len, void *arg)
{
	struct ifinfomsg *ifinfo; /* link layer specific message */
	struct ifaddrmsg *ifa; /* interface address message */
	struct rtattr *rta, *tb[IFA_MAX+1];
	int l, is_add, i, ii;
	struct sockaddr_storage ss_addr;
	struct sockaddr *addr;
	struct hip_locator_info_addr_item *locators;
	struct netdev_address *n;
	hip_list_t *item, *tmp;
	int pre_if_address_count;

	addr = (struct sockaddr*) &ss_addr;

	for (; NLMSG_OK(msg, (u32)len);
	     msg = NLMSG_NEXT(msg, len))
	{
		int ifindex, addr_exists;
		ifinfo = (struct ifinfomsg*)NLMSG_DATA(msg);
		ifindex = ifinfo->ifi_index;


		HIP_DEBUG("handling msg type %d ifindex=%d\n",
			  msg->nlmsg_type, ifindex);
		switch(msg->nlmsg_type)
		{
		case RTM_NEWLINK:
			HIP_DEBUG("RTM_NEWLINK\n");
			/* wait for RTM_NEWADDR to add addresses */
			break;
		case RTM_DELLINK:
			HIP_DEBUG("RTM_DELLINK\n");
			//ifinfo = (struct ifinfomsg*)NLMSG_DATA(msg);
			//delete_address_from_list(NULL, ifinfo->ifi_index);
			//delete_address_from_list(NULL, ifindex);
			/* should do here
			   hip_send_update_all(NULL, 0, ifindex, SEND_UPDATE_REA);
			   but ifconfig ethX down never seems to come here
			*/
			break;
			/* Add or delete address from addresses */
		case RTM_NEWADDR:
		case RTM_DELADDR:
			HIP_DEBUG("RTM_NEWADDR/DELADDR\n");
			ifa = (struct ifaddrmsg*)NLMSG_DATA(msg);
			rta = IFA_RTA(ifa);
			l = msg->nlmsg_len - NLMSG_LENGTH(sizeof(*ifa));
			if ((ifa->ifa_family != AF_INET) &&
			    (ifa->ifa_family != AF_INET6))
				continue;

			memset(tb, 0, sizeof(tb));
			memset(addr, 0, sizeof(struct sockaddr_storage));
			is_add = (msg->nlmsg_type==RTM_NEWADDR);

			/* parse list of attributes into table
			 * (same as parse_rtattr()) */
			while (RTA_OK(rta, l))
			{
				if (rta->rta_type <= IFA_MAX)
					tb[rta->rta_type] = rta;
				rta = RTA_NEXT(rta, l);
			}
			/* fix tb entry for inet6 */
			if (!tb[IFA_LOCAL])
				tb[IFA_LOCAL] = tb[IFA_ADDRESS];
			if (!tb[IFA_ADDRESS])
				tb[IFA_ADDRESS] = tb[IFA_LOCAL];

			if (!tb[IFA_LOCAL])
				continue;
			addr->sa_family = ifa->ifa_family;
			memcpy(hip_cast_sa_addr(addr), RTA_DATA(tb[IFA_LOCAL]),
			       RTA_PAYLOAD(tb[IFA_LOCAL]) );
			HIP_DEBUG("Address event=%s ifindex=%d\n",
				  is_add ? "add" : "del", ifa->ifa_index);

			/* update our address list */
			pre_if_address_count = count_if_addresses(ifa->ifa_index);
			HIP_DEBUG("%d addr(s) in ifindex %d before add/del\n",
				  pre_if_address_count, ifa->ifa_index);

			addr_exists = exists_address_in_list(addr,
							     ifa->ifa_index);
			HIP_DEBUG("is_add=%d, exists=%d\n", is_add, addr_exists);
			if ((is_add && addr_exists) ||
			    (!is_add && !addr_exists))
			{
				/* radvd can try to add duplicate addresses.
				   This can confused our address cache. */
				HIP_DEBUG("Address %s discarded.\n",
					  (is_add ? "add" : "del"));
				return 0;
			}

			if (is_add) {
				add_address_to_list(addr, ifa->ifa_index);
			} else {
				delete_address_from_list(addr, ifa->ifa_index);
				// hip_for_each_ha();
			}

			i = count_if_addresses(ifa->ifa_index);
			HIP_DEBUG("%d addr(s) in ifindex %d\n", i, ifa->ifa_index);

			/* handle HIP readdressing */

			if (i == 0 && pre_if_address_count > 0 &&
			    msg->nlmsg_type == RTM_DELADDR) {
				/* send 0-address REA if this was deletion of
				   the last address */
				HIP_DEBUG("sending 0-addr REA\n");
				hip_send_update_all(NULL, 0, ifa->ifa_index,
						    SEND_UPDATE_LOCATOR, is_add, addr);
			}
			else if (i == 0)
			{
				HIP_DEBUG("no need to readdress\n");
				goto skip_readdr;
			}

			locators = (struct hip_locator_info_addr_item *)
				malloc(i * sizeof(struct hip_locator_info_addr_item));
			if (locators)
			{
				i = 0;
				list_for_each_safe(item, tmp, addresses, ii)
				{
					n = list_entry(item);
					/* advertise only the addresses which are in
					   the same interface which caused the event */
					if (n->if_index != ifa->ifa_index)
						continue;

					memcpy(&locators[i].address, hip_cast_sa_addr(&n->addr),
					       hip_sa_addr_len(&n->addr));
					/* FIXME: Is this ok? (tkoponen), for boeing it is*/
					locators[i].traffic_type = HIP_LOCATOR_TRAFFIC_TYPE_DUAL;
					locators[i].locator_type = HIP_LOCATOR_LOCATOR_TYPE_IPV6;
					locators[i].locator_length = sizeof(struct in6_addr) / 4;

					/* For testing preferred address */
					//locators[i].reserved =
					//	i == 0 ? htonl(1 << 31) : 0;
					locators[i].lifetime = 0;
					i++;
				}
				HIP_DEBUG("UPDATE to be sent contains %i addr(s)\n", i);
				hip_send_update_all(locators, i,
						    ifa->ifa_index,
						    SEND_UPDATE_LOCATOR, is_add, addr);
				free(locators);
				break;
			}
		case XFRMGRP_ACQUIRE:
			/* XX TODO  does this ever happen? */
			HIP_DEBUG("\n");
			return -1;
			break;
		case XFRMGRP_EXPIRE:
			HIP_DEBUG("received expiration, ignored\n");
			return 0;
			break;
#if 0
		case XFRMGRP_SA:
			/* XX TODO  does this ever happen? */
			return -1;
			break;
		case XFRMGRP_POLICY:
			/* XX TODO  does this ever happen? */
			return -1;
			break;
#endif
		case XFRM_MSG_GETSA:
			return -1;
			break;
		case XFRM_MSG_ALLOCSPI:
			return -1;
			break;
		case XFRM_MSG_ACQUIRE:
			return hip_netdev_handle_acquire(msg);
			break;
		case XFRM_MSG_EXPIRE:
			return -1;
			break;
		case XFRM_MSG_UPDPOLICY:
			return -1;
			break;
		case XFRM_MSG_UPDSA:
			return -1;
			break;
		case XFRM_MSG_POLEXPIRE:
			return -1;
			break;
#if 0
		case XFRM_MSG_FLUSHSA:
			return -1;
			break;
		case XFRM_MSG_FLUSHPOLICY:
			return -1;
			break;
#endif
		skip_readdr:
			break;
		default:
			HIP_DEBUG("unhandled msg type %d\n", msg->nlmsg_type);
			break;
		}
	}

 out:

	return 0;
}

int hip_add_iface_local_hit(const hip_hit_t *local_hit)
{
	int err = 0;
	char *hit_str = NULL;
	struct idxmap *idxmap[16] = {0};

	HIP_IFE((!(hit_str = hip_convert_hit_to_str(local_hit, HIP_HIT_PREFIX_STR))), -1);
	HIP_DEBUG("Adding HIT: %s\n", hit_str);

	HIP_IFE(hip_ipaddr_modify(&hip_nl_route, RTM_NEWADDR, AF_INET6,
				  hit_str, HIP_HIT_DEV, idxmap), -1);

 out_err:

	if (hit_str)
		HIP_FREE(hit_str);

	return err;
}

int hip_add_iface_local_lsi(const hip_lsi_t lsi)
{
	int err = 0;
	char lsi_str[INET_ADDRSTRLEN+5];
	struct idxmap *idxmap[16] = {0};

	HIP_IFE((!(inet_ntop(AF_INET, &lsi, lsi_str, sizeof(lsi_str)))),
		-1);
	HIP_DEBUG("Adding LSI: %s\n", lsi_str);
	HIP_IFE(hip_ipaddr_modify(&hip_nl_route, RTM_NEWADDR, AF_INET,
                                  lsi_str, HIP_HIT_DEV, idxmap), -1);
 out_err:

	return err;
}

int hip_add_iface_local_route(const hip_hit_t *local_hit)
{
	int err = 0;
	char *hit_str = NULL;
	struct idxmap *idxmap[16] = {0};

	HIP_IFE((!(hit_str = hip_convert_hit_to_str(local_hit, HIP_HIT_FULL_PREFIX_STR))), -1);
	HIP_DEBUG("Adding local HIT route: %s\n", hit_str);
	HIP_IFE(hip_iproute_modify(&hip_nl_route, RTM_NEWROUTE,
				   NLM_F_CREATE|NLM_F_EXCL,
				   AF_INET6, hit_str, HIP_HIT_DEV, idxmap),
		-1);

 out_err:

	if (hit_str)
	  HIP_FREE(hit_str);

	return err;
}

int hip_add_iface_local_route_lsi(const hip_lsi_t lsi)
{
	int err = 0;
	struct idxmap *idxmap[16] = {0};
	char lsi_str[INET_ADDRSTRLEN+5];

	HIP_IFE((!(inet_ntop(AF_INET, &lsi, lsi_str, sizeof(lsi_str)))),
		-1);
	HIP_DEBUG("Adding local LSI route: %s\n", lsi_str);
	HIP_IFE(hip_iproute_modify(&hip_nl_route, RTM_NEWROUTE,
				   NLM_F_CREATE|NLM_F_EXCL,
				   AF_INET, lsi_str, HIP_HIT_DEV, idxmap),
		-1);

 out_err:

	return err;
}

int hip_select_source_address(struct in6_addr *src, struct in6_addr *dst)
{
	int err = 0;
	int family = AF_INET6;
//	int rtnl_rtdsfield_init;
//	char *rtnl_rtdsfield_tab[256] = { 0 };
	struct idxmap *idxmap[16] = { 0 };
		
	/* rtnl_rtdsfield_initialize() */
//	rtnl_rtdsfield_init = 1;
	
//	rtnl_tab_initialize("/etc/iproute2/rt_dsfield", rtnl_rtdsfield_tab, 256);
	HIP_DEBUG_IN6ADDR("dst", dst);
	HIP_DEBUG_IN6ADDR("src", src);

	HIP_IFEL(hip_iproute_get(&hip_nl_route, src, dst, NULL, NULL, family, idxmap), -1, "Finding ip route failed\n");

	HIP_DEBUG_IN6ADDR("src", src);

out_err:
//	for (i = 0; i < 256; i++) if (rtnl_rtdsfield_tab
	return err;
}

int hip_select_default_hit(struct in6_addr *src, struct in6_addr *dst, struct hip_common *msg)
{
	int err = 0;
	int family = AF_INET6;
	int rtnl_rtdsfield_init;
	char *rtnl_rtdsfield_tab[256] = { "0",};
	struct idxmap *idxmap[16] = { 0 };
	
	/* rtnl_rtdsfield_initialize() */
        rtnl_rtdsfield_init = 1;

        rtnl_tab_initialize("/etc/iproute2/rt_dsfield",rtnl_rtdsfield_tab, 256);
	set_hit_prefix(dst);
	HIP_IFEL(hip_iproute_get(&hip_nl_route, src, dst, NULL, NULL,family, idxmap), -1,"Finding ip route failed\n");
	HIP_DEBUG_IN6ADDR("src", src);
	hip_build_param_contents(msg,src,0,sizeof(struct in6_addr));
	
 out_err:

	return err;
}
