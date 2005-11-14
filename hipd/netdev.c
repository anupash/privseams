/**
 * This code is heavily based on Boeing HIPD hip_netlink.c
 *
 */
#include "netdev.h"

static int count_if_addresses(int ifindex)
{
	struct netdev_address *n, *t;
	int i = 0;

	list_for_each_entry_safe(n, t, &addresses, next) {
		if (n->if_index == ifindex)
			i++;
	}
	return i;
}


/* Returns 1 if the given address @addr is allowed to be one of the
   addresses of this host, 0 otherwise */
int filter_address(struct sockaddr *addr, int ifindex)
{
	HIP_DEBUG("ifindex=%d, address family=%d\n",
		  ifindex, addr->sa_family);
	HIP_HEXDUMP("testing address=", SA2IP(addr), SAIPLEN(addr));

	if (addr->sa_family == AF_INET6) {
		struct sockaddr_in6 *a = SA2IP(addr);
		if (IN6_IS_ADDR_UNSPECIFIED(a) ||
		    IN6_IS_ADDR_LOOPBACK(a) ||
		    IN6_IS_ADDR_MULTICAST(a) ||
		    IN6_IS_ADDR_LINKLOCAL(a) ||
		    IN6_IS_ADDR_SITELOCAL(a) ||
		    IN6_IS_ADDR_V4MAPPED(a) ||
		    IN6_IS_ADDR_V4COMPAT(a))
			return 0;
		return 1;
	}
	/* add more filtering tests here */
	return 0;
}

static void add_address_to_list(struct sockaddr *addr, int ifindex)
{
	struct netdev_address *n;

	if (!filter_address(addr, ifindex)) {
		HIP_DEBUG("filtering this address\n");
		return;
	}

	n = (struct netdev_address *) malloc(sizeof(struct netdev_address));
	if (!n) {
		// FIXME; memory error
		HIP_ERROR("Could not allocate memory\n");
		return;
	}

        memcpy(&n->addr, addr, SALEN(addr));
        n->if_index = ifindex;
	//INIT_LIST_HEAD(&n->next);
	list_add(&n->next, &addresses);
	address_count++;
	HIP_DEBUG("added address, address_count at exit=%d\n", address_count);
}

static void delete_address_from_list(struct sockaddr *addr, int ifindex)
{
        struct netdev_address *n, *t;

	HIP_HEXDUMP("deleting address=", SA2IP(addr), SAIPLEN(addr));
	HIP_DEBUG("address_count at entry=%d\n", address_count);

	list_for_each_entry_safe(n, t, &addresses, next) {
		int deleted = 0;

                /* remove from list if if_index matches */
                if (!addr) {
                        if (n->if_index == ifindex) {
				list_del(&n->next);
				deleted = 1;
			}
                } else {
			/* remove from list if address matches */
                        if ((n->addr.ss_family == addr->sa_family) &&
                            (memcmp(SA2IP(&n->addr), SA2IP(addr),
                                    SAIPLEN(addr))==0)) {
                                /* address match */
				list_del(&n->next);
				deleted = 1;
                        }
                }
		if (deleted) {
			address_count--;
			HIP_DEBUG("dec address_count to %d\n", address_count);
		}
        }

	HIP_DEBUG("address_count at exit=%d\n", address_count);
	if (address_count < 0)
		HIP_ERROR("BUG: address_count < 0\n", address_count);
}

void delete_all_addresses(void)
{
        struct netdev_address *n, *t;

	HIP_DEBUG("address_count at entry=%d\n", address_count);
	list_for_each_entry_safe(n, t, &addresses, next) {
		list_del(&n->next);
		HIP_FREE(n);
		address_count--;
        }

	if (address_count != 0)
		HIP_ERROR("BUG: address_count != 0\n", address_count);
}

int hip_netdev_find_if(struct sockaddr *addr)
{
        struct netdev_address *n;
	list_for_each_entry(n, &addresses, next) {
		if ((n->addr.ss_family == addr->sa_family) &&
		    (memcmp(SA2IP(&n->addr), SA2IP(addr),
			    SAIPLEN(addr))==0)) {
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
int hip_ipv6_devaddr2ifindex(struct in6_addr *addr)
{
	struct sockaddr_in6 a;
	a.sin6_family = AF_INET6;
	ipv6_addr_copy(&a.sin6_addr, addr);
	return hip_netdev_find_if((struct sockaddr *)&a);
}

int static add_address(const struct nlmsghdr *h, int len, void *arg) {
        struct sockaddr_storage ss_addr;
        struct sockaddr *addr = (struct sockaddr*) &ss_addr;

	while (NLMSG_OK(h, len)) {
		struct ifaddrmsg *ifa;
		struct rtattr *rta, *tb[IFA_MAX+1];
		
		memset(tb, 0, sizeof(tb));
		/* exit this loop on end or error */
		if (h->nlmsg_type == NLMSG_DONE) {
			int *done = (int *)arg;
			*done = 1;
			break;
		}

		if (h->nlmsg_type == NLMSG_ERROR) {
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
		while (RTA_OK(rta, len)) {
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
		if (tb[IFA_LOCAL]) {
			addr->sa_family = ifa->ifa_family;
			memcpy(SA2IP(addr), RTA_DATA(tb[IFA_LOCAL]),
			       RTA_PAYLOAD(tb[IFA_LOCAL]));
                                add_address_to_list(addr, ifa->ifa_index);
                                _HIP_DEBUG("ifindex=%d\n", ifa->ifa_index);
		}
		h = NLMSG_NEXT(h, len);
	}

	return 0;
}

/* 
 * function get_my_addresses()
 *
 * Use the netlink interface to retrieve a list of addresses for this
 * host's interfaces, and stores them into global addresses list.
 */
int hip_netdev_init_addresses(struct hip_nl_handle *nl)
{
        struct sockaddr_nl nladdr;
        char buf[8192];
        struct nlmsghdr *h;
        int status, done = 0;

        /* netlink packet */
        struct {
                struct nlmsghdr n;
                struct rtgenmsg g;
        } req;

        struct iovec iov = { buf, sizeof(buf) };
        /* message response */
        struct msghdr msg = {
                (void*)&nladdr, sizeof(nladdr),
                &iov, 1,
                NULL, 0,
                0
        };

	/* Initialize address list */
	HIP_DEBUG("Initializing addresses...\n");
	INIT_LIST_HEAD(&addresses);
	address_count = 0;

        /* setup request */
        memset(&req, 0, sizeof(req));
        req.n.nlmsg_len = sizeof(req);
        req.n.nlmsg_type = RTM_GETADDR;
        req.n.nlmsg_flags = NLM_F_ROOT | NLM_F_MATCH | NLM_F_REQUEST;
        req.n.nlmsg_pid = 0;
        req.n.nlmsg_seq = ++nl->seq;
        req.g.rtgen_family = 0;

	HIP_DEBUG("Sending an address request.\n");

        /* send request */
	if (hip_netlink_send_buf(nl, (const char *)&req, sizeof(req)) < 0) {
		HIP_ERROR("Netlink: sendto() error: %s\n", strerror(errno));
                return(-1);
        }

        HIP_DEBUG("Local addresses:\n");

        /* receiving loop 1
         * call recvmsg() repeatedly until we get a message
         * with the NLMSG_DONE flag set
         */
        while(!done) {
                /* get response */
		if (hip_netlink_receive(nl, add_address, &done)) {
                        HIP_ERROR("Netlink: recvmsg() error!\nerror: %s\n",
				  strerror(errno));
                        return(-1);
                }
        } /* end while(!done) - loop 1 */ 

	HIP_DEBUG("found %d usable addresses\n", address_count);
	HIP_DEBUG("addrs=0x%p\n", &addresses);
        return(0);
}

int hip_netdev_event(const struct nlmsghdr *msg, int len, void *arg)
{
	struct ifinfomsg *ifinfo; /* link layer specific message */
	struct ifaddrmsg *ifa; /* interface address message */
	struct rtattr *rta, *tb[IFA_MAX+1];
	int l, is_add, i;
	struct sockaddr_storage ss_addr;
	struct sockaddr *addr;
	struct hip_locator_info_addr_item *reas;
	struct netdev_address *n, *t;
	int pre_if_address_count;

	HIP_DEBUG("\n");
	addr = (struct sockaddr*) &ss_addr;
	
	for (; NLMSG_OK(msg, (u32)len);
	     msg = NLMSG_NEXT(msg, len)) {
		int ifindex;

		ifinfo = (struct ifinfomsg*)NLMSG_DATA(msg);
		ifindex = ifinfo->ifi_index;
		HIP_DEBUG("handling msg type %d ifindex=%d\n",
			  msg->nlmsg_type, ifindex);
		switch(msg->nlmsg_type) {
		case RTM_NEWLINK:
			HIP_DEBUG("RTM_NEWLINK\n");
			/* wait for RTM_NEWADDR to add addresses */
			break;
		case RTM_DELLINK:
			HIP_DEBUG("RTM_DELLINK\n");
			//ifinfo = (struct ifinfomsg*)NLMSG_DATA(msg);
			//delete_address_from_list(NULL, ifinfo->ifi_index);
			delete_address_from_list(NULL, ifindex);
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
			while (RTA_OK(rta, l)) {
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
			memcpy(SA2IP(addr), RTA_DATA(tb[IFA_LOCAL]),
			       RTA_PAYLOAD(tb[IFA_LOCAL]) );
			HIP_DEBUG("Address event=%s ifindex=%d\n",
				  is_add ? "add" : "del", ifa->ifa_index);
			
			/* update our address list */
			pre_if_address_count = count_if_addresses(ifa->ifa_index);
			HIP_DEBUG("%d addr(s) in ifindex %d before add/del\n",
				  pre_if_address_count, ifa->ifa_index);
			if (is_add)
				add_address_to_list(addr, ifa->ifa_index);
			else
				delete_address_from_list(addr, ifa->ifa_index);
			i = count_if_addresses(ifa->ifa_index);
			HIP_DEBUG("%d addr(s) in ifindex %d\n", i, ifa->ifa_index);

			/* handle HIP readdressing */

			if (i == 0 && pre_if_address_count > 0 &&
			    msg->nlmsg_type == RTM_DELADDR) {
				/* send 0-address REA is this was deletion of the
				   last address */			   
				HIP_DEBUG("sending 0-addr REA\n");
				hip_send_update_all(NULL, 0, ifa->ifa_index,
						    SEND_UPDATE_LOCATOR);
			} else if (i == 0) {
				HIP_DEBUG("no need to readdress\n");
				goto skip_readdr;
			}

			reas = (struct hip_locator_info_addr_item *)
			 malloc(i  *sizeof(struct hip_locator_info_addr_item));
			if (!reas) {
				HIP_ERROR("malloc failed\n");
				goto out;
			}

			i = 0;
			
			list_for_each_entry_safe(n, t, &addresses, next) {
				/* advertise only the addresses which are in
				   the same interface which caused the event */
				if (n->if_index != ifa->ifa_index)
					continue;
				
				memcpy(&reas[i].address, SA2IP(&n->addr),
				       SAIPLEN(&n->addr));
				/* FIXME: Is this ok? (tkoponen), for boeing it is*/					reas[i].lifetime = 0;
				/* For testing preferred address */
				reas[i].reserved = i == 0 ? htonl(1 << 31) : 0;
				
				reas[i].traffic_type = HIP_LOCATOR_TRAFFIC_TYPE_DUAL; 
				reas[i].locator_type = HIP_LOCATOR_LOCATOR_TYPE_IPV6; 
				reas[i].locator_length = sizeof(struct in6_addr) / 4; 
				reas[i].reserved = 0;
				reas[i].lifetime = 0;
				
				i++;
			}
			HIP_DEBUG("REA to be sent contains %i addr(s)\n", i);
			hip_send_update_all(reas, i,
					    ifa->ifa_index,
					    SEND_UPDATE_LOCATOR);
			free(reas);
			break;
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
