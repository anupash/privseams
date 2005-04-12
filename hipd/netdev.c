/**
 * This code is heavily based on Boeing HIPD hip_netlink.c
 *
 */
#include "netdev.h"

static int address_count;
static struct list_head addresses;

static void add_address_to_list(struct sockaddr *addr, int ifi)
{
	struct netdev_address *n;

	if (!(n = (struct netdev_address *)malloc(sizeof(struct netdev_address)))) {
		// FIXME; memory error
	}

        memcpy(&n->addr, addr, SALEN(addr));
        n->if_index = ifi;

	list_add(&n->next, &addresses);
}

static void delete_address_from_list(struct sockaddr *addr, int ifi)
{
        struct netdev_address *n, *t;
	list_for_each_entry_safe(n, t, &addresses, next) {
                /* remove from list if if_index matches */
                if (!addr) {
                        if (n->if_index == ifi) {
				list_del(&n->next);
			}
                } else {
			/* remove from list if address matches */
                        if ((n->addr.ss_family == addr->sa_family) &&
                            (memcmp(SA2IP(&n->addr), SA2IP(addr),
                                    SAIPLEN(addr))==0)) {
                                /* address match */
				list_del(&n->next);
                        }
                }
        }
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
                                HIP_DEBUG("(%d)%s\n", ifa->ifa_index);
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
		HIP_ERROR("Netlink: sentdo() error: %s\n", strerror(errno));
                return(-1);
        }

        HIP_DEBUG("Local addresses: \n");
        
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
	struct hip_rea_info_addr_item *reas;
	struct netdev_address *n, *t;

	addr = (struct sockaddr*) &ss_addr;
	
	for (; NLMSG_OK(msg, (u32)len);
	     msg = NLMSG_NEXT(msg, len)) {
		switch(msg->nlmsg_type) {
		case RTM_NEWLINK:
			/* wait for RTM_NEWADDR to add addresses */
			break;
		case RTM_DELLINK:
			ifinfo = (struct ifinfomsg*)NLMSG_DATA(msg);
			delete_address_from_list(NULL, ifinfo->ifi_index);
			break;
			/* Add or delete address from addresses */
		case RTM_NEWADDR:
		case RTM_DELADDR:
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
			HIP_DEBUG("Address %s: (%d) \n", (is_add) ? "added" :
				  "deleted", ifa->ifa_index);
			
			/* update our address list */
			if (is_add) {
				add_address_to_list(addr, ifa->ifa_index);
			} else {
				delete_address_from_list(addr, ifa->ifa_index);
			}

			/* handle HIP readdressing */
			reas = (struct hip_rea_info_addr_item *)malloc(address_count * sizeof(struct hip_rea_info_addr_item));

			i = 0;
			list_for_each_entry_safe(n, t, &addresses, next) {
				memcpy(&reas[i].address, SA2IP(&n->addr), SAIPLEN(&n->addr));
                                /* lifetime: select prefered_lft or valid_lft ? */
				reas[i].lifetime = 0; /* FIXME: Is this ok? (tkoponen), for boeing it is... */
				/* For testing preferred address */
				reas[i].reserved = i == 0 ? htonl(1 << 31) : 0;
			}

			hip_send_update_all(reas, address_count, ifa->ifa_index, SEND_UPDATE_REA);
			free(reas);
			break;
		default:
			break;
		}
	}

	return 0;
}

