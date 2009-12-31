#include "heartbeat.h"
#include "maintenance.h"

int hip_handle_update_heartbeat_trigger(hip_ha_t *ha, void *unused)
{
        struct hip_locator_info_addr_item *locators;
        hip_common_t *locator_msg;
	int err = 0;

        if (!(ha->hastate == HIP_HASTATE_HITOK &&
	      ha->state == HIP_STATE_ESTABLISHED &&
	      ha->disable_sas == 0))
		goto out_err;

	ha->update_trigger_on_heartbeat_counter++;
	_HIP_DEBUG("Trigger count %d/%d\n", ha->update_trigger_on_heartbeat_counter,
		  HIP_ADDRESS_CHANGE_HB_COUNT_TRIGGER * hip_icmp_interval);

	if (ha->update_trigger_on_heartbeat_counter <
	    HIP_ADDRESS_CHANGE_HB_COUNT_TRIGGER * hip_icmp_interval)
		goto out_err;

	/* Time to try a handover because heart beats have been failing.
	   Let's also reset to counter to avoid UPDATE looping in case e.g.
	   there is just no connectivity at all. */
	ha->update_trigger_on_heartbeat_counter = 0;

	HIP_DEBUG("Hearbeat counter with ha expired, trigger UPDATE\n");

        HIP_IFEL(!(locator_msg = hip_msg_alloc()), -ENOMEM,
            "Out of memory while allocation memory for the packet\n");
        HIP_IFE(hip_create_locators(locator_msg, &locators), -1);

	HIP_IFEL(hip_send_locators_to_one_peer(NULL, ha, &ha->our_addr,
					     &ha->peer_addr, locators, HIP_UPDATE_LOCATOR),
		 -1, "Failed to trigger update\n");
		 
	ha->update_trigger_on_heartbeat_counter = 0;

out_err:
	return err;
}

/** 
 * This function goes through the HA database and sends an icmp echo to all of them
 *
 * @param socket to send with
 *
 * @return 0 on success negative on error
 */
int hip_send_heartbeat(hip_ha_t *entry, void *opaq) {
	int err = 0;
	int *sockfd = (int *) opaq;

	if (entry->state == HIP_STATE_ESTABLISHED) {
	    if (entry->outbound_sa_count > 0) {
		    _HIP_DEBUG("list_for_each_safe\n");
		    HIP_IFEL(hip_send_icmp(*sockfd, entry), 0,
			     "Error sending heartbeat, ignore\n");
	    } else {
		    /* This can occur when ESP transform is not negotiated
		       with e.g. a HIP Relay or Rendezvous server */
		    HIP_DEBUG("No SA, sending NOTIFY instead of ICMPv6\n");
		    err = hip_nat_send_keep_alive(entry, NULL);
	    }
        }

out_err:
	return err;
}

/**
 * This function receives ICMPv6 msgs (heartbeats)
 *
 * @param sockfd to recv from
 *
 * @return 0 on success otherwise negative
 *
 * @note see RFC2292
 */
int hip_icmp_recvmsg(int sockfd) {
	int err = 0, ret = 0, identifier = 0;
	struct msghdr mhdr;
	struct cmsghdr * chdr;
	struct iovec iov[1];
	u_char cmsgbuf[CMSG_SPACE(sizeof(struct inet6_pktinfo))];
	u_char iovbuf[HIP_MAX_ICMP_PACKET];
	struct icmp6hdr * icmph = NULL;
	struct inet6_pktinfo * pktinfo;
	struct sockaddr_in6 src_sin6;
	struct in6_addr * src = NULL, * dst = NULL;
	struct timeval * stval = NULL, * rtval = NULL, * ptr = NULL;

	/* malloc what you need */
	stval = malloc(sizeof(struct timeval));
	HIP_IFEL((!stval), -1, "Malloc for stval failed\n");
	rtval = malloc(sizeof(struct timeval));
	HIP_IFEL((!rtval), -1, "Malloc for rtval failed\n");
	src = malloc(sizeof(struct in6_addr));
	HIP_IFEL((!src), -1, "Malloc for dst6 failed\n");
	dst = malloc(sizeof(struct in6_addr));
	HIP_IFEL((!dst), -1, "Malloc for dst failed\n");

	/* cast */
	chdr = (struct cmsghdr *)(void*)cmsgbuf;
	pktinfo = (struct inet6_pktinfo *)(void*)(CMSG_DATA(chdr));

	/* clear memory */
	memset(stval, 0, sizeof(struct timeval));
	memset(rtval, 0, sizeof(struct timeval));
	memset(src, 0, sizeof(struct in6_addr));
	memset(dst, 0, sizeof(struct in6_addr));
	memset (&src_sin6, 0, sizeof (struct sockaddr_in6));
	memset(&iov, 0, sizeof(&iov));
	memset(&iovbuf, 0, sizeof(iovbuf));
	memset(&mhdr, 0, sizeof(mhdr));

	/* receive control msg */
        chdr->cmsg_level = IPPROTO_IPV6;
	chdr->cmsg_type = IPV6_2292PKTINFO;
	chdr->cmsg_len = CMSG_LEN (sizeof (struct inet6_pktinfo));

	/* Input output buffer */
	iov[0].iov_base = &iovbuf;
	iov[0].iov_len = sizeof(iovbuf);

	/* receive msg hdr */
	mhdr.msg_iov = &(iov[0]);
	mhdr.msg_iovlen = 1;
	mhdr.msg_name = (caddr_t) &src_sin6;
	mhdr.msg_namelen = sizeof (struct sockaddr_in6);
	mhdr.msg_control = (caddr_t) cmsgbuf;
	mhdr.msg_controllen = sizeof (cmsgbuf);

	ret = recvmsg (sockfd, &mhdr, MSG_DONTWAIT);
	_HIP_PERROR("RECVMSG ");
	if (errno == EAGAIN) {
		err = 0;
		_HIP_DEBUG("Asynchronous, maybe next time\n");
		goto out_err;
	}
	if (ret < 0) {
		HIP_DEBUG("Recvmsg on ICMPv6 failed\n");
		err = -1;
		goto out_err;
 	}

	/* Get the current time as the return time */
	gettimeofday(rtval, (struct timezone *)NULL);

	/* Check if the process identifier is ours and that this really is echo response */
	icmph = (struct icmp6hdr *)(void*) iovbuf;
	if (icmph->icmp6_type != ICMPV6_ECHO_REPLY) {
		err = 0;
		goto out_err;
	}
	identifier = getpid() & 0xFFFF;
	if (identifier != icmph->icmp6_identifier) {
		err = 0;
		goto out_err;
	}

	/* Get the timestamp as the sent time*/
	ptr = (struct timeval *)(icmph + 1);
	memcpy(stval, ptr, sizeof(struct timeval));

	/* gather addresses */
	memcpy (src, &src_sin6.sin6_addr, sizeof (struct in6_addr));
	memcpy (dst, &pktinfo->ipi6_addr, sizeof (struct in6_addr));

	if (!ipv6_addr_is_hit(src) && !ipv6_addr_is_hit(dst)) {
	    HIP_DEBUG("Addresses are NOT HITs, this msg is not for us\n");
	}

	/* Calculate and store everything into the correct entry */
	HIP_IFEL(hip_icmp_statistics(src, dst, stval, rtval), -1,
		 "Failed to calculate the statistics and store the values\n");

out_err:
	
	if (stval) free(stval);
	if (rtval) free(rtval);
	if (src) free(src);
	if (dst) free(dst);
	
	return err;
}
