/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "maintenance.h"

#ifdef ANDROID_CHANGES
#define icmp6hdr icmp6_hdr
#define icmp6_identifier icmp6_id
#define ICMPV6_ECHO_REPLY ICMP6_ECHO_REPLY
#endif

int hip_firewall_sock_lsi_fd = -1;

float retrans_counter = HIP_RETRANSMIT_INIT;
float opp_fallback_counter = HIP_OPP_FALLBACK_INIT;
float precreate_counter = HIP_R1_PRECREATE_INIT;
int nat_keep_alive_counter = HIP_NAT_KEEP_ALIVE_INTERVAL;
//float queue_counter = QUEUE_CHECK_INIT;
int force_exit_counter = FORCE_EXIT_COUNTER_START;
int cert_publish_counter = CERTIFICATE_PUBLISH_INTERVAL;
int heartbeat_counter = 0;
int hip_firewall_status = 0;
int fall, retr;

extern int hip_icmp_interval;
extern int hip_icmp_sock;

/**
 * Handle packet retransmissions.
 */
int hip_handle_retransmission(hip_ha_t *entry, void *current_time)
{
	int err = 0;
	time_t *now = (time_t*) current_time;

	if (entry->hip_msg_retrans.buf == NULL)
		goto out_err;

	_HIP_DEBUG("Time to retrans: %d Retrans count: %d State: %s\n",
		   entry->hip_msg_retrans.last_transmit + HIP_RETRANSMIT_WAIT - *now,
		   entry->hip_msg_retrans.count, hip_state_str(entry->state));

	_HIP_DEBUG_HIT("hit_peer", &entry->hit_peer);
	_HIP_DEBUG_HIT("hit_our", &entry->hit_our);

	/* check if the last transmision was at least RETRANSMIT_WAIT seconds ago */
	if(*now - HIP_RETRANSMIT_WAIT > entry->hip_msg_retrans.last_transmit){
		_HIP_DEBUG("%d %d %d\n",entry->hip_msg_retrans.count,
			  entry->state, entry->retrans_state);
		if ((entry->hip_msg_retrans.count > 0) && entry->hip_msg_retrans.buf &&
		    ((entry->state != HIP_STATE_ESTABLISHED && entry->retrans_state != entry->state) ||
		     (entry->update_state != 0 && entry->retrans_state != entry->update_state) ||
		     entry->light_update_retrans == 1)) {
			HIP_DEBUG("state=%d, retrans_state=%d, update_state=%d\n",
				  entry->state, entry->retrans_state, entry->update_state, entry->retrans_state);

			/* @todo: verify that this works over slow ADSL line */
			err = entry->hadb_xmit_func->
				hip_send_pkt(&entry->hip_msg_retrans.saddr,
					     &entry->hip_msg_retrans.daddr,
					     (entry->nat_mode ? hip_get_local_nat_udp_port() : 0),
						     entry->peer_udp_port,
					     entry->hip_msg_retrans.buf,
					     entry, 0);

			/* Set entry state, if previous state was unassosiated
			   and type is I1. */
			if (!err && hip_get_msg_type(entry->hip_msg_retrans.buf)
			    == HIP_I1 && entry->state == HIP_STATE_UNASSOCIATED) {
				HIP_DEBUG("Resent I1 succcesfully\n");
				entry->state = HIP_STATE_I1_SENT;
			}

			entry->hip_msg_retrans.count--;
			/* set the last transmission time to the current time value */
			time(&entry->hip_msg_retrans.last_transmit);
		} else {
			if (entry->hip_msg_retrans.buf)
				HIP_FREE(entry->hip_msg_retrans.buf);
			entry->hip_msg_retrans.buf = NULL;
			entry->hip_msg_retrans.count = 0;

			if (entry->state == HIP_STATE_ESTABLISHED)
				entry->retrans_state = entry->update_state;
			else
				entry->retrans_state = entry->state;
		}
	}

 out_err:

	return err;
}

#ifdef CONFIG_HIP_OPPORTUNISTIC
int hip_scan_opp_fallback()
{
	int err = 0;
	time_t current_time;
	time(&current_time);

	HIP_IFEL(hip_for_each_opp(hip_handle_opp_fallback, &current_time), 0,
		 "for_each_ha err.\n");
 out_err:
	return err;
}
#endif

/**
 * Find packets, that should be retransmitted.
 */
int hip_scan_retransmissions()
{
	int err = 0;
	time_t current_time;
	time(&current_time);
	HIP_IFEL(hip_for_each_ha(hip_handle_retransmission, &current_time), 0,
		 "for_each_ha err.\n");
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
 * Periodic maintenance.
 *
 * @return ...
 */
int periodic_maintenance()
{
	int err = 0;

	if (hipd_get_state() == HIPD_STATE_CLOSING) {
		if (force_exit_counter > 0) {
			err = hip_count_open_connections();
			if (err < 1) hipd_set_state(HIPD_STATE_CLOSED);
		} else {
			hip_exit(SIGINT);
			exit(SIGINT);
		}
		force_exit_counter--;
	}

	/* If some HAs are still remaining after certain grace period
	   in closing or closed state, delete them */
	hip_for_each_ha(hip_purge_closing_ha, NULL);
	
	if (retrans_counter < 0) {
		HIP_IFEL(hip_scan_retransmissions(), -1,
			 "retransmission scan failed\n");
		retrans_counter = HIP_RETRANSMIT_INIT;
	} else {
		retrans_counter--;
	}

#ifdef CONFIG_HIP_OPPORTUNISTIC

	if (opp_fallback_counter < 0) {
		HIP_IFEL(hip_scan_opp_fallback(), -1,
			 "retransmission scan failed\n");
		opp_fallback_counter = HIP_OPP_FALLBACK_INIT;
	} else {
		opp_fallback_counter--;

	}
#endif

	if (precreate_counter < 0) {
		HIP_IFEL(hip_recreate_all_precreated_r1_packets(), -1,
			 "Failed to recreate puzzles\n");
		precreate_counter = HIP_R1_PRECREATE_INIT;
	} else {
		precreate_counter--;
	}

	/* is heartbeat support on */
	if (hip_icmp_interval > 0) {
		/* Check if there are any msgs in the ICMPv6 socket */
		/*
		HIP_IFEL(hip_icmp_recvmsg(hip_icmp_sock), -1,
			 "Failed to recvmsg from ICMPv6\n");
		*/
		/* Check if the heartbeats should be sent */
		if (heartbeat_counter < 1) {
			hip_for_each_ha(hip_send_heartbeat, &hip_icmp_sock);
			heartbeat_counter = hip_icmp_interval;
		} else {
			heartbeat_counter--;
		}
	} else if (hip_nat_status) {
		/* Send NOTIFY keepalives for NATs only when ICMPv6
		   keepalives are disabled */
		if (nat_keep_alive_counter < 0) {
			HIP_IFEL(hip_nat_refresh_port(),
				 -ECOMM,
				 "Failed to refresh NAT port state.\n");
			nat_keep_alive_counter = HIP_NAT_KEEP_ALIVE_INTERVAL;
		} else {
			nat_keep_alive_counter--;
		}
	}

	/* Clear the expired records from the relay hashtable. */
	hip_relht_maintenance();

	/* Clear the expired pending service requests. This is by no means time
	   critical operation and is not needed to be done on every maintenance
	   cycle. Once every 10 minutes or so should be enough. Just for the
	   record, if periodic_maintenance() is ever to be optimized. */
	hip_registration_maintenance();

 out_err:

	return err;
}

int hip_get_firewall_status(){
	return hip_firewall_status;
}

int hip_firewall_is_alive()
{
#ifdef CONFIG_HIP_FIREWALL
	if (hip_firewall_status) {
		HIP_DEBUG("Firewall is alive.\n");
	}
	else {
		HIP_DEBUG("Firewall is not alive.\n");
	}
	return hip_firewall_status;
#else
	HIP_DEBUG("Firewall is disabled.\n");
	return 0;
#endif // CONFIG_HIP_FIREWALL
}

int hip_firewall_set_i2_data(int action,  hip_ha_t *entry, 
			     struct in6_addr *hit_s, 
			     struct in6_addr *hit_r,
			     struct in6_addr *src,
			     struct in6_addr *dst) {

        struct hip_common *msg = NULL;
	struct sockaddr_in6 hip_firewall_addr;
	int err = 0, n = 0;
	HIP_IFEL(!(msg = HIP_MALLOC(HIP_MAX_PACKET, 0)), -1, "alloc\n");
	hip_msg_init(msg);
	HIP_IFEL(hip_build_user_hdr(msg, action, 0), -1, 
                 "Build hdr failed\n");
	            
        HIP_IFEL(hip_build_param_contents(msg, (void *)hit_r, HIP_PARAM_HIT,
                 sizeof(struct in6_addr)), -1, "build param contents failed\n");
	HIP_IFEL(hip_build_param_contents(msg, (void *)src, HIP_PARAM_HIT,
                 sizeof(struct in6_addr)), -1, "build param contents failed\n");
	
	socklen_t alen = sizeof(hip_firewall_addr);

	bzero(&hip_firewall_addr, alen);
	hip_firewall_addr.sin6_family = AF_INET6;
	hip_firewall_addr.sin6_port = htons(HIP_FIREWALL_PORT);
	hip_firewall_addr.sin6_addr = in6addr_loopback;

	//	if (hip_get_firewall_status()) {
	n = sendto(hip_firewall_sock_lsi_fd, msg, hip_get_msg_total_len(msg),
		   0, &hip_firewall_addr, alen);
		//}

	if (n < 0)
	  HIP_DEBUG("Send to firewall failed str errno %s\n",strerror(errno));
	HIP_IFEL( n < 0, -1, "Sendto firewall failed.\n");   

	HIP_DEBUG("Sendto firewall OK.\n");

out_err:
	if (msg)
		free(msg);

	return err;
}

int hip_firewall_set_bex_data(int action, hip_ha_t *entry, struct in6_addr *hit_s, struct in6_addr *hit_r)
{
        struct hip_common *msg = NULL;
	struct sockaddr_in6 hip_firewall_addr;
	int err = 0, n = 0, r_is_our;
	socklen_t alen = sizeof(hip_firewall_addr);

	if (!hip_get_firewall_status())
		goto out_err;

	/* Makes sure that the hits are sent always in the same order */
	r_is_our = hip_hidb_hit_is_our(hit_r);

	HIP_IFEL(!(msg = HIP_MALLOC(HIP_MAX_PACKET, 0)), -1, "alloc\n");
	hip_msg_init(msg);
	HIP_IFEL(hip_build_user_hdr(msg, action, 0), -1,
                 "Build hdr failed\n");

        HIP_IFEL(hip_build_param_contents(msg,
			    (void *)(r_is_our ? hit_s : hit_r), HIP_PARAM_HIT,
                sizeof(struct in6_addr)), -1, "build param contents failed\n");
	HIP_IFEL(hip_build_param_contents(msg,
		 (void *) (r_is_our ? hit_r : hit_s), HIP_PARAM_HIT,
                sizeof(struct in6_addr)), -1, "build param contents failed\n");

	bzero(&hip_firewall_addr, alen);
	hip_firewall_addr.sin6_family = AF_INET6;
	hip_firewall_addr.sin6_port = htons(HIP_FIREWALL_PORT);
	hip_firewall_addr.sin6_addr = in6addr_loopback;

	n = sendto(hip_firewall_sock_lsi_fd, msg, hip_get_msg_total_len(msg),
			   0, &hip_firewall_addr, alen);

	if (n < 0)
	  HIP_DEBUG("Send to firewall failed str errno %s\n",strerror(errno));
	HIP_IFEL( n < 0, -1, "Sendto firewall failed.\n");

	HIP_DEBUG("Sendto firewall OK.\n");

out_err:
	if (msg)
		free(msg);

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
	struct inet6_pktinfo * pktinfo, * pktinfo_in6;
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
	chdr = (struct cmsghdr *)cmsgbuf;
	pktinfo = (struct inet6_pktinfo *)(CMSG_DATA(chdr));

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
	mhdr.msg_iov = &iov;
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
	icmph = (struct icmpv6hdr *)&iovbuf;
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

#if 0
static long llsqrt(long long a)
{
        long long prev = ~((long long)1 << 63);
        long long x = a;

        if (x > 0) {
                while (x < prev) {
                        prev = x;
                        x = (x+(a/x))/2;
                }
        }

        return (long)x;
}
#endif

/**
 * This function calculates RTT and ... and then stores them to correct entry
 *
 * @param src HIT
 * @param dst HIT
 * @param time when sent
 * @param time when received
 *
 * @return 0 if success negative otherwise
 */
int hip_icmp_statistics(struct in6_addr * src, struct in6_addr * dst,
			struct timeval *stval, struct timeval *rtval) {
	int err = 0;
	uint32_t rcvd_heartbeats = 0;
	uint64_t rtt = 0;
	double avg = 0.0, std_dev = 0.0;
#if 0
	u_int32_t rtt = 0, usecs = 0, secs = 0, square = 0;
	u_int32_t sum1 = 0, sum2 = 0;
#endif
	char hit[INET6_ADDRSTRLEN];
	hip_ha_t * entry = NULL;

	hip_in6_ntop(src, hit);

	/* Find the correct entry */
	entry = hip_hadb_find_byhits(src, dst);
	HIP_IFEL((!entry), -1, "Entry not found\n");

	/* Calculate the RTT from given timevals */
	rtt = calc_timeval_diff(stval, rtval);

	/* add the heartbeat item to the statistics */
	add_statistics_item(&entry->heartbeats_statistics, rtt);

	/* calculate the statistics for immediate output */
	calc_statistics(&entry->heartbeats_statistics, &rcvd_heartbeats, NULL, NULL, &avg,
			&std_dev, STATS_IN_MSECS);

	HIP_DEBUG("\nHeartbeat from %s, RTT %.6f ms,\n%.6f ms mean, "
		  "%.6f ms std dev, packets sent %d recv %d lost %d\n",
		  hit, ((float)rtt / STATS_IN_MSECS), avg, std_dev, entry->heartbeats_sent,
		  rcvd_heartbeats, (entry->heartbeats_sent - rcvd_heartbeats));

#if 0
	secs = (rtval->tv_sec - stval->tv_sec) * 1000000;
	usecs = rtval->tv_usec - stval->tv_usec;
	rtt = secs + usecs;

	/* received count will vary from sent if errors */
	entry->heartbeats_received++;

	/* Calculate mean */
	entry->heartbeats_total_rtt += rtt;
	entry->heartbeats_total_rtt2 += rtt * rtt;
	if (entry->heartbeats_received > 1)
		entry->heartbeats_mean = entry->heartbeats_total_rtt / entry->heartbeats_received;

	/* Calculate variance  */
	if (entry->heartbeats_received > 1) {
		sum1 = entry->heartbeats_total_rtt;
		sum2 = entry->heartbeats_total_rtt2;
		sum1 /= entry->heartbeats_received;
		sum2 /= entry->heartbeats_received;
		entry->heartbeats_variance = llsqrt(sum2 - sum1 * sum1);
	}

	HIP_DEBUG("\nHeartbeat from %s, RTT %.6f ms,\n%.6f ms mean, "
		  "%.6f ms variance, packets sent %d recv %d lost %d\n",
		  hit, (rtt / 1000000.0), (entry->heartbeats_mean / 1000000.0),
		  (entry->heartbeats_variance / 1000000.0),
		  entry->heartbeats_sent, entry->heartbeats_received,
		  (entry->heartbeats_sent - entry->heartbeats_received));
#endif

out_err:
	return err;
}

int hip_firewall_set_esp_relay(int action)
{
	struct hip_common *msg = NULL;
	int err = 0;
	int sent;

	HIP_DEBUG("Setting ESP relay to %d\n", action);
	HIP_IFE(!(msg = hip_msg_alloc()), -ENOMEM);
	HIP_IFEL(hip_build_user_hdr(msg,
		 action ? SO_HIP_OFFER_FULLRELAY : SO_HIP_CANCEL_FULLRELAY, 0),
		-1, "Build header failed\n");

	sent = hip_sendto_firewall(msg);
	if (sent < 0) {
		HIP_PERROR("Send to firewall failed: ");
		err = -1;
		goto out_err;
	}
	HIP_DEBUG("Sent %d bytes to firewall.\n", sent);

out_err:
	if (msg)
		free(msg);
	return err;	
}
