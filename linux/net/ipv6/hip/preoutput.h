#ifndef HIP_PREOUTPUT_H
#define HIP_PREOUTPUT_H

/* Called by transport layer */
int hip_handle_output(struct ipv6hdr *hdr, struct sk_buff *skb);

/* Called by userspace daemon/packet processing to send a packet to wire */
int hip_csum_send_fl(struct in6_addr *src_addr, struct in6_addr *peer_addr,
                     struct hip_common* buf, struct flowi *out_fl);

#endif /* HIP_PREOUTPUT_H */
