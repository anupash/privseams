/**
 * @file
 *
 * Distributed under <a href="http://www.gnu.org/licenses/gpl2.txt">GNU/GPL</a>
 */
#ifndef HIP_FIREWALL_OPPTCP_H
#define HIP_FIREWALL_OPPTCP_H

int hip_fw_examine_incoming_tcp_packet(void *hdr, int ip_version,
                                       int header_size);
int tcp_packet_has_i1_option(void *tcphdrBytes, int hdrLen);

#endif /* HIP_FIREWALL_OPPTCP_H */
