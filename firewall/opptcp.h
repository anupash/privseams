#ifndef HIP_OPPTCP
#define HIP_OPPTCP

int hip_fw_examine_incoming_tcp_packet(void *hdr, int ip_version, int header_size);
int tcp_packet_has_i1_option(void * tcphdrBytes, int hdrLen);

#endif
