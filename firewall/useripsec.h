#ifndef HIP_USERIPSEC
#define HIP_USERIPSEC

#include "firewall.h"
//#include <libipq.h>

int hip_firewall_userspace_ipsec_input(int		    trafficType,
				       void		    *hdr,
				       ipq_packet_msg_t    *ip_packet_in_the_queue);

int hip_firewall_userspace_ipsec_output(hip_fw_context_t *ctx);


#endif /* HIP_USERIPSEC */
