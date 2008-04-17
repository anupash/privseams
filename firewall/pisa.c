/*
 * This code is GNU/GPL.
 */

#ifdef CONFIG_HIP_MIDAUTH

#include "midauth.h"
#include "pisa.h"
#include <string.h>

int filter_pisa_i1(ipq_packet_msg_t *m, struct midauth_packet *p)
{
	return NF_ACCEPT;
}

int filter_pisa_r1(ipq_packet_msg_t *m, struct midauth_packet *p)
{
	return NF_ACCEPT;
}

int filter_pisa_i2(ipq_packet_msg_t *m, struct midauth_packet *p)
{
	int verdict = NF_ACCEPT;
	struct hip_common *hip = (struct hip_common *)(((char*)p->buffer) +
	                         p->hdr_size);
	struct hip_solution_m *solution;
	char *nonce1 = "nonce-text";

	memcpy(p->buffer, m->payload, m->data_len);

	midauth_add_echo_request_m(hip, nonce1);
	midauth_add_puzzle_m(hip, 3, 4, "puzzle", 0xABCDABCDABCDABCDLL);

	p->size = hip_get_msg_total_len(hip);
	midauth_update_all_headers(p);

	return verdict;
}

int filter_pisa_r2(ipq_packet_msg_t *m, struct midauth_packet *p)
{
	int verdict = NF_ACCEPT;
	struct hip_common *hip = (struct hip_common *)(((char*)p->buffer) +
	                         p->hdr_size);
	struct hip_solution_m *solution;

	/* don't copy here, packet will not be modified anyway */
	memcpy(p->buffer, m->payload, m->data_len);

	/* check for ECHO_REPLY_M and SOLUTION_M here */
	solution = (struct hip_solution_m *)hip_get_param(hip, HIP_PARAM_SOLUTION_M);
	if (solution)
	{
		if (midauth_verify_solution_m(hip, solution) == 0)
			HIP_DEBUG("found correct hip_solution_m\n");
		else
			HIP_DEBUG("found wrong hip_solution_m\n");
	} else {
		HIP_DEBUG("found no hip_solution_m\n");
	}

	return verdict;
}

int filter_pisa_u1(ipq_packet_msg_t *m, struct midauth_packet *p)
{
	return NF_ACCEPT;
}

int filter_pisa_u2(ipq_packet_msg_t *m, struct midauth_packet *p)
{
	return NF_ACCEPT;
}

int filter_pisa_u3(ipq_packet_msg_t *m, struct midauth_packet *p)
{
	return NF_ACCEPT;
}

#endif

