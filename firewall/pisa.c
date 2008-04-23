/*
 * This code is GNU/GPL.
 */

#ifdef CONFIG_HIP_MIDAUTH

#include "midauth.h"
#include "pisa.h"
#include <string.h>

#define PISA_RANDOM_LEN 40

static char pisa_random_data[2][PISA_RANDOM_LEN];
static int pisa_random_current = 0;

static void pisa_generate_random(int position)
{
	get_random_bytes(&pisa_random_data[position][0], PISA_RANDOM_LEN);
}

static int pisa_insert_nonce(struct midauth_packet *p)
{
	int err = 0;
	char *nonce1 = "nonce-text";

	err = midauth_add_echo_request_m(p, nonce1);
out_err:
	return err;
}

static int pisa_insert_puzzle(struct midauth_packet *p)
{
	int err = 0;

	err = midauth_add_puzzle_m(p, 3, 4, "puzzle", 0xABCDABCDABCDABCDLL);
out_err:
	return err;
}

int pisa_handler_i2(struct midauth_packet *p)
{
	int verdict = NF_ACCEPT;

	pisa_insert_nonce(p);
	pisa_insert_puzzle(p);

	return verdict;
}

int pisa_handler_r2(struct midauth_packet *p)
{
	int verdict = NF_ACCEPT;
	struct hip_solution_m *solution;

	/* check for ECHO_REPLY_M and SOLUTION_M here */
	solution = (struct hip_solution_m *)hip_get_param(p->hip, HIP_PARAM_SOLUTION_M);
	if (solution)
	{
		if (midauth_verify_solution_m(p->hip, solution) == 0)
			HIP_DEBUG("found correct hip_solution_m\n");
		else
			HIP_DEBUG("found wrong hip_solution_m\n");
	} else {
		HIP_DEBUG("found no hip_solution_m\n");
	}

	return verdict;
}

void pisa_init(struct midauth_handlers *h)
{
	h->i1 = midauth_handler_accept;
	h->r1 = midauth_handler_accept;
	h->i2 = pisa_handler_i2;
	h->r2 = pisa_handler_r2;
	h->u1 = midauth_handler_accept;
	h->u2 = midauth_handler_accept;
	h->u3 = midauth_handler_accept;

	pisa_generate_random(0);
	pisa_generate_random(1);
}

#endif

