/*
 * This code is GNU/GPL.
 */

#ifdef CONFIG_HIP_MIDAUTH

#include "ife.h"
#include "midauth.h"
#include "misc.h"
#include "pisa.h"
#include "hslist.h"
#include <string.h>

#define PISA_RANDOM_LEN 16
#define PISA_PUZZLE_SEED 0xDEADC0DE
#define PISA_NONCE_LEN_1SPI (4 + HIP_AH_SHA_LEN)
#define PISA_NONCE_LEN_2SPI (8 + HIP_AH_SHA_LEN)

#ifdef CONFIG_HIP_PERFORMANCE
#include "performance.h"
#endif

/*#define PISA_TEST_MULTIPLE_PARAMETERS*/
/*#define PISA_INTRODUCE_ERROR_NONCE*/
/*#define PISA_INTRODUCE_ERROR_PUZZLE_OPAQUE*/
/*#define PISA_INTRODUCE_ERROR_PUZZLE_RANDOM*/

struct pisa_conn {
	uint32_t spi[2];
	struct in6_addr hit[2];
};

static SList *pisa_connections = NULL;

struct pisa_conn_query {
	struct in6_addr *hit[2];
};

static struct pisa_conn *pisa_find_conn(struct pisa_conn 
					*(*f)(SList *s, void *p),
					void *data)
{
	SList *l = pisa_connections;
	struct pisa_conn *pcd;

	while (l) {
		HIP_DEBUG("l=0x%x\n", l);
		pcd = f(l, data);
		HIP_DEBUG("pcd=0x%x\n", pcd);
		if (pcd != NULL)
			return pcd;
		l = l->next;
	}

	return NULL;
}

static struct pisa_conn *pisa_find_conn_by_hits2(SList *s, void *p)
{
	struct pisa_conn_query *query = (struct pisa_conn_query *) p;
	struct pisa_conn *data;

	if (s && s->data) {
		data = (struct pisa_conn *) s->data;
		if ((!ipv6_addr_cmp(&data->hit[0], query->hit[0]) &&
		     !ipv6_addr_cmp(&data->hit[1], query->hit[1])) ||
		    (!ipv6_addr_cmp(&data->hit[0], query->hit[1]) &&
		     !ipv6_addr_cmp(&data->hit[1], query->hit[0])))
			return data;
	}
	return NULL;
}

static struct pisa_conn *pisa_find_conn_by_hits(struct in6_addr *hit1,
						struct in6_addr *hit2)
{
	struct pisa_conn_query data;

	data.hit[0] = hit1;
	data.hit[1] = hit2;

	return pisa_find_conn(pisa_find_conn_by_hits2, &data);
}

static struct pisa_conn *pisa_find_conn_by_spi2(SList *s, void *p)
{
	uint32_t *spi = (uint32_t *) p;
	struct pisa_conn *data;

	HIP_DEBUG("s->data = %x\n", s->data);
	if (s && s->data) {
		data = (struct pisa_conn *) s->data;
		HIP_DEBUG("data->spi[0] = 0x%x, data->spi[1] = 0x%x\n", data->spi[0], data->spi[1]);
		if (data->spi[0] == *spi || data->spi[1] == *spi)
			return data;
	}

	return NULL;
}

static struct pisa_conn *pisa_find_conn_by_spi(uint32_t spi)
{
	return pisa_find_conn(pisa_find_conn_by_spi2, &spi);
}

struct pisa_puzzle_hash {
	u8 data[4];
	union {
		u8 raw[HIP_AH_SHA_LEN];
		struct {
			uint64_t random;
			u8 opaque[6];
		} pz;
	} u;
};

static char pisa_random_data[2][PISA_RANDOM_LEN];

/**
 * Generate a new random number and shift the old one down.
 */
static void pisa_generate_random()
{
	void *p0, *p1;

	p0 = &pisa_random_data[0][0];
	p1 = &pisa_random_data[1][0];

	memcpy(p0, p1, PISA_RANDOM_LEN);
	get_random_bytes(p1, PISA_RANDOM_LEN);
}

/**
 * Appends HMAC/SHA1 to a block of data.
 *
 * @param a first HIT
 * @param b second HIT
 * @param rnd which random number to use, either 0 or 1
 * @param spi SPI that will be signed
 * @param data pointer to buffer for data and the HMAC
 * @param data_len length of data
 */
static void pisa_append_hmac(struct in6_addr *a, struct in6_addr *b, 
			     int rnd, u32 spi, void *data, int data_len)
{
	u8 key[36 + PISA_RANDOM_LEN];
	int len = HIP_AH_SHA_LEN;

	if (!(data && a && b) || (rnd != 0 && rnd != 1) || data_len == 0)  {
		HIP_ERROR("failed pisa_create_nonce_hash sanity check.\n");
		return;
	}

	/* The key for HMAC/SHA1 consists of:
	 *    4 bytes SPI
	 *   16 bytes HIT1
	 *   16 bytes HIT2
	 *            pisa_random_data
	 */

	memcpy(key, &spi, sizeof(u32));
	ipv6_addr_copy((struct in6_addr *)(key+ 4), a);
	ipv6_addr_copy((struct in6_addr *)(key+20), b);
	memcpy(key+36, &pisa_random_data[rnd][0], PISA_RANDOM_LEN);

	HMAC(EVP_sha1(), key, 36 + PISA_RANDOM_LEN, data, data_len,
	     data + data_len, &len);
}

/**
 * Insert a PISA nonce into a packet that will contain 1 SPI.
 *
 * @param ctx context of the packet where the nonce will be inserted
 * @return success (0) or failure
 */
static int pisa_insert_nonce_1spi(hip_fw_context_t *ctx)
{
	u8 nonce[PISA_NONCE_LEN_1SPI];
	struct hip_esp_info *esp_info;
	struct hip_common *hip = ctx->transport_hdr.hip;
	u32 spi = 0;

	esp_info = hip_get_param(hip, HIP_PARAM_ESP_INFO);
	if (esp_info != NULL)
		spi = esp_info->new_spi;

#ifdef PISA_TEST_MULTIPLE_PARAMETERS
	{
		char *nonce1 = "asdf", *nonce2 = "012345678901234567890123";
		midauth_add_echo_request_m(ctx, nonce1, strlen(nonce1));
		midauth_add_echo_request_m(ctx, nonce2, strlen(nonce2));
	}
#endif
	/* The nonce looks like this:
	 *    4 bytes SPI
	 *   20 bytes HMAC of everything before
	 * As we only use the data in the firewall, byteorder is not an issue.
	 */

	memcpy(nonce, &spi, sizeof(u32));
	pisa_append_hmac(&hip->hits, &hip->hitr, 1, spi, nonce, sizeof(u32));

#ifdef PISA_INTRODUCE_ERROR_NONCE
	nonce[0]++;
#endif

	return midauth_add_echo_request_m(ctx, nonce, PISA_NONCE_LEN_1SPI);
}

/**
 * Insert a PISA nonce into a packet that will contain 2 SPIs.
 *
 * @param ctx context of the packet where the nonce will be inserted
 * @param old_nonce parameter in ctx that contains the old SPI
 * @return success (0) or failure
 */
static int pisa_insert_nonce_2spi(hip_fw_context_t *ctx,
				  struct hip_tlv_common *old_nonce)
{
	u8 nonce[PISA_NONCE_LEN_2SPI];
	struct hip_esp_info *esp_info;
	struct hip_common *hip = ctx->transport_hdr.hip;
	u32 spi[2] = {0, 0};

	if (old_nonce != NULL)
		spi[0] = *((u32 *)hip_get_param_contents_direct(old_nonce));

	esp_info = hip_get_param(hip, HIP_PARAM_ESP_INFO);
	if (esp_info != NULL)
		spi[1] = esp_info->new_spi;

#ifdef PISA_TEST_MULTIPLE_PARAMETERS
	{
		char *nonce1 = "asdf", *nonce2 = "0123456789012345678901234567";
		midauth_add_echo_request_m(ctx, nonce1, strlen(nonce1));
		midauth_add_echo_request_m(ctx, nonce2, strlen(nonce2));
	}
#endif
	/* The nonce looks like this:
	 *    4 bytes first SPI
	 *    4 bytes second SPI
	 *   20 bytes HMAC of everything before
	 * As we only use the data in the firewall, byteorder is not an issue.
	 */

	memcpy(nonce, &spi[0], sizeof(u32));
	memcpy(nonce+sizeof(u32), &spi[1], sizeof(u32));
	pisa_append_hmac(&hip->hits, &hip->hitr, 1, spi[0], nonce, sizeof(u32)*2);

#ifdef PISA_INTRODUCE_ERROR_NONCE
	nonce[0]++;
#endif

	return midauth_add_echo_request_m(ctx, nonce, PISA_NONCE_LEN_2SPI);
}

/**
 * Insert a PISA puzzle into a packet.
 *
 * @param ctx context of the packet where the puzzle will be inserted
 * @return success (0) or failure
 */
static int pisa_insert_puzzle(hip_fw_context_t *ctx)
{
	struct pisa_puzzle_hash hash;
	struct hip_common *hip = ctx->transport_hdr.hip;
	int seed = PISA_PUZZLE_SEED;

	memcpy(&hash, &seed, 4);

	/* here we switch order of initiator and receiver to obtain a
	 * different SHA1 hash */
	pisa_append_hmac(&hip->hitr, &hip->hits, 1, 0, &hash, 4);

#ifdef PISA_TEST_MULTIPLE_PARAMETERS
	midauth_add_puzzle_m(ctx, 3, 4, "puzzle", 0xABCDABCDABCDABCDLL);
	midauth_add_puzzle_m(ctx, 3, 4, "abcdef", 0x0123456789ABCDEFLL);
#endif

#ifdef PISA_INTRODUCE_ERROR_PUZZLE_OPAQUE
	hash.u.pz.opaque[0]++;
#endif

#ifdef PISA_INTRODUCE_ERROR_PUZZLE_RANDOM
	hash.u.pz.random++;
#endif

	return midauth_add_puzzle_m(ctx, 3, 4, hash.u.pz.opaque,
	                            hash.u.pz.random);
}

/**
 * Check the validity of a PISA nonce. Check against current random value
 * first. If that fails, check against old random value. If that fails too, 
 * consider the nonce to be invalid (either too old or not correct at any 
 * previous point in time).
 *
 * @param ctx context of the packet with the nonce to check
 * @return pointer to the nonce we accepted or NULL at failure
 */
static struct hip_tlv_common *pisa_check_nonce(hip_fw_context_t *ctx)
{
	struct hip_tlv_common *nonce;
	struct hip_common *hip = ctx->transport_hdr.hip;
	u8 valid[PISA_NONCE_LEN_2SPI], *nonce_data;
	u32 spi;
	int nonce_len;

	nonce = hip_get_param(hip, HIP_PARAM_ECHO_RESPONSE_M);

	while (nonce) {
		/* loop over all HIP_PARAM_ECHO_RESPONSE_M */
		if (hip_get_param_type(nonce) != HIP_PARAM_ECHO_RESPONSE_M)
			break;

		nonce_len = hip_get_param_contents_len(nonce);
		nonce_data = (u8 *)hip_get_param_contents_direct(nonce);

		/* if the payload has the size of a nonce ... */
		if (nonce_len == PISA_NONCE_LEN_1SPI ||
		    nonce_len == PISA_NONCE_LEN_2SPI) {
			int data_size = sizeof(u32);

			if (nonce_len == PISA_NONCE_LEN_2SPI)
				data_size = sizeof(u32) * 2;

			memcpy(valid, nonce_data, data_size);
			spi = *((u32 *)nonce_data);

			/* ... first check the current random value ... */
			pisa_append_hmac(&hip->hitr, &hip->hits, 1, spi,
			                 valid, data_size);
			if (!memcmp(valid, nonce_data, nonce_len))
				return nonce;

			/* ... and if that failed the old random value */
			pisa_append_hmac(&hip->hitr, &hip->hits, 0, spi,
			                 valid, data_size);
			if (!memcmp(valid, nonce_data, nonce_len))
				return nonce;
		}

		nonce = hip_get_next_param(hip, nonce);
	}

	return NULL;
}

/**
 * Check the validity of a PISA puzzle. 
 *
 * @param ctx context of the packet with the puzzle to check
 * @return pointer to the puzzle we accepted or NULL at failure
 */
static struct hip_solution_m *pisa_check_solution(hip_fw_context_t *ctx)
{
	struct hip_solution_m *solution;
	struct hip_common *hip = ctx->transport_hdr.hip;
	struct pisa_puzzle_hash hash[2];
	int seed = PISA_PUZZLE_SEED;

	memcpy(&hash[0], &seed, 4);
	memcpy(&hash[1], &seed, 4);

	pisa_append_hmac(&hip->hits, &hip->hitr, 0, 0, &hash[0], 4);
	pisa_append_hmac(&hip->hits, &hip->hitr, 1, 0, &hash[1], 4);

	solution = (struct hip_solution_m *)
	           hip_get_param(hip, HIP_PARAM_SOLUTION_M);

	while (solution) {
		/* loop over all HIP_PARAM_SOLUTION_M */
		if (hip_get_param_type(solution) != HIP_PARAM_SOLUTION_M)
			break;

		if ((!memcmp(solution->opaque, hash[1].u.pz.opaque, 6)
		      && solution->I == hash[1].u.pz.random) ||
		    (!memcmp(solution->opaque, hash[0].u.pz.opaque, 6)
		      && solution->I == hash[0].u.pz.random)) {
			if (midauth_verify_solution_m(hip, solution) == 0)
				return solution;
		}

		solution = (struct hip_solution_m *) hip_get_next_param(hip,
		             (struct hip_tlv_common *) solution);
	}

	return NULL;
}

/**
 * Check the signature of the packet.
 *
 * @param ctx context of the packet with the signature to check
 * @return success (0) or failure
 */
static int pisa_check_signature(hip_fw_context_t *ctx)
{
	struct hip_common *hip = ctx->transport_hdr.hip;
	int err = -1;
	struct hip_host_id *host_id;
	int (*verify_signature)(struct hip_host_id *, struct hip_common *);

	host_id = hip_get_param(hip, HIP_PARAM_HOST_ID);
	if (host_id == 0) {
		HIP_DEBUG("Cannot check signature: No HOST_ID found.\n");
	} else {
		if (hip_get_host_id_algo(host_id) == HIP_HI_RSA)
			verify_signature = hip_rsa_verify;
		else
			verify_signature = hip_dsa_verify;

		err = verify_signature(host_id, hip);
	}

out_err:
	return err;
}

/**
 * Accept a connection via PISA. Update firewall to allow further packages to
 * pass through.
 *
 * @param hits HIT of the sender
 * @param spi_s SPI of the sender
 * @param hitr HIT of the receiver
 * @param spi_r SPI of the receiver
 */
static void pisa_accept_connection(struct in6_addr *hits, uint32_t spi_s,
				   struct in6_addr *hitr, uint32_t spi_r)
{
	struct pisa_conn *pcd;

	/* add a new connection or update an old one */
	if ((pcd = pisa_find_conn_by_hits(hits, hitr)) == NULL) {
		pcd = malloc(sizeof(struct pisa_conn));
		HIP_DEBUG("Adding pcd = 0x%x\n", pcd);
		append_to_slist(pisa_connections, pcd);
	}

	ipv6_addr_copy(&pcd->hit[0], hits);
	ipv6_addr_copy(&pcd->hit[1], hitr);
	pcd->spi[0] = spi_s;
	pcd->spi[1] = spi_r;

	HIP_DEBUG_HIT("pcd->hit[0]: ", &pcd->hit[0]);
	HIP_DEBUG_HIT("pcd->hit[1]: ", &pcd->hit[1]);
	HIP_DEBUG("spi[0]: 0x%x, spi[1]: 0x%x\n", pcd->spi[0], pcd->spi[1]);

	HIP_INFO("PISA accepted the connection.\n");
}

/**
 * Accept a connection via PISA after receiving an I2 packet.
 *
 * @param ctx context of the packet that belongs to that connection
 * @param nonce the nonce we accepted
 */
static void pisa_accept_connection_i2(hip_fw_context_t *ctx,
				      struct hip_tlv_common *nonce)
{
	struct hip_common *hip = ctx->transport_hdr.hip;
	struct hip_esp_info *esp;
	uint32_t *spi;

	if (nonce == NULL) {
		HIP_DEBUG("Accepting failed: no nonce found.\n");
		return;
	}

	esp = hip_get_param(hip, HIP_PARAM_ESP_INFO);

	if (esp == NULL) {
		HIP_DEBUG("Accepting failed: no HIP_PARAM_ESP_INFO found.\n");
		return;
	}

	spi = (uint32_t *) hip_get_param_contents_direct(nonce);

	pisa_accept_connection(&hip->hits, esp->new_spi, &hip->hitr, *spi);
}

/**
 * Accept a connection via PISA after receiving an U3 packet.
 *
 * @param ctx context of the packet that belongs to that connection
 * @param nonce the nonce we accepted
 */
static void pisa_accept_connection_u3(hip_fw_context_t *ctx,
				      struct hip_tlv_common *nonce)
{
	struct hip_common *hip = ctx->transport_hdr.hip;
	uint32_t spi[2], *p;

	if (nonce == NULL) {
		HIP_DEBUG("Accepting failed: no nonce found.\n");
		return;
	}

	p = (uint32_t *) hip_get_param_contents_direct(nonce);
	spi[0] = *(p);
	spi[1] = *(p + 1);

	pisa_accept_connection(&hip->hits, spi[0], &hip->hitr, spi[1]);
}

/**
 * Reject a connection via PISA. Update firewall to allow no further packages
 * to pass through.
 *
 * @param ctx context of the packet that belongs to that connection
 */
static void pisa_reject_connection(hip_fw_context_t *ctx,
				   struct hip_tlv_common *nonce)
{
	/* @todo: FIXME - implement this stub */
	HIP_INFO("PISA rejected the connection.\n");
}

/**
 * Insert a PISA nonce and a PISA puzzle into the I2 packet.
 *
 * @param ctx context of the packet to modify
 * @return verdict, either NF_ACCEPT or NF_DROP
 */
static int pisa_handler_i2(hip_fw_context_t *ctx)
{
#ifdef CONFIG_HIP_PERFORMANCE
	HIP_DEBUG("Start PERF_I2\n");
	hip_perf_start_benchmark(perf_set, PERF_I2);
#endif
	int verdict = NF_ACCEPT;

	pisa_insert_nonce_1spi(ctx);
	pisa_insert_puzzle(ctx);

#ifdef CONFIG_HIP_PERFORMANCE
	HIP_DEBUG("Stop and write PERF_I2\n");
	hip_perf_stop_benchmark(perf_set, PERF_I2);
	hip_perf_write_benchmark(perf_set, PERF_I2);
#endif
	return verdict;
}

/**
 * Check for a PISA nonce and a PISA puzzle in the R2 packet.
 *
 * @param ctx context of the packet to check
 * @return verdict, either NF_ACCEPT or NF_DROP
 */
static int pisa_handler_r2(hip_fw_context_t *ctx)
{
#ifdef CONFIG_HIP_PERFORMANCE
	HIP_DEBUG("Start PERF_R2\n");
	hip_perf_start_benchmark(perf_set, PERF_R2);
#endif
	int verdict = NF_DROP, sig = 0;
	struct hip_solution_m *solution = NULL;
	struct hip_tlv_common *nonce = NULL;

	nonce = pisa_check_nonce(ctx);
	solution = pisa_check_solution(ctx);
	sig = pisa_check_signature(ctx);

	if (nonce == NULL || solution == NULL || sig != 0) {
		/* disallow further communication if either nonce, solution or
		 * signature were not correct */
		pisa_reject_connection(ctx, nonce);
		verdict = NF_DROP;
	} else {
		/* allow futher communication otherwise */
		pisa_accept_connection_i2(ctx, nonce);
		verdict = NF_ACCEPT;
	}

#ifdef CONFIG_HIP_PERFORMANCE
	HIP_DEBUG("Stop and write PERF_R2, PERF_BASE\n");
	hip_perf_stop_benchmark(perf_set, PERF_R2);
	hip_perf_stop_benchmark(perf_set, PERF_BASE);
	hip_perf_write_benchmark(perf_set, PERF_R2);
	hip_perf_write_benchmark(perf_set, PERF_BASE);
#endif
	return verdict;
}

/**
 * Insert a PISA nonce and a PISA puzzle into the U1 packet.
 *
 * @param ctx context of the packet to modify
 * @return verdict, either NF_ACCEPT or NF_DROP
 */
static int pisa_handler_u1(hip_fw_context_t *ctx)
{
	int verdict = NF_ACCEPT;

	pisa_insert_nonce_1spi(ctx);
	pisa_insert_puzzle(ctx);

	return verdict;
}

/**
 * Check for a PISA nonce and a PISA puzzle in the U2 packet.
 *
 * @param ctx context of the packet to check
 * @return verdict, either NF_ACCEPT or NF_DROP
 */
static int pisa_handler_u2(hip_fw_context_t *ctx)
{
	int verdict = NF_DROP, sig = 0;
	struct hip_solution_m *solution = NULL;
	struct hip_tlv_common *nonce = NULL;

	nonce = pisa_check_nonce(ctx);
	solution = pisa_check_solution(ctx);
	sig = pisa_check_signature(ctx);

	if (nonce == NULL || solution == NULL || sig != 0) {
		HIP_DEBUG("U2 packet did not match criteria: nonce %p, "
		          "solution %p, signature %i\n", nonce, solution, sig);
		verdict = NF_DROP;
	} else {
		/* packet was ok, forward the first SPI */
		pisa_insert_nonce_2spi(ctx, nonce);
		verdict = NF_ACCEPT;
	}

	return verdict;
}

/**
 * Check for a PISA nonce in the U3 packet.
 *
 * @param ctx context of the packet to check
 * @return verdict, either NF_ACCEPT or NF_DROP
 */
static int pisa_handler_u3(hip_fw_context_t *ctx)
{
	int verdict = NF_DROP, sig = 0;
	struct hip_tlv_common *nonce = NULL;

	nonce = pisa_check_nonce(ctx);
	sig = pisa_check_signature(ctx);

	if (nonce == NULL || sig != 0) {
		HIP_DEBUG("U2 packet did not match criteria: nonce %p, "
		          "signature %i\n", nonce, sig);
		verdict = NF_DROP;
	} else {
		/* allow futher communication otherwise */
		pisa_accept_connection_u3(ctx, nonce);
		verdict = NF_ACCEPT;
	}

	return verdict;
}


/**
 * Handle ESP data that should be forwarded.
 *
 * @param ctx context of the packet to check
 * @return verdict, either NF_ACCEPT or NF_DROP
 */
static int pisa_handler_esp(hip_fw_context_t *ctx)
{
	int err = NF_DROP;
	struct hip_esp *esp;
	struct pisa_conn *pcd;

	esp = ctx->transport_hdr.esp;
	HIP_IFEL(esp == NULL, NF_DROP, "No ESP Header found.\n");
	
	HIP_DEBUG("Before pisa_find_conn, spi=%d\n", esp->esp_spi);
	pcd = pisa_find_conn_by_spi(esp->esp_spi);
	HIP_DEBUG("After pisa_find_conn, pcd=%d\n", pcd);
	HIP_IFEL(pcd == NULL, NF_DROP, "Connection not found.\n");

	err = NF_ACCEPT;
	HIP_DEBUG("Connection found, forwarding ESP packet.\n");
out_err:
	return err;	
}

void pisa_init(struct midauth_handlers *h)
{
	h->i1 = midauth_handler_accept;
	h->r1 = midauth_handler_accept;
	h->i2 = pisa_handler_i2;
	h->r2 = pisa_handler_r2;
	h->u1 = pisa_handler_u1;
	h->u2 = pisa_handler_u2;
	h->u3 = pisa_handler_u3;
	h->esp = pisa_handler_esp;

	pisa_generate_random();
	pisa_generate_random();

	pisa_connections = alloc_slist();
}

#endif

