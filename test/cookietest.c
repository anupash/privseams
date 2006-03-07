#include "hip.h"
#include "debug.h"
#include "misc.h"
#include <sys/time.h>
#include <time.h>

/**
 * hip_solve_puzzle - Solve puzzle.
 * @puzzle_or_solution: Either a pointer to hip_puzzle or hip_solution structure
 * @hdr: The incoming R1/I2 packet header.
 * @mode: Either HIP_VERIFY_PUZZLE of HIP_SOLVE_PUZZLE
 *
 * The K and I is read from the @puzzle_or_solution. 
 *
 * The J that solves the puzzle is returned, or 0 to indicate an error.
 * NOTE! I don't see why 0 couldn't solve the puzzle too, but since the
 * odds are 1/2^64 to try 0, I don't see the point in improving this now.
 */
uint64_t hip_solve_puzzle(void *puzzle_or_solution, struct hip_common *hdr,
			  int mode)
{
	uint64_t mask = 0;
	uint64_t randval = 0;
	uint64_t maxtries = 0;
	uint64_t digest = 0;
	u8 cookie[48];
	u8 max_k = 0;
	int err = 0;
	union {
		struct hip_puzzle pz;
		struct hip_solution sl;
	} *u;

	/* pre-create cookie */
	u = puzzle_or_solution;

	max_k = 20;

	HIP_HEXDUMP("puzzle", puzzle_or_solution,
		    (mode == HIP_VERIFY_PUZZLE ? sizeof(struct hip_solution) : sizeof(struct hip_puzzle)));

	HIP_DEBUG("\n");

#if 0
	HIP_DEBUG("current hip_cookie_max_k_r1=%d\n", max_k);
	HIP_IFEL(u->pz.K > max_k, 0, 
		 "Cookie K %u is higher than we are willing to calculate"
		 " (current max K=%d)\n", u->pz.K, max_k);
#endif

	mask = hton64((1ULL << u->pz.K) - 1);
	memcpy(cookie, (u8 *)&(u->pz.I), sizeof(uint64_t));

	HIP_DEBUG("u->pz.I: 0x%llx\n", u->pz.I);

	if (mode == HIP_VERIFY_PUZZLE) {
		ipv6_addr_copy((hip_hit_t *)(cookie+8), &hdr->hits);
		ipv6_addr_copy((hip_hit_t *)(cookie+24), &hdr->hitr);
		randval = u->sl.J;
		HIP_DEBUG("u->sl.J: 0x%llx\n", randval);
		maxtries = 1;
	} else if (mode == HIP_SOLVE_PUZZLE) {
		ipv6_addr_copy((hip_hit_t *)(cookie+8), &hdr->hitr);
		ipv6_addr_copy((hip_hit_t *)(cookie+24), &hdr->hits);
		maxtries = 1ULL << (u->pz.K + 2); /* fix */
		get_random_bytes(&randval, sizeof(u_int64_t));
	} else {
		HIP_IFEL(1, 0, "Unknown mode: %d\n", mode);
	}

	//HIP_DEBUG("K=%u, maxtries (with k+2)=%llu\n", u->pz.K, maxtries);
	/* while loops should work even if the maxtries is unsigned
	 * if maxtries = 1 ---> while(1 > 0) [maxtries == 0 now]... 
	 * the next round while (0 > 0) [maxtries > 0 now]
	 */
	while(maxtries-- > 0) {
	 	u8 sha_digest[HIP_AH_SHA_LEN];
		
		/* must be 8 */
		memcpy(cookie + 40, (u8*) &randval, sizeof(uint64_t));

		hip_build_digest(HIP_DIGEST_SHA1, cookie, 48, sha_digest);

                /* copy the last 8 bytes for checking */
		memcpy(&digest, sha_digest + 12, sizeof(uint64_t));

		/* now, in order to be able to do correctly the bitwise
		 * AND-operation we have to remember that little endian
		 * processors will interpret the digest and mask reversely.
		 * digest is the last 64 bits of the sha1-digest.. how that is
		 * ordered in processors registers etc.. does not matter to us.
		 * If the last 64 bits of the sha1-digest is
		 * 0x12345678DEADBEEF, whether we have 0xEFBEADDE78563412
		 * doesn't matter because the mask matters... if the mask is
		 * 0x000000000000FFFF (or in other endianness
		 * 0xFFFF000000000000). Either ways... the result is
		 * 0x000000000000BEEF or 0xEFBE000000000000, which the cpu
		 * interprets as 0xBEEF. The mask is converted to network byte
		 * order (above).
		 */
		if ((digest & mask) == 0) {
			HIP_DEBUG("*** Puzzle solved ***: 0x%llx\n",randval);
			HIP_HEXDUMP("digest", sha_digest, HIP_AH_SHA_LEN);
			HIP_HEXDUMP("cookie", cookie, sizeof(cookie));
			return randval;
		}

		/* It seems like the puzzle was not correctly solved */
		HIP_IFEL(mode == HIP_VERIFY_PUZZLE, 0, "Puzzle incorrect\n");

		randval++;
	}

	HIP_ERROR("Could not solve the puzzle, no solution found\n");
 out_err:
	return err;
}

void hip_create_puzzle(struct hip_puzzle *puzzle, uint8_t val_K,
		       uint32_t opaque, uint64_t random_i) {
	/* only the random_j_k is in host byte order */
	puzzle->K = val_K;
	puzzle->lifetime = 0;
	puzzle->opaque[0] = opaque & 0xFF;
	puzzle->opaque[1] = (opaque & 0xFF00) >> 8;
	/* puzzle.opaque[2] = (opaque & 0xFF0000) >> 16; */
	puzzle->I = random_i;
}

int hip_verify_puzzle(struct hip_common *hdr, struct hip_puzzle *puzzle,
		      struct hip_solution *solution) {
	int err = 1; /* Not really an error: 1=success, 0=failure */

	if (solution->K != puzzle->K) {
		HIP_INFO("Solution's K (%d) does not match sent K (%d)\n",
			 solution->K, puzzle->K);
		
		HIP_IFEL(solution->K != puzzle->K, 0,
			"Solution's K did not match any sent Ks.\n");
		HIP_IFEL(solution->I != puzzle->I, 0, 
			 "Solution's I did not match the sent I\n");
		HIP_IFEL(memcmp(solution->opaque, puzzle->opaque, HIP_PUZZLE_OPAQUE_LEN), 0,
			 "Solution's opaque data does not match sent opaque data\n");
		HIP_DEBUG("Received solution to an old puzzle\n");

	} else {
		HIP_HEXDUMP("solution", solution, sizeof(*solution));
		HIP_HEXDUMP("puzzle", puzzle, sizeof(*puzzle));
		HIP_IFEL(solution->I != puzzle->I, 0,
			 "Solution's I did not match the sent I\n");
		HIP_IFEL(memcmp(solution->opaque, puzzle->opaque,
				HIP_PUZZLE_OPAQUE_LEN), 0, 
			 "Solution's opaque data does not match the opaque data sent\n");
	}
	HIP_IFEL(!hip_solve_puzzle(solution, hdr, HIP_VERIFY_PUZZLE), 0, 
		 "Puzzle incorrectly solved\n");
 out_err:
	return err;

}

int main(int argc, char *argv[]) {
	struct hip_puzzle pz;
	struct hip_solution sol;
	struct hip_common hdr = { 0 };
        struct timeval stats_before, stats_after, stats_res;
        unsigned long stats_diff_sec, stats_diff_usec;
	uint64_t solved_puzzle;
	uint8_t k;

	if (argc != 2) {
		printf("usage: cookietest k\n");
		exit(-1);
	}

	k = atoi(argv[1]);
	HIP_DEBUG("k=%d\n", k);

	hip_create_puzzle(&pz, k, 0, 0);

	gettimeofday(&stats_before, NULL);

	if ((solved_puzzle =
	     hip_solve_puzzle(&pz, &hdr, HIP_SOLVE_PUZZLE)) == 0) {
		HIP_ERROR("Puzzle not solved\n");
	}

	gettimeofday(&stats_after, NULL);

	hip_timeval_diff(&stats_after, &stats_before, &stats_res);
	HIP_INFO("puzzle solved in %ld.%06ld secs\n",
		 stats_res.tv_sec, stats_res.tv_usec);

	memcpy(&sol, &pz, sizeof(pz));
	sol.J = solved_puzzle;

	if (!hip_verify_puzzle(&hdr, &pz, &sol)) {
		HIP_ERROR("Verifying of puzzle failed\n");
	}

	HIP_DEBUG("Puzzle solved correctly\n");
}
