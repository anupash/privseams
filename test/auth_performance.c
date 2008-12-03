#include <stdio.h>		/* printf & co */
#include <stdlib.h>		/* exit & co */
#include <unistd.h>
#include "hip_statistics.h"
#include "crypto.h"
#include <openssl/ecdsa.h>

#define PACKET_LENGTH 1280

int num_measurements = 1000;
int key_pool_size = 10;

int rsa_key_len = 2048;
int dsa_key_len = 2048;
#define ECDSA_CURVE NID_X9_62_prime192v3

/*!
 * \brief 	Determine and print the gettimeofday time resolution.
 *
 * \author	Tobias Heer
 *
 * Determine the time resolution of gettimeofday.
 *
 * \return void
 */
void print_timeres(){

	struct timeval tv1, tv2;
	int i;
	printf(	"-------------------------------\n"
		"Determine gettimeofday resolution:\n");


	for(i = 0; i < 10; i++){
		gettimeofday(&tv1, NULL);
		do {
			gettimeofday(&tv2, NULL);
		} while (tv1.tv_usec == tv2.tv_usec);

		printf("Resolution: %d us\n", tv2.tv_usec - tv1.tv_usec +
			1000000 * (tv2.tv_sec - tv1.tv_sec));
	}

	printf(	"-------------------------------\n\n");
}

int main(int argc, char ** argv)
{
	int i;
	int err = 0;
	struct timeval start_time;
	struct timeval stop_time;
	statistics_data_t creation_stats;
	statistics_data_t verify_stats;
	uint64_t timediff = 0;
	uint32_t num_items = 0;
	double min = 0.0, max = 0.0, avg = 0.0;
	double std_dev = 0.0;

	int sig_len = 0;
	unsigned char data[PACKET_LENGTH * num_measurements];
	unsigned char hashed_data[SHA_DIGEST_LENGTH * num_measurements];

	RSA * rsa_key_pool[key_pool_size];
	unsigned char * rsa_sig_pool[num_measurements];

	DSA * dsa_key_pool[key_pool_size];
	DSA_SIG * dsa_sig_pool[num_measurements];

	EC_KEY * ecdsa_key_pool[key_pool_size];
	ECDSA_SIG * ecdsa_sig_pool[num_measurements];


	hip_set_logdebug(LOGDEBUG_NONE);

	memset(&creation_stats, 0, sizeof(statistics_data_t));
	memset(&verify_stats, 0, sizeof(statistics_data_t));

	print_timeres();

	// data to be signed
	printf("generating payload data for %i packets (packet length %i bytes)...\n\n",
			num_measurements, PACKET_LENGTH);
	RAND_bytes(data, PACKET_LENGTH * num_measurements);


	printf("-------------------------------\n"
			"SHA1 performance test\n"
			"-------------------------------\n");

	printf("Calculating hashes over %d packets...\n", num_measurements);

	for(i = 0; i < num_measurements; i++)
	{
		gettimeofday(&start_time, NULL);

		// SHA1 on data
		SHA1(&data[i * PACKET_LENGTH], PACKET_LENGTH, &hashed_data[i * SHA_DIGEST_LENGTH]);

		gettimeofday(&stop_time, NULL);

		timediff = calc_timeval_diff(&start_time, &stop_time);
		add_statistics_item(&creation_stats, timediff);
	}

	calc_statistics(&creation_stats, &num_items, &min, &max, &avg, &std_dev,
					STATS_IN_MSECS);
	printf("generation statistics - num_data_items: %u, min: %.3fms, max: %.3fms, avg: %.3fms, std_dev: %.3fms\n",
				num_items, min, max, avg, std_dev);



	// reinitialize statistics
	memset(&creation_stats, 0, sizeof(statistics_data_t));
	memset(&verify_stats, 0, sizeof(statistics_data_t));



	printf("\n-------------------------------\n"
			"RSA performance test\n"
			"-------------------------------\n");

	// create a key pool
	printf("Creating key pool of %d keys of length %d.\n", key_pool_size, rsa_key_len);
	for(i = 0; i < key_pool_size; i++)
	{
		rsa_key_pool[i] = create_rsa_key(rsa_key_len);
	}

	printf("Calculating %d RSA signatures\n", num_measurements);
	for(i = 0; i < num_measurements; i++)
	{
		sig_len = RSA_size(rsa_key_pool[i % key_pool_size]);

		rsa_sig_pool[i] = malloc(sig_len);

		gettimeofday(&start_time, NULL);

		// SHA1 on data
		SHA1(&data[i * PACKET_LENGTH], PACKET_LENGTH, &hashed_data[i * SHA_DIGEST_LENGTH]);

		// sign
		err = RSA_sign(NID_sha1, &hashed_data[i * SHA_DIGEST_LENGTH], SHA_DIGEST_LENGTH,
				rsa_sig_pool[i], &sig_len, rsa_key_pool[i % key_pool_size]);

		gettimeofday(&stop_time, NULL);

		timediff = calc_timeval_diff(&start_time, &stop_time);
		add_statistics_item(&creation_stats, timediff);

		if(!err)
		{
			printf("RSA signature unsuccessful\n");
		}
	}
	calc_statistics(&creation_stats, &num_items, &min, &max, &avg, &std_dev,
					STATS_IN_MSECS);
	printf("generation statistics - num_data_items: %u, min: %.3fms, max: %.3fms, avg: %.3fms, std_dev: %.3fms\n",
				num_items, min, max, avg, std_dev);

#if 0
	printf("\n");
	printf("Signature generation took %.3f sec (%.5f sec per key)\n",
		bench_secs, bench_secs / sw_bench_loops);
	printf("%4.2f signatures per sec, %4.2f signatures per min\n\n",
		sw_bench_loops/bench_secs, sw_bench_loops/bench_secs*60);
#endif


	printf("Verifying %d RSA signatures\n", num_measurements);
	for(i = 0; i < num_measurements; i++)
	{
		gettimeofday(&start_time, NULL);

		SHA1(&data[i * PACKET_LENGTH], PACKET_LENGTH, &hashed_data[i * SHA_DIGEST_LENGTH]);

		err = RSA_verify(NID_sha1, &hashed_data[i * SHA_DIGEST_LENGTH], SHA_DIGEST_LENGTH,
				rsa_sig_pool[i], RSA_size(rsa_key_pool[i % key_pool_size]),
				rsa_key_pool[i % key_pool_size]);

		gettimeofday(&stop_time, NULL);

		timediff = calc_timeval_diff(&start_time, &stop_time);
		add_statistics_item(&verify_stats, timediff);

		if(!err)
		{
			printf("Verification failed\n");
		}
	}

	calc_statistics(&verify_stats, &num_items, &min, &max, &avg, &std_dev,
			STATS_IN_MSECS);
	printf("verification statistics - num_data_items: %u, min: %.3fms, max: %.3fms, avg: %.3fms, std_dev: %.3fms\n",
				num_items, min, max, avg, std_dev);


	// reinitialize statistics
	memset(&creation_stats, 0, sizeof(statistics_data_t));
	memset(&verify_stats, 0, sizeof(statistics_data_t));



	printf("\n-------------------------------\n"
			"DSA performance test\n"
			"-------------------------------\n");

	printf("Creating key pool of %d keys of length %d...\n", key_pool_size, dsa_key_len);
	for(i = 0; i < key_pool_size; i++)
	{
		dsa_key_pool[i] = create_dsa_key(dsa_key_len);
	}

	printf("Calculating %d DSA signatures\n", num_measurements);
	for(i = 0; i < num_measurements; i++)
	{
		sig_len = sizeof(DSA_SIG *);

		dsa_sig_pool[i] = malloc(sig_len);

		gettimeofday(&start_time, NULL);

		// SHA1 on data
		SHA1(&data[i * PACKET_LENGTH], PACKET_LENGTH, &hashed_data[i * SHA_DIGEST_LENGTH]);

		// sign
		dsa_sig_pool[i] = DSA_do_sign(&hashed_data[i * SHA_DIGEST_LENGTH], SHA_DIGEST_LENGTH,
				dsa_key_pool[i % key_pool_size]);

		gettimeofday(&stop_time, NULL);

		timediff = calc_timeval_diff(&start_time, &stop_time);
		add_statistics_item(&creation_stats, timediff);

		if(!dsa_sig_pool[i]){
			printf("DSA signature is crap\n");
		}
	}
	calc_statistics(&creation_stats, &num_items, &min, &max, &avg, &std_dev,
					STATS_IN_MSECS);
	printf("generation statistics - num_data_items: %u, min: %.3fms, max: %.3fms, avg: %.3fms, std_dev: %.3fms\n",
				num_items, min, max, avg, std_dev);

	printf("Verifying %d DSA signatures\n", num_measurements);
	for(i = 0; i < num_measurements; i++)
	{
		gettimeofday(&start_time, NULL);

		SHA1(&data[i * PACKET_LENGTH], PACKET_LENGTH, &hashed_data[i * SHA_DIGEST_LENGTH]);

		err = DSA_do_verify(&hashed_data[i * SHA_DIGEST_LENGTH], SHA_DIGEST_LENGTH,
				dsa_sig_pool[i], dsa_key_pool[i % key_pool_size]);

		gettimeofday(&stop_time, NULL);

		timediff = calc_timeval_diff(&start_time, &stop_time);
		add_statistics_item(&verify_stats, timediff);

		if(err <= 0)
		{
			printf("Verification failed\n");
		}
	}

	calc_statistics(&verify_stats, &num_items, &min, &max, &avg, &std_dev,
			STATS_IN_MSECS);
	printf("verification statistics - num_data_items: %u, min: %.3fms, max: %.3fms, avg: %.3fms, std_dev: %.3fms\n",
				num_items, min, max, avg, std_dev);



	// reinitialize statistics
	memset(&creation_stats, 0, sizeof(statistics_data_t));
	memset(&verify_stats, 0, sizeof(statistics_data_t));



	printf("\n-------------------------------\n"
			"ECDSA performance test\n"
			"-------------------------------\n");

	printf("Creating key pool of %d keys for curve ECDSA_CURVE...\n", key_pool_size);
	for(i = 0; i < key_pool_size; i++)
	{
		ecdsa_key_pool[i] = EC_KEY_new_by_curve_name(ECDSA_CURVE);
		if (!ecdsa_key_pool[i])
		{
			printf("ec key setup failed!\n");
		}

		if (!EC_KEY_generate_key(ecdsa_key_pool[i]))
		{
			printf("ec key generation failed!\n");
		}
	}

	printf("Calculating %d ECDSA signatures\n", num_measurements);
	for(i = 0; i < num_measurements; i++)
	{
		sig_len = ECDSA_size(ecdsa_key_pool[i % key_pool_size]);

		ecdsa_sig_pool[i] = malloc(sig_len);

		gettimeofday(&start_time, NULL);

		// SHA1 on data
		SHA1(&data[i * PACKET_LENGTH], PACKET_LENGTH, &hashed_data[i * SHA_DIGEST_LENGTH]);

		// sign
		ecdsa_sig_pool[i] = ECDSA_do_sign(&hashed_data[i * SHA_DIGEST_LENGTH],
				SHA_DIGEST_LENGTH, ecdsa_key_pool[i % key_pool_size]);

		gettimeofday(&stop_time, NULL);

		timediff = calc_timeval_diff(&start_time, &stop_time);
		add_statistics_item(&creation_stats, timediff);

		if(!ecdsa_sig_pool[i])
		{
			printf("ECDSA signature not successful\n");
		}
	}
	calc_statistics(&creation_stats, &num_items, &min, &max, &avg, &std_dev,
					STATS_IN_MSECS);
	printf("generation statistics - num_data_items: %u, min: %.3fms, max: %.3fms, avg: %.3fms, std_dev: %.3fms\n",
				num_items, min, max, avg, std_dev);

	printf("Verifying %d ECDSA signatures\n", num_measurements);
	for(i = 0; i < num_measurements; i++)
	{
		gettimeofday(&start_time, NULL);

		SHA1(&data[i * PACKET_LENGTH], PACKET_LENGTH, &hashed_data[i * SHA_DIGEST_LENGTH]);

		err = ECDSA_do_verify(&hashed_data[i * SHA_DIGEST_LENGTH], SHA_DIGEST_LENGTH,
				ecdsa_sig_pool[i], ecdsa_key_pool[i % key_pool_size]);

		gettimeofday(&stop_time, NULL);

		timediff = calc_timeval_diff(&start_time, &stop_time);
		add_statistics_item(&verify_stats, timediff);

		if(err <= 0)
		{
			printf("Verification failed\n");
		}
	}

	calc_statistics(&verify_stats, &num_items, &min, &max, &avg, &std_dev,
			STATS_IN_MSECS);
	printf("verification statistics - num_data_items: %u, min: %.3fms, max: %.3fms, avg: %.3fms, std_dev: %.3fms\n",
				num_items, min, max, avg, std_dev);
}
