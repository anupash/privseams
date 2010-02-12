/*!
 * \file dh_performance.c
 *
 * \brief Performance testfile that can be used for benchmarking a system.
 * \author Tobias Heer
 *
 * This is file provides an executable that can be run to benchmark a HIP system.
 * It provides detailed information about the runtime of certain cryptographic
 * operations.
 *
 * \note Distributed under <a href="http://www.gnu.org/licenses/gpl.txt">GNU/GPL</a>.
 *
 */

#include <unistd.h>
#include <stdio.h>              /* printf & co */
#include <stdlib.h>             /* exit & co */
#include <openssl/dh.h>         /* open ssl library for DH operations */
#include <openssl/sha.h>        /* open ssl library for SHA operations */
#include <openssl/dsa.h>        /* open ssl library for DSA operations */

#ifdef HAVE_CONFIG_H
  #include "config.h"
#endif /* HAVE_CONFIG_H */

#include "lib/tool/crypto.h"
#include "lib/core/hashchain.h"

#include "lib/performance/performance.h"
#include <openssl/sha.h>

//int DH_compute_key(unsigned char *key, BIGNUM *pub_key, DH *dh);



/*! \brief Number of benchmark runs */
#define DHP_DEFAULT_LOOPS 100


#define TRUE  1
#define FALSE 0

/** @addtogroup notification
 * @{
 */

#define PS_DH_CREATE  0
/** \brief Perf set number: Shared secret creation */
#define PS_DH_SHARE   1
/*! \brief Perf set number: DSA key creation */
#define PS_DSA_CREATE 2
/*! \brief Perf set number: DSA signature creation */
#define PS_DSA_SIGN   3
/*! \brief Perf set number: DSA verification */
#define PS_DSA_VERIFY 4
/*! \brief Perf set number: DSA key creation */
#define PS_RSA_CREATE 5
/*! \brief Perf set number: RSA signature creation */
#define PS_RSA_SIGN   6
/*! \brief Perf set number: RSA verification */
#define PS_RSA_VERIFY 7
/*! \brief Perf set number: Hash chain creation */
#define PS_HC_CREATE  8
/*! \brief Perf set number: Hash computation */
#define PS_HASH       9
/* \brief Maximum perf set number. Number of file outputs */
#define PS_MAX       10
/*!@}*/

/*! \brief Input bytes for the hash function */
#define HASH_LEN     20


/*!
 * \brief Print command line options.
 *
 * Prints all possible command line options.
 *
 * \author	Tobias Heer
 *
 * \param progname The name of the executable
 * \return void
 */
void dhp_usage(char *progname)
{
    printf( "Usage: %s -c [NUM] -l [NUM]\n"
            "-c [NUM] : create [NUM] new dh keys for the benchmark\n"
            "-g [NUM] : dh group ID for dh keys (Default is 3 (1536 Oakley_5)\n"
            "-d [NUM] : create [NUM] new dsa keys for the benchmark\n"
            "-r [NUM] : create [NUM] new rsa keys for the benchmark\n"
            "-j [NUM] : rsa key length (default is 1024)\n"
            "-k [NUM] : dsa key length (default is %d)\n"
            "-l [NUM] : run the benchmark [NUM] times\n"
            "-p       : print keys (do not use this option for benchmarking!)\n"
            "-s [NUM] : shared key length (default is 192)\n"
            "-h [NUM] : hash chain length (default is 44 (20 trig, 20 sig, 4 binary)\n"
            "-x       : write singe time values to files (PS_* files)\n"
            "-b       : put load onto the cpu by calculating DH exchanges\n"
            "-f [NUM] : calculate [NUM] SHA-1 hashes\n"
            , progname, DSA_KEY_DEFAULT_BITS);
}

/*!
 * \brief Get the option values from the input parameters.
 *
 * Takes the input parameters, parses them and returns the option switches.
 *
 * \author	Tobias Heer
 *
 * \param argv The arguments array.
 * \param sw_create_dh How many DH keys should be used?
 * \param sw_dh_group_id Which DH group ID (key type) should be used?
 * \param sw_create_dsa How many DSA keys should be used?
 * \param sw_create_rsa How many RSA keys should be used?
 * \param sw_rsa_keylen RSA key length.
 * \param sw_dsa_keylen DSA key length.
 * \param sw_bench_loops Repetitions for the public-key measurements.
 * \param sw_print_keys  Print the DH, RSA, and DSA keys (for debug).
 * \param sw_shared_key_len Length of the shared keys.
 * \param sw_hash_chain_len Length of the hash chain (elements)
 * \param sw_file_output Print data to files or to stdout
 * \param sw_cpuload Don't measure, only load the CPU.
 * \param sw_hash_loops Number of hash computations.
 *
 * \note all sw_ paramters are pointers to ouput parameters that are modified
 *       by dhp_getopts.
 *
 * \return Returns error code. 0 = Success, 1 = Error.
 */
int dhp_getopts(int argc,
                char **argv,
                int  *sw_create_dh,
                int  *sw_dh_group_id,
                int  *sw_create_dsa,
                int  *sw_create_rsa,
                int  *sw_rsa_keylen,
                int  *sw_dsa_keylen,
                int  *sw_bench_loops,
                int  *sw_print_keys,
                int  *sw_shared_key_len,
                int  *sw_hash_chain_len,
                int  *sw_file_output,
                int  *sw_cpuload,
                int  *sw_hash_loops)
{
    int c;
    opterr = 0;

    while ((c = getopt(argc, argv, "c:l:ps:h:d:xbr:j:g:f:k:")) != -1) {
        switch (c) {
        case 'c':
            /* create n new dh keys */
            *sw_create_dh = atoi(optarg);
            if (*sw_create_dh < 2) {
                printf("The value for argument %c needs to be greater than 1\n",
                       optopt);
                return 0;
            }
            break;
        case 'd':
            *sw_create_dsa = atoi(optarg);
            if (*sw_create_dsa < 2) {
                printf("The value for argument %c needs to be greater than 1\n",
                       optopt);
                return 0;
            }
            break;
        case 'r':
            *sw_create_rsa = atoi(optarg);
            if (*sw_create_rsa < 2) {
                printf("The value for argument %c needs to be greater than 1\n",
                       optopt);
                return 0;
            }
            break;
        case 'l':
            /* number of benchmark loops */
            *sw_bench_loops = atoi(optarg);
            if (*sw_bench_loops < 1) {
                printf("The value for argument %c needs to be greater than 0\n",
                       optopt);
                return 0;
            }
            break;
        case 'p':
            *sw_print_keys = TRUE;
            break;
        case 'x':
            *sw_file_output = TRUE;
            break;
        case 'b':
            *sw_cpuload = TRUE;
            break;

        case 's':
            *sw_shared_key_len = atoi(optarg);
            if (*sw_shared_key_len < 1) {
                printf("The value for argument %c needs to be greater than 0\n",
                       optopt);
                return 0;
            }
            break;
        case 'j':
            *sw_rsa_keylen = atoi(optarg);
            if (*sw_rsa_keylen < 1) {
                return 0;
            }
            break;
        case 'k':
            *sw_dsa_keylen = atoi(optarg);
            if (*sw_dsa_keylen < 1) {
                return 0;
            }
            break;
        case 'h':
            *sw_hash_chain_len = atoi(optarg);
            if (*sw_shared_key_len < 1) {
                printf("The value for argument %c needs to be greater than 0\n",
                       optopt);
                return 0;
            }
            break;
        case 'f':
            *sw_hash_loops = atoi(optarg);
            if (*sw_hash_loops < 1 || *sw_hash_loops % 1000 != 0) {
                printf("The value must be a multitude of 1000\n");
                return 0;
            }
            break;
        case 'g':
            *sw_dh_group_id = atoi(optarg);
            if (*sw_dh_group_id < 1) {
                printf("The value for argument %c needs to be greater than 0\n",
                       optopt);
                return 0;
            }
            break;
        case ':':
            printf("Missing argument %c\n", optopt);
            return 0;

        case '?':
            printf("Unknown option %c\n", optopt);
            return 0;
        }
    }
    return 1;
}

/*!
 * \brief   Determine and print the gettimeofday time resolution.
 *
 * \author	Tobias Heer
 *
 * Determine the time resolution of gettimeofday.
 *
 * \return void
 */
static void print_timeres(void)
{
    struct timeval tv1, tv2;
    int i;
    printf( "-------------------------------\n"
            "Determine gettimeofday resolution:\n");


    for (i = 0; i < 10; i++) {
        gettimeofday(&tv1, NULL);
        do {
            gettimeofday(&tv2, NULL);
        } while (tv1.tv_usec == tv2.tv_usec);

        printf("Resolution: %ld us\n", tv2.tv_usec - tv1.tv_usec +
               1000000 * (tv2.tv_sec - tv1.tv_sec));
    }

    printf( "-------------------------------\n\n\n");
}

/*!
 * \brief Take time for benchmark.
 *
 * Starts a time interval.
 *
 * \author	Tobias Heer
 *
 * \param timeval timeval struct from the OS.
 * \return void
 */
void dhp_start_benchmark(struct timeval *bench_time)
{
    gettimeofday(bench_time, NULL);
}

/*!
 * \brief Take time for benchmark and return passed time.
 *
 * Concludes a time interval and returns the past time.
 *
 * \author	Tobias Heer
 *
 * \param timeval timeval struct from the OS.
 * \return passed time since beginning of the interval.
 */
double dhp_stop_benchmark(struct timeval *bench_time)
{
    struct timeval now;
    gettimeofday(&now, NULL);
    return ((now.tv_sec - bench_time->tv_sec)
            * 1000000 + (now.tv_usec - bench_time->tv_usec)) / 1000000.0;
}

/*!
 * \brief Main function that performs the measurements.
 *
 * \author	Tobias Heer
 *
 * \param argc Number of command line arguments
 * \param argv Command line argument array
 * .
 * \return Returns error code. 0 = Success, 1 = Error.
 */
int main(int argc, char **argv)
{
    int i;
    int err               = 0;
    /* switches */
    int sw_create_dh      = 5;
    int sw_create_dsa     = 5;
    int sw_create_rsa     = 5;
    int sw_bench_loops    = 0;
    int sw_file_output    = 0;
    int sw_print_keys     = FALSE;
    int sw_shared_key_len = 192;
    int sw_hash_chain_len = 46;
    int sw_cpuload        = 0;
    int sw_rsa_keylen     = 1024;
    int sw_dsa_keylen     = DSA_KEY_DEFAULT_BITS;
    int sw_hashloops      = 100000;
    int sw_dh_group_id    = HIP_FIRST_DH_GROUP_ID;
    RSA **rsa_key_pool    = NULL;
    DSA **dsa_key_pool    = NULL;
    DH **dh_key_pool      = NULL;
    BN_CTX *ctx           = NULL;
    float bench_secs      = 0.0;
    struct timeval bench_time;
    unsigned int sig_len;
    perf_set_t *perf_set = NULL;

    printf("Default settings RSA: key pool of %d keys of length %d.\n",
           sw_create_rsa,
           sw_rsa_keylen);

    if (!dhp_getopts(argc, argv,
                     &sw_create_dh,
                     &sw_dh_group_id,
                     &sw_create_dsa,
                     &sw_create_rsa,
                     &sw_rsa_keylen,
                     &sw_dsa_keylen,
                     &sw_bench_loops,
                     &sw_print_keys,
                     &sw_shared_key_len,
                     &sw_hash_chain_len,
                     &sw_file_output,
                     &sw_cpuload,
                     &sw_hashloops)) {
        dhp_usage(argv[0]);
        exit(0);
    }

    if (sw_file_output) {
        perf_set = hip_perf_create(PS_MAX);

        check_and_create_dir("results", DEFAULT_CONFIG_DIR_MODE);

        hip_perf_set_name(perf_set, PS_DH_CREATE, "PS_DH_CREATE.csv");
        hip_perf_set_name(perf_set, PS_DH_SHARE, "PS_DH_SHARE.csv");
        hip_perf_set_name(perf_set, PS_RSA_CREATE, "PS_RSA_CREATE.csv");
        hip_perf_set_name(perf_set, PS_RSA_SIGN, "PS_RSA_SIGN.csv");
        hip_perf_set_name(perf_set, PS_RSA_VERIFY, "PS_RSA_VERIFY.csv");
        hip_perf_set_name(perf_set, PS_DSA_CREATE, "PS_DSA_CREATE.csv");
        hip_perf_set_name(perf_set, PS_DSA_SIGN, "PS_DSA_SIGN.csv");
        hip_perf_set_name(perf_set, PS_DSA_VERIFY, "PS_DSA_VERIFY.csv");
        hip_perf_set_name(perf_set, PS_HC_CREATE, "PS_HC_CREATE.csv");
        hip_perf_set_name(perf_set, PS_HASH,
                          "PS_HC_HASHLOOPS_100_PER_ENTRY.csv");

        printf( "-------------------------------\n"
                "!!! NOTE: File output option set! The benchmark \n"
                "          results displayed here are not accurate!\n"
                "          They contain the time needed to write\n"
                "          the output to the files. Don't rely on these\n"
                "          values. Use the values provided in the\n"
                "          PS_*.csv files.\n\n"
                "          PS_DH_CREATE:  Diffie Hellman key creation\n"
                "          PS_DH_SHARE:   Diffie Hellman shared key creation\n"
                "          PS_DSA_CREATE: DSA key creation\n"
                "          PS_DSA_SIGN:   DSA signature\n"
                "          PS_DSA_VERIFY: DSA verification\n"
                "          PS_HC_CREATE:  Hash chain creation\n"
                "          PS_HC_HASHLOOPS_100_PER_ENTRY: Hash performance. 100 hashes per row!\n"
                "-------------------------------\n\n");
        hip_perf_open(perf_set);
    }

    if (!sw_cpuload) {
        print_timeres();

        printf( "-------------------------------\n"
                "RSA performance test\n"
                "-------------------------------\n\n");
        //impl_dsa_sign(u8 *digest, u8 *private_key, u8 *signature)


        rsa_key_pool = malloc(sw_create_rsa * sizeof(RSA *));
        printf("Creating key pool of %d keys of length %d.\n",
               sw_create_rsa,
               sw_rsa_keylen);
        dhp_start_benchmark(&bench_time);
        /* create new DH keys */
        for (i = 0; i < sw_create_rsa; i++) {
            //printf("Create key %d\n", i);
            if (sw_file_output) {
                hip_perf_start_benchmark(perf_set, PS_RSA_CREATE);
            }
            rsa_key_pool[i] = create_rsa_key(sw_rsa_keylen);
            if (!rsa_key_pool[i]) {
                printf("RSA key is crap!\n");
                exit(0);
            }
            if (sw_file_output) {
                hip_perf_stop_benchmark(perf_set, PS_RSA_CREATE);
                hip_perf_write_benchmark(perf_set, PS_RSA_CREATE);
            }
            if (sw_print_keys == TRUE) {
                printf("\nKey %d\n", i + 1);
            } else {
                //dhp_load_progress(i, sw_create_dsa, 50);
            }
        }


        printf("\n");
        bench_secs = dhp_stop_benchmark(&bench_time);
        printf("RSA key generation took %.3f sec (%.5f sec per key)\n",
               bench_secs, bench_secs / sw_create_rsa);
        printf("%4.2f keys per sec, %4.2f keys per min\n\n",
               sw_create_rsa / bench_secs, sw_create_rsa / bench_secs * 60);


        if (sw_bench_loops == 0) {
            printf( "Using standard number of loops (%d).\n"
                    "Use the -p parameter to use more loops\n"
                    "to get more realistic results.\n\n",
                    DHP_DEFAULT_LOOPS);
            sw_bench_loops = DHP_DEFAULT_LOOPS;
        }

        /* if sw_rsa_sig_len == 0 we will use the default lengths as they
         * occur in hip */
        u8 rsa_data[SHA_DIGEST_LENGTH];
        memset(rsa_data, 22, SHA_DIGEST_LENGTH);
        u8 **rsa_sig_pool;
        rsa_sig_pool = malloc(sw_bench_loops * sizeof(u8 *));

        printf("Calculating %d RSA signatures (len: %d)\n", sw_bench_loops, sw_rsa_keylen);

        dhp_start_benchmark(&bench_time);
        for (i = 0; i < sw_bench_loops; i++) {
            sig_len = RSA_size(rsa_key_pool[i % sw_create_rsa]);
            rsa_sig_pool[i] = malloc(sig_len);
            memset(rsa_sig_pool[i], 0, sig_len);
            ctx = BN_CTX_new();
            rsa_key_pool[i % sw_create_rsa]->iqmp = BN_mod_inverse(NULL, rsa_key_pool[i % sw_create_rsa]->p, rsa_key_pool[i % sw_create_rsa]->q, ctx);

            if (sw_file_output) {
                hip_perf_start_benchmark(perf_set, PS_RSA_SIGN);
            }
            err = RSA_sign(NID_sha1, rsa_data, SHA_DIGEST_LENGTH,
                           rsa_sig_pool[i], &sig_len,
                           rsa_key_pool[i % sw_create_rsa]);

            if (sw_file_output) {
                hip_perf_stop_benchmark(perf_set, PS_RSA_SIGN);
                hip_perf_write_benchmark(perf_set, PS_RSA_SIGN);
            }
            if (!err) {
                printf("RSA signature is crap\n");
            }


            if (sw_print_keys) {
                //  HIP_DEBUG("DSAsig.r: %s\n", BN_bn2hex(dsa_sig_pool[i]->r));
                //  HIP_DEBUG("DSAsig.s: %s\n", BN_bn2hex(dsa_sig_pool[i]->s));
            }
        }
        bench_secs = dhp_stop_benchmark(&bench_time);
        printf("\n");
        printf("Signature generation took %.3f sec (%.5f sec per key)\n",
               bench_secs, bench_secs / sw_bench_loops);
        printf("%4.2f signatures per sec, %4.2f signatures per min\n\n",
               sw_bench_loops / bench_secs, sw_bench_loops / bench_secs * 60);


        printf("Verifying %d RSA signatures\n", sw_bench_loops);
        dhp_start_benchmark(&bench_time);
        for (i = 0; i < sw_bench_loops; i++) {
            if (sw_file_output) {
                hip_perf_start_benchmark(perf_set, PS_RSA_VERIFY);
            }
            err = RSA_verify(NID_sha1, rsa_data, SHA_DIGEST_LENGTH,
                             rsa_sig_pool[i],
                             RSA_size(rsa_key_pool[i % sw_create_rsa]),
                             rsa_key_pool[i % sw_create_rsa]);

            if (!err) {
                printf("Verification failed\n");
            }
            if (sw_file_output) {
                hip_perf_stop_benchmark(perf_set, PS_RSA_VERIFY);
                hip_perf_write_benchmark(perf_set, PS_RSA_VERIFY);
            }
            if (sw_print_keys) {
                //HIP_DEBUG("DSAsig.r: %s\n", BN_bn2hex(dsa_sig_pool[i]->r));
                //HIP_DEBUG("DSAsig.s: %s\n", BN_bn2hex(dsa_sig_pool[i]->s));
            }
        }
        bench_secs = dhp_stop_benchmark(&bench_time);
        printf("\n");
        printf("Signature verification took %.3f sec (%.5f sec per key)\n",
               bench_secs, bench_secs / sw_bench_loops);
        printf("%4.2f signatures per sec, %4.2f signatures per min\n\n",
               sw_bench_loops / bench_secs, sw_bench_loops / bench_secs * 60);

        printf( "-------------------------------\n"
                "DSA performance test\n"
                "-------------------------------\n\n");
        //impl_dsa_sign(u8 *digest, u8 *private_key, u8 *signature)

        dsa_key_pool = malloc(sw_create_dsa * sizeof(DSA *));
        printf("Creating key pool of %d keys of length %d.\n",
               sw_create_dsa,
               sw_dsa_keylen);
        dhp_start_benchmark(&bench_time);
        /* create new DH keys */
        for (i = 0; i < sw_create_dsa; i++) {
            if (sw_file_output) {
                hip_perf_start_benchmark(perf_set, PS_DSA_CREATE);
            }
            dsa_key_pool[i] = create_dsa_key(sw_dsa_keylen);
            if (!dsa_key_pool[i]) {
                printf("DSA key is crap!\n");
                exit(0);
            }
            if (sw_file_output) {
                hip_perf_stop_benchmark(perf_set, PS_DSA_CREATE);
                hip_perf_write_benchmark(perf_set, PS_DSA_CREATE);
            }
            if (sw_print_keys == TRUE) {
                printf("\nKey %d\n", i + 1);
                printf("pub_key =%s\n", BN_bn2hex(dsa_key_pool[i]->pub_key));
                printf("priv_key =%s\n", BN_bn2hex(dsa_key_pool[i]->priv_key));
            } else {
                //dhp_load_progress(i, sw_create_dsa, 50);
            }
        }


        printf("\n");
        bench_secs = dhp_stop_benchmark(&bench_time);
        printf("DSA key generation took %.3f sec (%.5f sec per key)\n",
               bench_secs, bench_secs / sw_create_dsa);
        printf("%4.2f keys per sec, %4.2f keys per min\n\n",
               sw_create_dsa / bench_secs, sw_create_dsa / bench_secs * 60);


        if (sw_bench_loops == 0) {
            printf( "Using standard number of loops (%d).\n"
                    "Use the -p parameter to use more loops\n"
                    "to get more realistic results.\n\n",
                    DHP_DEFAULT_LOOPS);
            sw_bench_loops = DHP_DEFAULT_LOOPS;
        }


        /* if sw_dsa_sig_len == 0 we will use the default lengths as they
         * occur in hip */
        u8 dsa_data[SHA_DIGEST_LENGTH];
        memset(dsa_data, 22, SHA_DIGEST_LENGTH);
        DSA_SIG **dsa_sig_pool;
        dsa_sig_pool = malloc(sw_bench_loops * sizeof(DSA_SIG *));

        printf("Calculating %d DSA signatures\n", sw_bench_loops);
        dhp_start_benchmark(&bench_time);
        for (i = 0; i < sw_bench_loops; i++) {
            if (sw_file_output) {
                hip_perf_start_benchmark(perf_set, PS_DSA_SIGN);
            }
            dsa_sig_pool[i] = DSA_do_sign(dsa_data, SHA_DIGEST_LENGTH,
                                          dsa_key_pool[i % sw_create_dsa]);

            if (!dsa_sig_pool[i]) {
                printf("DSA signature is crap\n");
            }

            if (sw_file_output) {
                hip_perf_stop_benchmark(perf_set, PS_DSA_SIGN);
                hip_perf_write_benchmark(perf_set, PS_DSA_SIGN);
            }
            if (sw_print_keys) {
                HIP_DEBUG("DSAsig.r: %s\n", BN_bn2hex(dsa_sig_pool[i]->r));
                HIP_DEBUG("DSAsig.s: %s\n", BN_bn2hex(dsa_sig_pool[i]->s));
            }
        }
        bench_secs = dhp_stop_benchmark(&bench_time);
        printf("\n");
        printf("Signature generation took %.3f sec (%.5f sec per key)\n",
               bench_secs, bench_secs / sw_bench_loops);
        printf("%4.2f signatures per sec, %4.2f signatures per min\n\n",
               sw_bench_loops / bench_secs, sw_bench_loops / bench_secs * 60);


        printf("Verifying %d DSA signatures\n", sw_bench_loops);
        dhp_start_benchmark(&bench_time);
        for (i = 0; i < sw_bench_loops; i++) {
            if (sw_file_output) {
                hip_perf_start_benchmark(perf_set, PS_DSA_VERIFY);
            }
            if (0 == DSA_do_verify(dsa_data, SHA_DIGEST_LENGTH, dsa_sig_pool[i],
                                   dsa_key_pool[i % sw_create_dsa])) {
                printf("Verification failed\n");
            }
            if (sw_file_output) {
                hip_perf_stop_benchmark(perf_set, PS_DSA_VERIFY);
                hip_perf_write_benchmark(perf_set, PS_DSA_VERIFY);
            }
            if (sw_print_keys) {
                HIP_DEBUG("DSAsig.r: %s\n", BN_bn2hex(dsa_sig_pool[i]->r));
                HIP_DEBUG("DSAsig.s: %s\n", BN_bn2hex(dsa_sig_pool[i]->s));
            }
        }
        bench_secs = dhp_stop_benchmark(&bench_time);
        printf("\n");
        printf("Signature verification took %.3f sec (%.5f sec per key)\n",
               bench_secs, bench_secs / sw_bench_loops);
        printf("%4.2f signatures per sec, %4.2f signatures per min\n\n",
               sw_bench_loops / bench_secs, sw_bench_loops / bench_secs * 60);


        printf( "-------------------------------\n"
                "Diffie hellman performance test\n"
                "-------------------------------\n\n");
    } else {
        printf( "-------------------------------\n"
                "Diffie hellman cpu load\n"
                "-------------------------------\n\n");
    }
    /* allocate memory for the DH key pool a minimum size for
     * two keys must be allocated (own and peer key) */

    if (sw_create_dh == 0) {
        printf( "Using 2 DH keys.\n"
                "Use the -c parameter to create more dh\n"
                "keys and to get more realistic results.\n\n");

        /*  DH_generate_key(dh_key_pool[0]);
        *       DH_generate_key(dh_key_pool[1]); */
        sw_create_dh = 2;
    }
    dh_key_pool = malloc((sw_create_dh == 0 ? 2 : sw_create_dh) * sizeof(DH *));
    printf("Creating key pool of %d keys (Group %d).\n",
           (sw_create_dh == 0 ? 2 : sw_create_dh), sw_dh_group_id);

    dhp_start_benchmark(&bench_time);
    /* create new DH keys */
    for (i = 0; i < sw_create_dh; i++) {
        if (sw_file_output) {
            hip_perf_start_benchmark(perf_set, PS_DH_CREATE);
        }
        dh_key_pool[i] = hip_generate_dh_key(sw_dh_group_id);
        if (sw_file_output) {
            hip_perf_stop_benchmark(perf_set, PS_DH_CREATE);
            hip_perf_write_benchmark(perf_set, PS_DH_CREATE);
        }
        if (sw_print_keys == TRUE) {
            printf("\nKey %d\n", i + 1);
            printf("pub_key =%s\n", BN_bn2hex(dh_key_pool[i]->pub_key));
            printf("priv_key =%s\n", BN_bn2hex(dh_key_pool[i]->priv_key));
        } else {
            //dhp_load_progress(i, sw_create_dh, 50);
        }
    }
    printf("\n");
    bench_secs = dhp_stop_benchmark(&bench_time);
    printf("DH key generation took %.3f sec (%.5f sec per key)\n",
           bench_secs, bench_secs / sw_create_dh);
    printf("%4.2f keys per sec, %4.2f keys per min\n\n",
           sw_create_dh / bench_secs, sw_create_dh / bench_secs * 60);



    dhp_start_benchmark(&bench_time);
    int dh_size = hip_get_dh_size(HIP_FIRST_DH_GROUP_ID);
    u8 shared_key[sw_shared_key_len];
    uint8_t pub_key[dh_size];


    printf("Calculating %d DH shared secrets\n", sw_bench_loops);
    int k = 0;
    for (i = 0; i < sw_bench_loops; i++) {
        if (i % sw_create_dh == 0) {
            k++;
        }
        bn2bin_safe(dh_key_pool[(i + k) % sw_create_dh]->pub_key,
                    pub_key, dh_size);
        if (sw_file_output) {
            hip_perf_start_benchmark(perf_set, PS_DH_SHARE);
        }
        hip_gen_dh_shared_key(  dh_key_pool[i % sw_create_dh],
                                pub_key,
                                dh_size,
                                shared_key,
                                sw_shared_key_len);
        if (sw_file_output) {
            hip_perf_stop_benchmark(perf_set, PS_DH_SHARE);
            hip_perf_write_benchmark(perf_set, PS_DH_SHARE);
        }
        if (sw_print_keys) {
            HIP_HEXDUMP("Shared key:", shared_key, sw_shared_key_len);
        }
        if (sw_cpuload) {
            i = 0;
        }
    }
    printf("\n");
    bench_secs = dhp_stop_benchmark(&bench_time);
    printf("Shared Key generation took %.3f sec (%.5f sec per key)\n",
           bench_secs, bench_secs / sw_bench_loops);
    printf("%4.2f keys per sec, %4.2f keys per min\n\n",
           sw_bench_loops / bench_secs, sw_bench_loops / bench_secs * 60);

#ifdef HASHCHAIN
    printf( "-------------------------------\n"
            "Hash chain performance test\n"
            "-------------------------------\n\n");

    printf("Creating %d hash chains of length %d\n", sw_bench_loops, sw_hash_chain_len);
    hash_chain_t *current_chain;
    dhp_start_benchmark(&bench_time);

    for (i = 0; i < sw_bench_loops; i++) {
        if (sw_file_output) {
            hip_perf_start_benchmark(perf_set, PS_HC_CREATE);
        }
        current_chain = hchain_create(sw_hash_chain_len);
        if (sw_file_output) {
            hip_perf_stop_benchmark(perf_set, PS_HC_CREATE);
            hip_perf_write_benchmark(perf_set, PS_HC_CREATE);
        }
        if (sw_print_keys) {
            hchain_print(current_chain);
        }
    }
    printf("\n");
    bench_secs = dhp_stop_benchmark(&bench_time);
    printf("Hash chain generation took %.3f sec (%.10f sec per hash chain)\n",
           bench_secs, bench_secs / sw_bench_loops);
    printf("%4.2f hash chains per sec, %4.2f hash chains per min\n",
           sw_bench_loops / bench_secs, sw_bench_loops / bench_secs * 60 * 1000);

    //if(sw_file_output) hip_perf_close(perf_set);

#endif

    printf( "-------------------------------\n"
            "Hash function (SHA-1) performance test\n"
            "-------------------------------\n\n");

    printf("Creating %d hashes\n", sw_hashloops);
    u8 buffer1[HASH_LEN];
    u8 buffer2[HASH_LEN];
    memset(buffer1, 22, SHA_DIGEST_LENGTH);
    memset(buffer2, 25, SHA_DIGEST_LENGTH);

    dhp_start_benchmark(&bench_time);

    int j;

    for (i = 0; i < sw_hashloops / 100; i++) {
        if (sw_file_output) {
            hip_perf_start_benchmark(perf_set, PS_HASH);
        }
        for (j = 0; j < 100; j++) {
            HIP_SHA(buffer1, HASH_LEN, buffer2);
        }
        if (sw_file_output) {
            hip_perf_stop_benchmark(perf_set, PS_HASH);
            hip_perf_write_benchmark(perf_set, PS_HASH);
        }
    }
    printf("\n");
    bench_secs = dhp_stop_benchmark(&bench_time);
    printf("Hash calculation took %.3f sec (%.10f sec per hash)\n",
           bench_secs, bench_secs / sw_hashloops);
    printf("%4.2f hashes per sec, %4.2f hashes per min\n",
           sw_bench_loops / bench_secs * 1000, sw_hashloops / bench_secs * 60 * 1000);

#ifdef CONFIG_HIP_PERFORMANCE
    /* Deallocate memory of perf_set after finishing all of tests */
    hip_perf_destroy(perf_set);
#endif
    return err;
}
