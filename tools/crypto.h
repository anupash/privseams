#ifndef HIPD_CRYPTO
#define HIPD_CRYPTO

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <asm/types.h>
#include <string.h>

#include <netinet/in.h>

#include <openssl/dsa.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

#include <net/hip.h>

#include <openssl/err.h>

#include "debug.h"

// wrapper functions for -lcrypto

#define HIP_MAX_DSA_KEY_LEN 4096

#define HIP_HIT_TYPE_HASH126 1
#define HIP_HIT_TYPE_HAA_HASH 2

#define DSA_KEY_DEFAULT_BITS    (128 * 8)

#define DEFAULT_CONFIG_DIR        "/etc/hip"
#define DEFAULT_CONFIG_DIR_MODE   0755
#define DEFAULT_HOST_DSA_KEY_FILE_BASE "hip_host_dsa_key"
#define DEFAULT_PUB_FILE_SUFFIX ".pub"
#define DEFAULT_PARAMS_FILE_SUFFIX ".params"

/* Only one crypto-filefmt supported */
#define HIP_KEYFILE_FMT_HIP_DSA_PEM 1

#ifdef CONFIG_HIP_DEBUG
void keygen_callback(int a, int b, void* arg);
#define KEYGEN_CALLBACK keygen_callback
#else
#define KEYGEN_CALLBACK NULL
#endif

int dsa_to_hit(char *dsa, int type, struct in6_addr *hit);
int dsa_to_dns_key_rr(DSA *dsa, unsigned char **buf);

DSA *create_dsa_key(int bits);
int save_dsa_keys(char *filename, DSA *dsa);
DSA *load_dsa_keys(char *filename);

#endif /* HIPD_CRYPTO */
