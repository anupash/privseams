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
#include <hip.h>
#include <openssl/dsa.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "debug.h"

// wrapper functions for -lcrypto

#define HIP_MAX_DSA_KEY_LEN 4096
#define HIP_MAX_RSA_KEY_LEN 4096
#define HIP_MAX_DH_GROUP_ID 7 

#define DSA_KEY_DEFAULT_BITS    (128 * 8)
#define RSA_KEY_DEFAULT_BITS    1024

#define DEFAULT_CONFIG_DIR        "/etc/hip"
#define DEFAULT_CONFIG_DIR_MODE   0755
#define DEFAULT_HOST_DSA_KEY_FILE_BASE "hip_host_dsa_key"
#define DEFAULT_HOST_RSA_KEY_FILE_BASE "hip_host_rsa_key"
#define DEFAULT_PUB_FILE_SUFFIX ".pub"

#define DEFAULT_PUB_HI_FILE_NAME_SUFFIX "_pub"
#define DEFAULT_ANON_HI_FILE_NAME_SUFFIX "_anon"

/* Only one crypto-filefmt supported */
#define HIP_KEYFILE_FMT_HIP_PEM 1

#ifdef CONFIG_HIP_DEBUG
void keygen_callback(int a, int b, void* arg);
#define KEYGEN_CALLBACK keygen_callback
#else
#define KEYGEN_CALLBACK NULL
#endif

int dsa_to_hit(DSA *dsa_key, char *dsa, int type, struct in6_addr *hit);
int rsa_to_hit(RSA *rsa_key, char *rsa, int type, struct in6_addr *hit);
int dsa_to_dns_key_rr(DSA *dsa, unsigned char **buf);

DSA *create_dsa_key(int bits);
RSA *create_rsa_key(int bits);
int save_dsa_private_key(const char *filenamebase, DSA *dsa);
int load_dsa_private_key(const char *filenamebase, DSA **dsa);
int load_dsa_public_key(const char *filenamebase, DSA **dsa);

#endif /* HIPD_CRYPTO */
