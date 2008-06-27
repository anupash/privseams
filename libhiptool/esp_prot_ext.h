#ifndef ESP_PROT_EXT_H_
#define ESP_PROT_EXT_H_

#include <openssl/sha.h>

// the transforms used by esp protection extension
#define ESP_PROT_TRANSFORM_UNUSED		 0
#define ESP_PROT_TRANSFORM_DEFAULT		 1

// default length of the hash function output used in the chain
#define DEFAULT_HASH_LENGTH 4 // (in bytes)
//#define DEFAULT_SALT_LENGTH 0 // (in bytes)

// change this, if you are changing the hash function
#define MAX_HASH_LENGTH SHA_DIGEST_LENGTH

// different hc_length in order not to spoil calculation time for short connections
#define HC_LENGTH_BEX_STORE 1000 
#define HC_LENGTH_STEP1 10000
#define REMAIN_THRESHOLD 0.2

typedef struct esp_hash_item
{
	uint8_t transform; /* the transform determines the hash and salt lengths */
	unsigned char *hash; /* the hash value including the salt */
} esp_hash_item_t;

typedef struct esp_hchain
{
	uint8_t transform; /* the transform determines the hash and salt lengths */
	hash_chain_t *hchain; /* the hash-chain itself */
} esp_hchain_t;

// (hash, salt)-length for the respective transform in bytes
int esp_prot_transforms[2] = {0, 8};

int esp_prot_ext_init(void);
int add_esp_prot_hash(hip_sadb_entry *entry, unsigned char *out_hash, int *out_length);
int verify_esp_prot_hash(hip_sadb_entry *entry, unsigned char *hash_value);
int esp_prot_ext_maintainance(void);
int send_esp_protection_extension_to_hipd(void);
int send_anchor_list_update_to_hipd(void);
int send_next_anchor_to_hipd(unsigned char *anchor);

#endif /*ESP_PROT_EXT_H_*/
