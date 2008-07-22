#ifndef ESP_PROT_H_
#define ESP_PROT_H_

#include "hashchain_store.h"
#include "user_ipsec_sadb.h"

/* defines the default tolerance when verifying hash-chain elements */
#define DEFAULT_VERIFY_WINDOW 10

#define NUM_TRANSFORMS				1
#define NUM_HASH_FUNCTIONS			1
#define NUM_HASH_LENGTHS			1

#if 0
 /**** helper defines for the index boundaries of the static arrays defined below ****/

/* When adding a new transform, make sure to also add it in esp_prot_common.h.
 * Ensure to add new hash-functions in the end of hash_functions[] and keep the
 * same order of the hash-lengths in hash_lengths[][] as in the define list for the
 * transforms in esp_prot_common.h. */

/* for transforms array, ESP_PROT_TFM_UNUSED is not counted here */
#define NUM_TRANSFORMS				5
/* for first dimension */
#define NUM_HASH_FUNCTIONS			2
/* array index boundaries for second dimension */
#define NUM_HASH_LENGTHS			3
#endif

/* for bex_hchain_lengths[] */
#define NUM_BEX_HCHAIN_LENGTHS		1
 /* for update_hchain_lengths[] */
#define NUM_UPDATE_HCHAIN_LENGTHS	1

static const hash_function_t hash_functions[] = {SHA1};
static const int hash_lengths[][] = {{8}};

#if 0
static const hash_function_t hash_functions[] = {SHA1, MD5};
static const int hash_lengths[][] = {{8, 16, 20}, {8, 20, 0}};
#endif

static const int bex_hchain_lengths[] = {10};
static const int update_hchain_lengths[] = {1000};


/* maps from the transform_id defined above to the hash-function id
 * and hash length id
 *
 * NOTE: this ensures, we don't use uninitialised
 *       (hash_function, hash_length)-combinations
 */
typedef struct esp_prot_transform
{
	int hash_func_id;
	int hash_length_id;
} esp_prot_transform_t;


int esp_prot_init(void);
int esp_prot_set_sadb(hip_sa_entry_t *entry, uint8_t esp_prot_transform,
		unsigned char *esp_prot_anchor, int direction);
int add_esp_prot_hash(unsigned char *out_hash, int *out_length, hip_sa_entry_t *entry);
int verify_esp_prot_hash(hip_sa_entry_t *entry, unsigned char *hash_value);
hash_chain_t * esp_prot_get_corresponding_hchain(unsigned char *hchain_anchor,
		uint8_t transform);
int get_esp_data_offset(hip_sa_entry_t *entry);
int esp_prot_ext_maintainance(hip_sa_entry_t *entry);

#endif /*ESP_PROT_H_*/
