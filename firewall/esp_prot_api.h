#ifndef ESP_PROT_H_
#define ESP_PROT_H_

#include "hashchain_store.h"
#include "user_ipsec_sadb.h"

/* defines the default tolerance when verifying hash-chain elements */
#define DEFAULT_VERIFY_WINDOW 		10
/* if unused hchain element count of the active_hchain falls below
 * this threshold (% of max count), it will trigger the setup of
 * a new next_hchain */
#define REMAIN_ELEMENTS_TRESHOLD	0.2

/* as using different hchain lengths is not implemented in esp_prot for now,
 * we can set a default length statically */
#define DEFAULT_HCHAIN_LENGTH_ID	0

 /* for update_hchain_lengths[] */
#define NUM_UPDATE_HCHAIN_LENGTHS	1

static const int bex_hchain_length = 100;
static const int update_hchain_lengths[] = {1000};


/* maps from the transform_id defined above to the hash-function id
 * and hash length id
 *
 * NOTE: this ensures, we don't use uninitialized
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
esp_prot_transform_t * esp_prot_resolve_transform(uint8_t transform);
hash_function_t esp_prot_get_hash_function(uint8_t transform);
int esp_prot_get_hash_length(uint8_t transform);
hash_chain_t * esp_prot_get_bex_hchain_by_anchor(unsigned char *hchain_anchor,
		uint8_t transform);
int get_esp_data_offset(hip_sa_entry_t *entry);
int esp_prot_sadb_maintenance(hip_sa_entry_t *entry);

#endif /*ESP_PROT_H_*/
