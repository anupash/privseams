#ifndef ESP_PROT_API_H_
#define ESP_PROT_API_H_

#include "hashchain_store.h"
#include "user_ipsec_sadb.h"
#include "esp_prot_fw_msg.h"
#include "esp_prot_common.h"
#include "hip_statistics.h"

/* defines the default tolerance when verifying hash-chain elements
 *
 * @note set to the preferred anti-replay window size of ESP */
#define DEFAULT_VERIFY_WINDOW 		64
/* if unused hchain element count of the active_hchain falls below
 * this threshold (% of max count), it will trigger the setup of
 * a new next_hchain */
#define REMAIN_HASHES_TRESHOLD		0.0
#if 0
#define REMAIN_HASHES_TRESHOLD		0.5
#endif
/* as using different hchain lengths for bex is not supported in esp_prot,
 * we can set a default length statically */
#define DEFAULT_HCHAIN_LENGTH_ID	0
 /* for update_hchain_lengths[] */
#define NUM_UPDATE_HCHAIN_LENGTHS	1
/* number of hierarchies used to link hchains */
#define NUM_BEX_HIERARCHIES			1
#define NUM_UPDATE_HIERARCHIES		1


/* maps from the transform_id defined above to the hash-function id
 * and hash length id
 *
 * NOTE: this ensures, we don't use uninitialized
 *       (hash_function, hash_length)-combinations in the array
 */
typedef struct esp_prot_tfm
{
	int is_used;
	int hash_func_id;
	int hash_length_id;
} esp_prot_tfm_t;

struct esp_anchor_item
{
	uint32_t seq;
	uint8_t transform;
	uint32_t hash_item_length;
	unsigned char *active_anchor;
	unsigned char *next_anchor;
	uint8_t root_length;
	unsigned char *root;
};


int esp_prot_init(void);
int esp_prot_uninit(void);
int esp_prot_sa_entry_set(hip_sa_entry_t *entry, uint8_t esp_prot_transform,
		uint32_t hash_item_length, unsigned char *esp_prot_anchor, int update);
void esp_prot_sa_entry_free(hip_sa_entry_t *entry);
int esp_prot_add_hash(unsigned char *out_hash, int *out_length,
		hip_sa_entry_t *entry);
#if 0
int esp_prot_verify(hip_sa_entry_t *entry, unsigned char *hash_value);
#endif
int esp_prot_verify_hash(hash_function_t hash_function, int hash_length,
		unsigned char *active_anchor, unsigned char *next_anchor,
		unsigned char *hash_value, int tolerance, unsigned char *active_root,
		int active_root_length, unsigned char *next_root, int next_root_length);
esp_prot_tfm_t * esp_prot_resolve_transform(uint8_t transform);
hash_function_t esp_prot_get_hash_function(uint8_t transform);
int esp_prot_get_hash_length(uint8_t transform);
void * esp_prot_get_bex_item_by_anchor(unsigned char *item_anchor,
		uint8_t transform);
int esp_prot_get_data_offset(hip_sa_entry_t *entry);
int esp_prot_sadb_maintenance(hip_sa_entry_t *entry);

#endif /*ESP_PROT_API_H_*/
